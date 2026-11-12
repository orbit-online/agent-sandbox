package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/docopt/docopt-go"
	"github.com/orbit-online/agent-sandbox/internal/journal"
)

const usage = `request-send - Send one HTTP request for a sandboxed Claude with your users CA certificate

Usage:
  request-send send --scope=<scope> --step=<path> (--origin=<url> --env=<env> --ca=<file>)...
  request-send --help

Options:
  --scope=<scope>  read or write: the capability's. read sends GET only, write GET and POST.
  --step=<path>    The step binary, finding step-kms-plugin.
  --origin=<url>   An origin calls may send to, such as https://support-staff.org-production.orbit.dev, followed by
                   its --env and --ca.
  --env=<env>      production or staging: the client certificate for the origin is ~/.step/certs/cloud-<env>.crt, its
                   key the TPM key tpmkms:name=cloud-<env>.
  --ca=<file>      The PEM CAs the origin's server certificate must chain to, and the only ones trusted.

A host command of agent-sandbox's permissions broker, which runs it once per
call with the call as JSON on stdin: {"bounding": {"origin"}, "arguments":
{"method", "path", and for write "body"}}. It sends that one request to the
origin over TLS 1.3, presenting the certificate, the TPM signing the handshake,
and a body as application/json. It follows no redirects.

Prints {"status", "content_type", "body"}: the answer, refused when it's over
8 MiB or not UTF-8. Exits 2 on input it refuses, 1 when sending fails.
`

// What the broker hands a host command on stdin. Unknown fields are left alone, the broker may add some
type call struct {
	Command   string                     `json:"command"`
	Bounding  map[string]json.RawMessage `json:"bounding"`
	Arguments map[string]json.RawMessage `json:"arguments"`
}

// Exit codes
const (
	exitFailed  = 1
	exitRefused = 2
)

// An error from input the binary refuses, as opposed to sending failing
type refused struct{ error }

func refuse(format string, a ...any) error { return refused{fmt.Errorf(format, a...)} }

// The limits the Nix module declares, checked again here: the broker's checks are the module's, not this binary's
const (
	maxPath = 2048
	maxBody = 262144
	// The most of an answer passed on
	maxAnswer = 8 << 20
)

var (
	// A path and query: printable ASCII, no spaces, from the root
	pathPattern = regexp.MustCompile(`^/[!-~]*$`)
	methods     = map[string][]string{"read": {"GET"}, "write": {"GET", "POST"}}
	envs        = []string{"production", "staging"}
)

// The pause before retrying a signature the TPM failed intermittently, how often to try, how long step may take,
// and the request
var (
	retryAfter  = time.Second
	attempts    = 3
	stepTime    = 30 * time.Second
	requestTime = 60 * time.Second
)

func main() {
	journal.Setup()
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run is main for the tests: the exit code for args, the call on stdin
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	help := false
	parser := &docopt.Parser{HelpHandler: func(err error, _ string) { help = err == nil }}
	opts, err := parser.ParseArgs(usage, args, "")
	switch {
	case help:
		fmt.Fprint(stdout, usage)
		return 0
	case err != nil:
		fmt.Fprint(stderr, usage)
		return exitRefused
	}
	s := sender{origins: map[string]target{}}
	s.scope, _ = opts["--scope"].(string)
	s.step, _ = opts["--step"].(string)
	origins, _ := opts["--origin"].([]string)
	envs, _ := opts["--env"].([]string)
	cas, _ := opts["--ca"].([]string)
	if len(envs) != len(origins) || len(cas) != len(origins) {
		fmt.Fprint(stderr, usage)
		return exitRefused
	}
	for i, o := range origins {
		s.origins[o] = target{envs[i], cas[i]}
	}
	out, err := s.do(stdin)
	if err != nil {
		fmt.Fprintln(stderr, err)
		if errors.As(err, &refused{}) {
			return exitRefused
		}
		return exitFailed
	}
	if _, err := fmt.Fprintln(stdout, out); err != nil {
		fmt.Fprintln(stderr, err)
		return exitFailed
	}
	return 0
}

type sender struct {
	scope, step string
	origins     map[string]target
}

// target is an origin's certificate, by env, and the CAs its server's must chain to
type target struct {
	env, ca string
}

// request is what a call asks to send
type request struct {
	origin, method, path, body string
	target
}

// answer is what the binary prints
type answer struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Body        string `json:"body"`
}

// do sends the request of the call on stdin
func (s sender) do(stdin io.Reader) (string, error) {
	if _, ok := methods[s.scope]; !ok {
		return "", refuse("--scope is read or write, not %q", s.scope)
	}
	for o, t := range s.origins {
		if !slices.Contains(envs, t.env) {
			return "", refuse("--env is one of %v, not %q", envs, t.env)
		}
		if !filepath.IsAbs(t.ca) {
			return "", refuse("--ca of %s is an absolute path, not %q", o, t.ca)
		}
	}
	if !filepath.IsAbs(s.step) {
		return "", refuse("--step is an absolute path, not %q", s.step)
	}
	var c call
	if err := json.NewDecoder(io.LimitReader(stdin, 4<<20)).Decode(&c); err != nil {
		return "", refuse("Reading the call: %w", err)
	}
	r, err := s.read(c)
	if err != nil {
		return "", err
	}
	a, err := s.send(r)
	if err != nil {
		return "", err
	}
	out, err := json.Marshal(a)
	return string(out), err
}

// read checks the call: the command, an origin of the module's, exactly the arguments of the scope, each in its
// bounds
func (s sender) read(c call) (request, error) {
	var r request
	if c.Command != "send" {
		return r, refuse("No command %q", c.Command)
	}
	var ok bool
	if len(c.Bounding) != 1 || !str(c.Bounding["origin"], &r.origin) {
		return r, refuse("The call names no origin")
	}
	if r.target, ok = s.origins[r.origin]; !ok {
		return r, refuse("No origin %q", r.origin)
	}
	names := []string{"method", "path"}
	if s.scope == "write" {
		names = append(names, "body")
	}
	if len(c.Arguments) != len(names) {
		return r, refuse("The arguments are %v", names)
	}
	for _, n := range names {
		v := map[string]*string{"method": &r.method, "path": &r.path, "body": &r.body}[n]
		if !str(c.Arguments[n], v) {
			return r, refuse("Argument %s is missing or not a string", n)
		}
	}
	if !slices.Contains(methods[s.scope], r.method) {
		return r, refuse("The method is one of %v for %s, not %q", methods[s.scope], s.scope, r.method)
	}
	if len(r.path) > maxPath || !pathPattern.MatchString(r.path) {
		return r, refuse("The path is a path and query from /, printable ASCII, at most %d characters", maxPath)
	}
	if utf8.RuneCountInString(r.body) > maxBody {
		return r, refuse("The body is at most %d characters", maxBody)
	}
	if strings.IndexFunc(r.body, func(c rune) bool { return unicode.IsControl(c) && c != '\n' && c != '\t' }) >= 0 {
		return r, refuse("The body has control characters")
	}
	if r.method == "GET" && r.body != "" {
		return r, refuse("A GET has no body")
	}
	// The URL must be the origin's: a path can't move it elsewhere
	u, err := url.Parse(r.origin + r.path)
	if err != nil || u.Scheme+"://"+u.Host != r.origin || u.RequestURI() != r.path {
		return r, refuse("The request would go elsewhere than %s%s", r.origin, r.path)
	}
	return r, nil
}

// str decodes a JSON string, false if raw is none
func str(raw json.RawMessage, v *string) bool {
	return len(raw) > 0 && raw[0] == '"' && json.Unmarshal(raw, v) == nil
}

func (t target) key() string { return "tpmkms:name=cloud-" + t.env }

// send sends the request to its origin, and only there: TLS 1.3 to a server certificate from the origin's CAs,
// the origin's certificate, matched against its TPM key, as the client's
func (s sender) send(r request) (*answer, error) {
	cert, err := r.cert()
	if err != nil {
		return nil, err
	}
	pub, err := s.publicKey(r.target)
	if err != nil {
		return nil, err
	}
	if !pub.Equal(cert.PublicKey) {
		return nil, fmt.Errorf("The certificate %s is not the TPM key %s's", r.certPath(), r.key())
	}
	pemCAs, err := os.ReadFile(r.ca)
	if err != nil {
		return nil, fmt.Errorf("Reading the CAs of %s: %w", r.origin, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemCAs) {
		return nil, fmt.Errorf("No certificates in %s", r.ca)
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    roots,
				Certificates: []tls.Certificate{{Certificate: [][]byte{cert.Raw}, Leaf: cert,
					PrivateKey:                   tpmKey{s, r.target, pub},
					SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}}},
			},
			Proxy:             nil,
			ForceAttemptHTTP2: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       requestTime,
	}
	var body io.Reader
	if r.method != "GET" {
		body = strings.NewReader(r.body)
	}
	req, err := http.NewRequest(r.method, r.origin+r.path, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "request-send")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s%s: %w", r.method, r.origin, r.path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		return nil, fmt.Errorf("Reading the answer: %w", err)
	}
	if len(data) > maxAnswer {
		return nil, fmt.Errorf("The answer is over %d bytes", maxAnswer)
	}
	if !utf8.Valid(data) {
		return nil, errors.New("The answer isn't UTF-8")
	}
	slog.Info("Sent", "origin", r.origin, "method", r.method, "path", r.path, "body_bytes", len(r.body),
		"status", resp.StatusCode)
	return &answer{resp.StatusCode, resp.Header.Get("Content-Type"), string(data)}, nil
}

// tpmKey is the TPM key as a crypto.Signer: step kms sign signs the handshake's SHA-256 digest
type tpmKey struct {
	s   sender
	t   target
	pub *ecdsa.PublicKey
}

func (k tpmKey) Public() crypto.PublicKey { return k.pub }

// Sign returns the ASN.1 ECDSA signature step kms sign prints, base64, checked against the key. The TPM fails
// intermittently with "structure is the wrong size", which a retry gets past
func (k tpmKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 || len(digest) != 32 {
		return nil, fmt.Errorf("The TPM key signs SHA-256 digests only, not %v", opts.HashFunc())
	}
	var err error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			slog.Warn("The TPM failed intermittently, retrying", "err", err)
			time.Sleep(retryAfter)
		}
		var out []byte
		out, err = k.s.runStep(nil, "kms", "sign", k.t.key(), hex.EncodeToString(digest))
		if err == nil {
			sig, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
			if derr != nil || !ecdsa.VerifyASN1(k.pub, digest, sig) {
				return nil, fmt.Errorf("step kms sign returned no signature of the digest by %s", k.t.key())
			}
			return sig, nil
		}
		if !strings.Contains(err.Error(), "structure is the wrong size") {
			return nil, err
		}
	}
	return nil, err
}

func (t target) certPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".step", "certs", "cloud-"+t.env+".crt")
}

// cert is the users CA certificate, the first of its file, read at each call as step renews it, and valid now
func (t target) cert() (*x509.Certificate, error) {
	data, err := os.ReadFile(t.certPath())
	if err != nil {
		return nil, fmt.Errorf("Reading the certificate: %w", err)
	}
	var block *pem.Block
	for {
		block, data = pem.Decode(data)
		if block == nil || block.Type == "CERTIFICATE" {
			break
		}
	}
	if block == nil {
		return nil, fmt.Errorf("No certificate in %s", t.certPath())
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("The certificate in %s: %w", t.certPath(), err)
	}
	if now := time.Now(); now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, fmt.Errorf("The certificate %s is valid from %s to %s, not now: renew it", t.certPath(),
			cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	}
	return cert, nil
}

// publicKey is the TPM key's, a P-256 one
func (s sender) publicKey(t target) (*ecdsa.PublicKey, error) {
	out, err := s.runStep(nil, "kms", "key", t.key())
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(out)
	if block == nil {
		return nil, fmt.Errorf("step kms key printed no PEM key for %s", t.key())
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("The key of %s: %w", t.key(), err)
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("The key %s isn't a P-256 key", t.key())
	}
	return pub, nil
}

// runStep runs step with args, stdin on its stdin, and returns its stdout; its stderr is in the error
func (s sender) runStep(stdin []byte, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), stepTime)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.step, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 2000 {
			msg = msg[len(msg)-2000:]
		}
		return nil, fmt.Errorf("step %s: %w: %s", strings.Join(args[:2], " "), err, msg)
	}
	return stdout.Bytes(), nil
}
