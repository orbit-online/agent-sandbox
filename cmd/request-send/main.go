package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
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

const usage = `request-send - Send one HTTP request for a sandboxed agent through your authenticating proxy

Usage:
  request-send send --scope=<scope> (--origin=<url> --proxy=<url> --ca=<file>)...
  request-send --help

Options:
  --scope=<scope>  read or write: the capability's. read sends GET only, write GET and POST.
  --origin=<url>   An origin calls may send to, such as https://helpdesk.example.com, followed by its --proxy and
                   --ca.
  --proxy=<url>    The HTTPS proxy requests to the origin go through, https://host[:port], which authenticates them
                   as you, such as kmsproxy presenting your client certificate.
  --ca=<file>      The PEM CAs the proxy's certificate and the origin's, as the proxy presents it, must chain to,
                   and the only ones trusted.

A host command of agent-sandbox's permissions broker, which runs it once per
call with the call as JSON on stdin: {"bounding": {"origin"}, "arguments":
{"method", "path", and for write "body"}}. It sends that one request to the
origin through its proxy, TLS 1.3 to both, with a body as application/json.
It follows no redirects.

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
)

// How long a request may take
const requestTime = 60 * time.Second

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
	origins, _ := opts["--origin"].([]string)
	proxies, _ := opts["--proxy"].([]string)
	cas, _ := opts["--ca"].([]string)
	if len(proxies) != len(origins) || len(cas) != len(origins) {
		fmt.Fprint(stderr, usage)
		return exitRefused
	}
	for i, o := range origins {
		s.origins[o] = target{proxies[i], cas[i]}
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
	scope   string
	origins map[string]target
}

// target is an origin's proxy and the CAs the certificates must chain to
type target struct {
	proxy, ca string
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
		if u, err := url.Parse(t.proxy); err != nil || u.Scheme != "https" || u.Host == "" || u.Scheme+"://"+u.Host != t.proxy {
			return "", refuse("--proxy of %s is https://host[:port], not %q", o, t.proxy)
		}
		if !filepath.IsAbs(t.ca) {
			return "", refuse("--ca of %s is an absolute path, not %q", o, t.ca)
		}
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

// send sends the request to its origin through its proxy, and only there: TLS 1.3 to the proxy and the origin, both
// with certificates from the origin's CAs
func (s sender) send(r request) (*answer, error) {
	pemCAs, err := os.ReadFile(r.ca)
	if err != nil {
		return nil, fmt.Errorf("Reading the CAs of %s: %w", r.origin, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemCAs) {
		return nil, fmt.Errorf("No certificates in %s", r.ca)
	}
	proxy, _ := url.Parse(r.proxy)
	client := &http.Client{
		Transport: &http.Transport{
			// The proxy's TLS takes this config too
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots},
			Proxy:             http.ProxyURL(proxy),
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
