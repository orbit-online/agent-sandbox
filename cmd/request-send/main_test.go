package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The test binary is the fake step too: with FAKE_STEP_KEY set it answers `step kms key URI` with that key's public
// half and `step kms sign URI DIGEST` with its signature of the digest, base64 ASN.1, as step-kms-plugin does for a
// TPM key, recording each run in FAKE_STEP_LOG. FAKE_STEP_FAIL makes the first n signatures fail with the TPM's
// intermittent error
func TestMain(m *testing.M) {
	if os.Getenv("FAKE_STEP_KEY") != "" {
		os.Exit(fakeStep(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func fakeStep(args []string) int {
	keyPEM, _ := os.ReadFile(os.Getenv("FAKE_STEP_KEY"))
	block, _ := pem.Decode(keyPEM)
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	log, _ := os.OpenFile(os.Getenv("FAKE_STEP_LOG"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	line, _ := json.Marshal(args)
	fmt.Fprintf(log, "%s\n", line)
	log.Close()
	switch {
	case len(args) == 3 && args[0] == "kms" && args[1] == "key":
		der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
		pem.Encode(os.Stdout, &pem.Block{Type: "PUBLIC KEY", Bytes: der})
	case len(args) == 4 && args[0] == "kms" && args[1] == "sign":
		counter := os.Getenv("FAKE_STEP_FAIL")
		if n, _ := strconv.Atoi(readFile(counter)); n > 0 {
			os.WriteFile(counter, []byte(strconv.Itoa(n-1)), 0o600)
			fmt.Fprintln(os.Stderr, "error signing: tpm2: TPM_RC_SIZE (parameter 1): error code 0x15 : structure is the wrong size")
			return 1
		}
		digest, err := hex.DecodeString(args[3])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		sig, _ := ecdsa.SignASN1(rand.Reader, key, digest)
		fmt.Println(base64.StdEncoding.EncodeToString(sig))
	default:
		fmt.Fprintln(os.Stderr, "fake step: unexpected arguments", args)
		return 1
	}
	return 0
}

func readFile(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

// got is a request the server received, with the client certificate's CN
type got struct {
	Method, URI, ContentType, Body, CN string
}

// world is a home with a users CA certificate for cloud-production, the TPM key behind the fake step, and a server
// that requires a client certificate from that users CA
type world struct {
	key     *ecdsa.PrivateKey
	usersCA *x509.Certificate
	caKey   *ecdsa.PrivateKey
	step    string
	log     string
	failing string
	server  *httptest.Server
	caFile  string
	handler http.HandlerFunc

	mu   sync.Mutex
	reqs []got
}

func newWorld(t *testing.T) *world {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", filepath.Join(dir, "home"))
	w := &world{log: filepath.Join(dir, "step.log"), failing: filepath.Join(dir, "fail")}
	w.caKey = genKey(t)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "users CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &w.caKey.PublicKey, w.caKey)
	if err != nil {
		t.Fatal(err)
	}
	w.usersCA, _ = x509.ParseCertificate(der)
	w.key = genKey(t)
	writeCert(t, "production", w.certFor(t, &w.key.PublicKey, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)))
	keyFile := filepath.Join(dir, "key.pem")
	kd, _ := x509.MarshalECPrivateKey(w.key)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600)
	t.Setenv("FAKE_STEP_KEY", keyFile)
	t.Setenv("FAKE_STEP_LOG", w.log)
	t.Setenv("FAKE_STEP_FAIL", w.failing)
	// The fake step is this binary, by a name of its own
	w.step = filepath.Join(dir, "bin", "step")
	os.MkdirAll(filepath.Dir(w.step), 0o755)
	exe, _ := os.Executable()
	if err := os.Symlink(exe, w.step); err != nil {
		t.Fatal(err)
	}
	old := retryAfter
	retryAfter = time.Millisecond
	t.Cleanup(func() { retryAfter = old })

	w.server = httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		g := got{Method: r.Method, URI: r.RequestURI, ContentType: r.Header.Get("Content-Type"), Body: string(body)}
		if len(r.TLS.PeerCertificates) > 0 {
			g.CN = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		w.mu.Lock()
		w.reqs = append(w.reqs, g)
		w.mu.Unlock()
		if w.handler != nil {
			w.handler(rw, r)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(`{"ok":true}`))
	}))
	pool := x509.NewCertPool()
	pool.AddCert(w.usersCA)
	w.server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	w.server.StartTLS()
	t.Cleanup(w.server.Close)
	w.caFile = filepath.Join(dir, "ca.pem")
	os.WriteFile(w.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: w.server.Certificate().Raw}), 0o600)
	return w
}

func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// certFor is a client certificate for pub, as the users CA issues them
func (w *world) certFor(t *testing.T, pub *ecdsa.PublicKey, from, to time.Time) []byte {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "agent",
		Organization: []string{"employees"}}, NotBefore: from, NotAfter: to,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, w.usersCA, pub, w.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// writeCert writes the certificate where step keeps it, followed by its CA's as step writes a bundle
func writeCert(t *testing.T, env string, der []byte) {
	t.Helper()
	home, _ := os.UserHomeDir()
	path := filepath.Join(home, ".step", "certs", "cloud-"+env+".crt")
	os.MkdirAll(filepath.Dir(path), 0o700)
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("intermediate")})...)
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
}

type a = map[string]any

// send runs the binary as the broker does, with the module's argv for scope and the call on stdin, to the server
func (w *world) send(scope string, arguments any) (int, string, string) {
	return w.sendTo(scope, a{"origin": w.server.URL}, arguments, "production")
}

// sendTo is send with the server's origin for env, and another origin for the other env
func (w *world) sendTo(scope string, bounding, arguments any, env string) (int, string, string) {
	call, _ := json.Marshal(a{"capability": "request-send", "command": "send", "grant": "g-test",
		"bounding": bounding, "arguments": arguments, "validity": "PT1H"})
	other := map[string]string{"production": "staging", "staging": "production"}[env]
	return w.raw(string(call), "send", "--scope="+scope, "--step="+w.step,
		"--origin="+w.server.URL, "--env="+env, "--ca="+w.caFile,
		"--origin=https://other.example.com", "--env="+other, "--ca=/etc/ssl/other.pem")
}

func (w *world) raw(stdin string, argv ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := run(argv, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

func (w *world) got() []got {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]got(nil), w.reqs...)
}

// stepRuns is what the fake step was run with
func (w *world) stepRuns() [][]string {
	var runs [][]string
	for _, line := range strings.Split(strings.TrimSpace(readFile(w.log)), "\n") {
		var r []string
		if json.Unmarshal([]byte(line), &r) == nil {
			runs = append(runs, r)
		}
	}
	return runs
}

func decode(t *testing.T, out string) answer {
	t.Helper()
	var ans answer
	if err := json.Unmarshal([]byte(out), &ans); err != nil {
		t.Fatalf("%q: %v", out, err)
	}
	return ans
}

func TestSend(t *testing.T) {
	for _, tt := range []struct {
		scope, method, path, body string
	}{
		{"read", "GET", "/api/orbit/v1/tickets?query=printer+%26+co&status=open", ""},
		{"write", "GET", "/api/orbit/v1/meta", ""},
		{"write", "POST", "/api/orbit/v1/tickets/7/reply", `{"body":"Hi <b>there</b>\nBye","format":"html"}`},
	} {
		t.Run(tt.scope+" "+tt.method, func(t *testing.T) {
			w := newWorld(t)
			args := a{"method": tt.method, "path": tt.path}
			if tt.scope == "write" {
				args["body"] = tt.body
			}
			code, out, errOut := w.send(tt.scope, args)
			if code != 0 {
				t.Fatalf("exit %d: %s", code, errOut)
			}
			if ans := decode(t, out); ans != (answer{200, "application/json", `{"ok":true}`}) {
				t.Errorf("answer %+v", ans)
			}
			reqs := w.got()
			want := got{Method: tt.method, URI: tt.path, Body: tt.body, CN: "agent"}
			if tt.method == "POST" {
				want.ContentType = "application/json"
			}
			if len(reqs) != 1 || reqs[0] != want {
				t.Errorf("requests %+v, want %+v", reqs, want)
			}
			// The TPM key's public half, then its signature of the handshake
			runs := w.stepRuns()
			if len(runs) != 2 || strings.Join(runs[0], " ") != "kms key tpmkms:name=cloud-production" ||
				runs[1][2] != "tpmkms:name=cloud-production" || len(runs[1][3]) != 64 {
				t.Errorf("step runs %v", runs)
			}
		})
	}
}

func TestStagingKeyAndCert(t *testing.T) {
	w := newWorld(t)
	home, _ := os.UserHomeDir()
	os.Rename(filepath.Join(home, ".step", "certs", "cloud-production.crt"),
		filepath.Join(home, ".step", "certs", "cloud-staging.crt"))
	code, _, errOut := w.sendTo("read", a{"origin": w.server.URL}, a{"method": "GET", "path": "/"}, "staging")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if runs := w.stepRuns(); runs[0][2] != "tpmkms:name=cloud-staging" {
		t.Errorf("step runs %v", runs)
	}
}

// Calls the module's schema already keeps out are refused again, exit 2, before step or the server hear of them
func TestRefusals(t *testing.T) {
	long := "/" + strings.Repeat("x", maxPath)
	for _, tt := range []struct {
		name, scope string
		bounding    any
		args        any
	}{
		{"POST for read", "read", nil, a{"method": "POST", "path": "/"}},
		{"DELETE for write", "write", nil, a{"method": "DELETE", "path": "/", "body": ""}},
		{"an origin not configured", "read", a{"origin": "https://elsewhere.example.com"}, a{"method": "GET", "path": "/"}},
		{"no origin", "read", a{}, a{"method": "GET", "path": "/"}},
		{"an origin with a path", "read", a{"origin": "https://other.example.com/x"}, a{"method": "GET", "path": "/"}},
		{"a body for read", "read", nil, a{"method": "GET", "path": "/", "body": ""}},
		{"no body for write", "write", nil, a{"method": "POST", "path": "/"}},
		{"a GET with a body", "write", nil, a{"method": "GET", "path": "/", "body": "x"}},
		{"a relative path", "read", nil, a{"method": "GET", "path": "x"}},
		{"a path with a space", "read", nil, a{"method": "GET", "path": "/a b"}},
		{"a path with a fragment", "read", nil, a{"method": "GET", "path": "/a#b"}},
		{"a path to another host", "read", nil, a{"method": "GET", "path": "@evil.example.com/"}},
		{"a long path", "read", nil, a{"method": "GET", "path": long}},
		{"control characters", "write", nil, a{"method": "POST", "path": "/", "body": "a\x1bb"}},
		{"a long body", "write", nil, a{"method": "POST", "path": "/", "body": strings.Repeat("x", maxBody+1)}},
		{"a number", "read", nil, a{"method": "GET", "path": 1}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			w := newWorld(t)
			bounding := tt.bounding
			if bounding == nil {
				bounding = a{"origin": w.server.URL}
			}
			if code, out, _ := w.sendTo(tt.scope, bounding, tt.args, "production"); code != exitRefused {
				t.Errorf("exit %d: %s", code, out)
			}
			if len(w.got()) != 0 || len(w.stepRuns()) != 0 {
				t.Error("it went out")
			}
		})
	}
	w := newWorld(t)
	origin := []string{"--origin=" + w.server.URL, "--env=production", "--ca=" + w.caFile}
	if code, _, _ := w.raw(`{"command": "sign", "bounding": {"origin": "`+w.server.URL+`"}, "arguments": {"method": "GET", "path": "/"}}`,
		append([]string{"send", "--scope=read", "--step=" + w.step}, origin...)...); code != exitRefused {
		t.Errorf("command sign: exit %d", code)
	}
	for _, argv := range [][]string{
		append([]string{"send", "--scope=admin", "--step=" + w.step}, origin...),
		{"send", "--scope=read", "--step=" + w.step, "--origin=" + w.server.URL, "--env=dev", "--ca=" + w.caFile},
		{"send", "--scope=read", "--step=" + w.step, "--origin=" + w.server.URL, "--env=production", "--ca=ca.pem"},
		append([]string{"send", "--scope=read", "--step=step"}, origin...),
		{"send", "--scope=read", "--step=" + w.step, "--origin=" + w.server.URL, "--env=production"},
		{"send", "--scope=read", "--step=" + w.step},
	} {
		if code, _, _ := w.raw(`{}`, argv...); code != exitRefused {
			t.Errorf("%v: exit %d", argv, code)
		}
	}
}

// The answer as it came: an error status, a redirect not followed
func TestAnswers(t *testing.T) {
	w := newWorld(t)
	w.handler = func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/moved" {
			http.Redirect(rw, r, "https://elsewhere.example.com/", http.StatusFound)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(403)
		rw.Write([]byte(`{"error":"No active agent"}`))
	}
	_, out, _ := w.send("read", a{"method": "GET", "path": "/meta"})
	if ans := decode(t, out); ans != (answer{403, "application/json", `{"error":"No active agent"}`}) {
		t.Errorf("%+v", ans)
	}
	_, out, _ = w.send("read", a{"method": "GET", "path": "/moved"})
	if ans := decode(t, out); ans.Status != 302 {
		t.Errorf("%+v", ans)
	}
	if len(w.got()) != 2 {
		t.Errorf("requests %+v", w.got())
	}
}

// Sending fails, exit 1: an answer too big or not UTF-8, a server the CA doesn't vouch for, a certificate that isn't
// the TPM key's, isn't there or isn't valid now, step failing for good
func TestSendingFails(t *testing.T) {
	for _, tt := range []struct {
		name  string
		setup func(t *testing.T, w *world)
		want  string
	}{
		{"too big", func(t *testing.T, w *world) {
			w.handler = func(rw http.ResponseWriter, _ *http.Request) { rw.Write(bytes.Repeat([]byte("x"), maxAnswer+1)) }
		}, "over"},
		{"not UTF-8", func(t *testing.T, w *world) {
			w.handler = func(rw http.ResponseWriter, _ *http.Request) { rw.Write([]byte("\"\xff\"")) }
		}, "UTF-8"},
		{"another CA's server", func(t *testing.T, w *world) {
			// httptest's servers share one certificate: the users CA stands in for another CA
			os.WriteFile(w.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: w.usersCA.Raw}), 0o600)
		}, "certificate"},
		{"another key's certificate", func(t *testing.T, w *world) {
			writeCert(t, "production", w.certFor(t, &genKey(t).PublicKey, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)))
		}, "not the TPM key"},
		{"no certificate", func(t *testing.T, w *world) {
			home, _ := os.UserHomeDir()
			os.Remove(filepath.Join(home, ".step", "certs", "cloud-production.crt"))
		}, "Reading the certificate"},
		{"expired", func(t *testing.T, w *world) {
			writeCert(t, "production", w.certFor(t, &w.key.PublicKey, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)))
		}, "renew it"},
		{"step fails", func(t *testing.T, w *world) { t.Setenv("FAKE_STEP_KEY", "/nonexistent") }, "step kms key"},
		{"the TPM fails for good", func(t *testing.T, w *world) { os.WriteFile(w.failing, []byte("9"), 0o600) }, "wrong size"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			w := newWorld(t)
			tt.setup(t, w)
			code, out, errOut := w.send("read", a{"method": "GET", "path": "/"})
			if code != exitFailed || out != "" || !strings.Contains(errOut, tt.want) {
				t.Errorf("exit %d, %q, %q", code, out, errOut)
			}
		})
	}
}

// The TPM's intermittent failure is retried
func TestTPMRetry(t *testing.T) {
	w := newWorld(t)
	os.WriteFile(w.failing, []byte("2"), 0o600)
	if code, _, errOut := w.send("read", a{"method": "GET", "path": "/"}); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if n := len(w.stepRuns()); n != 4 {
		t.Errorf("%d step runs", n)
	}
}

func TestHelp(t *testing.T) {
	w := &world{}
	if code, out, _ := w.raw("", "--help"); code != 0 || !strings.Contains(out, "Usage:") {
		t.Errorf("%d %s", code, out)
	}
}
