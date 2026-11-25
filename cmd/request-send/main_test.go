package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// got is a request the origin received
type got struct {
	Method, URI, ContentType, Body string
}

// world is an origin and an HTTPS proxy that tunnels to it, both with httptest's certificate, which caFile holds
type world struct {
	server, proxy *httptest.Server
	caFile        string
	handler       http.HandlerFunc

	mu       sync.Mutex
	reqs     []got
	connects []string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{}
	w.server = httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.mu.Lock()
		w.reqs = append(w.reqs, got{r.Method, r.RequestURI, r.Header.Get("Content-Type"), string(body)})
		w.mu.Unlock()
		if w.handler != nil {
			w.handler(rw, r)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(w.server.Close)
	w.proxy = httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		w.connects = append(w.connects, r.Method+" "+r.Host)
		w.mu.Unlock()
		if r.Method != http.MethodConnect {
			http.Error(rw, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		up, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadGateway)
			return
		}
		rw.WriteHeader(http.StatusOK)
		conn, buf, _ := rw.(http.Hijacker).Hijack()
		go func() { io.Copy(up, buf); up.Close() }()
		io.Copy(conn, up)
		conn.Close()
	}))
	t.Cleanup(w.proxy.Close)
	w.caFile = filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(w.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: w.server.Certificate().Raw}), 0o600)
	return w
}

type a = map[string]any

// send runs the binary as the broker does, with the module's argv for scope and the call on stdin, to the server
func (w *world) send(scope string, arguments any) (int, string, string) {
	return w.sendTo(scope, a{"origin": w.server.URL}, arguments)
}

// sendTo is send with the call bounded by bounding, and another origin configured
func (w *world) sendTo(scope string, bounding, arguments any) (int, string, string) {
	call, _ := json.Marshal(a{"capability": "request-send", "command": "send", "grant": "g-test",
		"bounding": bounding, "arguments": arguments, "validity": "PT1H"})
	return w.raw(string(call), "send", "--scope="+scope,
		"--origin="+w.server.URL, "--proxy="+w.proxy.URL, "--ca="+w.caFile,
		"--origin=https://other.example.com", "--proxy=https://localhost:8090", "--ca=/etc/ssl/other.pem")
}

func (w *world) raw(stdin string, argv ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := run(argv, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

func (w *world) got() ([]got, []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]got(nil), w.reqs...), append([]string(nil), w.connects...)
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
			reqs, connects := w.got()
			want := got{Method: tt.method, URI: tt.path, Body: tt.body}
			if tt.method == "POST" {
				want.ContentType = "application/json"
			}
			if len(reqs) != 1 || reqs[0] != want {
				t.Errorf("requests %+v, want %+v", reqs, want)
			}
			if host := strings.TrimPrefix(w.server.URL, "https://"); len(connects) != 1 || connects[0] != "CONNECT "+host {
				t.Errorf("through the proxy %v, want CONNECT %s", connects, host)
			}
		})
	}
}

// Calls the module's schema already keeps out are refused again, exit 2, before the proxy hears of them
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
			if code, out, _ := w.sendTo(tt.scope, bounding, tt.args); code != exitRefused {
				t.Errorf("exit %d: %s", code, out)
			}
			if reqs, connects := w.got(); len(reqs) != 0 || len(connects) != 0 {
				t.Error("it went out")
			}
		})
	}
	w := newWorld(t)
	origin := func(proxy, ca string) []string {
		return []string{"send", "--scope=read", "--origin=" + w.server.URL, "--proxy=" + proxy, "--ca=" + ca}
	}
	if code, _, _ := w.raw(`{"command": "sign", "bounding": {"origin": "`+w.server.URL+`"}, "arguments": {"method": "GET", "path": "/"}}`,
		origin(w.proxy.URL, w.caFile)...); code != exitRefused {
		t.Errorf("command sign: exit %d", code)
	}
	for _, argv := range [][]string{
		{"send", "--scope=admin", "--origin=" + w.server.URL, "--proxy=" + w.proxy.URL, "--ca=" + w.caFile},
		origin("http://localhost:8090", w.caFile),
		origin("https://localhost:8090/", w.caFile),
		origin("https://user@localhost:8090", w.caFile),
		origin("localhost:8090", w.caFile),
		origin(w.proxy.URL, "ca.pem"),
		{"send", "--scope=read", "--origin=" + w.server.URL, "--ca=" + w.caFile},
		{"send", "--scope=read"},
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
	if reqs, _ := w.got(); len(reqs) != 2 {
		t.Errorf("requests %+v", reqs)
	}
}

// Sending fails, exit 1: an answer too big or not UTF-8, certificates the CAs don't vouch for, no proxy
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
		{"another CA", func(t *testing.T, w *world) {
			os.WriteFile(w.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: anotherCA(t)}), 0o600)
		}, "certificate"},
		{"no CAs", func(t *testing.T, w *world) { os.WriteFile(w.caFile, nil, 0o600) }, "No certificates"},
		{"no proxy", func(t *testing.T, w *world) { w.proxy.Close() }, "proxyconnect"},
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

// anotherCA is a CA certificate, DER
func anotherCA(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "another CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestHelp(t *testing.T) {
	w := &world{}
	if code, out, _ := w.raw("", "--help"); code != 0 || !strings.Contains(out, "Usage:") {
		t.Errorf("%d %s", code, out)
	}
}
