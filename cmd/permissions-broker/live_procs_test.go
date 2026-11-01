package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"pgregory.net/rapid"
)

// The processes of the live state machine (live_test.go): this test binary again, inside the sandbox, as callers on
// request.sock, and the host side's clients of control.sock

// liveHelper runs this binary as a process in the sandbox when its arguments say so, and doesn't return then.
//
// live-agent <socket>: a caller. Each line on stdin is a tag and a request, sent on a connection of its own; each
// answer is printed as the tag and the response, as it comes. The op mounts answers with the grant directory's mounts
// where the agent runs, one per line in Output. Prints the tag ready first, and exits once stdin ends and every request
// is answered.
//
// live-anchor <socket> <session>: a Claude Code session's anchor (when the binary is named claude): a live-agent child
// carrying CLAUDE_CODE_SESSION_ID, to which it passes stdin on. The line end, or the end of stdin, makes it exit, which
// ends the session; the agent goes on until its requests are answered
func liveHelper() {
	if len(os.Args) < 3 {
		return
	}
	switch os.Args[1] {
	case "live-agent":
		liveAgent(os.Args[2])
	case "live-anchor":
		if len(os.Args) < 4 {
			os.Exit(2)
		}
		cmd := exec.Command("/proc/self/exe", "live-agent", os.Args[2])
		cmd.Env = append(os.Environ(), "CLAUDE_CODE_SESSION_ID="+os.Args[3])
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		in, err := cmd.StdinPipe()
		if err != nil {
			os.Exit(1)
		}
		if err := cmd.Start(); err != nil {
			os.Exit(1)
		}
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() && sc.Text() != "end" {
			if _, err := fmt.Fprintln(in, sc.Text()); err != nil {
				break
			}
		}
		os.Exit(0)
	default:
		return
	}
	os.Exit(0)
}

func liveAgent(socket string) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	out := json.NewEncoder(os.Stdout)
	answer := func(tag string, res response) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Print(tag + " ")
		_ = out.Encode(res)
	}
	answer("ready", response{})
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		tag, data, _ := strings.Cut(sc.Text(), " ")
		var req request
		if err := json.Unmarshal([]byte(data), &req); err != nil {
			answer(tag, response{Error: "agent: " + err.Error()})
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if req.Op == "mounts" {
				answer(tag, agentMounts(socket))
				return
			}
			answer(tag, rawCall(socket, req))
		}()
	}
	wg.Wait()
}

// agentMounts lists the mountpoints beneath the grant directory where the agent runs
func agentMounts(socket string) response {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return response{Error: err.Error()}
	}
	defer f.Close()
	lines, err := parseMountinfo(f)
	if err != nil {
		return response{Error: err.Error()}
	}
	dir := socket[:strings.LastIndex(socket, "/")+1]
	var points []string
	for _, l := range lines {
		if strings.HasPrefix(l.point, dir) {
			points = append(points, l.point)
		}
	}
	return response{Output: strings.Join(points, "\n")}
}

// rawCall sends one request on socket and returns the response as it came, its error included
func rawCall(socket string, req request) response {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return response{Error: "dial: " + err.Error()}
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return response{Error: "send: " + err.Error()}
	}
	var res response
	if err := json.NewDecoder(conn).Decode(&res); err != nil {
		return response{Error: "no answer: " + err.Error()}
	}
	return res
}

// liveProc is a process in the sandbox, as the host side sees it: started through the launcher's re-entry, its
// requests sent by tag
type liveProc struct {
	name string
	sess string // its session, "" for none
	cmd  *exec.Cmd
	in   io.WriteCloser
	mu   sync.Mutex
	tags int
	wait map[string]chan response
	// Closed when its output ends
	gone chan struct{}
}

// startProc starts the binary inside the sandbox with args, and waits for its agent to be ready
func (lv *liveEnv) startProc(t *rapid.T, name, exe string, args ...string) *liveProc {
	cmd := exec.Command(lv.launcher, append([]string{"--exec", exe}, args...)...)
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	p := &liveProc{name: name, cmd: cmd, in: in, wait: map[string]chan response{"ready": make(chan response, 1)},
		gone: make(chan struct{})}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go p.read(out)
	select {
	case <-p.wait["ready"]:
	case <-time.After(liveSettle):
		_ = cmd.Process.Kill()
		t.Fatalf("%s didn't start in the sandbox", name)
	}
	return p
}

func (p *liveProc) read(out io.Reader) {
	defer close(p.gone)
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		tag, data, _ := strings.Cut(sc.Text(), " ")
		var res response
		if err := json.Unmarshal([]byte(data), &res); err != nil {
			res = response{Error: "unreadable answer: " + sc.Text()}
		}
		p.mu.Lock()
		ch := p.wait[tag]
		delete(p.wait, tag)
		p.mu.Unlock()
		if ch != nil {
			ch <- res
		}
	}
}

// send sends a request and returns where its response arrives
func (p *liveProc) send(req request) chan response {
	ch := make(chan response, 1)
	data, _ := json.Marshal(req)
	p.mu.Lock()
	p.tags++
	tag := strconv.Itoa(p.tags)
	p.wait[tag] = ch
	p.mu.Unlock()
	if _, err := fmt.Fprintf(p.in, "%s %s\n", tag, data); err != nil {
		ch <- response{Error: "send to " + p.name + ": " + err.Error()}
	}
	return ch
}

// do sends a request and waits for its response
func (p *liveProc) do(t *rapid.T, req request) response {
	select {
	case res := <-p.send(req):
		return res
	case <-time.After(liveSettle):
		t.Fatalf("%s: no answer to %+v", p.name, req)
		return response{}
	}
}

// end ends an anchor, which ends its session; its agent ends once its requests are answered
func (p *liveProc) end() {
	_, _ = fmt.Fprintln(p.in, "end")
}

// kill ends the process and what it started in the sandbox: its stdin closes, which ends an agent and an anchor
func (p *liveProc) kill() {
	p.in.Close()
	select {
	case <-p.gone:
	case <-time.After(3 * time.Second):
		_ = p.cmd.Process.Kill()
	}
	_ = p.cmd.Wait()
}

// liveEvents follows the daemon's watch events on control.sock, again after each restart
type liveEvents struct {
	mu      sync.Mutex
	granted []string
	ended   map[string]bool
	// Connections made so far: a restart's new daemon is followed once it grows
	conns int
	stop  chan struct{}
}

func (lv *liveEnv) watch() *liveEvents {
	ev := &liveEvents{ended: map[string]bool{}, stop: make(chan struct{})}
	go func() {
		for {
			select {
			case <-ev.stop:
				return
			default:
			}
			conn, err := net.Dial("unix", lv.cfg.ControlSocket)
			if err != nil {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			if _, err := conn.Write([]byte(`{"op":"watch"}` + "\n")); err != nil {
				conn.Close()
				continue
			}
			ev.mu.Lock()
			ev.conns++
			ev.mu.Unlock()
			go func() {
				<-ev.stop
				conn.Close()
			}()
			sc := bufio.NewScanner(conn)
			for sc.Scan() {
				var e struct{ Event, ID string }
				_ = json.Unmarshal(sc.Bytes(), &e)
				ev.mu.Lock()
				switch e.Event {
				case "granted":
					ev.granted = append(ev.granted, e.ID)
				case "ended":
					ev.ended[e.ID] = true
				}
				ev.mu.Unlock()
			}
			conn.Close()
		}
	}()
	return ev
}
