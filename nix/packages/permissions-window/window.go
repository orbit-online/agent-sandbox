package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

// How long a call to control.sock may take: state runs the plugins' list commands
const callTimeout = 15 * time.Second

// window is what the QML shows and does, without Qt: the broker's state as JSON (what still holds ended folder grants
// among it, which the user may end) and an error
type window struct {
	socket string

	mu    sync.Mutex
	state string // control.sock's state answer, as JSON
	err   string
}

// A command from the QML: an operation on control.sock
type command struct {
	Op      string          `json:"op"`
	Pending string          `json:"pending,omitempty"`
	Allow   bool            `json:"allow,omitempty"`
	Lease   string          `json:"lease,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Grant   string          `json:"grant,omitempty"`
	Grants  []string        `json:"grants,omitempty"`
}

// call sends one request to control.sock and returns the answer, its error as an error
func call(socket string, request any) (map[string]json.RawMessage, error) {
	conn, err := net.DialTimeout("unix", socket, callTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(callTimeout))
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return nil, err
	}
	var answer map[string]json.RawMessage
	if err := json.NewDecoder(conn).Decode(&answer); err != nil {
		return nil, fmt.Errorf("Read the broker's answer: %w", err)
	}
	if e, ok := answer["error"]; ok {
		var msg string
		_ = json.Unmarshal(e, &msg)
		return nil, errors.New(msg)
	}
	return answer, nil
}

// do runs a command from the QML, then refreshes the state
func (w *window) do(data string) {
	var c command
	if err := json.Unmarshal([]byte(data), &c); err != nil {
		w.setError(fmt.Sprintf("Not a command: %v", err))
		return
	}
	if _, err := call(w.socket, c); err != nil {
		w.setError(describe(err))
	}
	w.refresh()
}

// refresh asks the broker for its state
func (w *window) refresh() {
	answer, err := call(w.socket, map[string]string{"op": "state"})
	if err != nil {
		w.setError(describe(err))
		return
	}
	state, _ := json.Marshal(answer)
	w.mu.Lock()
	w.state, w.err = string(state), ""
	w.mu.Unlock()
}

func (w *window) setError(err string) {
	w.mu.Lock()
	w.err = err
	w.mu.Unlock()
}

func describe(err error) string {
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
		return "The permissions broker isn't running: start the sandbox first"
	}
	return err.Error()
}

// view is what the QML reads: the state and the error, each as a string
func (w *window) view() (state, err string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.state, w.err
}

// watch follows the broker's watch stream, calling changed on every event, and stopped when it ends
func (w *window) watch(changed, stopped func()) {
	conn, err := net.Dial("unix", w.socket)
	if err != nil {
		return
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, `{"op": "watch"}`+"\n"); err != nil {
		return
	}
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		changed()
	}
	w.setError("The permissions broker stopped")
	stopped()
}
