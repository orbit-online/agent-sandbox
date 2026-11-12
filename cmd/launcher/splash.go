package main

import (
	"bufio"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
)

// splash is the window the launcher shows while the sandbox starts, and its errors after: a process of its own (Qt,
// see the permissions-window package's sandbox-splash), told what to show as JSON lines on its stdin; its Abort
// button prints "abort" on its stdout. Best effort:
// without a display, or when it fails, the launcher goes on without it
type splash struct {
	// Closed when the user aborts the start from the splash
	aborted chan struct{}

	mu  sync.Mutex
	cmd *exec.Cmd
	in  io.WriteCloser
	enc *json.Encoder
}

// What a line tells the splash; it keeps what a line leaves out
type splashState struct {
	Dark     *bool    `json:"dark,omitempty"`
	Text     string   `json:"text,omitempty"`
	Progress *float64 `json:"progress,omitempty"` // 0 to 1; none for a step of unknown length
	Error    string   `json:"error,omitempty"`    // Shown until the user closes the window
	Host     string   `json:"host,omitempty"`     // The host side's warnings and errors, beneath the error
	Log      string   `json:"log,omitempty"`      // The app's last output, beneath those
	Activate string   `json:"activate,omitempty"` // An xdg-activation token: the window to the front
}

func showSplash(cfg *config) *splash {
	s := &splash{aborted: make(chan struct{})}
	if len(cfg.Splash) == 0 {
		return s
	}
	cmd := exec.Command(cfg.Splash[0], append(cfg.Splash[1:], "--app-id="+cfg.AppID)...)
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	var out io.ReadCloser
	if err == nil {
		out, err = cmd.StdoutPipe()
	}
	if err == nil {
		err = cmd.Start()
	}
	if err != nil {
		slog.Warn("No splash", "err", err)
		return s
	}
	s.cmd, s.in, s.enc = cmd, in, json.NewEncoder(in)
	// Its Abort button's line
	go func() {
		lines := bufio.NewScanner(out)
		for lines.Scan() {
			if lines.Text() == "abort" {
				close(s.aborted)
				return
			}
		}
	}()
	return s
}

func (s *splash) send(st splashState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.enc != nil && s.enc.Encode(st) != nil {
		// It went away: the user closed it, or it failed
		s.enc = nil
	}
}

func (s *splash) step(text string, progress *float64) {
	s.send(splashState{Text: text, Progress: progress})
}

// up says whether the window is there to show something
func (s *splash) up() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc != nil
}

func (s *splash) dark(dark bool) { s.send(splashState{Dark: &dark}) }

// close ends the splash: its stdin closing tells it to quit
func (s *splash) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd == nil {
		return
	}
	s.in.Close()
	s.cmd.Wait()
	s.cmd, s.enc = nil, nil
}

// fail shows msg, the host side's warnings and the app's output, and waits until the user closes the window
func (s *splash) fail(msg, host, log string) {
	s.send(splashState{Error: msg, Host: host, Log: log})
	s.mu.Lock()
	cmd := s.cmd
	s.mu.Unlock()
	if cmd != nil {
		cmd.Wait()
	}
}
