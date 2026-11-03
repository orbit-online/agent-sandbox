// Package wire is the broker's protocol on request.sock and control.sock, as its clients speak it: a JSON request,
// a JSON answer
package wire

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	// No answer in this long denies
	AskTimeout = 2 * time.Minute
	// Once the user opens the window on a request, it waits this long at most
	OptionsTimeout = 10 * time.Minute
)

// Request is a request on request.sock, or an operation on control.sock
type Request struct {
	Op         string          `json:"op"`
	Capability string          `json:"capability,omitempty"`
	Params     json.RawMessage `json:"params,omitempty"`
	Reason     string          `json:"reason,omitempty"`
	Lease      string          `json:"lease,omitempty"`
	Grant      string          `json:"grant,omitempty"`
	// call: the host command, and its free arguments (Params holds the bounding ones)
	Command   string          `json:"command,omitempty"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
	// control.sock's answer to a pending request
	Pending string `json:"pending,omitempty"`
	Allow   bool   `json:"allow,omitempty"`
	// control.sock's end: the ended grants whose holders to end, as the window shows them
	Grants []string `json:"grants,omitempty"`
}

// ErrNotRunning is Call's error when nothing listens at the socket
var ErrNotRunning = errors.New("The permissions broker isn't running")

// Call sends one request and decodes the answer into res, or returns the error it carries. A request waits for the
// user: two minutes, or ten with the window open
func Call(socket string, req Request, res any) error {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotRunning, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(AskTimeout + OptionsTimeout + time.Minute))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return err
	}
	var raw json.RawMessage
	if err := json.NewDecoder(conn).Decode(&raw); err != nil {
		return fmt.Errorf("Read the broker's answer: %w", err)
	}
	var answer struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		return fmt.Errorf("Read the broker's answer: %w", err)
	}
	if answer.Error != "" {
		return errors.New(strings.TrimSpace(answer.Error))
	}
	if err := json.Unmarshal(raw, res); err != nil {
		return fmt.Errorf("Read the broker's answer: %w", err)
	}
	return nil
}
