package main

import (
	"encoding/json"
	"fmt"
)

// state is what the splash shows, from the launcher's lines on stdin: each sets what it names (launcher's
// splashState) and leaves the rest
type state struct {
	Dark     bool    `json:"dark"`
	Text     string  `json:"text"`
	Progress float64 `json:"progress"` // -1: a step of unknown length
	Error    string  `json:"error"`
	Host     string  `json:"host"` // The host side's warnings, labelled by the launcher
	Log      string  `json:"log"`  // The app's output
	// How often the launcher asked to bring the window to the front, and the activation token for the next time
	Activations int    `json:"-"`
	Token       string `json:"-"`
}

func newState() *state { return &state{Text: "Starting", Progress: -1} }

// apply takes one line. A step without progress is one of unknown length
func (s *state) apply(line []byte) error {
	var l struct {
		Dark     *bool    `json:"dark"`
		Text     *string  `json:"text"`
		Progress *float64 `json:"progress"`
		Error    *string  `json:"error"`
		Host     *string  `json:"host"`
		Log      *string  `json:"log"`
		Activate *string  `json:"activate"`
	}
	if err := json.Unmarshal(line, &l); err != nil {
		return fmt.Errorf("Read a line from the launcher: %w", err)
	}
	if l.Dark != nil {
		s.Dark = *l.Dark
	}
	if l.Text != nil {
		s.Text = *l.Text
		s.Progress = -1
	}
	if l.Progress != nil {
		s.Progress = min(max(*l.Progress, 0), 1)
	}
	if l.Error != nil {
		s.Error = *l.Error
	}
	if l.Host != nil {
		s.Host = *l.Host
	}
	if l.Log != nil {
		s.Log = *l.Log
	}
	if l.Activate != nil {
		s.Token = *l.Activate
		s.Activations++
	}
	return nil
}
