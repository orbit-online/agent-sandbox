package main

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// What goes wrong in the start that the sandbox can start without, a hook of the network say: bwrap's helper on the
// host hands it to supervise over a socket in the host's runtime dir, which no sandbox reaches (binds there are refused),
// and holds the start until supervise answers, once the user chose Continue on the splash. Without supervise listening,
// or without a splash, the start goes on at once

// warnSocket is where supervise listens for the warnings of the start of unit
func warnSocket(unit string) string {
	return filepath.Join(runtimeDir(), unit+".warn")
}

// The most a warning may be
const warnMax = 8 << 10

// acknowledge has supervise of unit show warnings and returns once the user acknowledged them, or at once when no
// supervise listens
func acknowledge(unit string, warnings []string) {
	for _, w := range warnings {
		slog.Warn("Warning", "text", w)
	}
	c, err := net.Dial("unix", warnSocket(unit))
	if err != nil {
		slog.Warn("No splash to acknowledge the warnings on", "err", err)
		return
	}
	defer c.Close()
	if _, err := c.Write([]byte(strings.Join(warnings, "\n\n"))); err != nil {
		slog.Warn("Send the warnings", "err", err)
		return
	}
	c.(*net.UnixConn).CloseWrite()
	// supervise closes once the user acknowledged
	io.Copy(io.Discard, c)
}

// warnings is supervise's end
type warnings struct {
	ln   net.Listener
	path string
}

// listenWarnings serves the warnings of the start on sp until close
func listenWarnings(cfg *config, sp *splash) *warnings {
	w := &warnings{path: warnSocket(cfg.Unit)}
	if err := os.MkdirAll(filepath.Dir(w.path), 0o700); err != nil {
		slog.Warn("No warnings on the splash", "err", err)
		return w
	}
	os.Remove(w.path)
	ln, err := net.Listen("unix", w.path)
	if err != nil {
		slog.Warn("No warnings on the splash", "err", err)
		return w
	}
	w.ln = ln
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveWarning(c, sp)
		}
	}()
	return w
}

// serveWarning shows a warning on sp until the user goes on, or the splash is gone, then lets the helper go on
func serveWarning(c net.Conn, sp *splash) {
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, err := io.ReadAll(io.LimitReader(c, warnMax))
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		slog.Warn("Read a warning", "err", err)
	}
	text := string(data)
	slog.Warn("The start goes on with a warning", "text", text)
	sp.warn(text)
}

func (w *warnings) close() {
	if w.ln != nil {
		w.ln.Close()
		os.Remove(w.path)
	}
}
