// Package journal is how the helpers log: slog's text to stderr, which systemd-cat connects to the launcher's journal
// namespace (Wrap). There each line starts with the <N> priority prefix journald reads, so `journalctl -p warning`
// finds the warnings
package journal

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"syscall"
)

// Setup makes slog's default logger write to stderr, with priority prefixes and without slog's time when stderr is a
// journal stream: journald stamps the time
func Setup() {
	slog.SetDefault(slog.New(Handler(os.Stderr, IsStream(os.Stderr))))
}

// IsStream says whether f is the journal stream $JOURNAL_STREAM names (its device and inode), as systemd and
// systemd-cat set it. Inherited by a process whose stderr goes elsewhere, it no longer matches
func IsStream(f *os.File) bool {
	var dev, ino uint64
	if _, err := fmt.Sscanf(os.Getenv("JOURNAL_STREAM"), "%d:%d", &dev, &ino); err != nil {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && uint64(st.Dev) == dev && uint64(st.Ino) == ino
}

// Handler writes slog's text lines to w, each prefixed with its syslog priority when prefixed is set
func Handler(w io.Writer, prefixed bool) slog.Handler {
	if !prefixed {
		return slog.NewTextHandler(w, nil)
	}
	mu := &sync.Mutex{}
	noTime := func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 && a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}
	h := prefixHandler{}
	for i, p := range priorities {
		h[i] = slog.NewTextHandler(&prefixWriter{w: w, mu: mu, prefix: p.prefix},
			&slog.HandlerOptions{Level: slog.LevelDebug, ReplaceAttr: noTime})
	}
	return h
}

// slog's levels and syslog's priorities: error 3, warning 4, info 6, debug 7
var priorities = [...]struct {
	level  slog.Level
	prefix string
}{{slog.LevelError, "<3>"}, {slog.LevelWarn, "<4>"}, {slog.LevelInfo, "<6>"}, {slog.LevelDebug, "<7>"}}

// One text handler per priority, the record going to the first whose level it reaches
type prefixHandler [len(priorities)]slog.Handler

func (h prefixHandler) pick(l slog.Level) slog.Handler {
	for i, p := range priorities {
		if l >= p.level {
			return h[i]
		}
	}
	return h[len(h)-1]
}

func (h prefixHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= slog.LevelInfo }

func (h prefixHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.pick(r.Level).Handle(ctx, r)
}

func (h prefixHandler) WithAttrs(as []slog.Attr) slog.Handler {
	for i := range h {
		h[i] = h[i].WithAttrs(as)
	}
	return h
}

func (h prefixHandler) WithGroup(name string) slog.Handler {
	for i := range h {
		h[i] = h[i].WithGroup(name)
	}
	return h
}

// Writes each line slog hands it with the prefix in front, in one write under the lock all priorities share
type prefixWriter struct {
	w      io.Writer
	mu     *sync.Mutex
	prefix string
}

func (p *prefixWriter) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, err := p.w.Write(append([]byte(p.prefix), b...)); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Wrap is the command line that runs argv with its stdout and stderr in the journal namespace under identifier, through
// systemd-cat; argv as it is without a namespace
func Wrap(systemdCat, namespace, identifier string, argv ...string) []string {
	if systemdCat == "" || namespace == "" {
		return argv
	}
	return append([]string{systemdCat, "--namespace=" + namespace, "--identifier=" + identifier, "--"}, argv...)
}
