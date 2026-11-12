package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// What the splash learns from the launcher's journal namespaces through journalctl. The host side's is written by the
// host's helpers alone, so its identifiers can label what the splash shows; the sandbox's holds whatever the sandbox
// wrote there, which the splash shows only as the app's output (models/journal.als, S15)

// An entry, with the fields the splash uses. journald wakes a follower on a timer, 250 ms to over 450 ms after an
// entry and in batches, so a marker counts from at, when journald received it
type entry struct {
	ident, msg string
	at         time.Time
}

// journalctl runs journalctl on the namespace with args, handing each entry to each, and returns once it ends
func journalctl(cfg *config, namespace string, each func(entry), args ...string) error {
	cmd := exec.Command(cfg.Tools.Journalctl, append([]string{"--namespace=" + namespace, "--no-pager", "-q",
		"-o", "json", "--output-fields=MESSAGE,SYSLOG_IDENTIFIER"}, args...)...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	readEntries(out, each)
	return cmd.Wait()
}

func readEntries(r io.Reader, each func(entry)) {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64<<10), 4<<20)
	for s.Scan() {
		var e struct {
			Message json.RawMessage `json:"MESSAGE"`
			Ident   json.RawMessage `json:"SYSLOG_IDENTIFIER"`
			At      string          `json:"__REALTIME_TIMESTAMP"`
		}
		if json.Unmarshal(s.Bytes(), &e) == nil {
			at := time.Now()
			if us, err := strconv.ParseInt(e.At, 10, 64); err == nil {
				at = time.UnixMicro(us)
			}
			each(entry{ident: field(e.Ident), msg: field(e.Message), at: at})
		}
	}
}

// field is a field's value: journalctl's JSON has a string, an array of bytes when it isn't UTF-8, or an array of
// those when the field repeats, of which the first counts
func field(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var b []byte
	var ints []int
	if json.Unmarshal(raw, &ints) == nil {
		for _, i := range ints {
			b = append(b, byte(i))
		}
		return string(b)
	}
	var many []json.RawMessage
	if json.Unmarshal(raw, &many) == nil && len(many) > 0 {
		return field(many[0])
	}
	return ""
}

func since(t time.Time) string { return fmt.Sprintf("--since=@%d.%06d", t.Unix(), t.Nanosecond()/1000) }

// followHost hands each entry of the host side's namespace since began to each until stop
func followHost(cfg *config, began time.Time, each func(entry)) (stop func()) {
	if cfg.Journal == "" || cfg.Tools.Journalctl == "" {
		return func() {}
	}
	cmd := exec.Command(cfg.Tools.Journalctl, "--namespace="+cfg.Journal, "--no-pager", "-q", "-o", "json",
		"--output-fields=MESSAGE,SYSLOG_IDENTIFIER", since(began), "--lines=all", "--follow")
	out, err := cmd.StdoutPipe()
	if err == nil {
		err = cmd.Start()
	}
	if err != nil {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		readEntries(out, each)
		close(done)
	}()
	return func() {
		cmd.Process.Kill()
		// Closes the pipe, which a child of journalctl's might still hold
		cmd.Wait()
		<-done
	}
}

// readHost hands each entry of the host side's namespace since began to each, as the journal's files have them now
func readHost(cfg *config, began time.Time, each func(entry)) {
	if cfg.Journal != "" && cfg.Tools.Journalctl != "" {
		journalctl(cfg, cfg.Journal, each, since(began))
	}
}

// Started lines of earlier launches this many back at most, of supervise's lines this many back
const (
	historyLaunches = 5
	historyLines    = 300
)

// history reads the durations to each step from supervise's Started lines of the latest launches, newest first
func history(cfg *config) []map[string]time.Duration {
	if cfg.Journal == "" || cfg.Tools.Journalctl == "" {
		return nil
	}
	var h []map[string]time.Duration
	journalctl(cfg, cfg.Journal, func(e entry) {
		if len(h) < historyLaunches {
			if d := parseStarted(e.msg); d != nil {
				h = append(h, d)
			}
		}
	}, "--identifier="+progName(cfg), "--reverse", "--lines="+strconv.Itoa(historyLines))
	return h
}

// Logs settle this long before a failure shows them: a helper's last lines may still be on their way to journald
const settle = 300 * time.Millisecond

// What a failed start shows of the host side's journal: its warnings and errors since began
const hostLines = 50

// failureLogs are the host side's warnings and errors since began, each labelled with its identifier, and the
// sandbox's last entries, or tail without them
func failureLogs(cfg *config, began time.Time, pumped *tail) (host, app string) {
	if cfg.Tools.Journalctl == "" {
		return "", pumped.String()
	}
	time.Sleep(settle)
	var lines []string
	if cfg.Journal != "" {
		journalctl(cfg, cfg.Journal, func(e entry) {
			lines = append(lines, e.ident+": "+readable(e.msg))
		}, since(began), "--priority=warning", "--lines="+strconv.Itoa(hostLines))
	}
	host = strings.Join(lines, "\n")
	if cfg.SandboxJournal == "" {
		return host, pumped.String()
	}
	out := &tail{max: tailMax}
	err := journalctl(cfg, cfg.SandboxJournal, func(e entry) {
		// The pump's lines, the app's own, carry the launcher's name
		if e.ident == progName(cfg) {
			out.add(e.msg)
		} else {
			out.add(e.ident + ": " + e.msg)
		}
	}, since(began), "--lines=1000")
	if err != nil || len(out.lines) == 0 {
		return host, pumped.String()
	}
	return host, out.String()
}

// readable drops the level from a line of slog's text, and the quotes from its message:
// `level=WARN msg="No address" k=v` is `No address k=v`
func readable(msg string) string {
	rest, ok := strings.CutPrefix(msg, "level=")
	if !ok {
		return msg
	}
	_, rest, _ = strings.Cut(rest, " ")
	rest, ok = strings.CutPrefix(rest, "msg=")
	if !ok {
		return msg
	}
	if strings.HasPrefix(rest, `"`) {
		q, err := strconv.QuotedPrefix(rest)
		if err != nil {
			return msg
		}
		m, _ := strconv.Unquote(q)
		return m + rest[len(q):]
	}
	return rest
}
