package main

import (
	"log/slog"
	"sync"

	"github.com/godbus/dbus/v5"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/judge"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/wire"
)

// Distinct refusals counted before the rest share one count, and the length a logged field is cut to: the client
// picks both, so neither the map nor the log grows with what it sends
const (
	maxRefusalKeys  = 1024
	maxRefusalField = 256
)

// What a refusal is logged by: the message's header fields and the name a bus call asked about, nothing else of
// its body
type refusalKey struct{ typ, dest, path, iface, member, name, err string }

// refusals logs what the proxy refuses a client: a kind of refusal the first time, then at its 10th, 100th, ...
type refusals struct {
	log    *slog.Logger
	mu     sync.Mutex
	counts map[refusalKey]uint64
	other  uint64
}

func newRefusals(log *slog.Logger) *refusals {
	return &refusals{log: log, counts: map[refusalKey]uint64{}}
}

func cut(s string) string {
	if len(s) > maxRefusalField {
		return s[:maxRefusalField] + "…"
	}
	return s
}

func (r *refusals) note(m *wire.Message, errName, name string) {
	k := refusalKey{m.Type.String(), cut(m.Header(dbus.FieldDestination)), cut(m.Header(dbus.FieldPath)),
		cut(m.Header(dbus.FieldInterface)), cut(m.Header(dbus.FieldMember)), cut(name), errName}
	r.mu.Lock()
	n, ok := r.counts[k]
	overflow := !ok && len(r.counts) >= maxRefusalKeys
	if overflow {
		r.other++
		n = r.other
	} else {
		n++
		r.counts[k] = n
	}
	r.mu.Unlock()
	if !milestone(n) {
		return
	}
	if overflow {
		r.log.Warn("Refused", "kind", "other", "count", n)
		return
	}
	args := []any{"type", k.typ, "destination", k.dest, "path", k.path, "interface", k.iface, "member", k.member}
	if k.name != "" {
		args = append(args, "name", k.name)
	}
	if k.err == judge.AnsweredFalse {
		// NameHasOwner of a hidden name: the client got no error
		args = append(args, "answer", "false")
	} else {
		args = append(args, "error", k.err)
	}
	r.log.Warn("Refused", append(args, "count", n)...)
}

// 1, 10, 100, ...
func milestone(n uint64) bool {
	for n >= 10 && n%10 == 0 {
		n /= 10
	}
	return n == 1
}
