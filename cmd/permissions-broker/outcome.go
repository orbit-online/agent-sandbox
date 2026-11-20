package main

import (
	"encoding/json"
	"log/slog"
)

// What came of asking the user, and its line in the journal

// How an answer came, or why there was none
const (
	howButton  = "button"  // Allow or Deny on the notification
	howBody    = "body"    // a click on the notification's body, which denies
	howForeign = "foreign" // an action key that isn't the broker's: a replacement's button
	howWindow  = "window"
	howClosed  = "closed"  // the notification closed unanswered
	howTimeout = "timeout" // no answer in time
	howGone    = "gone"    // the caller hung up
)

type decision struct {
	Allow  bool
	Lease  string
	Params json.RawMessage
	How    string
}

// logAnswer puts how p ended into the journal; options: the window had it
func logAnswer(p *pending, options bool, d decision, err error) {
	attrs := []any{"pending", p.ID, "capability", p.Capability}
	switch {
	case err != nil:
		slog.Warn("Asking failed", append(attrs, "err", err)...)
	case d.How == howTimeout:
		waited := "notification"
		if options {
			waited = "window"
		}
		slog.Info("Timed out", append(attrs, "waiting", waited)...)
	case d.How == howGone:
		slog.Info("Caller stopped waiting", attrs...)
	case d.How == howClosed:
		slog.Info("Closed unanswered", attrs...)
	default:
		attrs = append(attrs, "allow", d.Allow, "via", d.How)
		if d.Allow {
			attrs = append(attrs, "lease", d.Lease, "narrowed", len(d.Params) > 0)
		}
		slog.Info("Answered", attrs...)
	}
}
