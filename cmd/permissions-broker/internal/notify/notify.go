// Package notify asks the user about a request with a desktop notification
package notify

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/duration"
)

// The notification's question and the user's answer: allow, deny or options
type Prompt struct {
	Summary, Reason, Lease string
	// Host commands: what the grant covers, shown before the reason, and the bounding values it's on. With them, the
	// summary says what Claude wants to do, and for how long
	Scope, Bounds string
	// Host commands: the consent's title, which the summary uses without the bounding values: a server cuts the
	// summary to a line, and the body has them
	Title string
	// Whether to offer Options, which needs the window
	Options bool
}

// Why a notification is taken down early: the user answered in the window
var ErrAnswered = errors.New("answered in the window")

const (
	notifyName  = "org.freedesktop.Notifications"
	notifyPath  = dbus.ObjectPath("/org/freedesktop/Notifications")
	notifyIface = "org.freedesktop.Notifications"
)

// An action within this long of the notification appearing is ignored, and the question asked again
var notifyMature = time.Second

// Ask asks with a notification on the session bus, as askOn describes
func Ask(ctx context.Context, p Prompt) (string, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return "", fmt.Errorf("Connect to the session bus: %w", err)
	}
	defer conn.Close()
	return askOn(ctx, conn, p)
}

// askOn asks with a notification that has Allow, Deny and Options buttons and returns allow, deny, options or "" (closed
// unanswered). A click on its body sends the action named default, which denies, or on COSMIC opens the window (see
// bodyClick). The sandbox talks to the notification server too: it can replace the broker's notification by its id
// with buttons of its own, and send signals. So each button's action key is random, per notification, and only
// ActionInvoked and NotificationClosed from the server itself (the current owner of its name) count. A replaced
// notification can still be clicked, but its keys aren't the broker's: that's a deny. An answer within a second of
// the notification appearing is ignored and the question asked again, against look-alikes timed to sit where the user
// is about to click. Not answering in time denies, and the notification is replaced by one without buttons
func askOn(ctx context.Context, conn *dbus.Conn, p Prompt) (string, error) {
	match := []dbus.MatchOption{dbus.WithMatchObjectPath(notifyPath), dbus.WithMatchInterface(notifyIface)}
	if err := conn.AddMatchSignal(match...); err != nil {
		return "", fmt.Errorf("Watch the notifications: %w", err)
	}
	signals := make(chan *dbus.Signal, 64)
	conn.Signal(signals)
	defer conn.RemoveSignal(signals)
	server := conn.Object(notifyName, notifyPath)
	for {
		var owner string
		if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, notifyName).
			Store(&owner); err != nil {
			return "", fmt.Errorf("Find the notification server: %w", err)
		}
		click, label, hint := bodyClick(ctx, server, p)
		summary, body := Text(p, hint)
		allow, deny, options := randomKey(), randomKey(), randomKey()
		keys := map[string]string{"default": click, allow: "allow", deny: "deny"}
		// The default action goes first: a server that draws no buttons and finds none named default may take the first
		actions := []string{"default", label, allow, "Allow " + leaseLabel(p.Lease), deny, "Deny"}
		if p.Options {
			keys[options] = "options"
			actions = append(actions, options, "Options…")
		}
		var id uint32
		if err := server.CallWithContext(ctx, notifyIface+".Notify", 0, "Claude permissions", uint32(0),
			"security-medium", summary, body, actions, map[string]dbus.Variant{"urgency": dbus.MakeVariant(byte(2))},
			int32(0)).Store(&id); err != nil {
			if ctx.Err() != nil {
				return "deny", nil
			}
			return "", fmt.Errorf("Post the notification: %w", err)
		}
		shown := time.Now()
		action, err := awaitAction(ctx, signals, owner, id, keys)
		if err != nil {
			return "", err
		}
		if ctx.Err() != nil {
			title, text := "Claude's request timed out", "Not granted: "+escapeMarkup(p.Summary)
			if errors.Is(context.Cause(ctx), ErrAnswered) {
				title, text = "Answered in the Permissions window", escapeMarkup(p.Summary)
			}
			_ = server.Call(notifyIface+".Notify", 0, "Claude permissions", id, "security-medium", title, text,
				[]string{}, map[string]dbus.Variant{}, int32(10000)).Err
			return "deny", nil
		}
		if action != "" && time.Since(shown) < notifyMature {
			continue
		}
		return action, nil
	}
}

// Text is the notification's summary and body, markup escaped, with hint, a line saying what a click on the body does,
// before the reason
func Text(p Prompt, hint string) (string, string) {
	summary := "Claude asks for " + escapeMarkup(p.Summary)
	if p.Scope != "" {
		what := p.Summary
		if p.Title != "" {
			what = p.Title
		}
		summary = "Claude wants to " + escapeMarkup(what) + " " + leaseLabel(p.Lease)
	}
	// Ahead of the reason: a server may cut what's long, and the scope is what's granted. The bounding values and the
	// lease again, since the sandbox chose the values and a long one pushes the rest of a summary out where it's cut
	var lines []string
	if p.Scope != "" {
		head := leaseLabel(p.Lease)
		if p.Bounds != "" {
			head = "On " + p.Bounds + " " + head
		} else {
			head = strings.ToUpper(head[:1]) + head[1:]
		}
		lines = append(lines, escapeMarkup(head+": "+p.Scope))
	}
	if hint != "" {
		lines = append(lines, hint)
	}
	reason := "Claude's reason, in its own words: " + escapeMarkup(strconv.Quote(p.Reason))
	return summary, strings.Join(append(lines, reason), "\n")
}

// The name cosmic-notifications gives in GetServerInformation
const cosmicServer = "cosmic-notifications"

// bodyClick is what the default action, a click on the notification's body, answers, its label, and a line for the body
// saying so. It denies, as closing the notification does. cosmic-notifications draws no buttons, so there it opens the
// window with the request still pending, when there is one. Only the server's name picks it: a wrong match costs the
// window, and a failed GetServerInformation denies
func bodyClick(ctx context.Context, server dbus.BusObject, p Prompt) (string, string, string) {
	var name, vendor, version, spec string
	if err := server.CallWithContext(ctx, notifyIface+".GetServerInformation", 0).
		Store(&name, &vendor, &version, &spec); err == nil && name == cosmicServer && p.Options {
		return "options", "Options…", "Click to answer in the Permissions window."
	}
	return "deny", "Deny", ""
}

// awaitAction waits for the server's answer to notification id: the action of the key clicked, deny for a key that
// isn't one of keys (a replacement's button), "" when it closed unanswered, and "" when ctx ends. Signals from
// anything other than owner, the server, are ignored
func awaitAction(ctx context.Context, signals <-chan *dbus.Signal, owner string, id uint32, keys map[string]string) (string, error) {
	for {
		select {
		case <-ctx.Done():
			return "", nil
		case s, ok := <-signals:
			if !ok {
				return "", errors.New("Lost the session bus")
			}
			if s.Sender != owner || s.Path != notifyPath || len(s.Body) < 2 {
				continue
			}
			if got, ok := s.Body[0].(uint32); !ok || got != id {
				continue
			}
			switch s.Name {
			case notifyIface + ".ActionInvoked":
				key, _ := s.Body[1].(string)
				if action, ok := keys[key]; ok {
					return action, nil
				}
				return "deny", nil
			case notifyIface + ".NotificationClosed":
				return "", nil
			}
		}
	}
}

func escapeMarkup(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func leaseLabel(lease string) string {
	switch lease {
	case "lock":
		return "until the screen locks"
	case "once":
		return "for this call only"
	}
	if d, err := duration.Parse(lease); err == nil {
		return "for " + spokenDuration(d)
	}
	return lease
}

// spokenDuration says d in hours and minutes, as "1 h 30 min", or in seconds when it's shorter than a minute
func spokenDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d s", int(d.Seconds()))
	}
	h, m := int(d.Hours()), int(d.Minutes())%60
	switch {
	case h == 0:
		return fmt.Sprintf("%d min", m)
	case m == 0:
		return fmt.Sprintf("%d h", h)
	}
	return fmt.Sprintf("%d h %d min", h, m)
}

// randomKey is an action key the sandbox can't guess
func randomKey() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
