package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

// openWindow opens the Permissions window on the host, as a unit of its own
func (b *broker) openWindow() error {
	if len(b.cfg.Window) == 0 {
		return errors.New("No window configured")
	}
	args := append([]string{"--user", "--collect", "--quiet", "--"}, b.cfg.Window...)
	return exec.Command(systemdRun, args...).Run()
}

const (
	notifyName  = "org.freedesktop.Notifications"
	notifyPath  = dbus.ObjectPath("/org/freedesktop/Notifications")
	notifyIface = "org.freedesktop.Notifications"
)

// An action within this long of the notification appearing is ignored, and the question asked again
var notifyMature = time.Second

// notifyAsk asks with a notification on the session bus, as askOn describes
func notifyAsk(ctx context.Context, p prompt) (string, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return "", fmt.Errorf("Connect to the session bus: %w", err)
	}
	defer conn.Close()
	return askOn(ctx, conn, p)
}

// askOn asks with a notification that has Allow, Deny and Options buttons and returns allow, deny, options or "" (closed
// unanswered). The sandbox talks to the notification server too: it can replace the broker's notification by its id
// with buttons of its own, and send signals. So each button's action key is random, per notification, and only
// ActionInvoked and NotificationClosed from the server itself (the current owner of its name) count. A replaced
// notification can still be clicked, but its keys aren't the broker's: that's a deny. An answer within a second of
// the notification appearing is ignored and the question asked again, against look-alikes timed to sit where the user
// is about to click. Not answering in time denies, and the notification is replaced by one without buttons
func askOn(ctx context.Context, conn *dbus.Conn, p prompt) (string, error) {
	summary := "Claude asks for " + escapeMarkup(p.Summary)
	body := "Claude's reason, in its own words: " + escapeMarkup(strconv.Quote(p.Reason))
	if p.Scope != "" {
		// Ahead of the reason: a server may cut what's long, and this is what's granted
		body = "Covers: " + escapeMarkup(p.Scope) + "\n" + body
	}
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
		allow, deny, options := randomID(), randomID(), randomID()
		keys := map[string]string{allow: "allow", deny: "deny"}
		actions := []string{allow, "Allow " + leaseLabel(p.Lease), deny, "Deny"}
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
			if errors.Is(context.Cause(ctx), errAnswered) {
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
	case "session":
		return "until this Claude session ends"
	case "lock":
		return "until the screen locks"
	}
	if d, err := parseDuration(lease); err == nil {
		return "for " + d.String()
	}
	return lease
}
