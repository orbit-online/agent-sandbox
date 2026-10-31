package main

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// openWindow opens the Permissions window on the host, as a unit of its own
func (b *broker) openWindow() error {
	if len(b.cfg.Window) == 0 {
		return errors.New("No window configured")
	}
	args := append([]string{"--user", "--collect", "--quiet", "--"}, b.cfg.Window...)
	return exec.Command(systemdRun, args...).Run()
}

// notifyAsk asks with a notification that has Allow, Deny and Options buttons. Not answering in time denies, and the
// notification is replaced by one without buttons, so a late click doesn't look like it worked. An answer within a
// second of the notification appearing is ignored and the question asked again: the sandbox can post look-alike
// notifications, timed to sit where the user is about to click
func notifyAsk(ctx context.Context, p prompt) (string, error) {
	summary := "Claude asks for " + escapeMarkup(p.Summary)
	body := "Claude's reason, in its own words: " + escapeMarkup(strconv.Quote(p.Reason))
	allow := "Allow " + leaseLabel(p.Lease)
	for {
		idR, idW, err := os.Pipe()
		if err != nil {
			return "", err
		}
		args := []string{"--app-name=Claude permissions", "--icon=security-medium", "--urgency=critical", "--id-fd=3",
			"--action=allow=" + allow, "--action=deny=Deny"}
		if p.Options {
			args = append(args, "--action=options=Options…")
		}
		cmd := exec.CommandContext(ctx, notifySend, append(args, summary, body)...)
		cmd.ExtraFiles = []*os.File{idW}
		var out strings.Builder
		cmd.Stdout = &out
		if err := cmd.Start(); err != nil {
			idW.Close()
			idR.Close()
			return "", err
		}
		idW.Close()
		// notify-send prints the id once the notification is up: the second counts from there
		id, _ := bufio.NewReader(idR).ReadString('\n')
		shown := time.Now()
		idR.Close()
		err = cmd.Wait()
		if ctx.Err() != nil {
			title, body := "Claude's request timed out", "Not granted: "+escapeMarkup(p.Summary)
			if errors.Is(context.Cause(ctx), errAnswered) {
				title, body = "Answered in the Permissions window", escapeMarkup(p.Summary)
			}
			if id = strings.TrimSpace(id); id != "" {
				_ = exec.Command(notifySend, "--app-name=Claude permissions", "--icon=security-medium",
					"--replace-id="+id, "--expire-time=10000", title, body).Run()
			}
			return "deny", nil
		}
		if err != nil {
			return "", err
		}
		action := strings.TrimSpace(out.String())
		if action != "" && time.Since(shown) < time.Second {
			continue
		}
		return action, nil
	}
}

func escapeMarkup(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func leaseLabel(lease string) string {
	switch lease {
	case "session":
		return "for this session"
	case "lock":
		return "until the screen locks"
	}
	if d, err := parseDuration(lease); err == nil {
		return "for " + d.String()
	}
	return lease
}
