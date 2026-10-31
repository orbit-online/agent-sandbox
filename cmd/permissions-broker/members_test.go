package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// reenter starts sh -c script in the sandbox's user namespace, and its mount namespace with mnt, through nsenter from
// here, as claude-desktop --shell does: no descendant of the sandbox's pid. env is its environment. Returns the pid
// script prints
func reenter(t *testing.T, sb *sandbox, mnt bool, env []string, script string) int {
	t.Helper()
	args := []string{fmt.Sprintf("--user=/proc/%d/ns/user", sb.pid), "--preserve-credentials"}
	if mnt {
		args = append(args, fmt.Sprintf("--mount=/proc/%d/ns/mnt", sb.pid))
	}
	cmd := exec.Command("nsenter", append(args, "sh", "-c", script)...)
	cmd.Env = env
	out, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	line, err := bufio.NewReader(out).ReadString('\n')
	pid, perr := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || perr != nil {
		t.Fatalf("Re-entry: %q, %v", line, err)
	}
	return pid
}

// P8: a re-entry whose host parent carries a session (claude-desktop --shell run from a host Claude Code session's
// shell, its parent a claude) gets none: the walk stops where the sandbox does
func TestSessionReentry(t *testing.T) {
	b, _, _ := sandboxC(t)
	t.Setenv("REENTER", fmt.Sprintf(`env -u CLAUDE_CODE_SESSION_ID nsenter --user=/proc/%d/ns/user `+
		`--preserve-credentials sh -c 'echo $$; exec sleep 60'; :`, b.sb.pid))
	_, pids := startAnchorMode(t, "claude", "reenter", 1)
	pid := pids[0]
	if !b.sb.contains(pid) {
		t.Fatal("The re-entry isn't in the sandbox")
	}
	if s, err := b.sb.sessionOf(pid); err != nil || s != nil {
		t.Errorf("Anchored a re-entry's session outside the sandbox: %+v, %v", s, err)
	}
}

// P5: a re-entry with its working directory on a folder grant is listed as a holder, and can be ended
func TestHoldersReentry(t *testing.T) {
	src := t.TempDir()
	b, _, _ := sandboxC(t, "allow")
	c := folders(t, `{"path": "`+src+`"}`)
	b.caps[c.id()] = c
	g, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "`+src+`"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	pid := reenter(t, b.sb, true, os.Environ(), "cd "+g.Path+" && echo $$ && exec sleep 60")
	holders, err := b.revoke(g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(holders, func(h holder) bool { return h.Pid == pid }) {
		t.Fatalf("The re-entry %d isn't among the holders %+v", pid, holders)
	}
	if err := b.endHeld(g.ID); err != nil {
		t.Fatal(err)
	}
	for range 50 {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d/cwd", pid)); err != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("The re-entry wasn't ended")
}

// L9: share after a process of the sandbox is in a copy of M1 (the FHS env's bwrap ran) would reach nothing: refused
func TestShareTooLate(t *testing.T) {
	b, _ := testBroker(t)
	dir := t.TempDir()
	cmd := ownNs(t, dir)
	b.sb = pinned(t, cmd.Process.Pid, peerAt(t, cmd.Process.Pid).pidfd)
	b.cfg.SandboxGrantDir = dir
	reenter(t, b.sb, false, os.Environ(), "exec unshare --mount sh -c 'echo $$; exec sleep 60'")
	if err := b.shareFrom(peerAt(t, cmd.Process.Pid)); err == nil {
		t.Error("Shared after the sandbox's mount namespace was copied")
	}
}

// P5: holders are shown however the grant ended, released from inside too, and ending them signals only the process
// recorded, not a later one with its pid
func TestHoldersOnRelease(t *testing.T) {
	src := t.TempDir()
	b, hold, out := sandboxC(t, "allow")
	c := folders(t, `{"path": "`+src+`"}`)
	b.caps[c.id()] = c
	g, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "`+src+`"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(hold, "hold %s\n", g.Path)
	var pid int
	if _, err := fmt.Fscan(out, &pid); err != nil || pid <= 0 {
		t.Fatal(pid, err)
	}
	if err := b.release(g.ID, "released from inside"); err != nil {
		t.Fatal(err)
	}
	res := b.handleControl(nil, peerAt(t, os.Getpid()), request{Op: "state"})
	if len(res.Held) != 1 || res.Held[0].Grant != g.ID || len(res.Held[0].Holders) != 1 || res.Held[0].Holders[0].Pid != pid {
		t.Fatalf("Held after a release: %+v", res.Held)
	}
	// Recorded with another start time: a process that reused the pid isn't signalled
	stale := res.Held[0].Holders[0]
	stale.Start++
	if err := b.endHolders([]holder{stale}); err != nil {
		t.Error(err)
	}
	time.Sleep(300 * time.Millisecond)
	if _, ok := startTime(pid); !ok {
		t.Error("Ended a process by a stale record")
	}
	if res := b.handleControl(nil, peerAt(t, os.Getpid()), request{Op: "end", Grants: []string{g.ID}}); res.Error != "" {
		t.Error(res.Error)
	}
	for range 50 {
		if _, ok := startTime(pid); !ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("The holder wasn't ended")
}
