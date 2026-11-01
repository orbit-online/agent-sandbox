package main

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/orbit-online/agent-sandbox/internal/proc"
)

// What still holds an attach grant after it ended, however it ended (revoked, released from inside, its lease ran out):
// the window shows each and offers to end them

// How many ended grants' holders are kept for the window
const maxHeld = 20

// The holders of a grant that ended
type held struct {
	Grant   string    `json:"grant"`
	Summary string    `json:"summary"`
	Why     string    `json:"why"`
	Time    time.Time `json:"time"`
	Holders []holder  `json:"holders"`
}

// recordHeld keeps what still holds g after it ended for the window
func (b *broker) recordHeld(g *grant, why string) {
	if len(g.Holders) == 0 {
		return
	}
	b.mu.Lock()
	b.heldGrants = append(b.heldGrants, held{Grant: g.ID, Summary: g.Summary, Why: why, Time: b.now(), Holders: g.Holders})
	if n := len(b.heldGrants); n > maxHeld {
		b.heldGrants = b.heldGrants[n-maxHeld:]
	}
	b.mu.Unlock()
	b.event("held", g.ID)
}

// heldViews is what's still held, without the processes gone since
func (b *broker) heldViews() []held {
	b.mu.Lock()
	all := slices.Clone(b.heldGrants)
	b.mu.Unlock()
	var out []held
	for _, h := range all {
		h.Holders = slices.DeleteFunc(slices.Clone(h.Holders), func(p holder) bool {
			start, ok := startTime(p.Pid)
			return !ok || start != p.Start
		})
		if len(h.Holders) > 0 {
			out = append(out, h)
		}
	}
	return out
}

// endHeld ends what still holds an ended grant, as recorded, and forgets it
func (b *broker) endHeld(grant string) error {
	b.mu.Lock()
	i := slices.IndexFunc(b.heldGrants, func(h held) bool { return h.Grant == grant })
	if i < 0 {
		b.mu.Unlock()
		return fmt.Errorf("Nothing recorded as holding %q", grant)
	}
	hs := b.heldGrants[i].Holders
	b.heldGrants = slices.Delete(b.heldGrants, i, i+1)
	b.mu.Unlock()
	return b.endHolders(hs)
}

// endHolders ends holders with SIGKILL, which no process can ignore or handle, each through a pidfd taken first, and
// only while the pidfd's process is the one recorded (its start time) and in the sandbox, as checked after those reads:
// a pid since reused isn't signalled
func (b *broker) endHolders(hs []holder) error {
	var errs []error
	for _, h := range hs {
		fd, err := unix.PidfdOpen(h.Pid, 0)
		if err != nil {
			continue // gone already
		}
		start, ok := startTime(h.Pid)
		switch {
		case !ok || start != h.Start || !proc.Alive(fd):
			// another process by now, or gone
		case !b.sb.contains(h.Pid) || !proc.Alive(fd):
			errs = append(errs, fmt.Errorf("%d isn't in the sandbox", h.Pid))
		default:
			if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
				errs = append(errs, fmt.Errorf("End %d: %w", h.Pid, err))
			}
		}
		unix.Close(fd)
	}
	return errors.Join(errs...)
}

// startTime is a running process's start time, in clock ticks since boot (field 22 of /proc/<pid>/stat). Not for a
// zombie: it holds nothing any more
func startTime(pid int) (uint64, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, false
	}
	// The command name, in parentheses, may hold anything: the fields follow its last ')'
	i := strings.LastIndexByte(string(data), ')')
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(string(data[i+1:]))
	if len(f) < 20 || f[0] == "Z" || f[0] == "X" {
		return 0, false
	}
	start, err := strconv.ParseUint(f[19], 10, 64)
	return start, err == nil
}
