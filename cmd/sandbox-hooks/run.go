package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// A hook gets this long before it is killed
var hookTimeout = 30 * time.Second

// errHooks: a hook failed, the others ran. main exits with 3 for it, so the launcher starts the sandbox anyway and
// says so
var errHooks = errors.New("A hook failed")

// runHooks runs each hook of phase in order, on one locked thread whose credentials each child copies: the wrapper's
// group as real, effective and saved gid (bash without -p drops an effective gid other than the real one), and per
// hook its capabilities alone as inheritable and ambient, so that is all it holds after the exec. Every hook runs; a
// failed one is logged and makes errHooks
func runHooks(list []hook, phase string, uid int, name string, files []*os.File) error {
	runtime.LockOSThread()
	// Never unlocked: the thread's credentials stay changed, so it goes when the goroutine ends
	if egid := unix.Getegid(); unix.Setresgid(egid, egid, egid) != nil {
		return fmt.Errorf("Take gid %d for the hooks", egid)
	}
	failed := false
	for _, h := range list {
		if err := runHook(h, phase, uid, name, files); err != nil {
			slog.Error("Hook failed", "phase", phase, "hook", h.Path, "err", err)
			failed = true
		}
	}
	if failed {
		return errHooks
	}
	return nil
}

func runHook(h hook, phase string, uid int, name string, files []*os.File) error {
	if err := capsFor(h.caps); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), hookTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.Path, phase, strconv.Itoa(uid), name)
	// Not nil, which would pass on the caller's environment
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	cmd.ExtraFiles = files
	cmd.SysProcAttr = &syscall.SysProcAttr{AmbientCaps: h.caps, Pdeathsig: syscall.SIGKILL, Setpgid: true}
	// The hook's process group, so what it started goes too
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	err := cmd.Run()
	if ctx.Err() != nil {
		return fmt.Errorf("Killed after %s", hookTimeout)
	}
	return err
}

// capsFor makes caps the inheritable set of the thread and clears its ambient set; the child raises them as ambient.
// A capability the thread doesn't hold is an error: the wrapper holds the union of the hooks' (the NixOS module)
func capsFor(caps []uintptr) error {
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("Clear the ambient capabilities: %w", err)
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("Read the capabilities: %w", err)
	}
	data[0].Inheritable, data[1].Inheritable = 0, 0
	for _, c := range caps {
		if data[c/32].Permitted&(1<<(c%32)) == 0 {
			return fmt.Errorf("The wrapper doesn't hold capability %d", c)
		}
		data[c/32].Inheritable |= 1 << (c % 32)
	}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("Set the inheritable capabilities: %w", err)
	}
	return nil
}
