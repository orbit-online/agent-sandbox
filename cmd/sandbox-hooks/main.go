package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/docopt/docopt-go"
	"github.com/orbit-online/agent-sandbox/internal/caller"
	"github.com/orbit-online/agent-sandbox/internal/journal"
	"golang.org/x/sys/unix"
)

const usage = `sandbox-hooks - Run the hooks root configured for a phase of a sandbox

Usage:
  sandbox-hooks start [--name=<name>] <pid>
  sandbox-hooks stop [--name=<name>]

The launcher runs it at each phase of a sandbox: start once the network
namespace of the sandbox is set up and before the app starts, stop after the
sandbox ended. It checks what the caller names first: the caller in group
users, the launcher name, and for start that <pid> belongs to the caller and
its network namespace to a user namespace below the caller's, through a child
of it that the caller owns (as netns-netkit up checks it). Then it runs each
hook of the phase in /etc/agent-sandbox/hooks.json
({"start": [{"path": "/abs/path", "capabilities": ["CAP_NET_ADMIN"]}],
"stop": [...]}, agent-sandbox.hooks of the NixOS module), in order, as
<hook> <phase> <uid> <name> (name empty for the default launcher):

- with the capabilities it declares alone, which the wrapper holds for the
  union of what the hooks declare
- the caller's uid, and the wrapper's group as real, effective and saved gid
- an empty environment, / as its directory, stdin /dev/null and its output on
  stderr, in a process group of its own, killed after 30 seconds
- for start, the network namespace of the sandbox on fd 3

The file and each hook must be regular files of root, links followed, or it
refuses before any hook runs. Every hook runs; when one fails it exits with 3.
`

func main() {
	journal.Setup()
	opts, err := docopt.ParseDoc(usage)
	if err != nil {
		slog.Error("Parse arguments", "err", err)
		os.Exit(2)
	}
	if err := run(opts, hooksConfig, 0); errors.Is(err, errHooks) {
		slog.Error(err.Error())
		os.Exit(3)
	} else if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

// The check of the caller's group; tests run outside group users
var human = caller.Human

// run checks what the caller names, then runs the hooks of the phase from config, which owner must own
func run(opts docopt.Opts, config string, owner uint32) error {
	name, _ := opts.String("--name")
	if !caller.LauncherName.MatchString(name) {
		return fmt.Errorf("Launcher name %q is not [a-z][a-z0-9-]*, at most 46 characters", name)
	}
	if err := human(); err != nil {
		return err
	}
	phase := "stop"
	if opts["start"] == true {
		phase = "start"
	}
	h, err := loadHooks(config, owner)
	if err != nil {
		return err
	}
	if len(h[phase]) == 0 {
		return nil
	}
	uid := unix.Getuid()
	var files []*os.File
	if phase == "start" {
		pid, err := strconv.Atoi(opts["<pid>"].(string))
		if err != nil || pid <= 0 {
			return fmt.Errorf("Pid %q is not a process", opts["<pid>"])
		}
		netnsFd, err := caller.OpenNetns(pid, uid, "/proc/self/ns/user")
		if err != nil {
			return err
		}
		netns := os.NewFile(uintptr(netnsFd), "netns")
		defer netns.Close()
		files = append(files, netns)
	}
	return runHooks(h[phase], phase, uid, name, files)
}
