package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// The hooks, which only root configures (agent-sandbox.hooks of the NixOS module). They run with capabilities on the
// host, so the file and every hook must be root's. Only root writes /etc and /nix/store, where they are, so that is
// all to check
var hooksConfig = "/etc/agent-sandbox/hooks.json"

// A hook of a phase: what to run, and the capabilities it gets
type hook struct {
	Path         string   `json:"path"`
	Capabilities []string `json:"capabilities"`
	caps         []uintptr
}

// The phases and their hooks
type hooks map[string][]hook

var phases = []string{"start", "stop"}

// loadHooks reads config, none when it is missing, after checking that owner (root but in tests) owns it and every
// hook in it, and that the hooks name capabilities that exist
func loadHooks(config string, owner uint32) (hooks, error) {
	h := hooks{}
	err := rootOwned(config, owner)
	if errors.Is(err, fs.ErrNotExist) {
		return h, nil
	} else if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(config)
	if err != nil {
		return nil, fmt.Errorf("Read %s: %w", config, err)
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return nil, fmt.Errorf("Parse %s: %w", config, err)
	}
	for phase, list := range h {
		if !contains(phases, phase) {
			return nil, fmt.Errorf("%s names phase %q, not one of %v", config, phase, phases)
		}
		for i := range list {
			hk := &list[i]
			if !filepath.IsAbs(hk.Path) {
				return nil, fmt.Errorf("Hook %q in %s is not an absolute path", hk.Path, config)
			}
			if err := rootOwned(hk.Path, owner); err != nil {
				return nil, err
			}
			for _, c := range hk.Capabilities {
				n, ok := capNames[c]
				if !ok {
					return nil, fmt.Errorf("Hook %s in %s declares %q, no capability", hk.Path, config, c)
				}
				hk.caps = append(hk.caps, n)
			}
		}
	}
	return h, nil
}

// rootOwned checks that the file path names, links followed, is a regular file of owner
func rootOwned(path string, owner uint32) error {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return &fs.PathError{Op: "stat", Path: path, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if st.Uid != owner {
		return fmt.Errorf("%s is not root owned: it belongs to uid %d", path, st.Uid)
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, l := range list {
		if l == s {
			return true
		}
	}
	return false
}

// The capabilities by the names capabilities(7) gives them
var capNames = map[string]uintptr{
	"CAP_CHOWN": unix.CAP_CHOWN, "CAP_DAC_OVERRIDE": unix.CAP_DAC_OVERRIDE,
	"CAP_DAC_READ_SEARCH": unix.CAP_DAC_READ_SEARCH, "CAP_FOWNER": unix.CAP_FOWNER, "CAP_FSETID": unix.CAP_FSETID,
	"CAP_KILL": unix.CAP_KILL, "CAP_SETGID": unix.CAP_SETGID, "CAP_SETUID": unix.CAP_SETUID,
	"CAP_SETPCAP": unix.CAP_SETPCAP, "CAP_LINUX_IMMUTABLE": unix.CAP_LINUX_IMMUTABLE,
	"CAP_NET_BIND_SERVICE": unix.CAP_NET_BIND_SERVICE, "CAP_NET_BROADCAST": unix.CAP_NET_BROADCAST,
	"CAP_NET_ADMIN": unix.CAP_NET_ADMIN, "CAP_NET_RAW": unix.CAP_NET_RAW, "CAP_IPC_LOCK": unix.CAP_IPC_LOCK,
	"CAP_IPC_OWNER": unix.CAP_IPC_OWNER, "CAP_SYS_MODULE": unix.CAP_SYS_MODULE, "CAP_SYS_RAWIO": unix.CAP_SYS_RAWIO,
	"CAP_SYS_CHROOT": unix.CAP_SYS_CHROOT, "CAP_SYS_PTRACE": unix.CAP_SYS_PTRACE, "CAP_SYS_PACCT": unix.CAP_SYS_PACCT,
	"CAP_SYS_ADMIN": unix.CAP_SYS_ADMIN, "CAP_SYS_BOOT": unix.CAP_SYS_BOOT, "CAP_SYS_NICE": unix.CAP_SYS_NICE,
	"CAP_SYS_RESOURCE": unix.CAP_SYS_RESOURCE, "CAP_SYS_TIME": unix.CAP_SYS_TIME,
	"CAP_SYS_TTY_CONFIG": unix.CAP_SYS_TTY_CONFIG, "CAP_MKNOD": unix.CAP_MKNOD, "CAP_LEASE": unix.CAP_LEASE,
	"CAP_AUDIT_WRITE": unix.CAP_AUDIT_WRITE, "CAP_AUDIT_CONTROL": unix.CAP_AUDIT_CONTROL,
	"CAP_SETFCAP": unix.CAP_SETFCAP, "CAP_MAC_OVERRIDE": unix.CAP_MAC_OVERRIDE, "CAP_MAC_ADMIN": unix.CAP_MAC_ADMIN,
	"CAP_SYSLOG": unix.CAP_SYSLOG, "CAP_WAKE_ALARM": unix.CAP_WAKE_ALARM, "CAP_BLOCK_SUSPEND": unix.CAP_BLOCK_SUSPEND,
	"CAP_AUDIT_READ": unix.CAP_AUDIT_READ, "CAP_PERFMON": unix.CAP_PERFMON, "CAP_BPF": unix.CAP_BPF,
	"CAP_CHECKPOINT_RESTORE": unix.CAP_CHECKPOINT_RESTORE,
}
