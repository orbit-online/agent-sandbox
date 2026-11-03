package main

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/mountinfo"
	"golang.org/x/sys/unix"
)

// An attach grant's mount in M1, found when it's attached by the tree's mount id, not by its path: the sandbox can
// rename the grant directory in M1 (models/README.md, Attacker 6). Its id, peer group, and device and root, by which
// copies of it are found; the tree itself, which the daemon keeps open, and its device as stat gives it (srcDev) and
// as mountinfo and maps give it (sbDev, the superblock's; btrfs's stat gives a subvolume's)
type grantMount struct {
	id        uint64
	group     string
	dev, root string
	tree      *os.File
	srcDev    uint64
	sbDev     uint64
}

// grantMountOf finds the mount the tree (attached in M1) is in M1's mountinfo, by its mount id
func (s *sandbox) grantMountOf(tree *os.File) (*grantMount, error) {
	var stx unix.Statx_t
	if err := unix.Statx(int(tree.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &stx); err != nil ||
		stx.Mask&unix.STATX_MNT_ID == 0 {
		return nil, fmt.Errorf("The grant's mount id: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(tree.Fd()), &st); err != nil {
		return nil, err
	}
	lines, err := s.mountinfo()
	if err != nil {
		return nil, fmt.Errorf("The sandbox's mounts: %w", err)
	}
	for _, l := range lines {
		if l.ID == stx.Mnt_id {
			m := &grantMount{id: l.ID, dev: l.Dev, root: l.Root, tree: tree, srcDev: st.Dev, sbDev: parseDev(l.Dev)}
			for _, o := range l.Optional {
				if g, ok := strings.CutPrefix(o, "shared:"); ok {
					m.group = g
				}
			}
			return m, nil
		}
	}
	return nil, fmt.Errorf("The grant's mount (%d) isn't in the sandbox's mount namespace", stx.Mnt_id)
}

// copyOf reports whether l is the grant's mount, or one propagated from it: in its peer group or its slave
func (m *grantMount) copyOf(l mountinfo.Line) bool {
	if l.ID == m.id {
		return true
	}
	return m.group != "" && slices.ContainsFunc(l.Optional, func(o string) bool {
		return o == "shared:"+m.group || o == "master:"+m.group
	})
}

// isShared reports whether dir is a shared mount in the sandbox's mount namespace: a daemon started again finds the
// grant directory shared by the one before
func (s *sandbox) isShared(dir string) bool {
	lines, err := s.mountinfo()
	if err != nil {
		return false
	}
	for _, l := range lines {
		if l.Point == dir && slices.ContainsFunc(l.Optional, func(o string) bool { return strings.HasPrefix(o, "shared:") }) {
			return true
		}
	}
	return false
}

// parseDev reads a device as mountinfo gives it, major:minor in decimal
func parseDev(s string) uint64 {
	major, minor, _ := strings.Cut(s, ":")
	maj, _ := strconv.ParseUint(major, 10, 32)
	mn, _ := strconv.ParseUint(minor, 10, 32)
	return unix.Mkdev(uint32(maj), uint32(mn))
}
