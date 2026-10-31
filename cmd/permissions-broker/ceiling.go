package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// A source an attach grant may attach: a path beneath one of the ceiling's roots
type source struct {
	Path string `json:"path"`
	RW   bool   `json:"rw"`
}

// attachCeiling is what an attach plugin's ceiling says the daemon may attach at all
type attachCeiling struct {
	Sources []source `json:"sources"`
}

// checkSource finds the ceiling root src lies beneath, the longest that matches, and whether it may be read-write.
// Lexical, so it refuses early what the ceiling doesn't cover; clone-tree checks what the path is when it opens it
func checkSource(ceil attachCeiling, denied []string, src string, ro bool) (root, rel string, err error) {
	if !filepath.IsAbs(src) {
		return "", "", fmt.Errorf("Not an absolute path: %q", src)
	}
	src = filepath.Clean(src)
	for _, d := range denied {
		if src == d || strings.HasPrefix(src, d+"/") || strings.HasPrefix(d, strings.TrimSuffix(src, "/")+"/") {
			return "", "", fmt.Errorf("%s is never granted", src)
		}
	}
	var best *source
	for i, s := range ceil.Sources {
		r := filepath.Clean(s.Path)
		if src != r && !strings.HasPrefix(src, strings.TrimSuffix(r, "/")+"/") {
			continue
		}
		if best == nil || len(r) > len(filepath.Clean(best.Path)) {
			best = &ceil.Sources[i]
		}
	}
	if best == nil {
		return "", "", fmt.Errorf("%s isn't beneath anything the ceiling allows", src)
	}
	if !ro && !best.RW {
		return "", "", fmt.Errorf("%s may only be granted read-only", src)
	}
	root = filepath.Clean(best.Path)
	rel, _ = filepath.Rel(root, src)
	return root, rel, nil
}

// checkDenied validates the denied directories from the config: absolute, non-empty after the environment's
// expansion, and as the system resolves them, so they compare by identity whatever path leads there
func checkDenied(denied []string) ([]string, error) {
	out := make([]string, 0, len(denied))
	for _, d := range denied {
		if !filepath.IsAbs(d) {
			return nil, fmt.Errorf("Denied directory %q isn't an absolute path (an unset variable?)", d)
		}
		if real, err := filepath.EvalSymlinks(d); err == nil {
			d = real
		}
		out = append(out, filepath.Clean(d))
	}
	return out, nil
}

type fileID struct{ dev, ino uint64 }

func (id fileID) String() string { return fmt.Sprintf("%d:%d", id.dev, id.ino) }

// openSource opens rel beneath root as a grant's source: root without following any link, rel beneath it without
// following links or crossing mounts. Returns the source's fd and the root's
func openSource(root, rel string) (int, int, error) {
	noLinks := uint64(unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS)
	rootFd, err := unix.Openat2(unix.AT_FDCWD, root, &unix.OpenHow{
		Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: noLinks})
	if err != nil {
		return -1, -1, fmt.Errorf("Open %s, which must be reached without links: %w", root, err)
	}
	fd, err := unix.Openat2(rootFd, rel, &unix.OpenHow{
		Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: noLinks | unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV})
	if err != nil {
		unix.Close(rootFd)
		return -1, -1, fmt.Errorf("Open %s beneath %s without links or crossing mounts: %w", rel, root, err)
	}
	return fd, rootFd, nil
}

// identify is the identity of what a source names now, opened as the clone helper will open it: what the user is
// asked about, which the helper then requires
func identify(root, rel string) (string, error) {
	fd, rootFd, err := openSource(root, rel)
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)
	defer unix.Close(rootFd)
	id, err := idOf(fd)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

func idOf(fd int) (fileID, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fileID{}, err
	}
	return fileID{st.Dev, st.Ino}, nil
}

// checkIdentity refuses fd if it, or a directory between it and root, is a denied directory, or if a denied
// directory lies beneath it. By device and inode: no path to a denied directory, link or bind mount, gets around it
func checkIdentity(fd, rootFd int, denied []string) error {
	deniedIDs := map[fileID]string{}
	for _, d := range denied {
		var st unix.Stat_t
		if err := unix.Stat(d, &st); err == nil {
			deniedIDs[fileID{st.Dev, st.Ino}] = d
		}
	}
	rootID, err := idOf(rootFd)
	if err != nil {
		return err
	}
	src, err := idOf(fd)
	if err != nil {
		return err
	}
	// Up from the source to the root
	cur, err := unix.Dup(fd)
	if err != nil {
		return err
	}
	for {
		id, err := idOf(cur)
		if err != nil {
			unix.Close(cur)
			return err
		}
		if d, ok := deniedIDs[id]; ok {
			unix.Close(cur)
			return fmt.Errorf("Never granted: it's %s or beneath it", d)
		}
		if id == rootID {
			unix.Close(cur)
			break
		}
		up, err := unix.Openat(cur, "..", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		unix.Close(cur)
		if err != nil {
			return err
		}
		if upID, _ := idOf(up); upID == id {
			unix.Close(up)
			return errors.New("The source isn't beneath its root")
		}
		cur = up
	}
	// Up from each denied directory to /: the source mustn't be on the way
	for _, d := range denied {
		cur, err := unix.Open(d, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			continue
		}
		for {
			id, err := idOf(cur)
			if err != nil || id == src {
				unix.Close(cur)
				if err == nil {
					return fmt.Errorf("Never granted: %s lies beneath it", d)
				}
				return err
			}
			up, err := unix.Openat(cur, "..", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			unix.Close(cur)
			if err != nil {
				return err
			}
			if upID, _ := idOf(up); upID == id {
				unix.Close(up)
				break
			}
			cur = up
		}
	}
	return nil
}
