package main

import (
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
// Lexical, as are the denied directories it refuses: clone-tree then opens the path without following links or
// crossing mounts, so the path checked is the one cloned
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
// expansion, and as the system resolves them: a source is opened without following links, so only a path without
// any compares against them
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

// openSource opens rel beneath root as a grant's source: root without following any link, rel beneath it without
// following links or crossing mounts
func openSource(root, rel string) (int, error) {
	noLinks := uint64(unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS)
	rootFd, err := unix.Openat2(unix.AT_FDCWD, root, &unix.OpenHow{
		Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: noLinks})
	if err != nil {
		return -1, fmt.Errorf("Open %s, which must be reached without links: %w", root, err)
	}
	defer unix.Close(rootFd)
	fd, err := unix.Openat2(rootFd, rel, &unix.OpenHow{
		Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: noLinks | unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return -1, fmt.Errorf("Open %s beneath %s without links or crossing mounts: %w", rel, root, err)
	}
	return fd, nil
}
