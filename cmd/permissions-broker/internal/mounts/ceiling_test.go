package mounts

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckDenied(t *testing.T) {
	for _, bad := range []string{"", "relative", "./x"} {
		if _, err := CheckDenied([]string{bad}); err == nil {
			t.Errorf("checkDenied accepted %q", bad)
		}
	}
	dir := t.TempDir()
	if err := os.Symlink(dir, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if got, err := CheckDenied([]string{filepath.Join(dir, "link")}); err != nil || got[0] != dir {
		t.Errorf("checkDenied = %v, %v; want the link resolved", got, err)
	}
}

func TestCheckSource(t *testing.T) {
	ceil := []Source{{Path: "/srv/notes"}, {Path: "/srv/work", RW: true}, {Path: "/srv/work/keep-ro"}, {Path: "/dev/kvm"}}
	denied := []string{"/srv/work/state"}
	for _, ok := range []struct {
		src       string
		ro        bool
		root, rel string
	}{
		{"/srv/notes", true, "/srv/notes", "."},
		{"/srv/notes/a/../b", true, "/srv/notes", "b"},
		{"/srv/work/x", false, "/srv/work", "x"},
		{"/srv/work/keep-ro/x", true, "/srv/work/keep-ro", "x"},
		{"/dev/kvm", true, "/dev/kvm", "."},
	} {
		root, rel, err := CheckSource(ceil, denied, ok.src, ok.ro)
		if err != nil || root != ok.root || rel != ok.rel {
			t.Errorf("checkSource(%s) = %s, %s, %v", ok.src, root, rel, err)
		}
	}
	for _, bad := range []struct {
		src string
		ro  bool
	}{
		{"/srv/notes", false},       // read-only only
		{"/srv/notesx", true},       // not beneath, only a prefix of the name
		{"/srv/notes/../etc", true}, // out by ..
		{"srv/notes", true},         // relative
		{"/srv/work/state/x", true}, // denied
		{"/srv/work", true},         // holds a denied directory
		{"/srv", true},
		{"/srv/work/keep-ro/x", false}, // the longest source decides, and it's read-only
	} {
		if _, _, err := CheckSource(ceil, denied, bad.src, bad.ro); err == nil {
			t.Errorf("checkSource(%s, ro=%v) accepted", bad.src, bad.ro)
		}
	}
}
