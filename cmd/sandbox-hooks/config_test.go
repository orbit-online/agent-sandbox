package main

import (
	"errors"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"testing"
)

func write(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	os.Chmod(path, mode)
}

// A regular file of the owner (root but in tests), links followed
func TestRootOwned(t *testing.T) {
	dir := t.TempDir()
	me := uint32(os.Getuid())
	write(t, dir+"/ok", "", 0o755)
	os.Symlink(dir+"/ok", dir+"/link")
	os.Mkdir(dir+"/sub", 0o755)
	for _, tc := range []struct {
		path, want string
		owner      uint32
	}{
		{"ok", "", me},
		{"link", "", me},
		{"sub", "is not a regular file", me},
		{"ok", "belongs to uid " + strconv.Itoa(int(me)), me + 1},
		{"link", "belongs to uid " + strconv.Itoa(int(me)), me + 1},
	} {
		err := rootOwned(dir+"/"+tc.path, tc.owner)
		if tc.want == "" && err != nil {
			t.Errorf("%s: %v", tc.path, err)
		} else if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: err = %v, want %q", tc.path, err, tc.want)
		}
	}
	if err := rootOwned(dir+"/missing", me); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing: err = %v, want ErrNotExist", err)
	}
}

// No config is no hooks; the phases with their hooks and capabilities; anything else refused
func TestLoadHooks(t *testing.T) {
	dir := t.TempDir()
	me := uint32(os.Getuid())
	if h, err := loadHooks(dir+"/none.json", me); err != nil || len(h) != 0 {
		t.Errorf("missing config: %v, %v", h, err)
	}
	write(t, dir+"/hook", "", 0o755)
	write(t, dir+"/ok.json", `{"start": [{"path": "`+dir+`/hook", "capabilities": ["CAP_NET_ADMIN", "CAP_BPF"]}],
		"stop": [{"path": "`+dir+`/hook", "capabilities": []}]}`, 0o644)
	h, err := loadHooks(dir+"/ok.json", me)
	if err != nil || len(h["start"]) != 1 || len(h["stop"]) != 1 {
		t.Fatalf("ok config: %v, %v", h, err)
	}
	if got := h["start"][0].caps; len(got) != 2 || got[0] != capNames["CAP_NET_ADMIN"] || got[1] != capNames["CAP_BPF"] {
		t.Errorf("start caps %v", got)
	}
	if len(h["stop"][0].caps) != 0 {
		t.Errorf("stop caps %v", h["stop"][0].caps)
	}
	for f, tc := range map[string]struct{ content, want string }{
		"rel.json":     {`{"start": [{"path": "hook"}]}`, "not an absolute path"},
		"missing.json": {`{"start": [{"path": "` + dir + `/nohook"}]}`, "no such file"},
		"cap.json":     {`{"start": [{"path": "` + dir + `/hook", "capabilities": ["CAP_EVERYTHING"]}]}`, "no capability"},
		"phase.json":   {`{"boot": [{"path": "` + dir + `/hook"}]}`, `phase "boot"`},
		"field.json":   {`{"start": [{"path": "` + dir + `/hook", "uid": 0}]}`, "unknown field"},
		"bad.json":     {`{"start": "x"}`, "Parse"},
	} {
		write(t, dir+"/"+f, tc.content, 0o644)
		if _, err := loadHooks(dir+"/"+f, me); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", f, err, tc.want)
		}
	}
	if _, err := loadHooks(dir+"/ok.json", me+1); err == nil || !strings.Contains(err.Error(), "ok.json is not root owned") {
		t.Errorf("config of another owner: %v", err)
	}
}
