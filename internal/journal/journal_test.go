package journal

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"syscall"
	"testing"
)

// Each record gets its priority's prefix and no time; attrs and groups reach every priority
func TestPrefixes(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(Handler(&buf, true)).With("c", 1).WithGroup("g")
	l.Error("e", "k", "v")
	l.Warn("w")
	l.Info("i")
	l.Debug("d")
	l.Log(t.Context(), slog.LevelWarn+2, "between")
	want := []string{
		`<3>level=ERROR msg=e c=1 g.k=v`,
		`<4>level=WARN msg=w c=1`,
		`<6>level=INFO msg=i c=1`,
		`<4>level=WARN+2 msg=between c=1`,
	}
	if got := strings.Split(strings.TrimSpace(buf.String()), "\n"); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("Got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestPlain(t *testing.T) {
	var buf bytes.Buffer
	slog.New(Handler(&buf, false)).Warn("w")
	if s := buf.String(); !strings.HasPrefix(s, "time=") || !strings.Contains(s, "level=WARN msg=w") {
		t.Errorf("%q", s)
	}
}

func TestIsStream(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "s")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	for _, c := range []struct {
		env  string
		want bool
	}{{fmt.Sprintf("%d:%d", st.Dev, st.Ino), true}, {fmt.Sprintf("%d:%d", st.Dev, st.Ino+1), false}, {"", false}, {"x", false}} {
		t.Setenv("JOURNAL_STREAM", c.env)
		if got := IsStream(f); got != c.want {
			t.Errorf("%q: %t", c.env, got)
		}
	}
}

func TestWrap(t *testing.T) {
	if got := fmt.Sprint(Wrap("/sc", "ns", "id", "a", "b")); got != "[/sc --namespace=ns --identifier=id -- a b]" {
		t.Error(got)
	}
	if got := fmt.Sprint(Wrap("", "ns", "id", "a")); got != "[a]" {
		t.Error(got)
	}
}
