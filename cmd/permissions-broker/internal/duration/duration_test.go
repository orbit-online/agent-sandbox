package duration

import (
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	for s, want := range map[string]time.Duration{"PT1H": time.Hour, "PT30M": 30 * time.Minute, "PT1H30M": 90 * time.Minute,
		"PT2S": 2 * time.Second} {
		if got, err := Parse(s); err != nil || got != want {
			t.Errorf("Parse(%q) = %v, %v; want %v", s, got, err, want)
		}
	}
	for _, s := range []string{"", "PT", "1H", "PT0H", "P1D", "PT1h", "session"} {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) accepted", s)
		}
	}
}

// A duration past what time.Duration holds is refused, not wrapped around to another: PT5124096H was 25 minutes
func TestParseOverflow(t *testing.T) {
	if got, err := Parse("PT2562047H47M16S"); err != nil || got != 2562047*time.Hour+47*time.Minute+16*time.Second {
		t.Errorf("Parse(PT2562047H47M16S) = %v, %v", got, err)
	}
	for _, s := range []string{"PT2562048H", "PT5124096H", "PT5124096H90S", "PT99999999999999999999H",
		"PT2562047H47M17S"} {
		if d, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) = %v", s, d)
		}
	}
}
