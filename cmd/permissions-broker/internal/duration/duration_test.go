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
