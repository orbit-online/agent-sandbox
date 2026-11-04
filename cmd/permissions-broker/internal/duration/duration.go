// Package duration reads and writes the ISO 8601 durations of leases and host commands' validity
package duration

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"time"
)

var durationRe = regexp.MustCompile(`^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$`)

// Parse reads the ISO 8601 durations leases use: PT1H, PT30M, PT1H30M
func Parse(s string) (time.Duration, error) {
	m := durationRe.FindStringSubmatch(s)
	if m == nil || s == "PT" {
		return 0, fmt.Errorf("Not a duration such as PT1H: %q", s)
	}
	var d time.Duration
	for i, unit := range []time.Duration{time.Hour, time.Minute, time.Second} {
		if m[i+1] == "" {
			continue
		}
		// Past what a Duration holds (292 years) it would wrap around: a lease of minutes for one of millions of hours
		n, err := strconv.ParseInt(m[i+1], 10, 64)
		if err != nil || n > (math.MaxInt64-int64(d))/int64(unit) {
			return 0, fmt.Errorf("Too long a duration: %q", s)
		}
		d += time.Duration(n) * unit
	}
	if d <= 0 {
		return 0, fmt.Errorf("Not a positive duration: %q", s)
	}
	return d, nil
}

func Format(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return fmt.Sprintf("PT%dS", int(d.Round(time.Second)/time.Second))
}
