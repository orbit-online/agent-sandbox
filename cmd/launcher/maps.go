package main

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// The id maps bwrap's user namespace gets, as newuidmap and newgidmap take them: inner, outer, count triples

// subidMap maps the user's /etc/subuid (or subgid) range: inner id x is outer start+x, except own, the user's own
// id, which stays itself
func subidMap(subid io.Reader, user string, own int) ([]int, error) {
	start, count := -1, 0
	s := bufio.NewScanner(subid)
	for s.Scan() {
		f := strings.Split(s.Text(), ":")
		if len(f) == 3 && f[0] == user {
			start, _ = strconv.Atoi(f[1])
			count, _ = strconv.Atoi(f[2])
			break
		}
	}
	if start < 0 || count <= own {
		return nil, fmt.Errorf("%s needs a range of at least %d ids", user, own+1)
	}
	return []int{0, start, own, own, own, 1, own + 1, start + own + 1, count - own - 1}, nil
}

// identityMap maps every id of the parent user namespace as itself, from its uid_map or gid_map
func identityMap(procMap io.Reader) ([]int, error) {
	var m []int
	s := bufio.NewScanner(procMap)
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) != 3 {
			return nil, fmt.Errorf("A map line %q", s.Text())
		}
		inner, err1 := strconv.Atoi(f[0])
		count, err2 := strconv.Atoi(f[2])
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("A map line %q", s.Text())
		}
		m = append(m, inner, inner, count)
	}
	return m, s.Err()
}

// subidLines lists an identity map's ids minus own as /etc/subuid (or subgid) lines of user, for rootless tools
func subidLines(m []int, user string, own int) string {
	var b strings.Builder
	for i := 0; i+2 < len(m); i += 3 {
		start, count := m[i], m[i+2]
		if own < start || own >= start+count {
			fmt.Fprintf(&b, "%s:%d:%d\n", user, start, count)
			continue
		}
		if own > start {
			fmt.Fprintf(&b, "%s:%d:%d\n", user, start, own-start)
		}
		if own < start+count-1 {
			fmt.Fprintf(&b, "%s:%d:%d\n", user, own+1, start+count-own-1)
		}
	}
	return b.String()
}

func mapArgs(m []int) []string {
	a := make([]string, len(m))
	for i, v := range m {
		a[i] = strconv.Itoa(v)
	}
	return a
}
