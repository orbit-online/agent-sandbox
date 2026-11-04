// Package spec is a reference model of the D-Bus specification (https://dbus.freedesktop.org/doc/dbus-specification.html,
// "Message Protocol") for the proxy's tests: names, signatures, the wire format of a message and its body, written
// from the specification alone, and the proxy's own rules on top from docs/permissions.md (proxy.go). It decides
// what's valid without the proxy's parsers or godbus, so tests can hold them against it. Where the specification is
// silent, the comment says whose behaviour is taken (libdbus's, the reference implementation)
package spec

import "strings"

// The longest bus name, interface, member or error name ("Valid Names")
const MaxNameLength = 255

func nameChar(c byte, hyphen bool) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || hyphen && c == '-'
}

// Elements separated by dots: at least two, none empty, each of [A-Za-z0-9_] (and '-' with hyphen), none starting
// with a digit unless digits may lead
func dotted(s string, hyphen, digitFirst bool) bool {
	elems := strings.Split(s, ".")
	if len(elems) < 2 {
		return false
	}
	for _, e := range elems {
		if e == "" || !digitFirst && e[0] >= '0' && e[0] <= '9' {
			return false
		}
		for i := 0; i < len(e); i++ {
			if !nameChar(e[i], hyphen) {
				return false
			}
		}
	}
	return true
}

// UniqueName: a colon, then two or more elements of [A-Za-z0-9_-], which may start with a digit
func UniqueName(s string) bool {
	return len(s) <= MaxNameLength && strings.HasPrefix(s, ":") && dotted(s[1:], true, true)
}

// WellKnownName: two or more elements of [A-Za-z0-9_-], none starting with a digit
func WellKnownName(s string) bool {
	return len(s) <= MaxNameLength && dotted(s, true, false)
}

// BusName: unique or well-known
func BusName(s string) bool { return UniqueName(s) || WellKnownName(s) }

// Interface: two or more elements of [A-Za-z0-9_], none starting with a digit
func Interface(s string) bool { return len(s) <= MaxNameLength && dotted(s, false, false) }

// ErrorName: as an interface
func ErrorName(s string) bool { return Interface(s) }

// Member: [A-Za-z0-9_], not starting with a digit, at least one byte
func Member(s string) bool {
	if s == "" || len(s) > MaxNameLength || s[0] >= '0' && s[0] <= '9' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !nameChar(s[i], false) {
			return false
		}
	}
	return true
}

// Path: "/", or "/"-separated elements of [A-Za-z0-9_], none empty, with no trailing "/"
func Path(s string) bool {
	if s == "/" {
		return true
	}
	if !strings.HasPrefix(s, "/") {
		return false
	}
	for _, e := range strings.Split(s[1:], "/") {
		if e == "" {
			return false
		}
		for i := 0; i < len(e); i++ {
			if !nameChar(e[i], false) {
				return false
			}
		}
	}
	return true
}

// The reserved path and interface a message may not use: the bus daemon disconnects a client that sends them
const (
	LocalPath      = "/org/freedesktop/DBus/Local"
	LocalInterface = "org.freedesktop.DBus.Local"
)
