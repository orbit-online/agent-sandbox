package wire

import (
	"errors"
	"strings"

	"github.com/godbus/dbus/v5"
)

// The checks on header fields godbus's IsValid and ParseSignature leave out: the destination and sender are bus names,
// nothing uses the reserved local path or interface, which the bus daemon disconnects a client for, and a signature
// has no empty struct and no dict entry with a key that isn't a basic type

const (
	localPath      = "/org/freedesktop/DBus/Local"
	localInterface = "org.freedesktop.DBus.Local"
)

// A bus name: unique (a colon, then elements that may start with a digit) or well-known (none starting with one),
// two or more elements of [A-Za-z0-9_-], at most 255 bytes
func validBusName(s string) bool {
	if len(s) > 255 {
		return false
	}
	unique := strings.HasPrefix(s, ":")
	elems := strings.Split(strings.TrimPrefix(s, ":"), ".")
	if len(elems) < 2 {
		return false
	}
	for _, e := range elems {
		if e == "" || !unique && e[0] >= '0' && e[0] <= '9' {
			return false
		}
		for i := 0; i < len(e); i++ {
			c := e[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}

func checkNames(h map[dbus.HeaderField]dbus.Variant) error {
	for _, f := range []dbus.HeaderField{dbus.FieldDestination, dbus.FieldSender} {
		if v, ok := h[f]; ok && !validBusName(v.Value().(string)) {
			return errors.New("Invalid bus name")
		}
	}
	if v, ok := h[dbus.FieldSignature]; ok && !fullSignature(v.Value().(dbus.Signature).String()) {
		return errors.New("Invalid signature")
	}
	if v, ok := h[dbus.FieldPath]; ok && string(v.Value().(dbus.ObjectPath)) == localPath {
		return errors.New("The reserved local path")
	}
	if v, ok := h[dbus.FieldInterface]; ok && v.Value().(string) == localInterface {
		return errors.New("The reserved local interface")
	}
	return nil
}

// What the D-Bus specification refuses in a signature godbus parsed: "()" and a dict key other than a basic type
func fullSignature(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '(' && s[i+1] == ')' {
			return false
		}
		if s[i] == '{' && !strings.ContainsRune("ybnqiuxtdhsog", rune(s[i+1])) {
			return false
		}
	}
	return true
}
