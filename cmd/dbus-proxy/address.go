package main

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/godbus/dbus/v5"
)

// A bus address's unix transports, the only kind a session or system bus address names here: path= and abstract=,
// tried in order. Other transports and keys are skipped; an address with no usable entry is an error
func parseAddress(addr string) ([]*net.UnixAddr, error) {
	var out []*net.UnixAddr
	for _, entry := range strings.Split(addr, ";") {
		transport, params, ok := strings.Cut(entry, ":")
		if !ok || transport != "unix" {
			continue
		}
		for _, kv := range strings.Split(params, ",") {
			k, v, _ := strings.Cut(kv, "=")
			val, err := dbus.UnescapeBusAddressValue(v)
			if err != nil {
				return nil, fmt.Errorf("Parse bus address %q: %w", addr, err)
			}
			switch k {
			case "path":
				out = append(out, &net.UnixAddr{Name: val, Net: "unix"})
			case "abstract":
				out = append(out, &net.UnixAddr{Name: "@" + val, Net: "unix"})
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("No unix path or abstract socket in bus address %q", addr)
	}
	return out, nil
}

func dialBus(addrs []*net.UnixAddr) (*net.UnixConn, error) {
	var errs []error
	for _, a := range addrs {
		conn, err := net.DialUnix("unix", nil, a)
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
	}
	return nil, fmt.Errorf("Connect to the bus: %w", errors.Join(errs...))
}
