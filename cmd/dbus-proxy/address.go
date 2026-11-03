package main

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
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
			val, err := unescape(v)
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

// D-Bus address values escape bytes as %XX
func unescape(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", errors.New("Truncated escape")
		}
		n, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
		if err != nil {
			return "", fmt.Errorf("Invalid escape %q", s[i:i+3])
		}
		b.WriteByte(byte(n))
		i += 2
	}
	return b.String(), nil
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
