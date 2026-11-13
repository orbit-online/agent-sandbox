package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Ports: the capability built into the broker that lets the host reach a TCP or UDP port of the sandbox, one port per
// grant. netns-netkit (the setcap helper that joined the sandbox to the host) switches the port on in the ports map of
// the sandbox and off again with the flows recorded on it; the broker runs it as the user, for sandboxes of the user only

const portID = "port"

// portCap is the port capability, none without the helper
func portCap(cfg config) (*capability, error) {
	if cfg.NetnsNetkit == "" {
		return nil, nil
	}
	c := &capability{Name: portID, Type: "port", Description: "a port of the sandbox, reachable from the host",
		Params: map[string]json.RawMessage{
			"protocol": json.RawMessage(`{"type": "string", "enum": ["tcp", "udp"], "description": "tcp or udp"}`),
			"port":     json.RawMessage(`{"type": "integer", "minimum": 1, "maximum": 65535, "description": "the port the sandbox listens on"}`),
		}}
	if err := c.check(); err != nil {
		return nil, fmt.Errorf("Ports: %w", err)
	}
	return c, nil
}

// portOf is the protocol and port a validated request names, refused when it lacks one
func portOf(params json.RawMessage) (proto string, port int, err error) {
	var p struct {
		Protocol string `json:"protocol"`
		Port     int    `json:"port"`
	}
	_ = json.Unmarshal(params, &p)
	if p.Protocol == "" || p.Port == 0 {
		return "", 0, refusef(refParams, "A port grant names its protocol and port")
	}
	return p.Protocol, p.Port, nil
}

// netkit runs the helper for the sandbox of the launcher and returns what it printed
func netkit(cfg config, args ...string) (string, error) {
	if cfg.Launcher != "" {
		args = append([]string{args[0], "--name=" + cfg.Launcher}, args[1:]...)
	}
	out, err := exec.Command(cfg.NetnsNetkit, args...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			err = fmt.Errorf("%w: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return "", fmt.Errorf("netns-netkit %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

// portAddrs is where the host reaches port: the IPv4 and IPv6 address of the sandbox, which addr prints
func portAddrs(out string, port int) ([]string, error) {
	f := strings.Fields(out)
	if len(f) != 2 {
		return nil, fmt.Errorf("Addresses %q", out)
	}
	var addrs []string
	for _, s := range f {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("Addresses %q: %w", out, err)
		}
		addrs = append(addrs, netip.AddrPortFrom(a, uint16(port)).String())
	}
	return addrs, nil
}

// portKind is the kind of the port capability: a grant switches its port on in the programs of the sandbox, its end off
type portKind struct{ baseKind }

func (portKind) describe(_ *broker, _ *capability, params json.RawMessage) (string, error) {
	proto, port, err := portOf(params)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s port %d of the sandbox, reachable from the host", strings.ToUpper(proto), port), nil
}

// portState is a port as this daemon switched it: the live grants holding it on, and closing while a revoke of it
// failed and is tried again. mu serializes the runs of the helper for the port, so a grant never interleaves with the
// end of another. In b.ports, made on first use
type portState struct {
	mu      sync.Mutex
	holders map[string]bool
	closing bool
}

// The pauses between the tries of a revoke as a grant ends; after them, closing tries on in the background
var revokeRetries = []time.Duration{100 * time.Millisecond, 500 * time.Millisecond}

func (b *broker) port(proto string, port int) *portState {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := proto + "-" + strconv.Itoa(port)
	s := b.ports[key]
	if s == nil {
		s = &portState{holders: map[string]bool{}}
		b.ports[key] = s
	}
	return s
}

// live switches the port on and finds where the host reaches it: with no address, no grant
func (portKind) live(b *broker, g *grant) error {
	proto, port, err := portOf(g.Params)
	if err != nil {
		return err
	}
	s := b.port(proto, port)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := netkit(b.cfg, "grant", proto, strconv.Itoa(port)); err != nil {
		return err
	}
	s.closing = false
	out, err := netkit(b.cfg, "addr")
	if err == nil {
		g.Addresses, err = portAddrs(out, port)
	}
	if err != nil {
		b.portOff(s, proto, port)
		return err
	}
	s.holders[g.ID] = true
	return nil
}

// end switches the port off unless another live grant holds it. A sandbox that ended took the port with it
func (portKind) end(b *broker, g *grant, _ string) {
	proto, port, _ := portOf(g.Params)
	s := b.port(proto, port)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.holders, g.ID)
	if !b.sb.alive() {
		s.closing = false
		return
	}
	b.portOff(s, proto, port)
}

// portOff revokes the port under s.mu unless a live grant holds it, trying a few times. When that keeps failing the
// port is closing: on, without a grant, until a try in the background succeeds
func (b *broker) portOff(s *portState, proto string, port int) {
	if len(s.holders) > 0 {
		return
	}
	for i := 0; ; i++ {
		_, err := netkit(b.cfg, "revoke", proto, strconv.Itoa(port))
		if err == nil {
			s.closing = false
			return
		}
		slog.Warn("Revoke a port", "protocol", proto, "port", port, "err", err)
		if i == len(revokeRetries) {
			break
		}
		time.Sleep(revokeRetries[i])
	}
	if !s.closing {
		s.closing = true
		go b.closePort(s, proto, port)
	}
}

// closePort tries the revoke of a closing port again until it succeeds, a grant of the port switched it on again or the
// sandbox ended
func (b *broker) closePort(s *portState, proto string, port int) {
	slog.Warn("A port stays on until its revoke succeeds", "protocol", proto, "port", port)
	retry(b.clock, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closing && b.sb.alive() {
			if _, err := netkit(b.cfg, "revoke", proto, strconv.Itoa(port)); err != nil {
				slog.Warn("Revoke a closing port", "protocol", proto, "port", port, "err", err)
				return false
			}
			slog.Info("Closed a port", "protocol", proto, "port", port)
		}
		s.closing = false
		return true
	})
}

// retry runs try after a second, then after twice as long each time it fails, up to a minute, until it succeeds
func retry(clk clock, try func() bool) {
	for wait := time.Second; ; wait = min(2*wait, time.Minute) {
		<-clk.after(wait)
		if try() {
			return
		}
	}
}

// revokePorts ends every port grant a daemon left, on cleanup: none is live when a daemon starts. Revoking needs only
// the name of the launcher; without the sandbox there's nothing to revoke, and the helper says so. While the sandbox
// runs, a failed revoke is tried again until it succeeds: until then its ports stay on without a grant
func revokePorts(cfg config, sb *sandbox, clk clock) {
	if cfg.NetnsNetkit == "" {
		return
	}
	try := func() bool {
		_, err := netkit(cfg, "revoke", "--all")
		switch {
		case err == nil:
			slog.Info("Revoked the ports")
		case sb == nil || !sb.alive():
			slog.Info("No ports to revoke", "err", err)
		default:
			slog.Warn("Revoke the ports", "err", err)
			return false
		}
		return true
	}
	if !try() {
		retry(clk, try)
	}
}
