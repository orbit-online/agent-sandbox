package dbusgrant

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

// Set is the rule set as the proxy's control socket takes it
type Set struct {
	Op        string   `json:"op"`
	ID        string   `json:"id"`
	See       []string `json:"see,omitempty"`
	Talk      []string `json:"talk,omitempty"`
	Own       []string `json:"own,omitempty"`
	Call      []string `json:"call,omitempty"`
	Broadcast []string `json:"broadcast,omitempty"`
}

// Set is d's rule set, to add under id
func (d *Config) Set(id string) Set {
	s := Set{Op: "add", ID: id, See: d.See, Talk: d.Talk, Own: d.Own}
	for name, rules := range d.Call {
		for _, r := range rules {
			s.Call = append(s.Call, name+"="+r)
		}
	}
	for name, rules := range d.Broadcast {
		for _, r := range rules {
			s.Broadcast = append(s.Broadcast, name+"="+r)
		}
	}
	return s
}

// Proxy is the connection to one bus's proxy, made at the first grant and again after it broke
type Proxy struct {
	path string
	mu   sync.Mutex
	conn net.Conn
	r    *bufio.Reader
}

// How long the proxy has to answer
var Timeout = 10 * time.Second

// do sends one request and reads its answer. A broken connection is closed, reported as lost: the proxy dropped
// every set of the broker's with it. dial false doesn't connect anew: a removal has nothing to remove then
func (p *Proxy) do(req Set, dial bool) (lost bool, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn == nil {
		if !dial {
			return false, nil
		}
		conn, err := net.DialTimeout("unix", p.path, Timeout)
		if err != nil {
			return false, fmt.Errorf("Reach the D-Bus proxy: %w", err)
		}
		p.conn, p.r = conn, bufio.NewReader(conn)
	}
	data, _ := json.Marshal(req)
	_ = p.conn.SetDeadline(time.Now().Add(Timeout))
	var res struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	line := []byte{}
	_, err = p.conn.Write(append(data, '\n'))
	if err == nil {
		line, err = p.r.ReadBytes('\n')
	}
	if err == nil {
		err = json.Unmarshal(line, &res)
	}
	if err != nil {
		p.conn.Close()
		p.conn = nil
		return true, fmt.Errorf("The D-Bus proxy's connection broke: %w", err)
	}
	if !res.OK {
		return false, fmt.Errorf("The D-Bus proxy refused the rules: %s", res.Error)
	}
	return false, nil
}

// NewProxy is the connection to the proxy whose control socket is at path, not made yet
func NewProxy(path string) *Proxy { return &Proxy{path: path} }

// Add adds d's rule set under id. lost reports that the connection broke, which dropped every set the broker added
func (p *Proxy) Add(id string, d *Config) (lost bool, err error) { return p.do(d.Set(id), true) }

// Remove removes the rule set added under id. Without a connection there's nothing to remove
func (p *Proxy) Remove(id string) (lost bool, err error) {
	return p.do(Set{Op: "remove", ID: id}, false)
}

// Close closes the connection, so the proxy drops the broker's rule sets
func (p *Proxy) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
	}
}
