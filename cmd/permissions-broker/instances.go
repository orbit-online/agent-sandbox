package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// Instances: what a capability's instances glob matches, which requests must match, and the host-wide locks on an
// exclusive capability's instances

// listInstances is what can be asked for: the instances glob's matches, as a JSON array of objects each naming the
// value of the bounding argument; for folders, the ceiling's sources
func (c *capability) listInstances() (json.RawMessage, error) {
	if c.Type == "attach" {
		return json.Marshal(c.Sources)
	}
	if c.glob == "" {
		return nil, nil
	}
	c.listMu.Lock()
	defer c.listMu.Unlock()
	if time.Since(c.listedAt) < 5*time.Second {
		return c.listed, c.listErr
	}
	c.listed, c.listErr = c.globInstances()
	c.listedAt = time.Now()
	return c.listed, c.listErr
}

// instancesOf returns the instances params match: an instance matches when each of its keys has the same value in
// params. Without an instances glob, and for folders (whose requests may name a folder below a source, so the ceiling
// decides), none and no error
func (c *capability) instancesOf(params json.RawMessage) ([]map[string]any, error) {
	if c.glob == "" || c.Type == "attach" {
		return nil, nil
	}
	listed, err := c.listInstances()
	if err != nil {
		return nil, err
	}
	var instances []map[string]any
	dec := json.NewDecoder(bytes.NewReader(listed))
	dec.UseNumber()
	if err := dec.Decode(&instances); err != nil {
		return nil, fmt.Errorf("Instances of %s: not an array of objects: %w", c.id(), err)
	}
	var p map[string]any
	dec = json.NewDecoder(bytes.NewReader(params))
	dec.UseNumber()
	_ = dec.Decode(&p)
	var matched []map[string]any
	for _, inst := range instances {
		match := true
		for k, v := range inst {
			if pv, ok := p[k]; !ok || !reflect.DeepEqual(pv, v) {
				match = false
				break
			}
		}
		if match {
			matched = append(matched, inst)
		}
	}
	if len(matched) == 0 {
		return nil, fmt.Errorf("%s has no such instance: see list", c.id())
	}
	return matched, nil
}

// inList refuses params that match none of the instances
func (c *capability) inList(params json.RawMessage) error {
	_, err := c.instancesOf(params)
	return err
}

// exclusiveLock takes the host-wide locks on the instances of an exclusive capability params match, so two launchers'
// daemons don't grant one at once, whatever other parameters (a mode, read-only) their requests carry. Without an
// instances glob the parameters are the instance. Returns the release, or the holder's launcher
func (c *capability) exclusiveLock(launcher string, params json.RawMessage) (func(), error) {
	if !c.Exclusive {
		return func() {}, nil
	}
	instances, err := c.instancesOf(params)
	if err != nil {
		return nil, err
	}
	keys := []json.RawMessage{params}
	if len(instances) > 0 {
		keys = nil
		for _, inst := range instances {
			key, _ := json.Marshal(inst) // sorted keys
			keys = append(keys, key)
		}
	}
	dir := filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "agent-sandbox-permissions")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	c.locksMu.Lock()
	defer c.locksMu.Unlock()
	if c.locks == nil {
		c.locks = map[string]int{}
	}
	// Shared only by grants of this launcher with the same parameters (a once grant beside another): other parameters
	// are another client of the instance. By launcher too: tests run two on one capability
	lockKey := func(name string) string { return launcher + "\x00" + name + "\x00" + string(params) }
	var taken []string
	// Under c.locksMu: drop this grant's holds, and a lock file once no grant of ours holds it
	drop := func() {
		for _, name := range taken {
			if c.locks[lockKey(name)]--; c.locks[lockKey(name)] == 0 {
				delete(c.locks, lockKey(name))
				_ = os.Remove(name)
			}
		}
	}
	for _, key := range keys {
		name := filepath.Join(dir, strings.ReplaceAll(c.id(), "/", "_")+"-"+hashOf(key))
		// The file is the lock: a count without it (a cleanup removed it) starts over
		if data, err := os.ReadFile(name); err != nil || string(data) != launcher+"\n" {
			delete(c.locks, lockKey(name))
		}
		if c.locks[lockKey(name)] == 0 {
			err := createWith(name, launcher+"\n")
			if errors.Is(err, os.ErrExist) {
				drop()
				holder, _ := os.ReadFile(name)
				if h := strings.TrimSpace(string(holder)); h != "" {
					return nil, fmt.Errorf("Granted to the launcher %s already", h)
				}
				return nil, errors.New("Granted to the default launcher already")
			}
			if err != nil {
				drop()
				return nil, err
			}
		}
		// Ours now, or already, held by a grant of this daemon's with the same parameters
		c.locks[lockKey(name)]++
		taken = append(taken, name)
	}
	return func() {
		c.locksMu.Lock()
		defer c.locksMu.Unlock()
		drop()
	}, nil
}

// createWith creates name holding data, failing when it exists, and never visible without it: written to a file of its
// own first, then linked into place. Created empty and written after, the default launcher's lock ("\n") would look
// like any other daemon's lock in the making, which removeLocks("") would remove
func createWith(name, data string) error {
	f, err := os.CreateTemp(filepath.Dir(name), ".new-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.WriteString(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Link(f.Name(), name)
}

// removeLocks removes the launcher's exclusive locks. Never one without content, which is no lock of this launcher's
// (see createWith)
func removeLocks(launcher string) {
	dir := filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "agent-sandbox-permissions")
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if strings.HasPrefix(e.Name(), ".new-") {
			continue
		}
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 && strings.TrimSpace(string(data)) == launcher {
			_ = os.Remove(path)
		}
	}
}
