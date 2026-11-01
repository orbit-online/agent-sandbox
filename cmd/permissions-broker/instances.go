package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// Instances: what a capability's list prints, which requests must match, and the host-wide locks on an exclusive
// capability's instances

// listInstances runs a plugin's list command, which prints a JSON array of instances
func (c *capability) listInstances(ctx context.Context) (json.RawMessage, error) {
	if len(c.List) == 0 {
		return nil, nil
	}
	c.listMu.Lock()
	defer c.listMu.Unlock()
	if time.Since(c.listedAt) < 5*time.Second {
		return c.listed, c.listErr
	}
	in, _ := json.Marshal(pluginInput{Ceiling: c.Ceiling.Raw})
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.List[0], c.List[1:]...)
	cmd.Stdin = bytes.NewReader(in)
	var out bytes.Buffer
	cmd.Stdout = &out
	c.listed, c.listErr = nil, nil
	if err := cmd.Run(); err != nil {
		c.listErr = fmt.Errorf("List %s: %w", c.id(), err)
	} else if !json.Valid(out.Bytes()) {
		c.listErr = fmt.Errorf("List %s: not JSON", c.id())
	} else {
		c.listed = out.Bytes()
	}
	c.listedAt = time.Now()
	return c.listed, c.listErr
}

// instancesOf returns the instances list prints that params match: an instance matches when each of its keys has the
// same value in params. Without a list, and for attach capabilities (whose requests may name a folder below a listed
// root, so its sources decide), none and no error
func (c *capability) instancesOf(ctx context.Context, params json.RawMessage) ([]map[string]any, error) {
	if len(c.List) == 0 || c.Type == "attach" {
		return nil, nil
	}
	listed, err := c.listInstances(ctx)
	if err != nil {
		return nil, err
	}
	var instances []map[string]any
	dec := json.NewDecoder(bytes.NewReader(listed))
	dec.UseNumber()
	if err := dec.Decode(&instances); err != nil {
		return nil, fmt.Errorf("List %s: not an array of objects: %w", c.id(), err)
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

// inList refuses params that match none of the instances list prints
func (c *capability) inList(ctx context.Context, params json.RawMessage) error {
	_, err := c.instancesOf(ctx, params)
	return err
}

// exclusiveLock takes the host-wide locks on the instances of an exclusive capability params match, so two launchers'
// daemons don't grant one at once, whatever other parameters (a mode, read-only) their requests carry. Without a list
// the parameters are the instance. Returns the release, or the holder's launcher
func (c *capability) exclusiveLock(ctx context.Context, launcher string, params json.RawMessage) (func(), error) {
	if !c.Exclusive {
		return func() {}, nil
	}
	instances, err := c.instancesOf(ctx, params)
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
	var taken []string
	release := func() {
		for _, name := range taken {
			_ = os.Remove(name)
		}
	}
	for _, key := range keys {
		name := filepath.Join(dir, strings.ReplaceAll(c.id(), "/", "_")+"-"+hashOf(key))
		err := createWith(name, launcher+"\n")
		if errors.Is(err, os.ErrExist) {
			release()
			holder, _ := os.ReadFile(name)
			if h := strings.TrimSpace(string(holder)); h != "" {
				return nil, fmt.Errorf("Granted to the launcher %s already", h)
			}
			return nil, errors.New("Granted to the default launcher already")
		}
		if err != nil {
			release()
			return nil, err
		}
		taken = append(taken, name)
	}
	return release, nil
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
