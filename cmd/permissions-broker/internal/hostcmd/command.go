// Package hostcmd is the host commands' declarations (docs/permissions.md): a command's checks, its free arguments
// validated, what a grant covers as the consent says it (each command's phrase, and in detail), and what the command reads on stdin. Running one under a
// grant is the broker's
package hostcmd

import (
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/duration"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/schema"
)

// Command is a host command as the config declares it
type Command struct {
	// For Claude: what the command does, its MCP tool's description
	Description string `json:"description"`
	// For the user: what the command lets Claude do, in a short phrase the consent shows
	Consent     string                     `json:"consent"`
	Arguments   map[string]json.RawMessage `json:"arguments"`
	Result      string                     `json:"result"`
	Run         []string                   `json:"run,omitempty"`
	Timeout     string                     `json:"timeout"`
	MaxValidity string                     `json:"maxValidity"`

	args map[string]*schema.Schema
}

const (
	// A free string without maxLength may be this long: the consent covers it whole, the window shows it
	MaxFree = 64 << 10
	// MCP tool names: <capability>_<command>
	MaxToolName = 64
	// A call's timeout unless its command declares one
	DefaultTimeout = "PT1M"
	// A consent phrase, a command's or a capability's title, is at most this long: the notification shows them
	// together on a line or two
	MaxPhrase = 80
)

// A command's name: it makes an MCP tool name with its capability's
var nameRe = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

// ReservedArgs are the names the broker adds to every command's arguments, or uses itself
var ReservedArgs = []string{"reason", "lease"}

// Check checks the command name of capability capName, whose bounding arguments are bounding: a name that makes an
// MCP tool name, a description and run, a result, timeout and maxValidity that parse, and every free argument
// described, of a schema the broker checks, and named apart from the bounding ones and the broker's. Fills in the
// defaults
func (cmd *Command) Check(capName, name string, bounding map[string]*schema.Schema) error {
	if !nameRe.MatchString(name) || len(capName)+1+len(name) > MaxToolName {
		return fmt.Errorf("command %q: letters, digits and -, and %s_%s at most %d characters", name, capName,
			name, MaxToolName)
	}
	if cmd.Description == "" || len(cmd.Run) == 0 {
		return fmt.Errorf("command %s needs a description and run", name)
	}
	if err := CheckPhrase(cmd.Consent); err != nil {
		return fmt.Errorf("command %s: consent: %w", name, err)
	}
	switch {
	case cmd.Result == "":
		cmd.Result = "text"
	case cmd.Result != "text" && !strings.HasPrefix(cmd.Result, "image/"):
		return fmt.Errorf("command %s: result %q, text or an image MIME type", name, cmd.Result)
	}
	if cmd.Timeout == "" {
		cmd.Timeout = DefaultTimeout
	}
	if _, err := duration.Parse(cmd.Timeout); err != nil {
		return fmt.Errorf("command %s: timeout: %w", name, err)
	}
	if cmd.MaxValidity != "" {
		if _, err := duration.Parse(cmd.MaxValidity); err != nil {
			return fmt.Errorf("command %s: maxValidity: %w", name, err)
		}
	}
	cmd.args = map[string]*schema.Schema{}
	for arg, raw := range cmd.Arguments {
		s, err := schema.Parse(raw)
		if err != nil {
			return fmt.Errorf("command %s: argument %s: %w", name, arg, err)
		}
		switch {
		case s.Description == "":
			return fmt.Errorf("command %s: argument %s has no description: the consent names it", name, arg)
		case slices.Contains(ReservedArgs, arg) || bounding[arg] != nil:
			return fmt.Errorf("command %s: argument %s: a bounding argument or the broker's has that name", name, arg)
		case s.Instances != "":
			return fmt.Errorf("command %s: argument %s: instances are for bounding arguments", name, arg)
		}
		cmd.args[arg] = s
	}
	return nil
}

// CheckPhrase checks a phrase the consent shows the user: there, one line of at most MaxPhrase characters
func CheckPhrase(p string) error {
	switch {
	case strings.TrimSpace(p) == "":
		return fmt.Errorf("none: the consent shows it")
	case utf8.RuneCountInString(p) > MaxPhrase:
		return fmt.Errorf("longer than %d characters", MaxPhrase)
	case strings.ContainsFunc(p, unicode.IsControl):
		return fmt.Errorf("one line, without control characters")
	}
	return nil
}

// ValidateArgs checks a call's free arguments: each declared one, of its schema, and no other. Returns them re-encoded
// with sorted keys
func (cmd *Command) ValidateArgs(raw json.RawMessage) (json.RawMessage, error) {
	args, err := schema.DecodeObject(raw)
	if err != nil {
		return nil, fmt.Errorf("Arguments aren't an object: %w", err)
	}
	for k := range args {
		if cmd.args[k] == nil {
			return nil, fmt.Errorf("No argument %q", k)
		}
	}
	for k, s := range cmd.args {
		v, ok := args[k]
		if !ok {
			return nil, fmt.Errorf("Argument %s is missing", k)
		}
		if err := s.CheckValue(v, MaxFree); err != nil {
			return nil, fmt.Errorf("Argument %s: %w", k, err)
		}
	}
	return json.Marshal(args)
}

// Shown is a call's arguments as the window shows them: opaque ones by digest, strings longer than cut cut (none with
// cut 0, for the call asking the user, whose script they read whole)
func (cmd *Command) Shown(args json.RawMessage, cut int) json.RawMessage {
	m, _ := schema.DecodeObject(args)
	for k, v := range m {
		s, ok := v.(string)
		switch {
		case ok && cmd.args[k].Opaque:
			m[k] = schema.OpaqueDigest(s)
		case ok && cut > 0 && utf8.RuneCountInString(s) > cut:
			m[k] = fmt.Sprintf("%s… (%d characters)", string([]rune(s)[:cut]), utf8.RuneCountInString(s))
		}
	}
	data, _ := json.Marshal(m)
	return data
}

// Input is what a host command reads on stdin
type Input struct {
	Capability string          `json:"capability"`
	Command    string          `json:"command"`
	Grant      string          `json:"grant"`
	Bounding   json.RawMessage `json:"bounding"`
	Arguments  json.RawMessage `json:"arguments"`
	Validity   string          `json:"validity,omitempty"`
}

// ScopeItem is one part of what a grant of a host command capability covers in detail: a command without free
// arguments, or one free argument of a command with its declaration's description and what its schema lets through.
// The window shows them under Details, and counts the free arguments in its badges
type ScopeItem struct {
	Command     string `json:"command"`
	Description string `json:"description"`
	Argument    string `json:"argument,omitempty"`
	About       string `json:"about,omitempty"`
	Allows      string `json:"allows,omitempty"`
	// Any text: no enum or pattern
	Unrestricted bool `json:"unrestricted,omitempty"`
}

// ScopeItems is what a grant of a capability with cmds covers: unrestricted free arguments first, then the rest, each by command and
// argument name
func ScopeItems(cmds map[string]*Command) []ScopeItem {
	var open, bounded []ScopeItem
	for _, name := range slices.Sorted(maps.Keys(cmds)) {
		cmd := cmds[name]
		if len(cmd.args) == 0 {
			bounded = append(bounded, ScopeItem{Command: name, Description: cmd.Description})
		}
		for _, arg := range slices.Sorted(maps.Keys(cmd.args)) {
			s := cmd.args[arg]
			item := ScopeItem{Command: name, Description: cmd.Description, Argument: arg, About: s.Description,
				Allows: s.Allows(), Unrestricted: s.Unrestricted()}
			if item.Unrestricted {
				open = append(open, item)
			} else {
				bounded = append(bounded, item)
			}
		}
	}
	return append(open, bounded...)
}

// ConsentItem is a line of the consent: a phrase, the commands that have it (commands sharing a phrase share the
// line), and whether a free argument of one of them takes any text, which the broker derives from the schema rather
// than trusting the phrase
type ConsentItem struct {
	Consent      string   `json:"consent"`
	Commands     []string `json:"commands"`
	Unrestricted bool     `json:"unrestricted,omitempty"`
}

// ConsentItems is what a grant of a capability with cmds covers, a line per phrase: unrestricted ones first, then the
// rest, each in the order of its first command's name
func ConsentItems(cmds map[string]*Command) []ConsentItem {
	var items []ConsentItem
	at := map[string]int{}
	for _, name := range slices.Sorted(maps.Keys(cmds)) {
		cmd := cmds[name]
		i, ok := at[cmd.Consent]
		if !ok {
			i = len(items)
			at[cmd.Consent] = i
			items = append(items, ConsentItem{Consent: cmd.Consent})
		}
		items[i].Commands = append(items[i].Commands, name)
		for _, s := range cmd.args {
			items[i].Unrestricted = items[i].Unrestricted || s.Unrestricted()
		}
	}
	slices.SortStableFunc(items, func(a, b ConsentItem) int {
		switch {
		case a.Unrestricted == b.Unrestricted:
			return 0
		case a.Unrestricted:
			return -1
		}
		return 1
	})
	return items
}

// Warning marks an unrestricted command's phrase in the notification
const Warning = "⚠ "

// Covers says what a grant of a capability with cmds covers, for the notification: the commands' phrases in
// ConsentItems' order, an unrestricted one marked
func Covers(cmds map[string]*Command) string {
	var parts []string
	for _, item := range ConsentItems(cmds) {
		if item.Unrestricted {
			parts = append(parts, Warning+item.Consent)
		} else {
			parts = append(parts, item.Consent)
		}
	}
	return strings.Join(parts, "; ")
}
