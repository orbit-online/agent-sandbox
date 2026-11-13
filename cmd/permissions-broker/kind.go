package main

import (
	"encoding/json"
)

// kind is what a capability's type adds to what every capability shares: the checks of its declaration, what makes
// its grants live and ends them, and what the consent and the list say it covers. Each type's is in its own file:
// commands.go, hostsockets.go, attach.go and ports.go. A kind embeds baseKind and overrides what its type needs
type kind interface {
	// check checks the type's own part of c's declaration, after the parameters' schemas
	check(c *capability) error
	// usable refuses a request before anything else is checked, when the broker can't grant the type at all
	usable(b *broker) error
	// describe is the consent's summary of a request of c with validated params, and refuses one the type can't grant
	describe(b *broker, c *capability, params json.RawMessage) (string, error)
	// start readies c when the daemon starts, before the standing grants
	start(b *broker, c *capability)
	// live makes a new grant live, before it's recorded: on an error nothing of it is left
	live(b *broker, g *grant) error
	// end takes away what live gave, once the grant ended and its connections closed
	end(b *broker, g *grant, why string)
	// scope says what a grant of c covers, and the bounding values of params, for the notification's body
	scope(c *capability, params json.RawMessage) (scope, bounds string)
	// info adds what the type shows of c to the list
	info(c *capability, i *capabilityInfo)
}

// The kinds by capability type
var kinds = map[string]kind{"command": commandKind{}, "socket": socketKind{}, "attach": attachKind{}, "port": portKind{}}

// kind is c's type's kind, nil for a type there's none of
func (c *capability) kind() kind { return kinds[c.Type] }

// baseKind does nothing more than every capability does
type baseKind struct{}

func (baseKind) check(*capability) error { return nil }
func (baseKind) usable(*broker) error    { return nil }
func (baseKind) describe(_ *broker, c *capability, params json.RawMessage) (string, error) {
	return c.describe(params), nil
}
func (baseKind) start(*broker, *capability)                                {}
func (baseKind) live(*broker, *grant) error                                { return nil }
func (baseKind) end(*broker, *grant, string)                               {}
func (baseKind) scope(*capability, json.RawMessage) (scope, bounds string) { return "", "" }
func (baseKind) info(*capability, *capabilityInfo)                         {}
