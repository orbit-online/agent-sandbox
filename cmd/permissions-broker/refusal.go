package main

import (
	"errors"
	"fmt"
)

// Why the broker refuses a request or a call: one category per check of docs/permissions.md (Declared host commands,
// Requests, Leases and triggers), named in the answer's refused beside the message, which says the rest. Clients and
// tests go by the category, never by the message
type refusal string

const (
	// No such capability, a call of one that isn't host commands, or no such command
	refUnknown refusal = "unknown"
	// The parameters (bounding values): not an object, a key not declared, a value against its schema, one of a port
	// missing; or those of a host command or port grant changed in the window
	refParams refusal = "params"
	// A call's free arguments: not an object, one missing or not declared, a value against its schema
	refArguments refusal = "arguments"
	// No reason left once whitespace and control characters are folded
	refReason refusal = "reason"
	// Not a lease: none of lock, a positive duration, or once for a call; or lock while the lock isn't watched
	refLease refusal = "lease"
	// Folders before the sandbox's grant directory was shared
	refUnshared refusal = "unshared"
	// A folder no ceiling source covers, one it allows read-only only, or a denied one
	refCeiling refusal = "ceiling"
	// No instance with these bounding values
	refInstance refusal = "instance"
	// An exclusive instance another launcher holds
	refHeld refusal = "held"
	// The user hasn't answered the last request for the capability
	refAsking refusal = "asking"
	// Three refusals in a row: no requests for the capability for a while
	refBlocked refusal = "blocked"
	// The user said no, or didn't answer in time
	refDenied refusal = "denied"
	// Making the grant live failed: a mount, an address
	refFailed refusal = "failed"
	// release or revoke of a grant there isn't
	refNoGrant refusal = "nogrant"
	// The caller ended before it was answered
	refGone refusal = "gone"
)

// refusedError is an error with its category; its message is the error's own
type refusedError struct {
	why refusal
	err error
}

func (e *refusedError) Error() string { return e.err.Error() }
func (e *refusedError) Unwrap() error { return e.err }

// refuse marks err with why, unless it carries a category already. nil stays nil
func refuse(why refusal, err error) error {
	if err == nil {
		return nil
	}
	var r *refusedError
	if errors.As(err, &r) {
		return err
	}
	return &refusedError{why: why, err: err}
}

// refusef is refuse of a new error
func refusef(why refusal, format string, args ...any) error {
	return &refusedError{why: why, err: fmt.Errorf(format, args...)}
}

// refusalOf is err's category, none for an error without one
func refusalOf(err error) refusal {
	var r *refusedError
	if errors.As(err, &r) {
		return r.why
	}
	return ""
}
