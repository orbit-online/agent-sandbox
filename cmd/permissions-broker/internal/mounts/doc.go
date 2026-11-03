// Package mounts is what attach grants do in the sandbox's mount namespace, M1: the folders ceiling, cloning a host
// path and attaching it in the grant directory, sharing that directory and detaching grants there, all through
// helpers of the daemon's own binary run with nsenter (helpers.go, tree.go), the grant's mount in M1, and the scan
// for what still holds a grant after its detach (scan.go). The sandbox itself, found and pinned, comes in as a
// Sandbox
package mounts
