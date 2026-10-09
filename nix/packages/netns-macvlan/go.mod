module github.com/orbit-online/agent-sandbox/nix/packages/netns-macvlan

go 1.26.0

require (
	github.com/docopt/docopt-go v0.0.0-20180111231733-ee0de3bc6815
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/sys v0.48.0
)

require github.com/vishvananda/netns v0.0.5 // indirect
