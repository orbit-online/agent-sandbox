/*
 * The sandbox network on netkit, over time (README.md, N1-N7). Designed,
 * not built: it replaces the macvlan, so the citations are `design:`
 * until the code exists, and kernel behaviour cites the kernel
 * (v6.18).
 *
 * Each launcher gets a netkit pair in L3 mode, both ends with policy
 * NETKIT_DROP: the primary in the host netns, the peer (eth0) in the
 * sandbox netns, over which the sandbox holds no capabilities. A PEER
 * program runs in netkit_xmit when the sandbox sends; skb->dev is the
 * primary then, so its bpf_fib_lookup resolves in the host netns. A
 * PRIMARY program runs when the host sends to the sandbox. einat-ebpf,
 * unmodified, SNATs on the uplinks at tcx egress and reverse-SNATs at tcx
 * ingress, returning TCX_NEXT; a program of ours ahead of it on ingress
 * (pre) drops packets addressed straight to a sandbox prefix, one after
 * it (post) hands packets for a sandbox prefix to the netkit peer with
 * bpf_redirect_peer. Netfilter is on no path of the design; it shows up
 * here only where a missing guard hands a packet to the host stack.
 *
 * The attacker is both sandboxes (any packet on eth0, any source and
 * destination), every LAN host (any packet to an uplink), every peer
 * behind another host device (a VPN, a bridge with containers), and the
 * host setup: `env` changes the ruleset (flush, FORWARD policy),
 * forwarding sysctls (the primary included), route_localnet, routes and
 * the default route (Ethernet and Wi-Fi, a VPN taking it), what the
 * program believes the default-route device is (stale or fresh), which
 * programs are attached, and whether einat runs, at any step. The broker
 * grants and revokes ports, and the LRU map evicts, at any step.
 *
 * Each check a program makes is a Guard, so a revert check is the same
 * system without it (as proxy.als). Some guards are not in the design
 * yet: the model needs them for the properties, and their revert checks
 * are the design as written (README.md, Network).
 *
 * Abstracted: a Flow stands for a 5-tuple and, at einat, for the external
 * port its binding got; einat is endpoint-independent, so any LAN host
 * reaches a binding. A binding taken by another address drops the packet
 * (einat would pick another port). Ext is every host address
 * (the uplinks' external ones, subnet broadcasts), Mcast every multicast
 * and broadcast destination, Remote everything off the host. One flow
 * map serves all launchers, keyed by the whole tuple, the sandbox source
 * included (a map per launcher is only narrower). IPv6 link-local
 * sources, mDNS, DNS and ICMP errors are the VM checks'.
 */
module network

// HIDE: Guard

abstract sig Node {}
// Local delivery in the host netns
one sig Host extends Node {}
abstract sig Device extends Node {}
// einat uplinks (the physical NICs of its config), with its bindings
sig Uplink extends Device {
  var nat: Flow -> lone SbxAddr
}
// Every other host device: VPN, bridges, NICs einat doesn't know
sig Tunnel extends Device {}
// A launcher: its netkit pair (the primary stands for it in routes) and
// sandbox
sig Sandbox extends Node {
  addr: one SbxAddr,
  // Ports the broker granted for forwarding
  var granted: set Port,
  // The LRU map of host-started flows in the PRIMARY program
  var rec: set Flow,
  // Ghosts: flows the host really started to it under a grant, and flows
  // it sent out itself
  var started: set Flow,
  var outBy: set Flow
}

abstract sig Addr {}
sig SbxAddr extends Addr {}
one sig Loopback, Ext, Mcast extends Addr {}
sig Remote extends Addr {}

sig Port {}
sig Flow { port: one Port }

fact prefixes { all a: SbxAddr | one addr.a }

// The host: the kernel default route, routes off the host, and what the
// PEER program holds as the default-route device (a map the helper
// writes, so possibly stale)
one sig K {
  var dflt: lone Device,
  var route: Remote -> one Device,
  var view: lone Device
}
// Ruleset flushed or FORWARD accepting; route_localnet=1
var sig Flushed, LocalNet in Host {}
// Forwarding on the primary (the lookup needs it); programs attached
var sig Fwd, PeerOn, PrimOn in Sandbox {}
// Forwarding on another ingress device
var sig FwdOn in Device {}
// Attached on an uplink: pre, post, einat; pre ahead of einat
var sig PreOn, PostOn, EinatOn, Ahead in Uplink {}

// Ghost: the packet of this step. Where it came from, its flow and
// destination, where it ended up, the source einat bound it to on
// egress, the uplink whose binding reverse-NATed it
one sig Pkt {
  var from: lone Node,
  var fl: lone Flow,
  var dst: lone Addr,
  var to: set Node,
  var natted: lone SbxAddr,
  var via: lone Uplink
}

abstract sig Guard {}
one sig
  PolicyDrop,    // design: both ends NETKIT_DROP, so no program means no traffic (netkit.c:298-373)
  EndsOnVerdict, // design: the PEER program never ends on NETKIT_NEXT, which counts as pass (netkit.c:38-48)
  MultiDrop,     // design: PEER drops multicast and broadcast before the lookup
  LocalDrop,     // design: PEER drops NOT_FWDED unless the tuple is a recorded host-started flow
  DfltOnly,      // design: PEER redirects only to the default-route device
  FwdDisabled,   // kernel: the lookup returns FWD_DISABLED without forwarding on the primary (filter.c:6092)
  GrantCheck,    // design: PRIMARY passes and records only flows to a granted port
  PreDrop,       // design: pre drops uplink packets addressed to a sandbox prefix
  SrcCheck,      // gap: PEER drops sources other than the sandbox address
  UplinkOnly,    // gap: PEER redirects only to an einat uplink
  EgressSrcDrop, // gap: a program after einat on uplink egress drops sandbox sources
  LocalOrigin,   // gap: PRIMARY passes only packets the host itself sent
  Handoff,       // gap: post redirects only packets pre passed (a mark)
  RevokeClears   // gap, open: a revoke removes the flows of the port from the map
  extends Guard {}

// Where the host netns routes a destination
fun hop[d: Addr]: lone Node {
  d in Loopback + Ext => Host
  else d in SbxAddr => addr.d
  else d = Mcast => K.dflt
  else K.route[d]
}

// ---------------------------------------------------------------------
// Frames

pred keepHost {
  K.dflt' = K.dflt and K.route' = K.route and K.view' = K.view
  Flushed' = Flushed and LocalNet' = LocalNet and Fwd' = Fwd and FwdOn' = FwdOn
  PeerOn' = PeerOn and PrimOn' = PrimOn
  PreOn' = PreOn and PostOn' = PostOn and EinatOn' = EinatOn and Ahead' = Ahead
}
pred keepFlows { rec' = rec and started' = started and outBy' = outBy and nat' = nat }
pred quiet {
  no Pkt.from' and no Pkt.fl' and no Pkt.dst' and no Pkt.to' and no Pkt.natted' and no Pkt.via'
}

// Where the packet landed, and what it left behind
pred land[t: set Node, n: lone SbxAddr, v: lone Uplink, r, st, ob: Sandbox -> Flow,
          b: Uplink -> Flow -> SbxAddr] {
  Pkt.to' = t and Pkt.natted' = n and Pkt.via' = v
  rec' = rec + r and started' = started + st and outBy' = outBy + ob and nat' = nat + b
}
pred drop { land[none, none, none, none -> none, none -> none, none -> none, none -> none -> none] }
pred toHost { land[Host, none, none, none -> none, none -> none, none -> none, none -> none -> none] }

// ---------------------------------------------------------------------
// The datapath

// A packet on flow f from o reaches s through its primary: the PRIMARY
// program, or the policy without one
pred primaryIn[g: set Guard, s: Sandbox, f: Flow, o: Node, v: lone Uplink] {
  let st = { x: s, y: f | o = Host and f.port in s.granted } {
    s in PrimOn implies {
      ((GrantCheck in g implies f.port in s.granted) and (LocalOrigin in g implies o = Host))
        implies land[s, none, v, s -> f, st, none -> none, none -> none -> none]
        else drop
    } else {
      PolicyDrop in g
        implies drop
        else land[s, none, v, none -> none, st, none -> none, none -> none -> none]
    }
  }
}

// A packet of s with source a leaves through dv; tcx egress runs on
// redirected packets too (dev.c:4776), so einat SNATs it when attached
pred egress[g: set Guard, s: Sandbox, dv: Device, a: Addr, f: Flow] {
  (dv in EinatOn and a in SbxAddr) implies {
    (some dv.nat[f] and dv.nat[f] != a)
      implies drop
      else land[dv, a, none, none -> none, none -> none, s -> f, dv -> f -> a]
  } else (dv in Uplink and EgressSrcDrop in g and a in SbxAddr) implies drop
  else land[dv, none, none, none -> none, none -> none, s -> f, none -> none -> none]
}

// A packet of s passed into the host stack (no program and policy pass, or
// NETKIT_NEXT at the end): local delivery, or forwarding when the
// primary forwards and the ruleset lets it
pred stackFromSbx[g: set Guard, s: Sandbox, a, d: Addr, f: Flow] {
  d = Loopback implies { some LocalNet implies toHost else drop }
  else d in Ext + Mcast implies toHost
  else (s in Fwd and some Flushed) implies {
    hop[d] in Device implies egress[g, s, hop[d], a, f]
    else hop[d] in Sandbox implies primaryIn[g, hop[d], f, s, none]
    else drop
  } else drop
}

// A packet from device dv in the host stack, forwarded to a sandbox
// prefix when dv forwards and the ruleset lets it
pred stackFromDev[g: set Guard, dv: Device, d: Addr, f: Flow, v: lone Uplink] {
  (d in SbxAddr and dv in FwdOn and some Flushed) implies primaryIn[g, addr.d, f, dv, v] else drop
}

// The end of the PEER program for anything it doesn't send on
pred verdictEnd[g: set Guard, s: Sandbox, a, d: Addr, f: Flow] {
  EndsOnVerdict in g implies drop else stackFromSbx[g, s, a, d, f]
}

// ---------------------------------------------------------------------
// Events

// sbxSend: sandbox s sends a packet with source a to d on flow f
pred sbxSend[g: set Guard, s: Sandbox, a, d: Addr, f: Flow] {
  keepHost and granted' = granted
  Pkt.from' = s and Pkt.fl' = f and Pkt.dst' = d
  s not in PeerOn implies { PolicyDrop in g implies drop else stackFromSbx[g, s, a, d, f] }
  else (MultiDrop in g and d = Mcast) implies drop
  else (SrcCheck in g and a != s.addr) implies drop
  else (FwdDisabled in g and s not in Fwd) implies verdictEnd[g, s, a, d, f]
  // NOT_FWDED: local delivery, 127.0.0.1 whatever route_localnet says
  else hop[d] = Host implies {
    (some x: Sandbox | x.addr = a and f in x.rec)
      implies toHost
      else { LocalDrop in g implies drop else stackFromSbx[g, s, a, d, f] }
  }
  // SUCCESS: bpf_redirect_neigh to the device the lookup found
  else (some hop[d] and (DfltOnly in g implies hop[d] = K.view)
        and (UplinkOnly in g implies hop[d] in Uplink)) implies {
    hop[d] in Device implies egress[g, s, hop[d], a, f] else primaryIn[g, hop[d], f, s, none]
  }
  else verdictEnd[g, s, a, d, f]
}

// lanSend: a LAN host sends a packet to d on flow f, arriving on u. pre
// runs ahead of einat, or after it once einat restarted (it attaches
// first, einat aya.rs:200-203); einat reverse-NATs to the address of a
// binding (endpoint-independent) and returns TCX_NEXT (einat.bpf.c:1880)
pred lanSend[g: set Guard, u: Uplink, d: Addr, f: Flow] {
  keepHost and granted' = granted
  Pkt.from' = u and Pkt.fl' = f and Pkt.dst' = d
  let rev = { x: u | x in EinatOn and d = Ext and some x.nat[f] },
      d2 = rev.nat[f] + { x: d | no rev } {
    (PreDrop in g and u in PreOn and (u in Ahead => d else d2) in SbxAddr) implies drop
    else d2 in SbxAddr implies {
      (u in PostOn and (Handoff in g implies u in PreOn))
        implies land[addr.d2, none, rev, none -> none, none -> none, none -> none, none -> none -> none]
        else stackFromDev[g, u, d2, f, rev]
    }
    // The host stack: the host and the LAN between them
    else drop
  }
}

// tunnelSend: a peer behind another device (VPN, container bridge)
// sends to d on flow f
pred tunnelSend[g: set Guard, t: Tunnel, d: Addr, f: Flow] {
  keepHost and granted' = granted
  Pkt.from' = t and Pkt.fl' = f and Pkt.dst' = d
  stackFromDev[g, t, d, f, none]
}

// hostSend: a host process sends to sandbox s on flow f
pred hostSend[g: set Guard, s: Sandbox, f: Flow] {
  keepHost and granted' = granted
  Pkt.from' = Host and Pkt.fl' = f and Pkt.dst' = s.addr
  primaryIn[g, s, f, Host, none]
}

// env: anything about the host setup changes. einat loses its bindings
// when it stops (maps not pinned) and attaches first when it starts
pred env {
  granted' = granted and rec' = rec and started' = started and outBy' = outBy
  all u: Uplink | u in EinatOn' => u.nat' = u.nat else no u.nat'
  no (EinatOn' - EinatOn) & Ahead'
  quiet
}

// grant, revoke: the broker. evict: the LRU map drops a flow
pred grant[s: Sandbox, p: Port] {
  granted' = granted + s -> p
  keepHost and keepFlows and quiet
}
pred revoke[g: set Guard, s: Sandbox, p: Port] {
  granted' = granted - s -> p
  rec' = (RevokeClears in g => rec - s -> port.p else rec)
  started' = started and outBy' = outBy and nat' = nat
  keepHost and quiet
}
pred evict[s: Sandbox, f: Flow] {
  rec' = rec - s -> f
  started' = started and outBy' = outBy and nat' = nat and granted' = granted
  keepHost and quiet
}

pred stutter { keepHost and keepFlows and granted' = granted and quiet }

pred init {
  no rec + started + outBy and no nat
  no Pkt.from + Pkt.fl + Pkt.dst + Pkt.to + Pkt.natted + Pkt.via
}

pred system[g: set Guard] {
  init
  always (
    stutter or env
    or (some s: Sandbox, a, d: Addr, f: Flow | sbxSend[g, s, a, d, f])
    or (some u: Uplink, d: Addr, f: Flow | lanSend[g, u, d, f])
    or (some t: Tunnel, d: Addr, f: Flow | tunnelSend[g, t, d, f])
    or (some s: Sandbox, f: Flow | hostSend[g, s, f] or evict[s, f])
    or (some s: Sandbox, p: Port | grant[s, p] or revoke[g, s, p])
  )
}

// ---------------------------------------------------------------------
// Properties. Scope: two sandboxes, two uplinks (Ethernet and Wi-Fi),
// one other device, one remote address, two flows and ports.

// N1. No sandbox packet reaches local delivery on the host except on a
// flow the host started to that sandbox under a grant (design: PEER
// drops NOT_FWDED unless the tuple is recorded, LocalDrop; PRIMARY
// records granted flows, GrantCheck; the tuple carries the sandbox
// source, SrcCheck; no program means drop, PolicyDrop).
assert N1hostDelivery {
  system[Guard] implies always all s: Sandbox | (Pkt.from = s and Host in Pkt.to) implies Pkt.fl in s.started
}
check N1hostDelivery for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 0

// N1, reverts: without LocalDrop an unrecorded local packet goes to the
// host stack; without PolicyDrop a detached PEER program passes
// everything there; without SrcCheck a sandbox matches the other
// sandbox tuple in the map by spoofing its source (design as written).
assert N1revertLocal { system[Guard - LocalDrop] implies always all s: Sandbox | (Pkt.from = s and Host in Pkt.to) implies Pkt.fl in s.started }
check N1revertLocal for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert N1revertPolicy { system[Guard - PolicyDrop] implies always all s: Sandbox | (Pkt.from = s and Host in Pkt.to) implies Pkt.fl in s.started }
check N1revertPolicy for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert N1revertSrc { system[Guard - SrcCheck] implies always all s: Sandbox | (Pkt.from = s and Host in Pkt.to) implies Pkt.fl in s.started }
check N1revertSrc for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N1, premise: a reply on a forwarded port reaches the host.
run N1premise {
  system[Guard]
  eventually some s: Sandbox | Pkt.from = s and Host in Pkt.to
} for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N2. A sandbox packet leaves the host only through the device the
// PEER program holds as the default route, only when that is an einat
// uplink, SNATed from that sandbox address, and never to a multicast or
// broadcast destination (design: DfltOnly, MultiDrop; gaps: UplinkOnly,
// EgressSrcDrop, SrcCheck; EndsOnVerdict keeps the rest out of the host
// stack, which would forward it with a flushed ruleset).
pred egressOk {
  all s: Sandbox | (Pkt.from = s and some Pkt.to & Device) implies
    (Pkt.to & Device in K.view & Uplink and Pkt.natted = s.addr and Pkt.dst != Mcast)
}
assert N2egress { system[Guard] implies always egressOk }
check N2egress for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 0

// N2, reverts: without DfltOnly a lookup through another uplink is sent
// there; without MultiDrop multicast and broadcast match the default
// route; without EndsOnVerdict a packet to a VPN route falls through to
// the host stack and out; and, the design as written: without UplinkOnly
// a VPN holding the default route takes sandbox traffic, without
// EgressSrcDrop a packet leaves un-NATed while einat restarts.
assert N2revertDflt { system[Guard - DfltOnly] implies always egressOk }
check N2revertDflt for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert N2revertMulti { system[Guard - MultiDrop] implies always egressOk }
check N2revertMulti for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert N2revertVerdict { system[Guard - EndsOnVerdict] implies always egressOk }
check N2revertVerdict for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert N2revertUplink { system[Guard - UplinkOnly] implies always egressOk }
check N2revertUplink for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert N2revertEgressSrc { system[Guard - EgressSrcDrop] implies always egressOk }
check N2revertEgressSrc for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N2, premise: a sandbox packet leaves through each uplink, once the
// default route moved (Ethernet to Wi-Fi).
run N2premise {
  system[Guard]
  all u: Uplink | eventually some s: Sandbox | Pkt.from = s and u in Pkt.to
} for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N3. A packet from outside the host (LAN, VPN, container bridge)
// reaches a sandbox only reverse-NATed by an einat binding, on a flow
// that sandbox sent out itself (design: PreDrop; gaps: SrcCheck, so a
// binding names its sender; LocalOrigin, so a forwarded packet isn't
// taken for the host; Handoff, so post alone doesn't redirect).
pred inboundOk {
  all s: Sandbox | (Pkt.from in Device and s in Pkt.to) implies (some Pkt.via and Pkt.fl in s.outBy)
}
assert N3inbound { system[Guard] implies always inboundOk }
check N3inbound for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 0

// N3, reverts: without PreDrop a LAN host addresses the sandbox prefix
// and post redirects it; and, the design as written: without SrcCheck
// one sandbox sends with the other address and the reply reaches the
// other; without LocalOrigin a container or VPN peer reaches a forwarded
// port through host forwarding; without Handoff a detached pre lets the
// prefix through.
assert N3revertPre { system[Guard - PreDrop] implies always inboundOk }
check N3revertPre for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert N3revertSrc { system[Guard - SrcCheck] implies always inboundOk }
check N3revertSrc for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert N3revertOrigin { system[Guard - LocalOrigin] implies always inboundOk }
check N3revertOrigin for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert N3revertHandoff { system[Guard - Handoff] implies always inboundOk }
check N3revertHandoff for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N3, premise: a reply from the LAN reaches the sandbox that started
// the flow.
run N3premise {
  system[Guard]
  eventually some s: Sandbox | Pkt.from in Uplink and s in Pkt.to
} for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N4. No packet of one sandbox reaches another directly (design: the
// other primary is never the default-route device, DfltOnly, nor an
// uplink, UplinkOnly; what falls through is dropped, EndsOnVerdict, and
// would still meet PRIMARY, LocalOrigin). Through the LAN it is N3.
pred apart { all s: Sandbox | Pkt.from = s implies no Pkt.to & Sandbox - s }
assert N4apart { system[Guard] implies always apart }
check N4apart for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 0

// N4, reverts, each dropping two layers since each holds alone: without
// both device checks and LocalOrigin PEER redirects to the other primary
// and PRIMARY takes it for the host; without EndsOnVerdict and
// LocalOrigin the host stack forwards it there.
assert N4revertDevice { system[Guard - DfltOnly - UplinkOnly - LocalOrigin] implies always apart }
check N4revertDevice for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert N4revertStack { system[Guard - EndsOnVerdict - LocalOrigin] implies always apart }
check N4revertStack for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N4, premise: both sandboxes get replies from the LAN, and one sends to
// the other.
run N4premise {
  system[Guard]
  all s: Sandbox | eventually (Pkt.from in Uplink and s in Pkt.to)
  eventually some s: Sandbox | Pkt.from = s and Pkt.dst in (Sandbox - s).addr
} for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N5. Failures only narrow (N1-N4, N6 hold under every `env` step: a
// ruleset flush or FORWARD drop policy, sysctl resets, route and
// default-route changes, detached programs, einat restarts). Besides:
// a sandbox whose PEER program is detached or whose primary lost
// forwarding gets nothing through (PolicyDrop; FwdDisabled, the lookup
// fails before any flag); an uplink without einat carries no sandbox
// packet and delivers nothing to a sandbox (EgressSrcDrop, PreDrop);
// after an einat restart puts einat ahead of pre, nothing from that
// uplink reaches a sandbox until pre is ahead again (PreDrop: pre sees
// the rewritten destination); a flow the LRU map evicted gets no reply
// to the host (LocalDrop).
pred failClosed {
  all s: Sandbox | (Pkt.from = s and s not in PeerOn & Fwd) implies no Pkt.to
  all u: Uplink - EinatOn | (Pkt.from in Sandbox implies u not in Pkt.to) and (Pkt.from = u implies no Pkt.to & Sandbox)
  all u: Uplink - Ahead | Pkt.from = u implies no Pkt.to & Sandbox
  all s: Sandbox | (Pkt.from = s and Host in Pkt.to) implies Pkt.fl in s.rec
}
assert N5failClosed { system[Guard] implies always failClosed }
check N5failClosed for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 0

// N5, reverts: without PolicyDrop a detached program passes; without the
// kernel FWD_DISABLED a primary without forwarding still sends; without
// EgressSrcDrop an uplink without einat carries the packet; without
// PreDrop an einat ahead of pre lets replies in, and so does a missing
// einat with the prefix; without LocalDrop an evicted flow passes.
assert N5revertPolicy { system[Guard - PolicyDrop] implies always failClosed }
check N5revertPolicy for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert N5revertFwd { system[Guard - FwdDisabled] implies always failClosed }
check N5revertFwd for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert N5revertEgressSrc { system[Guard - EgressSrcDrop] implies always failClosed }
check N5revertEgressSrc for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert N5revertPre { system[Guard - PreDrop] implies always failClosed }
check N5revertPre for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert N5revertLocal { system[Guard - LocalDrop] implies always failClosed }
check N5revertLocal for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N5, premise: each failure meets a packet: a sandbox sends while its
// primary lost forwarding, a sandbox sends while an uplink has no einat,
// a LAN reply arrives after an einat restart, and a sandbox replies on
// an evicted flow.
run N5premise {
  system[Guard]
  eventually some s: Sandbox | Pkt.from = s and s in PeerOn - Fwd
  eventually some s: Sandbox | Pkt.from = s and K.view in Uplink - EinatOn and Pkt.dst = Remote
  eventually some u: Uplink - Ahead | Pkt.from = u and u in EinatOn and some u.nat[Pkt.fl] and Pkt.dst = Ext
  eventually some s: Sandbox | Pkt.from = s and Pkt.fl in s.started - s.rec and Pkt.dst = Ext
} for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..8 steps expect 1

// N6. Port forwarding only for granted ports: a packet from the host
// reaches a sandbox only on a flow to a port granted to it (design:
// PRIMARY checks the grant, GrantCheck; both ends drop without a
// program, PolicyDrop).
pred forwardOk { all s: Sandbox | (Pkt.from = Host and s in Pkt.to) implies Pkt.fl.port in s.granted }
assert N6granted { system[Guard] implies always forwardOk }
check N6granted for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 0

// N6, reverts: without GrantCheck any port; without PolicyDrop a detached
// PRIMARY program passes everything.
assert N6revertGrant { system[Guard - GrantCheck] implies always forwardOk }
check N6revertGrant for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert N6revertPolicy { system[Guard - PolicyDrop] implies always forwardOk }
check N6revertPolicy for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N6, premise: the host reaches a granted port.
run N6premise {
  system[Guard]
  eventually some s: Sandbox | Pkt.from = Host and s in Pkt.to
} for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N7. A forwarded port that the broker revoked carries nothing more: no
// sandbox reply on its flows reaches the host (as P4; gap, open: the
// design records flows on grant but says nothing of the revoke,
// RevokeClears).
pred revokedOk { all s: Sandbox | (Pkt.from = s and Host in Pkt.to) implies Pkt.fl.port in s.granted }
assert N7revoked { system[Guard] implies always revokedOk }
check N7revoked for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 0

// N7, revert (the design as written): without RevokeClears the recorded
// flow outlives the grant.
assert N7revertClear { system[Guard - RevokeClears] implies always revokedOk }
check N7revertClear for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N7, premise: a flow recorded under a grant, the grant revoked, the
// sandbox sends on the flow.
run N7premise {
  system[Guard]
  eventually some s: Sandbox | Pkt.from = s and Pkt.fl in s.started and Pkt.fl.port not in s.granted
    and Pkt.dst = Ext
} for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
