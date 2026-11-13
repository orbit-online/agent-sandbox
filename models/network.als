/*
 * The sandbox network on netkit, over time (README.md, N1-N14). Citations
 * are the code: the helper netns-netkit (cmd/netns-netkit: pair.go,
 * bpf.go, the programs in netkit.bpf.c), the uplink programs and
 * sandbox-uplink (cmd/sandbox-uplink: uplink.bpf.c, attach.go,
 * sandboxes.go), and the kernel (v6.18) for its behaviour.
 *
 * Each launcher gets a netkit pair in L3 mode, both ends with policy
 * NETKIT_POLICY_BLACKHOLE (NETKIT_DROP): the primary sbx-<uid>-<hash> in
 * the host netns, the peer (eth0) in the sandbox netns, over which the
 * sandbox holds no capabilities. The program peer runs in netkit_xmit
 * when the sandbox sends; skb->dev is the primary then, so its
 * bpf_fib_lookup resolves in the host netns. The program primary runs
 * when the host sends to the sandbox. einat-ebpf, unmodified, SNATs on
 * the uplinks at tcx egress and reverse-SNATs at tcx ingress, returning
 * TCX_NEXT; a program of ours ahead of it on ingress (pre) drops packets
 * addressed straight to a sandbox prefix, one after it (post) hands
 * packets for a sandbox prefix to the netkit peer with bpf_redirect_peer.
 * Netfilter is on no path; it shows up here only where a missing guard
 * hands a packet to the host stack.
 *
 * The attacker is both sandboxes (any packet on eth0, any source and
 * destination), every LAN host (any packet to an uplink), every peer
 * behind another host device (a VPN, a bridge with containers), and the
 * host setup: `env` changes the ruleset (flush, FORWARD policy),
 * forwarding sysctls (the primary included), route_localnet, routes and
 * the default route (Ethernet and Wi-Fi, a VPN taking it), which
 * programs are attached, and whether einat runs, at any step. The broker
 * grants and revokes ports, and the LRU map evicts, at any step.
 *
 * Each check a program makes is a Guard, so a revert check is the same
 * system without it (as proxy.als). Six of them were missing from the
 * first design and came out of this model as counterexamples (README.md,
 * Network); their revert checks are that design.
 *
 * Abstracted: a Flow stands for a 5-tuple and, at einat, for the external
 * port its binding got; einat is endpoint-independent, so any LAN host
 * reaches a binding. A binding taken by another address drops the packet
 * (einat would pick another port). Ext is every host address
 * (the uplinks' external ones, subnet broadcasts), Mcast every multicast
 * and broadcast destination, Remote everything off the host. Each
 * launcher has a flow map of its own (rec), pinned with its programs and
 * keyed by the tuple without the sandbox address, so peer looks up only
 * the flows of its own sandbox. IPv6 link-local sources, DNS and ICMP
 * errors are the VM checks'.
 *
 * mDNS (N8, N9): a launcher with network.mdns loads its programs with
 * the constant mdns set (netns-netkit up --mdns, bpf.go attach), and
 * registers its primary in the mdns map of sandbox-uplink. peer copies a
 * query of the sandbox out of the gateway uplink from the uplink address
 * and port 5353 (query_out), which einat leaves alone, then drops the
 * packet; pre copies a response from the LAN to the egress of each
 * registered primary, marked, and primary passes a marked mDNS response
 * with mdns set. MdnsQuery, MdnsProbe and MdnsResponse are packets to the
 * mDNS group by their DNS header; only root on the host sets the mark
 * otherwise.
 *
 * Also: a VLAN tag in the skb (Tagged), a TCP RST of the host (Rst), a
 * host process of another user than the owner of the sandbox (Others),
 * the source of a LAN packet (src), and Metadata, a destination off the
 * host where a cloud metadata service listens (link-local, or a known
 * ULA or CGNAT one of a cloud). Flows of
 * granted ports go idle as time passes (idle; the timeouts of
 * netkit.bpf.c, IDLE_TCP and IDLE_SHORT, a FIN of the host picking the
 * short one) until a packet of the host refreshes them.
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
  // The LRU map of host-started flows the primary program records, one
  // per sandbox (netns-netkit bpf.go pins it in its dir)
  var rec: set Flow,
  // Ghosts: flows the host really started to it under a grant, and flows
  // it sent out itself; flows idle past their timeout, and flows the host
  // reset (a RST of it reached the sandbox) and didn't send on since
  var started: set Flow,
  var outBy: set Flow,
  var idle: set Flow,
  var reset: set Flow
}

abstract sig Addr {}
sig SbxAddr extends Addr {}
one sig Loopback, Ext, Mcast, Metadata extends Addr {}
// To the mDNS group: a query (QR 0, no authority section), a probe (QR 0
// with one), a response or announcement (QR 1)
one sig MdnsQuery, MdnsProbe, MdnsResponse extends Addr {}
sig Remote extends Addr {}

sig Port {}
sig Flow { port: one Port }

fact prefixes { all a: SbxAddr | one addr.a }

fun mdns: set Addr { MdnsQuery + MdnsProbe + MdnsResponse }
fun group: set Addr { Mcast + mdns }

// Launchers with network.mdns, their programs loaded with the constant
// mdns (netns-netkit main.go, bpf.go attach)
sig Mdns in Sandbox {}

// The host: the kernel default route and routes off the host, and the
// einat uplink with the default route that sandbox-uplink publishes in
// the gateways map (sandboxes.go publish), stale or fresh
one sig K {
  var dflt: lone Device,
  var route: (Remote + Metadata) -> one Device,
  var gw: lone Uplink
}
// Ruleset flushed or FORWARD accepting; route_localnet=1
var sig Flushed, LocalNet in Host {}
// Forwarding on the primary (the lookup needs it; sandbox-uplink sets it
// again within half a second, sandboxes.go); programs attached
var sig Fwd, PeerOn, PrimOn in Sandbox {}
// Forwarding on another ingress device
var sig FwdOn in Device {}
// Attached on an uplink: pre, post, egress, einat; pre ahead of einat
var sig PreOn, PostOn, EgressOn, EinatOn, Ahead in Uplink {}
// Uplinks whose post and egress sandbox-uplink is moving back after einat,
// detached meanwhile but still in the uplinks map, which it updates after
// the round (only without MakeBeforeBreak)
var sig Moving in Uplink {}
// Primaries in the mdns map: those netns-netkit up --mdns registered,
// until down or sandbox-uplink removes them (sandboxes.go collect, once
// the ifindex names no netkit primary); a stale entry names whatever
// primary got its ifindex since
var sig MdnsReg in Sandbox {}

// Ghost: the packet of this step. Where it came from, its flow and
// destination, where it ended up, the source einat bound it to on
// egress, the uplink whose binding reverse-NATed it
one sig Pkt {
  var from: lone Node,
  var fl: lone Flow,
  var src: lone Addr,
  var dst: lone Addr,
  var to: set Node,
  var natted: lone SbxAddr,
  var via: lone Uplink
}
// The packet carries a VLAN tag, is a TCP RST, comes from a process of
// another user than the owner of the sandbox, starts a flow (a TCP SYN
// without ACK, a datagram of a connected UDP socket; anything else of the
// host answers a packet, which a bridge without rp_filter may have
// carried in from a sandbox address)
var sig Tagged, Rst, Others, Start in Pkt {}

abstract sig Guard {}
one sig
  PolicyDrop,    // code: netns-netkit pair.go creates both ends with NETKIT_POLICY_BLACKHOLE, so no program
                 // means no traffic (kernel netkit.c:298-373)
  EndsOnVerdict, // code: peer (netkit.bpf.c) drops what it doesn't redirect or pass, never NETKIT_NEXT, which
                 // counts as pass (kernel netkit.c:38-48)
  MultiDrop,     // code: peer (netkit.bpf.c) drops multicast and broadcast before the lookup
  LocalDrop,     // code: peer (netkit.bpf.c) passes NOT_FWDED only for a recorded flow
  FwdDisabled,   // kernel: the lookup returns FWD_DISABLED without forwarding on the primary (filter.c:6092)
  GrantCheck,    // code: primary (netkit.bpf.c) records and passes only TCP and UDP flows to a granted port
  PreDrop,       // code: pre (uplink.bpf.c) drops uplink packets addressed to a sandbox block
  SrcCheck,      // code: peer (netkit.bpf.c) drops sources other than the sandbox address
  UplinkOnly,    // code: peer (netkit.bpf.c) redirects with bpf_redirect_neigh only to an ifindex in the
                 // uplinks map, the einat uplinks sandbox-uplink publishes (sandboxes.go), and what the
                 // lookup sends elsewhere to the uplink of the gateways map
  GatewayOnly,   // code: peer (netkit.bpf.c) drops what the lookup sends through an uplink other than the one of
                 // the gateways map (the subnets of other NICs)
  MakeBeforeBreak, // code: place (sandbox-uplink attach.go) attaches the other instance of a program it moves
                 // before it detaches the old link, so a published uplink never lacks post or egress
  AttachedOnly,  // code: sandbox-uplink publishes an uplink only with pre, post and egress attached on it
                 // (attach.go keep, attached)
  EgressSrcDrop, // code: egress (uplink.bpf.c), after einat on uplink egress, drops sandbox sources
  LocalOrigin,   // code: primary (netkit.bpf.c) requires skb->sk, so passes only packets the host itself sent
  Handoff,       // code: post (uplink.bpf.c) redirects only packets pre marked, drops the rest to a sandbox
  RevokeClears,  // code: revoke (netns-netkit bpf.go) deletes the recorded flows of the port
  QueryOnly,     // code: query_out (netkit.bpf.c) copies out only QR 0, opcode 0 without an authority section
  MdnsConst,     // code: peer and primary (netkit.bpf.c) handle mDNS only with the constant mdns, which
                 // netns-netkit up --mdns sets (bpf.go attach)
  ResponseOnly,  // code: pre (uplink.bpf.c, mdns_response) copies in only QR 1 from port 5353
  RegOnly,       // code: pre (uplink.bpf.c) copies only to the primaries of the mdns map
  VlanDrop,      // code: peer and primary (netkit.bpf.c) drop skb->vlan_present, post (uplink.bpf.c) drops it to
                 // a sandbox, pre copies no mDNS response with it
  IdleCheck,     // code: peer (netkit.bpf.c) passes a reply only on a flow primary renewed within IDLE_TCP or
                 // IDLE_SHORT; peer renews nothing
  RstClears,     // code: primary (netkit.bpf.c) deletes the flow of a TCP RST of the host
  OwnerOnly,     // code: primary (netkit.bpf.c) passes only bpf_get_socket_uid equal to the uid in the sandbox
                 // map, which netns-netkit up puts there (main.go up)
  PreSrcDrop,    // code: pre (uplink.bpf.c, sandbox_end) drops uplink packets from a sandbox block
  LinkLocalDrop, // code: peer (netkit.bpf.c, metadata) drops link-local destinations and known cloud metadata addresses
  PortCheck,     // code: peer (netkit.bpf.c) passes a reply only while its port is in the ports map
  StartOnly      // code: primary (netkit.bpf.c) records a flow only on a TCP SYN without ACK or from a connected
                 // UDP socket (bpf_sk_fullsock, BPF_TCP_ESTABLISHED), and passes anything else only on a recorded flow
  extends Guard {}

// The uplinks map: the uplinks sandbox-uplink publishes. It syncs every
// half second; the model takes the map as current
fun pub[g: set Guard]: set Uplink { AttachedOnly in g => (PreOn & PostOn & EgressOn) + Moving else Uplink }

// Where the host netns routes a destination
fun hop[d: Addr]: lone Node {
  d in Loopback + Ext => Host
  else d in SbxAddr => addr.d
  else d in group => K.dflt
  else K.route[d]
}

// ---------------------------------------------------------------------
// Frames

pred keepHost {
  K.dflt' = K.dflt and K.route' = K.route and K.gw' = K.gw
  Flushed' = Flushed and LocalNet' = LocalNet and Fwd' = Fwd and FwdOn' = FwdOn
  PeerOn' = PeerOn and PrimOn' = PrimOn
  PreOn' = PreOn and PostOn' = PostOn and EgressOn' = EgressOn and EinatOn' = EinatOn and Ahead' = Ahead
  MdnsReg' = MdnsReg and Moving' = Moving
}
pred keepFlows { rec' = rec and started' = started and outBy' = outBy and nat' = nat }
pred quiet {
  no Pkt.from' and no Pkt.fl' and no Pkt.dst' and no Pkt.to' and no Pkt.natted' and no Pkt.via'
  no Pkt.src' and no Tagged' and no Rst' and no Others' and no Start'
}

// Where the packet landed, and what it left behind
pred land[t: set Node, n: lone SbxAddr, v: lone Uplink, r, st, ob: Sandbox -> Flow,
          b: Uplink -> Flow -> SbxAddr] {
  Pkt.to' = t and Pkt.natted' = n and Pkt.via' = v
  rec' = rec + r and started' = started + st and outBy' = outBy + ob and nat' = nat + b
}
// A RST of the host landing in the sandbox: its flow deleted
pred landReset[t: set Node, v: lone Uplink, cut, st: Sandbox -> Flow] {
  Pkt.to' = t and no Pkt.natted' and Pkt.via' = v
  rec' = rec - cut and started' = started + st and outBy' = outBy and nat' = nat
}
pred drop { land[none, none, none, none -> none, none -> none, none -> none, none -> none -> none] }
pred toHost { land[Host, none, none, none -> none, none -> none, none -> none, none -> none -> none] }

// ---------------------------------------------------------------------
// The datapath

// A packet on flow f from o reaches s through its primary: the primary
// program, or the policy without one
pred primaryIn[g: set Guard, s: Sandbox, f: Flow, o: Node, v: lone Uplink] {
  let st = { x: s, y: f | o = Host and f.port in s.granted and some Start' } {
    s in PrimOn implies {
      ((GrantCheck in g implies f.port in s.granted) and (LocalOrigin in g implies o = Host)
       and (VlanDrop in g implies no Tagged') and (OwnerOnly in g implies no Others')
       and (StartOnly in g implies (some Start' or f in s.rec)))
        implies { (RstClears in g and some Rst') implies landReset[s, v, s -> f, st]
                  else land[s, none, v, s -> f, st, none -> none, none -> none -> none] }
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
  } else (dv in EgressOn and EgressSrcDrop in g and a in SbxAddr) implies drop
  else land[dv, none, none, none -> none, none -> none, s -> f, none -> none -> none]
}

// A packet of s passed into the host stack (no program and policy pass, or
// NETKIT_NEXT at the end): local delivery, or forwarding when the
// primary forwards and the ruleset lets it
pred stackFromSbx[g: set Guard, s: Sandbox, a, d: Addr, f: Flow] {
  d = Loopback implies { some LocalNet implies toHost else drop }
  else d in Ext + group implies toHost
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

// The end of the peer program for anything it doesn't send on
pred verdictEnd[g: set Guard, s: Sandbox, a, d: Addr, f: Flow] {
  EndsOnVerdict in g implies drop else stackFromSbx[g, s, a, d, f]
}

// ---------------------------------------------------------------------
// Events

// sbxSend: sandbox s sends a packet with source a to d on flow f
pred sbxSend[g: set Guard, s: Sandbox, a, d: Addr, f: Flow] {
  keepHost and granted' = granted
  Pkt.from' = s and Pkt.fl' = f and Pkt.dst' = d
  no Pkt.src' and no Rst' and no Others' and no Start'
  s not in PeerOn implies { PolicyDrop in g implies drop else stackFromSbx[g, s, a, d, f] }
  else (VlanDrop in g and some Tagged') implies drop
  // query_out: a copy out of the gateway uplink from the uplink address; the
  // packet itself then meets MultiDrop
  else (d in mdns and (MdnsConst in g implies s in Mdns) and (QueryOnly in g implies d = MdnsQuery)
        and some K.gw & pub[g])
    implies land[K.gw, none, none, none -> none, none -> none, none -> none, none -> none -> none]
  else (MultiDrop in g and d in group) implies drop
  else (SrcCheck in g and a != s.addr) implies drop
  else (LinkLocalDrop in g and d = Metadata) implies drop
  else (FwdDisabled in g and s not in Fwd) implies verdictEnd[g, s, a, d, f]
  // NOT_FWDED: local delivery, 127.0.0.1 whatever route_localnet says
  else hop[d] = Host implies {
    (f in s.rec and (IdleCheck in g implies f not in s.idle) and (PortCheck in g implies f.port in s.granted))
      implies toHost
      else { LocalDrop in g implies drop else stackFromSbx[g, s, a, d, f] }
  }
  // SUCCESS through an einat uplink: bpf_redirect_neigh there, if it is
  // the gateway uplink
  else hop[d] in pub[g] implies {
    (GatewayOnly in g and hop[d] != K.gw) implies drop else egress[g, s, hop[d], a, f]
  }
  // SUCCESS through another device (a VPN, a bridge, another primary):
  // out through the gateway uplink, or nowhere without one
  else some hop[d] implies {
    UplinkOnly in g implies { some K.gw & pub[g] implies egress[g, s, K.gw, a, f] else drop }
    else hop[d] in Device implies egress[g, s, hop[d], a, f] else primaryIn[g, hop[d], f, s, none]
  }
  else verdictEnd[g, s, a, d, f]
}

// lanSend: a LAN host sends a packet to d on flow f, arriving on u. pre
// runs ahead of einat, or after it once einat restarted (it attaches
// first, einat aya.rs:200-203); einat reverse-NATs to the address of a
// binding (endpoint-independent) and returns TCX_NEXT (einat.bpf.c:1880)
pred lanSend[g: set Guard, u: Uplink, a, d: Addr, f: Flow] {
  keepHost and granted' = granted
  Pkt.from' = u and Pkt.fl' = f and Pkt.dst' = d and Pkt.src' = a
  no Rst' and no Others' and no Start'
  let rev = { x: u | x in EinatOn and d = Ext and some x.nat[f] },
      d2 = rev.nat[f] + { x: d | no rev } {
    // pre: a sandbox source dropped first
    (PreSrcDrop in g and u in PreOn and a in SbxAddr) implies drop
    // pre: copies of an mDNS response to the registered primaries, whose
    // program (or policy) decides; the response itself goes to the host
    else (d in mdns and u in PreOn) implies land[
      { x: Sandbox | (ResponseOnly in g implies d = MdnsResponse) and (RegOnly in g implies x in MdnsReg)
        and (VlanDrop in g implies no Tagged')
        and (x in PrimOn implies (MdnsConst in g implies x in Mdns) else PolicyDrop not in g) },
      none, none, none -> none, none -> none, none -> none, none -> none -> none]
    else (PreDrop in g and u in PreOn and (u in Ahead => d else d2) in SbxAddr) implies drop
    else d2 in SbxAddr implies {
      (u in PostOn and (Handoff in g implies u in PreOn))
        implies { (VlanDrop in g and some Tagged') implies drop
                  else land[addr.d2, none, rev, none -> none, none -> none, none -> none, none -> none -> none] }
        else stackFromDev[g, u, d2, f, rev]
    }
    // The host stack takes what is addressed to the host
    else d2 = Ext implies toHost
    else drop
  }
}

// tunnelSend: a peer behind another device (VPN, container bridge)
// sends to d on flow f
pred tunnelSend[g: set Guard, t: Tunnel, d: Addr, f: Flow] {
  keepHost and granted' = granted
  Pkt.from' = t and Pkt.fl' = f and Pkt.dst' = d
  no Pkt.src' and no Tagged' and no Rst' and no Others' and no Start'
  stackFromDev[g, t, d, f, none]
}

// hostSend: a host process sends to sandbox s on flow f
pred hostSend[g: set Guard, s: Sandbox, f: Flow] {
  keepHost and granted' = granted
  Pkt.from' = Host and Pkt.fl' = f and Pkt.dst' = s.addr
  no Pkt.src' and no Rst' & Start'
  primaryIn[g, s, f, Host, none]
}

// env: anything about the host setup changes. einat loses its bindings
// when it stops (maps not pinned) and attaches first when it starts
pred env {
  granted' = granted and rec' = rec and started' = started and outBy' = outBy
  all u: Uplink | u in EinatOn' => u.nat' = u.nat else no u.nat'
  no (EinatOn' - EinatOn) & Ahead'
  Moving' = Moving
  quiet
}

// reorder, settle: sandbox-uplink moves post and egress of u back after
// einat (attach.go place). Without MakeBeforeBreak the old links go
// first, and the round ends (the uplinks map updated) once the new ones
// are attached; with it the programs stay attached throughout, a stutter
pred reorder[g: set Guard, u: Uplink] {
  MakeBeforeBreak not in g and u in EinatOn & PostOn & EgressOn - Moving
  PostOn' = PostOn - u and EgressOn' = EgressOn - u and Moving' = Moving + u
  K.dflt' = K.dflt and K.route' = K.route and K.gw' = K.gw
  Flushed' = Flushed and LocalNet' = LocalNet and Fwd' = Fwd and FwdOn' = FwdOn
  PeerOn' = PeerOn and PrimOn' = PrimOn and PreOn' = PreOn and EinatOn' = EinatOn and Ahead' = Ahead
  MdnsReg' = MdnsReg and granted' = granted
  keepFlows and quiet
}
pred settle[u: Uplink] {
  u in Moving
  PostOn' = PostOn + u and EgressOn' = EgressOn + u and Moving' = Moving - u
  K.dflt' = K.dflt and K.route' = K.route and K.gw' = K.gw
  Flushed' = Flushed and LocalNet' = LocalNet and Fwd' = Fwd and FwdOn' = FwdOn
  PeerOn' = PeerOn and PrimOn' = PrimOn and PreOn' = PreOn and EinatOn' = EinatOn and Ahead' = Ahead
  MdnsReg' = MdnsReg and granted' = granted
  keepFlows and quiet
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
  no rec + started + outBy + idle + reset and no nat
  MdnsReg = Mdns and no Moving
  no Pkt.from + Pkt.fl + Pkt.dst + Pkt.to + Pkt.natted + Pkt.via
}

// Time passes for every flow at every step (idle grows freely); a packet
// of the host that lands in the sandbox refreshes its flow (primary
// stores bpf_ktime_get_boot_ns, netkit.bpf.c), and a RST of it marks the
// flow reset until the host sends on it again
pred ghosts {
  all s: Sandbox | let h = { f: Pkt.fl' | Pkt.from' = Host and s in Pkt.to' } {
    no s.idle' & h and s.idle - s.idle' in h
    s.reset' = (some Rst' => s.reset + h else s.reset - h)
  }
}

pred system[g: set Guard] {
  init
  always ghosts
  always (
    stutter or env
    or (some s: Sandbox, a, d: Addr, f: Flow | sbxSend[g, s, a, d, f])
    or (some u: Uplink, a, d: Addr, f: Flow | lanSend[g, u, a, d, f])
    or (some t: Tunnel, d: Addr, f: Flow | tunnelSend[g, t, d, f])
    or (some s: Sandbox, f: Flow | hostSend[g, s, f] or evict[s, f])
    or (some s: Sandbox, p: Port | grant[s, p] or revoke[g, s, p])
    or (some u: Uplink | reorder[g, u] or settle[u])
  )
}

// ---------------------------------------------------------------------
// Properties. Scope: two sandboxes, two uplinks (Ethernet and Wi-Fi),
// one other device, one remote address, two flows and ports.

// N1. No sandbox packet reaches local delivery on the host except on a
// flow the host started to that sandbox under a grant (code: peer passes
// NOT_FWDED only for a recorded flow of its own sandbox, LocalDrop;
// primary records granted flows, GrantCheck; pair.go leaves no program
// meaning drop,
// PolicyDrop; what peer refuses it drops, EndsOnVerdict; primary records
// a flow only on a packet that starts one, StartOnly).
assert N1hostDelivery {
  system[Guard] implies always all s: Sandbox | (Pkt.from = s and Host in Pkt.to) implies Pkt.fl in s.started
}
check N1hostDelivery for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 0

// N1, reverts: without LocalDrop an unrecorded local packet goes to the
// host stack; without PolicyDrop a detached peer program passes
// everything there; without EndsOnVerdict a packet the lookup refuses (FWD_DISABLED) falls
// through to the host stack, which delivers it locally.
assert N1revertLocal { system[Guard - LocalDrop] implies always all s: Sandbox | (Pkt.from = s and Host in Pkt.to) implies Pkt.fl in s.started }
check N1revertLocal for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert N1revertPolicy { system[Guard - PolicyDrop] implies always all s: Sandbox | (Pkt.from = s and Host in Pkt.to) implies Pkt.fl in s.started }
check N1revertPolicy for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert N1revertVerdict { system[Guard - EndsOnVerdict] implies always all s: Sandbox | (Pkt.from = s and Host in Pkt.to) implies Pkt.fl in s.started }
check N1revertVerdict for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N1, revert: without StartOnly the answer of a host listener to a packet
// from a sandbox address (spoofed on a bridge without rp_filter) records
// a flow the host never started, which the sandbox then sends on.
assert N1revertStart { system[Guard - StartOnly] implies always all s: Sandbox | (Pkt.from = s and Host in Pkt.to) implies Pkt.fl in s.started }
check N1revertStart for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N1, premise: a reply on a forwarded port reaches the host.
run N1premise {
  system[Guard]
  eventually some s: Sandbox | Pkt.from = s and Host in Pkt.to
} for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N2. A sandbox packet leaves the host only through the einat uplink
// with the default route (the gateways map), SNATed from that sandbox
// address, and never to a multicast or broadcast destination (code: peer
// redirects only to the uplinks map, UplinkOnly, which holds only
// uplinks with egress attached, AttachedOnly, and there only to the
// gateway uplink, GatewayOnly, as the macvlan did: never onto the subnet
// of another NIC; drops multicast and broadcast, MultiDrop, and other
// sources, SrcCheck; egress, EgressSrcDrop).
// Behind a full-tunnel VPN the lookup finds the tunnel, and peer sends
// the packet out through the einat uplink with the default route instead
// (the gateways map), never into the tunnel.
// An mDNS query leaves as a copy from the uplink address (N8).
pred egressOk {
  all s: Sandbox | (Pkt.from = s and some Pkt.to & Device) implies (Pkt.to & Device in K.gw and
    ((Pkt.natted = s.addr and Pkt.dst not in group) or (Pkt.dst = MdnsQuery and no Pkt.natted)))
}
assert N2egress { system[Guard] implies always egressOk }
check N2egress for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 0

// N2, reverts: without MultiDrop multicast and broadcast match the
// default route; and, the first design: without
// UplinkOnly a VPN holding a route takes sandbox traffic, without
// EgressSrcDrop a packet leaves un-NATed while einat restarts; without
// AttachedOnly an uplink whose egress failed to attach is published, and
// a packet leaves it un-NATed while einat restarts (2026-11-13); without
// GatewayOnly a route through another NIC (a storage or BMC network)
// takes sandbox traffic NATed (2026-11-13).
assert N2revertMulti { system[Guard - MultiDrop] implies always egressOk }
check N2revertMulti for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert N2revertUplink { system[Guard - UplinkOnly] implies always egressOk }
check N2revertUplink for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert N2revertEgressSrc { system[Guard - EgressSrcDrop] implies always egressOk }
check N2revertEgressSrc for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert N2revertAttached { system[Guard - AttachedOnly] implies always egressOk }
check N2revertAttached for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert N2revertGateway { system[Guard - GatewayOnly] implies always egressOk }
check N2revertGateway for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N2, premise: a sandbox packet leaves through each uplink, once the
// route moved (Ethernet to Wi-Fi).
run N2premise {
  system[Guard]
  all u: Uplink | eventually some s: Sandbox | Pkt.from = s and u in Pkt.to
} for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N2, premise: behind a full-tunnel VPN (the lookup finds a tunnel) a
// sandbox packet still leaves, through the gateway uplink.
run N2vpnPremise {
  system[Guard]
  eventually some s: Sandbox | Pkt.from = s and hop[Pkt.dst] in Tunnel and some Pkt.to & Uplink
} for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N3. A packet from outside the host (LAN, VPN, container bridge)
// reaches a sandbox only reverse-NATed by an einat binding, on a flow
// that sandbox sent out itself (code: PreDrop; Handoff, so post alone
// doesn't redirect; SrcCheck, so a binding names its sender;
// LocalOrigin, so a forwarded packet isn't taken for the host), or as
// an mDNS response copied to a sandbox with mDNS (N9).
pred inboundOk {
  all s: Sandbox | (Pkt.from in Device and s in Pkt.to) implies
    ((some Pkt.via and Pkt.fl in s.outBy) or (Pkt.dst = MdnsResponse and s in Mdns))
}
assert N3inbound { system[Guard] implies always inboundOk }
check N3inbound for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 0

// N3, reverts: without PreDrop a LAN host addresses the sandbox prefix
// and post redirects it; and, the first design: without SrcCheck
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

// N4. No packet of one sandbox reaches another directly (code: the
// other primary is not in the uplinks map, so peer sends it to the
// gateway uplink, UplinkOnly; it would still meet primary, LocalOrigin).
// Through the LAN it is N3.
pred apart { all s: Sandbox | Pkt.from = s implies no Pkt.to & Sandbox - s }
assert N4apart { system[Guard] implies always apart }
check N4apart for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 0

// N4, revert, dropping both layers since each holds alone: without
// UplinkOnly and LocalOrigin peer redirects to the other primary and
// primary takes it for the host.
assert N4revertDevice { system[Guard - UplinkOnly - LocalOrigin] implies always apart }
check N4revertDevice for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

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
// a sandbox whose peer program is detached or whose primary lost
// forwarding gets nothing through (PolicyDrop; FwdDisabled, the lookup
// fails before any flag); an uplink without einat carries no sandbox
// packet and delivers nothing to a sandbox (EgressSrcDrop, PreDrop);
// after an einat restart puts einat ahead of pre, nothing from that
// uplink reaches a sandbox until pre is ahead again (PreDrop: pre sees
// the rewritten destination; sandbox-uplink puts it ahead again,
// cmd/sandbox-uplink/attach.go sync); moving post and egress back after
// einat leaves a published uplink without them at no point
// (MakeBeforeBreak), so einat stopping meanwhile lets nothing out; a flow
// the LRU map evicted gets no reply to the host (LocalDrop). sandbox-uplink sets forwarding on the
// primaries again (sandboxes.go), which only ends the outage.
pred failClosed {
  // query_out copies before the lookup, so an mDNS query still leaves
  all s: Sandbox | (Pkt.from = s and (s not in PeerOn or (s not in Fwd and Pkt.dst != MdnsQuery))) implies no Pkt.to
  all u: Uplink - EinatOn | Pkt.dst not in mdns implies
    ((Pkt.from in Sandbox implies u not in Pkt.to) and (Pkt.from = u implies no Pkt.to & Sandbox))
  all u: Uplink - Ahead | (Pkt.from = u and Pkt.dst not in mdns) implies no Pkt.to & Sandbox
  all s: Sandbox | (Pkt.from = s and Host in Pkt.to) implies Pkt.fl in s.rec
}
assert N5failClosed { system[Guard] implies always failClosed }
check N5failClosed for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 0

// N5, reverts: without PolicyDrop a detached program passes; without the
// kernel FWD_DISABLED a primary without forwarding still sends; without
// EgressSrcDrop an uplink without einat carries the packet; without
// PreDrop an einat ahead of pre lets replies in, and so does a missing
// einat with the prefix; without LocalDrop an evicted flow passes;
// without MakeBeforeBreak einat stops while sandbox-uplink moves egress,
// and a packet leaves the still published uplink un-NATed (2026-11-13).
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
assert N5revertMove { system[Guard - MakeBeforeBreak] implies always failClosed }
check N5revertMove for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N5, premise: each failure meets a packet: a sandbox sends while its
// primary lost forwarding, a sandbox sends while an uplink has no einat,
// a LAN reply arrives after an einat restart, and a sandbox replies on
// an evicted flow.
run N5premise {
  system[Guard]
  eventually some s: Sandbox | Pkt.from = s and s in PeerOn - Fwd
  eventually some s: Sandbox | Pkt.from = s and Pkt.dst = Remote and K.route[Remote] in Uplink - EinatOn
  eventually some u: Uplink - Ahead | Pkt.from = u and u in EinatOn and some u.nat[Pkt.fl] and Pkt.dst = Ext
  eventually some s: Sandbox | Pkt.from = s and Pkt.fl in s.started - s.rec and Pkt.dst = Ext
} for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..8 steps expect 1

// N6. Port forwarding only for granted ports: a packet from the host
// reaches a sandbox only on a flow to a port granted to it (code:
// primary checks the grant, GrantCheck; pair.go makes both ends drop
// without a program, PolicyDrop).
pred forwardOk { all s: Sandbox | (Pkt.from = Host and s in Pkt.to) implies Pkt.fl.port in s.granted }
assert N6granted { system[Guard] implies always forwardOk }
check N6granted for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 0

// N6, reverts: without GrantCheck any port; without PolicyDrop a detached
// primary program passes everything.
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
// sandbox reply on its flows reaches the host (as P4; code: revoke
// deletes the recorded flows of the port, RevokeClears; peer passes a
// reply only while its port is in the ports map, PortCheck).
pred revokedOk { all s: Sandbox | (Pkt.from = s and Host in Pkt.to) implies Pkt.fl.port in s.granted }
assert N7revoked { system[Guard] implies always revokedOk }
check N7revoked for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 0

// N7, revert (the first design): without RevokeClears and PortCheck the
// recorded flow outlives the grant. Either alone holds it.
assert N7revertClear { system[Guard - RevokeClears - PortCheck] implies always revokedOk }
check N7revertClear for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert N7portAlone { system[Guard - RevokeClears] implies always revokedOk }
check N7portAlone for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 0

// N7, premise: a flow recorded under a grant, the grant revoked, the
// sandbox sends on the flow.
run N7premise {
  system[Guard]
  eventually some s: Sandbox | Pkt.from = s and Pkt.fl in s.started and Pkt.fl.port not in s.granted
    and Pkt.dst = Ext
} for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N8. A sandbox sends nothing to the mDNS group out but queries, and only
// with mDNS: no responses, announcements or probes, so it claims no name
// on the LAN (code: QueryOnly; MdnsConst).
pred mdnsOut {
  all s: Sandbox | (Pkt.from = s and some Pkt.to & Device and Pkt.dst in mdns) implies
    (Pkt.dst = MdnsQuery and s in Mdns)
}
assert M1mdnsOut { system[Guard] implies always mdnsOut }
check M1mdnsOut for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 0

// N8, reverts: without QueryOnly a response leaves; without MdnsConst a
// sandbox without mDNS sends queries out.
assert M1revertQuery { system[Guard - QueryOnly] implies always mdnsOut }
check M1revertQuery for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert M1revertConst { system[Guard - MdnsConst] implies always mdnsOut }
check M1revertConst for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N9. What reaches a sandbox from the mDNS group of the LAN is a
// response, and only a sandbox with mDNS gets it, a stale mdns map entry
// included (code: ResponseOnly; MdnsConst, which holds alone; RegOnly).
pred mdnsIn {
  all s: Sandbox | (Pkt.from in Device and s in Pkt.to and Pkt.dst in mdns) implies
    (Pkt.dst = MdnsResponse and s in Mdns)
}
assert M2mdnsIn { system[Guard] implies always mdnsIn }
check M2mdnsIn for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 0

// N9, reverts: without ResponseOnly LAN queries come in; without
// MdnsConst a stale entry of the mdns map copies into a sandbox without
// mDNS; without RegOnly and MdnsConst every sandbox gets the copies;
// without PolicyDrop a primary with its program detached passes them.
assert M2revertResponse { system[Guard - ResponseOnly] implies always mdnsIn }
check M2revertResponse for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert M2revertConst { system[Guard - MdnsConst] implies always mdnsIn }
check M2revertConst for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert M2revertReg { system[Guard - RegOnly - MdnsConst] implies always mdnsIn }
check M2revertReg for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert M2revertPolicy { system[Guard - PolicyDrop] implies always mdnsIn }
check M2revertPolicy for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N8, N9, premise: one sandbox with mDNS and one without; a query of the
// first leaves and a response reaches it.
run Mpremise {
  system[Guard]
  some Mdns and some Sandbox - Mdns
  eventually some s: Sandbox | Pkt.from = s and Pkt.dst = MdnsQuery and some Pkt.to & Uplink
  eventually some s: Sandbox | Pkt.from in Uplink and Pkt.dst = MdnsResponse and s in Pkt.to
} for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N10. A VLAN tag (a VLAN device on eth0, or on the LAN) reaches no
// sandbox, and nothing of a sandbox goes anywhere with one (code:
// VlanDrop).
pred vlanOk { some Tagged implies (no Pkt.to & Sandbox and (Pkt.from in Sandbox implies no Pkt.to)) }
assert N10vlan { system[Guard] implies always vlanOk }
check N10vlan for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 0

// N10, revert: without VlanDrop the tagged packet of a sandbox leaves
// through the uplink, and a tagged reply or mDNS response comes in.
assert N10revertVlan { system[Guard - VlanDrop] implies always vlanOk }
check N10revertVlan for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N10, premise: a sandbox and a LAN host send tagged packets.
run N10premise {
  system[Guard]
  eventually (some Tagged and Pkt.from in Sandbox)
  eventually (some Tagged and Pkt.from in Uplink)
} for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N11. Flows of granted ports end: no sandbox reply reaches the host on a
// flow idle past its timeout, which only packets of the host renew, or one
// the host reset and hasn't sent on since (code: IdleCheck; RstClears).
// The state is the one peer saw.
pred flowsOk {
  all s: Sandbox, f: Flow | (Pkt.from = s and Host in Pkt.to and Pkt.fl = f) implies before f not in s.idle + s.reset
}
assert N11flows { system[Guard] implies always flowsOk }
check N11flows for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 0

// N11, reverts: without IdleCheck an idle flow carries replies for
// ever; without RstClears a reset one does.
assert N11revertIdle { system[Guard - IdleCheck] implies always flowsOk }
check N11revertIdle for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
assert N11revertRst { system[Guard - RstClears] implies always flowsOk }
check N11revertRst for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N11, premise: a flow the host reset, then started again, carries a
// reply.
run N11premise {
  system[Guard]
  some s: Sandbox, f: Flow | eventually (f in s.reset and eventually (Pkt.from = s and Host in Pkt.to and Pkt.fl = f))
} for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..8 steps expect 1

// N12. Only processes of the owner of a sandbox reach its granted ports
// (code: OwnerOnly; LocalOrigin keeps forwarded packets out, N3).
pred ownerOk { all s: Sandbox | (Pkt.from = Host and s in Pkt.to) implies no Others }
assert N12owner { system[Guard] implies always ownerOk }
check N12owner for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 0

// N12, revert: without OwnerOnly another user reaches the granted port.
assert N12revertOwner { system[Guard - OwnerOnly] implies always ownerOk }
check N12revertOwner for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N12, premise: another user sends to a granted port.
run N12premise {
  system[Guard]
  eventually some s: Sandbox | Pkt.from = Host and some Others and Pkt.dst = s.addr and Pkt.fl.port in s.granted
} for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N13. A LAN packet from a sandbox address reaches nothing while pre is
// attached, the host stack included, so the host answers no LAN host in
// the name of a sandbox (code: PreSrcDrop).
pred lanSrcOk { all u: Uplink | (Pkt.from = u and Pkt.src in SbxAddr and before u in PreOn) implies no Pkt.to }
assert N13lanSrc { system[Guard] implies always lanSrcOk }
check N13lanSrc for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 0

// N13, revert: without PreSrcDrop the host stack takes it.
assert N13revertSrc { system[Guard - PreSrcDrop] implies always lanSrcOk }
check N13revertSrc for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N13, premise: a LAN host sends to the host from a sandbox address.
run N13premise {
  system[Guard]
  eventually some u: Uplink | Pkt.from = u and Pkt.src in SbxAddr and Pkt.dst = Ext and before u in PreOn
} for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N14. No sandbox packet reaches a link-local destination off the host or
// a known cloud metadata address (code: LinkLocalDrop).
pred metadataOk { all s: Sandbox | (Pkt.from = s and Pkt.dst = Metadata) implies no Pkt.to }
assert N14linkLocal { system[Guard] implies always metadataOk }
check N14linkLocal for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 0

// N14, revert: without LinkLocalDrop einat NATs it out of the uplink.
assert N14revertLinkLocal { system[Guard - LinkLocalDrop] implies always metadataOk }
check N14revertLinkLocal for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1

// N14, premise: a sandbox sends to it while the host routes it through
// an einat uplink and the sandbox reaches out.
run N14premise {
  system[Guard]
  eventually some s: Sandbox | Pkt.from = s and Pkt.dst = Metadata and before (K.route[Metadata] in EinatOn and s in PeerOn & Fwd)
} for 3 but 2 Sandbox, 2 SbxAddr, 2 Uplink, 1 Tunnel, 1 Remote, 2 Port, 2 Flow, 1..6 steps expect 1
