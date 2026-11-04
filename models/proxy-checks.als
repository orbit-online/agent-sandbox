/*
 * The D-Bus proxy's properties (README.md, D1, D2 and D4) over the system in
 * proxy.als. Each claim has a `run` for its premise, so a check can't
 * hold vacuously, and a revert check per guard that enforces it: the
 * same claim without the guard, which must fail (`expect 1`).
 */
open proxy

// HIDE: Guard

// D1. Nothing reaches a name or method outside the rules: a call
// reaches its destination only when the rules let the client call that
// method there, by the name or by its owner's unique name as the proxy
// saw it own the name (Verdict: verdict and judgeClient).
assert D1rules { system[Guard] implies always no Overreached }
check D1rules for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 1..6 steps expect 0

// D1, revert: without Verdict a call passes to any name.
assert D1revertVerdict { system[Guard - Verdict] implies always no Overreached }
check D1revertVerdict for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 1..6 steps expect 1

// D1's premise: a call the rules allow reaches its name's owner by the
// owner's unique name, which the proxy learned when the name changed
// hands.
run D1premise {
  system[Guard]
  eventually some c: Client, s: Serial, p: Peer, m: Method |
    m in allowed[c, p] and call[Guard, c, s, p, m] and after s -> p in c.pend
} for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 1..8 steps expect 1

// D2. A reply only answers a call let through: no two calls the proxy let
// through await replies on one serial (SerialReuse: expectFromBus ends
// the connection), a reply reaches a client only for a serial awaiting
// one (ReplyAwaited: judgeBus's awaitBus) and, for a call to the bus,
// only from the bus (BusSender: judgeBus), and a client's reply reaches
// only a peer whose call to it awaits one (PeerAwaited: judgeClient's
// awaitPeer).
assert D2replies {
  system[Guard] implies always {
    all c: Client, s: Serial | lone c.awaiting[s]
    no Misanswered + Fooled
  }
}
check D2replies for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 1..6 steps expect 0

// D2, reverts: without SerialReuse a second call on a pending serial
// overwrites the first, and the bus's reply to one is read as the
// other's; without ReplyAwaited an unasked reply passes; without
// BusSender a peer answers a call to the bus; without PeerAwaited a
// client answers a call it never got.
assert D2revertSerial { system[Guard - SerialReuse] implies always all c: Client, s: Serial | lone c.awaiting[s] }
check D2revertSerial for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 1..6 steps expect 1
assert D2revertAwaited { system[Guard - ReplyAwaited] implies always no Misanswered }
check D2revertAwaited for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 1..6 steps expect 1
assert D2revertBusSender { system[Guard - BusSender] implies always no Misanswered }
check D2revertBusSender for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 1..6 steps expect 1
assert D2revertPeer { system[Guard - PeerAwaited] implies always no Fooled }
check D2revertPeer for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 1..6 steps expect 1

// D2's premise: replies reach clients from a peer and from the bus, and
// a client's reply reaches the peer that called it.
run D2premise {
  system[Guard]
  eventually some p: Peer, c: Client, s: Serial | c.pend[s] in Name + Party and reply[Guard, p, c, s]
  eventually some c: Client, s: Serial | c.pend[s] = Bus and reply[Guard, Bus, c, s]
  eventually some p: Peer, c: Client, s: Serial | clientReply[Guard, c, p, s]
} for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 1..8 steps expect 1

// D4. No eavesdropping: a client gets no call addressed to another
// (NoEavesdrop: readsOthersTraffic refuses eavesdropping match rules and
// BecomeMonitor, whatever the rules).
assert D4noEavesdrop { system[Guard] implies always no Overheard }
check D4noEavesdrop for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 1..6 steps expect 0

// D4, revert: without NoEavesdrop a client's match rule gets it another's
// calls.
assert D4revert { system[Guard - NoEavesdrop] implies always no Overheard }
check D4revert for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 1..6 steps expect 1

// D4's premise: a call reaches a peer while another client is registered.
run D4premise {
  system[Guard]
  eventually some c: Registered - Closed, s: Serial, n: Name, m: Method |
    some Registered - Closed - c and n.owner in Peer and call[Guard, c, s, n, m] and m in allowed[c, n]
} for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 1..6 steps expect 1
