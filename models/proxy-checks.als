/*
 * The D-Bus proxy's properties (README.md, D1-D4) over the system in
 * proxy.als. Each claim has a `run` for its premise, so a check can't
 * hold vacuously, and a revert check per guard that enforces it: the
 * same claim without the guard, which must fail (`expect 1`).
 */
open proxy

// HIDE: Guard

// D1. Nothing reaches a name or method outside the rules in force: a
// call reaches its destination only when the static rules and the live
// sets in force now let the client call that method there, and a
// NameOwnerChanged only for a name they let it see. The proxy judges each
// message by the rules there are when it reads it (Refresh: c.cur =
// c.p.current() in fromClient and judgeBus), so a set removed applies to
// the next message, and owners looked up for a set removed meanwhile give
// nothing (looked).
assert D1rules { system[Guard] implies always no Overreached }
check D1rules for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 2 RuleSet, 1..6 steps expect 0

// D1, revert: without Refresh a client's message is judged by the rules
// of its last message, and reaches a name a removed set gave it.
assert D1revertRefresh { system[Guard - Refresh] implies always no Overreached }
check D1revertRefresh for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 2 RuleSet, 1..6 steps expect 1

// D1's premise: a call only a live set allows reaches its name's owner,
// and after the set's removal, which ends that client, another's call
// there is refused.
run D1premise {
  system[Guard]
  eventually some disj c, o: Client, s: Serial, n: Name, m: Method, rs: Live |
    m in allowed[c, n, rs] - allowed[c, n, Static] and some n.owner and call[Guard, c, s, n, m]
    and after eventually (rs not in Live and some s2: Serial | call[Guard, o, s2, n, m] and after s2 -> Bus in o.pend)
} for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 2 RuleSet, 1..8 steps expect 1
// D1's premise: a set removed while a client's lookups for it are in
// flight, the answers coming after; then the client calls.
run D1inflight {
  system[Guard]
  eventually some c: Held, rs: c.inflight | remove[Guard, rs] and after (looked[c] and after (some s: Serial, d: Dest, m: Method | call[Guard, c, s, d, m]))
} for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 2 RuleSet, 1..8 steps expect 1

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
check D2replies for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 2 RuleSet, 1..6 steps expect 0

// D2, reverts: without SerialReuse a second call on a pending serial
// overwrites the first, and the bus's reply to one is read as the
// other's; without ReplyAwaited an unasked reply passes; without
// BusSender a peer answers a call to the bus; without PeerAwaited a
// client answers a call it never got.
assert D2revertSerial { system[Guard - SerialReuse] implies always all c: Client, s: Serial | lone c.awaiting[s] }
check D2revertSerial for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 2 RuleSet, 1..6 steps expect 1
assert D2revertAwaited { system[Guard - ReplyAwaited] implies always no Misanswered }
check D2revertAwaited for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 2 RuleSet, 1..6 steps expect 1
assert D2revertBusSender { system[Guard - BusSender] implies always no Misanswered }
check D2revertBusSender for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 2 RuleSet, 1..6 steps expect 1
assert D2revertPeer { system[Guard - PeerAwaited] implies always no Fooled }
check D2revertPeer for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 2 RuleSet, 1..6 steps expect 1

// D2's premise: replies reach clients from a peer and from the bus, and
// a client's reply reaches the peer that called it.
run D2premise {
  system[Guard]
  eventually some p: Peer, c: Client, s: Serial | c.pend[s] in Name + Party and reply[Guard, p, c, s]
  eventually some c: Client, s: Serial | c.pend[s] = Bus and reply[Guard, Bus, c, s]
  eventually some p: Peer, c: Client, s: Serial | clientReply[Guard, c, p, s]
} for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 2 RuleSet, 1..8 steps expect 1

// D3. A removed set's clients are closed: every client a message it sent
// or got was judged under a set (a filter for its destination, sender or
// name, whatever the verdict) has its connection ended by the set's
// removal, alone or with the broker's connection (MarkUsed:
// client.lookup; CloseOnRemove: removeSet).
assert D3closeOnRemove { system[Guard] implies always no Kept }
check D3closeOnRemove for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 2 RuleSet, 1..6 steps expect 0

// D3, reverts: without MarkUsed nothing marks the set, without
// CloseOnRemove nothing ends: a client that used it keeps its connection.
assert D3revertMark { system[Guard - MarkUsed] implies always no Kept }
check D3revertMark for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 2 RuleSet, 1..6 steps expect 1
assert D3revertClose { system[Guard - CloseOnRemove] implies always no Kept }
check D3revertClose for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 2 RuleSet, 1..6 steps expect 1

// D3's premise: a removal ends one client, which used the set by a
// NameOwnerChanged alone, and leaves another registered.
run D3premise {
  system[Guard]
  eventually some rs: Live, disj c, o: Registered - Closed |
    remove[Guard, rs] and rs in c.used and rs not in o.used and after (c in Closed and o not in Closed)
  eventually some n: Name, p: Party, w: Registered | owned[Guard, n, p] and w.used' != w.used
} for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 2 RuleSet, 1..8 steps expect 1

// D4. No eavesdropping: a client gets no call addressed to another
// (NoEavesdrop: readsOthersTraffic refuses eavesdropping match rules and
// BecomeMonitor, whatever the rules).
assert D4noEavesdrop { system[Guard] implies always no Overheard }
check D4noEavesdrop for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 2 RuleSet, 1..6 steps expect 0

// D4, revert: without NoEavesdrop a client's match rule gets it another's
// calls.
assert D4revert { system[Guard - NoEavesdrop] implies always no Overheard }
check D4revert for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 2 RuleSet, 1..6 steps expect 1

// D4's premise: a call reaches a peer while another client is registered.
run D4premise {
  system[Guard]
  eventually some c: Registered - Closed, s: Serial, n: Name, m: Method |
    some Registered - Closed - c and n.owner in Peer and call[Guard, c, s, n, m] and m in allowed[c, n, inForce]
} for 3 but 2 Client, 1 Peer, 2 Name, 1 Method, 2 Serial, 2 RuleSet, 1..6 steps expect 1
