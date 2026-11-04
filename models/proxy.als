/*
 * The D-Bus proxy (cmd/dbus-proxy) over time: clients in the sandbox
 * talking to the bus through it under static rules, and peers straight
 * on the bus (README.md, D1, D2 and D4). The first critical proxy bug was
 * a sequencing bug: a serial reused between a call and its reply. So the
 * model is the proxy's state and the order of events, with the rule
 * matching itself reduced to a relation (internal/rules and its tests
 * hold xdg-dbus-proxy's semantics). D-Bus grants, whose live rule sets
 * D3 was about, aren't built (docs/permissions.md, D-Bus).
 *
 * Sources: cmd/dbus-proxy/internal/judge (fromclient.go FromClient,
 * judgeClient and verdict, frombus.go FromBus, judgeBus and
 * passNameOwnerChanged, judge.go expectFromBus, hold.go lookupNames).
 *
 * The attacker is every client: it registers, calls any destination
 * (the bus, a well-known name, a unique name) with any serial, a fresh
 * one or one still awaiting its reply, replies to anything with any
 * serial, and asks for eavesdropping match rules. Peers are the bus's
 * other connections; they own names, call clients and send replies,
 * asked or forged: the test's bus lets unrequested replies through,
 * so the proxy is what refuses them (a real dbus-daemon refuses them
 * too). The bus driver answers calls to it.
 *
 * Each check the code makes is a Guard, so a revert check is the same
 * system without it (as launch.als). The properties are stated over
 * ghost state the events record whatever the guards: what reached a
 * client or peer, and the calls let through awaiting replies.
 *
 * Abstracted: the rules are the methods they let a client call on each
 * name, and the names they mention (any rule lets a client see its
 * name); own rules are folded into calls. A unique name stands for its
 * connection, and the proxy's table of what each owned (judge/names.go)
 * is `known`, sticky as xdg-dbus-proxy's. Broadcasts, file descriptors,
 * budgets and SASL are other tests' (README.md, D-Bus proxy).
 */
module proxy

// HIDE: Guard

abstract sig Dest {}
sig Name extends Dest {
  var owner: lone Party
}
abstract sig Party extends Dest {}
sig Peer extends Party {}
one sig Bus extends Dest {}
sig Serial {}
sig Method {}

// The proxy's rules, fixed at its start
one sig Rules {
  calls: Name -> Method,
  sees: set Name
}

// A client's connection through the proxy: the proxy's state for it
sig Client extends Party {
  // Its calls the proxy let through, or refused through a Ping on the
  // call's serial, awaiting their replies (awaitBus): the destination
  var pend: Serial -> lone Dest,
  // Calls to it awaiting its reply (awaitPeer): caller and serial
  var asked: Party -> Serial,
  // Who the proxy saw owning which name (judge/names.go)
  var known: Party -> Name,
  // Ghost: the calls let through awaiting a reply, all of them
  var awaiting: Serial -> Dest
}
var sig Registered, Closed in Client {}
// Clients with an eavesdropping match rule on the bus
var sig Eaves in Client {}

// Ghosts the properties are stated over: a call outside the rules
// reached its end; a reply reached a client for no call let through, or
// from a peer for a call to the bus; a client's reply reached a peer that
// didn't call it; a client got a message addressed to another
var sig Overreached, Misanswered, Overheard in Client {}
var sig Fooled in Peer {}

abstract sig Guard {}
one sig
  Verdict,       // judgeClient, verdict: a call passes only where the rules let the client call
  SerialReuse,   // expectFromBus: a serial awaiting its reply ends the connection
  ReplyAwaited,  // judgeBus: a reply only to a serial in awaitBus
  BusSender,     // judgeBus: a reply to a call to the bus only from the bus
  PeerAwaited,   // judgeClient: a client's reply only to a call in awaitPeer, to its caller
  NoEavesdrop    // readsOthersTraffic: eavesdropping match rules refused
  extends Guard {}

// The names the rules mention
fun mentions: set Name { (Rules.calls).Method + Rules.sees }

// The names a destination stands for at c's proxy: itself, or what its
// unique name was seen owning
fun names[c: Client, d: Dest]: set Name { (d & Name) + c.known[d & Party] }

// The methods c's proxy lets it call on d
fun allowed[c: Client, d: Dest]: set Method { names[c, d].(Rules.calls) }

// ---------------------------------------------------------------------
// Frames

pred keepClient[cs: set Client] {
  all x: cs {
    x.pend' = x.pend and x.asked' = x.asked and x.known' = x.known and x.awaiting' = x.awaiting
  }
}
pred keepFlags { Registered' = Registered and Closed' = Closed and Eaves' = Eaves }
pred keepGhosts {
  Overreached' = Overreached and Misanswered' = Misanswered and Overheard' = Overheard and Fooled' = Fooled
}
pred keepBus { owner' = owner }

// ---------------------------------------------------------------------
// Events

// hello: a client registers. The proxy watches the names of the rules
// and asks who owns them, and holds the client's next message until the
// answers came (initialNameOps, lookupNames, Held), so it is one step
pred hello[c: Client] {
  c not in Registered + Closed
  Registered' = Registered + c
  c.known' = c.known + { p: Party, n: mentions | n.owner = p }
  c.pend' = c.pend and c.asked' = c.asked and c.awaiting' = c.awaiting
  Closed' = Closed and Eaves' = Eaves
  keepClient[Client - c] and keepGhosts and keepBus
}

// end: connections close, their names go
pred ends[cs: set Client] {
  Closed' = Closed + cs
  all n: Name | n.owner' = n.owner - cs
}

// disconnect: a client hangs up
pred disconnect[c: Client] {
  c not in Closed
  ends[c]
  Registered' = Registered and Eaves' = Eaves
  keepClient[Client] and keepGhosts
}

// call: client c sends a call with serial s to d, method m. A serial
// awaiting its reply ends the connection; a call the rules refuse goes
// to the bus as a Ping on its serial; one they let through reaches d's
// owner, and every client eavesdropping
pred call[g: set Guard, c: Client, s: Serial, d: Dest, m: Method] {
  c in Registered - Closed
  let ok = d = Bus or m in allowed[c, d] or Verdict not in g,
      t = (d in Name implies d.owner else d) {
    c.asked' = c.asked and c.known' = c.known
    Registered' = Registered and Eaves' = Eaves
    Misanswered' = Misanswered and Fooled' = Fooled
    SerialReuse in g and some c.pend[s] implies {
      ends[c]
      c.pend' = c.pend and c.awaiting' = c.awaiting
      Overreached' = Overreached and Overheard' = Overheard
      keepClient[Client - c]
    } else {
      Closed' = Closed and owner' = owner
      c.pend' = c.pend ++ s -> (ok implies d else Bus)
      c.awaiting' = c.awaiting + s -> (ok implies d else Bus)
      Overreached' = Overreached + { x: c | ok and d != Bus and m not in allowed[c, d] }
      Overheard' = Overheard + { x: Eaves - c - t | ok and d != Bus }
      // A client called gets it through its own proxy, which awaits its reply
      ok and d != Bus and t in Client - c - Closed implies {
        t.asked' = t.asked + c -> s
        t.pend' = t.pend and t.known' = t.known and t.awaiting' = t.awaiting
        keepClient[Client - c - t]
      } else keepClient[Client - c]
    }
  }
}

// eavesdrop: a client asks the bus for an eavesdropping match rule
pred eavesdrop[g: set Guard, c: Client] {
  c in Registered - Closed
  NoEavesdrop not in g
  Eaves' = Eaves + c
  Registered' = Registered and Closed' = Closed
  keepClient[Client] and keepGhosts and keepBus
}

// peerCall: a peer calls a client
pred peerCall[p: Peer, c: Client, s: Serial] {
  c in Registered - Closed
  c.asked' = c.asked + p -> s
  c.pend' = c.pend and c.known' = c.known and c.awaiting' = c.awaiting
  keepClient[Client - c] and keepFlags and keepGhosts and keepBus
}

// clientReply: client c replies to serial s of p, asked or not
pred clientReply[g: set Guard, c: Client, p: Peer, s: Serial] {
  c in Registered - Closed
  PeerAwaited in g implies p -> s in c.asked
  c.asked' = c.asked - p -> s
  Fooled' = Fooled + { x: p | p -> s not in c.asked }
  c.pend' = c.pend and c.known' = c.known and c.awaiting' = c.awaiting
  Overreached' = Overreached and Misanswered' = Misanswered and Overheard' = Overheard
  keepClient[Client - c] and keepFlags and keepBus
}

// reply: the bus, a callee or a forger sends client c a reply to serial
// s, which its proxy passes or drops
pred reply[g: set Guard, x: Peer + Bus, c: Client, s: Serial] {
  c in Registered - Closed
  ReplyAwaited in g implies some c.pend[s]
  BusSender in g implies (c.pend[s] = Bus implies x = Bus)
  c.pend' = c.pend - s -> Dest
  c.awaiting' = c.awaiting - s -> Dest
  Misanswered' = Misanswered + { y: c | no c.awaiting[s] or Bus in c.awaiting[s] and x != Bus }
  c.asked' = c.asked and c.known' = c.known
  Overreached' = Overreached and Overheard' = Overheard and Fooled' = Fooled
  keepClient[Client - c] and keepFlags and keepBus
}

// owned: a name's owner changes (a peer or a client takes or releases
// it). The bus's NameOwnerChanged reaches each client whose proxy
// watches the name, the rules' names, and its new owner takes on the
// name's rules (passNameOwnerChanged)
pred owned[n: Name, p: lone Party] {
  p != n.owner and p not in Closed
  n.owner' = p
  all o: Name - n | o.owner' = o.owner
  let ws = { w: Registered - Closed | n in mentions } {
    all w: ws {
      w.known' = w.known + p -> n
      w.pend' = w.pend and w.asked' = w.asked and w.awaiting' = w.awaiting
    }
    keepClient[Client - ws]
  }
  keepFlags and keepGhosts
}

pred stutter { keepClient[Client] and keepFlags and keepGhosts and keepBus }

pred init {
  no Registered + Closed + Eaves
  no Overreached + Misanswered + Overheard + Fooled
  no pend + awaiting
  no asked + known
}

pred system[g: set Guard] {
  init
  always (
    stutter
    or (some c: Client | hello[c] or disconnect[c] or eavesdrop[g, c])
    or (some c: Client, s: Serial, d: Dest, m: Method | call[g, c, s, d, m])
    or (some p: Peer, c: Client, s: Serial | peerCall[p, c, s] or clientReply[g, c, p, s])
    or (some x: Peer + Bus, c: Client, s: Serial | reply[g, x, c, s])
    or (some n: Name, p: Party | owned[n, p]) or (some n: Name | owned[n, none])
  )
}
