/*
 * The D-Bus proxy (cmd/dbus-proxy) over time: clients in the sandbox
 * talking to the bus through it, peers straight on the bus, and the
 * broker adding and removing live rule sets on its control socket
 * (README.md, D1-D4). Both critical proxy bugs so far were sequencing
 * bugs: a serial reused between a call and its reply, and a rule set
 * changing while a lookup was in flight. So the model is the proxy's
 * state and the order of events, with the rule matching itself reduced
 * to a relation (rules.go and rules_test.go hold xdg-dbus-proxy's
 * semantics).
 *
 * Sources: cmd/dbus-proxy/*.go at f2faa0f (fromclient.go judgeClient and
 * verdict, frombus.go judgeBus and passNameOwnerChanged, client.go
 * expectFromBus, livesets.go lookup, syncSets, addSet and removeSet,
 * control.go serve).
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
 * client or peer, the calls let through awaiting replies, and the live
 * sets a client's messages were judged under.
 *
 * Abstracted: a rule set is the methods it lets a client call on each
 * name, and the names it mentions (any rule lets a client see its name);
 * own rules are folded into calls. A unique name stands for its
 * connection, and the proxy's table of what each owned (names.go) is
 * `known`, sticky as xdg-dbus-proxy's. Broadcasts, file descriptors,
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

sig RuleSet {
  calls: Name -> Method,
  sees: set Name
}
one sig Static extends RuleSet {}
var sig Live in RuleSet {}

// A client's connection through the proxy: the proxy's state for it
sig Client extends Party {
  // The rules its last message was judged by (c.cur)
  var cur: set RuleSet,
  // Its calls the proxy let through, or refused through a Ping on the
  // call's serial, awaiting their replies (awaitBus): the destination
  var pend: Serial -> lone Dest,
  // Calls to it awaiting its reply (awaitPeer): caller and serial
  var asked: Party -> Serial,
  // Who the proxy saw owning which name (names.go)
  var known: Party -> Name,
  // The live sets whose names it watches, and those whose owners it
  // is still looking up (syncSets, lookupSet)
  var watching: set RuleSet,
  var inflight: set RuleSet,
  // The live sets the proxy marked as used: a removal ends it
  var used: set RuleSet,
  // Ghosts. awaiting: the calls let through awaiting a reply, all of them;
  // touched: the live sets a message it sent or got was judged under
  var awaiting: Serial -> Dest,
  var touched: set RuleSet
}
var sig Registered, Closed, Held in Client {}
// Clients with an eavesdropping match rule on the bus
var sig Eaves in Client {}

// Ghosts the properties are stated over: a call or NameOwnerChanged
// outside the rules in force reached its end; a reply reached a client
// for no call let through, or from a peer for a call to the bus; a
// client's reply reached a peer that didn't call it; a client got a
// message addressed to another; a client kept its connection past the
// removal of a set it used
var sig Overreached, Misanswered, Overheard, Kept in Client {}
var sig Fooled in Peer {}

abstract sig Guard {}
one sig
  SerialReuse,   // expectFromBus: a serial awaiting its reply ends the connection
  ReplyAwaited,  // judgeBus: a reply only to a serial in awaitBus
  BusSender,     // judgeBus: a reply to a call to the bus only from the bus
  PeerAwaited,   // judgeClient: a client's reply only to a call in awaitPeer, to its caller
  Refresh,       // fromClient, judgeBus: c.cur = c.p.current() before judging
  MarkUsed,      // client.lookup: a live set with a filter for the name is used
  CloseOnRemove, // removeSet: the connections that used the set end
  NoEavesdrop    // readsOthersTraffic: eavesdropping match rules refused
  extends Guard {}

fact { always Static not in Live }

fun inForce: set RuleSet { Static + Live }

// The names rule sets mention
fun mentions[rs: set RuleSet]: set Name { (rs.calls).Method + rs.sees }

// The names a destination stands for at c's proxy: itself, or what its
// unique name was seen owning
fun names[c: Client, d: Dest]: set Name { (d & Name) + c.known[d & Party] }

// The methods c's proxy lets it call on d under rules rs
fun allowed[c: Client, d: Dest, rs: set RuleSet]: set Method { names[c, d].(rs.calls) }

// The live sets among rs with a rule for one of d's names
fun mentioning[c: Client, d: Dest, rs: set RuleSet]: set RuleSet {
  { r: rs & Live | some names[c, d] & mentions[r] }
}

// The rules a message is judged by
fun judgedBy[g: set Guard, c: Client]: set RuleSet { Refresh in g implies inForce else c.cur }

// ---------------------------------------------------------------------
// Frames

pred keepClient[cs: set Client] {
  all x: cs {
    x.cur' = x.cur and x.pend' = x.pend and x.asked' = x.asked and x.known' = x.known
    x.watching' = x.watching and x.inflight' = x.inflight and x.used' = x.used
    x.awaiting' = x.awaiting and x.touched' = x.touched
  }
}
pred keepFlags {
  Registered' = Registered and Closed' = Closed and Held' = Held and Eaves' = Eaves
}
pred keepGhosts {
  Overreached' = Overreached and Misanswered' = Misanswered and Overheard' = Overheard
  Kept' = Kept and Fooled' = Fooled
}
pred keepBus { Live' = Live and owner' = owner }

// ---------------------------------------------------------------------
// Events

// hello: a client registers. The proxy watches the names of the rules
// in force and asks who owns them (initialNameOps)
pred hello[c: Client] {
  c not in Registered + Closed
  Registered' = Registered + c
  c.cur' = inForce and c.watching' = Live
  c.known' = c.known + { p: Party, n: mentions[inForce] | n.owner = p }
  c.pend' = c.pend and c.asked' = c.asked and c.inflight' = c.inflight and c.used' = c.used
  c.awaiting' = c.awaiting and c.touched' = c.touched
  Closed' = Closed and Held' = Held and Eaves' = Eaves
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
  Registered' = Registered and Held' = Held and Eaves' = Eaves and Live' = Live
  keepClient[Client] and keepGhosts
}

// call: client c sends a call with serial s to d, method m. A serial
// awaiting its reply ends the connection; a call the rules refuse goes
// to the bus as a Ping on its serial; one they let through reaches d's
// owner, and every client eavesdropping
pred call[g: set Guard, c: Client, s: Serial, d: Dest, m: Method] {
  c in Registered - Closed - Held
  let rs = judgedBy[g, c], ok = d = Bus or m in allowed[c, d, rs],
      t = (d in Name implies d.owner else d) {
    c.cur' = rs
    c.touched' = c.touched + mentioning[c, d, inForce]
    c.used' = (MarkUsed in g implies c.used + mentioning[c, d, rs] else c.used)
    c.asked' = c.asked and c.known' = c.known and c.watching' = c.watching and c.inflight' = c.inflight
    Registered' = Registered and Held' = Held and Eaves' = Eaves and Live' = Live
    Misanswered' = Misanswered and Kept' = Kept and Fooled' = Fooled
    SerialReuse in g and some c.pend[s] implies {
      ends[c]
      c.pend' = c.pend and c.awaiting' = c.awaiting
      Overreached' = Overreached and Overheard' = Overheard
      keepClient[Client - c]
    } else {
      Closed' = Closed and owner' = owner
      c.pend' = c.pend ++ s -> (ok implies d else Bus)
      c.awaiting' = c.awaiting + s -> (ok implies d else Bus)
      Overreached' = Overreached + { x: c | ok and d != Bus and m not in allowed[c, d, inForce] }
      Overheard' = Overheard + { x: Eaves - c - t | ok and d != Bus }
      // A client called gets it through its own proxy, which awaits its reply
      ok and d != Bus and t in Client - c - Closed implies {
        t.asked' = t.asked + c -> s
        t.cur' = t.cur and t.pend' = t.pend and t.known' = t.known and t.watching' = t.watching
        t.inflight' = t.inflight and t.used' = t.used and t.awaiting' = t.awaiting and t.touched' = t.touched
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
  Registered' = Registered and Closed' = Closed and Held' = Held
  keepClient[Client] and keepGhosts and keepBus
}

// peerCall: a peer calls a client
pred peerCall[p: Peer, c: Client, s: Serial] {
  c in Registered - Closed
  c.asked' = c.asked + p -> s
  c.cur' = c.cur and c.pend' = c.pend and c.known' = c.known and c.watching' = c.watching
  c.inflight' = c.inflight and c.used' = c.used and c.awaiting' = c.awaiting and c.touched' = c.touched
  keepClient[Client - c] and keepFlags and keepGhosts and keepBus
}

// clientReply: client c replies to serial s of p, asked or not
pred clientReply[g: set Guard, c: Client, p: Peer, s: Serial] {
  c in Registered - Closed
  PeerAwaited in g implies p -> s in c.asked
  c.asked' = c.asked - p -> s
  Fooled' = Fooled + { x: p | p -> s not in c.asked }
  c.cur' = c.cur and c.pend' = c.pend and c.known' = c.known and c.watching' = c.watching
  c.inflight' = c.inflight and c.used' = c.used and c.awaiting' = c.awaiting and c.touched' = c.touched
  Overreached' = Overreached and Misanswered' = Misanswered and Overheard' = Overheard and Kept' = Kept
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
  c.cur' = c.cur and c.asked' = c.asked and c.known' = c.known and c.watching' = c.watching
  c.inflight' = c.inflight and c.used' = c.used and c.touched' = c.touched
  Overreached' = Overreached and Overheard' = Overheard and Kept' = Kept and Fooled' = Fooled
  keepClient[Client - c] and keepFlags and keepBus
}

// owned: a name's owner changes (a peer or a client takes or releases
// it). The bus's NameOwnerChanged reaches each client whose proxy
// watches the name, which judges it (passNameOwnerChanged): it passes
// for a name the client may see, and its new owner takes on the name's
// rules
pred owned[g: set Guard, n: Name, p: lone Party] {
  p != n.owner and p not in Closed
  n.owner' = p
  all o: Name - n | o.owner' = o.owner
  let ws = { w: Registered - Closed | n in mentions[Static + w.watching] } {
    all w: ws | let rs = judgedBy[g, w] {
      w.cur' = rs
      w.touched' = w.touched + mentioning[w, n, inForce]
      w.used' = (MarkUsed in g implies w.used + mentioning[w, n, rs] else w.used)
      w.known' = w.known + { q: p, o: n | n in mentions[rs] }
      w.pend' = w.pend and w.asked' = w.asked and w.watching' = w.watching
      w.inflight' = w.inflight and w.awaiting' = w.awaiting
    }
    keepClient[Client - ws]
    Overreached' = Overreached + { w: ws | n in mentions[judgedBy[g, w]] - mentions[inForce] }
  }
  Misanswered' = Misanswered and Overheard' = Overheard and Kept' = Kept and Fooled' = Fooled
  keepFlags and Live' = Live
}

// addSet: the broker adds a live set. Each registered client's proxy
// looks up the owners of its names before the client's next message,
// which waits for the answers (syncSets)
pred addSet[rs: RuleSet] {
  rs not in Static + Live
  Live' = Live + rs
  let ws = Registered - Closed {
    Held' = Held + ws
    all w: ws {
      w.watching' = w.watching + rs and w.inflight' = w.inflight + rs
      w.cur' = w.cur and w.pend' = w.pend and w.asked' = w.asked and w.known' = w.known
      w.used' = w.used and w.awaiting' = w.awaiting and w.touched' = w.touched
    }
    keepClient[Client - ws]
  }
  Registered' = Registered and Closed' = Closed and Eaves' = Eaves and owner' = owner
  keepGhosts
}

// looked: the bus answered a held client's lookups: the owners as they
// are now, of the names of sets that may have gone meanwhile
pred looked[c: Client] {
  c in Held
  Held' = Held - c
  c.known' = c.known + { p: Party, n: mentions[c.inflight] | n.owner = p }
  c.inflight' = none
  c.cur' = c.cur and c.pend' = c.pend and c.asked' = c.asked and c.watching' = c.watching
  c.used' = c.used and c.awaiting' = c.awaiting and c.touched' = c.touched
  Registered' = Registered and Closed' = Closed and Eaves' = Eaves
  keepClient[Client - c] and keepGhosts and keepBus
}

// remove: the broker removes live sets, one or, when its connection
// drops, all. The rules change first, then the connections that used
// one end; the others stop watching their names
pred remove[g: set Guard, rss: set RuleSet] {
  some rss and rss in Live
  Live' = Live - rss
  let k = { w: Client - Closed | CloseOnRemove in g and some w.used & rss } {
    ends[k]
    Kept' = Kept + { w: Registered - Closed - k | some w.touched & rss }
  }
  all w: Client {
    w.watching' = w.watching - rss and w.used' = w.used - rss and w.touched' = w.touched - rss
    w.cur' = w.cur and w.pend' = w.pend and w.asked' = w.asked and w.known' = w.known
    w.inflight' = w.inflight and w.awaiting' = w.awaiting
  }
  Registered' = Registered and Held' = Held and Eaves' = Eaves
  Overreached' = Overreached and Misanswered' = Misanswered and Overheard' = Overheard and Fooled' = Fooled
}

pred stutter { keepClient[Client] and keepFlags and keepGhosts and keepBus }

pred init {
  no Live + Registered + Closed + Held + Eaves
  no Overreached + Misanswered + Overheard + Kept + Fooled
  no cur + watching + inflight + used + touched
  no pend + awaiting
  no asked + known
}

pred system[g: set Guard] {
  init
  always (
    stutter
    or (some c: Client | hello[c] or disconnect[c] or eavesdrop[g, c] or looked[c])
    or (some c: Client, s: Serial, d: Dest, m: Method | call[g, c, s, d, m])
    or (some p: Peer, c: Client, s: Serial | peerCall[p, c, s] or clientReply[g, c, p, s])
    or (some x: Peer + Bus, c: Client, s: Serial | reply[g, x, c, s])
    or (some n: Name, p: Party | owned[g, n, p]) or (some n: Name | owned[g, n, none])
    or (some rs: RuleSet | addSet[rs] or remove[g, rs]) or remove[g, Live]
  )
}
