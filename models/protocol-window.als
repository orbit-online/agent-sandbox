/*
 * The Permissions window's view of pending requests while the user
 * answers one (P1, P6 on the window's side). The window refreshes its
 * state on every event of the broker's watch stream (window.go,
 * main.go), which the sandbox triggers at will: a request for another
 * capability (`pending`), a release (`ended`), a request an always grant
 * covers (`granted`). The broker sends the pending requests in arrival
 * order (sockets.go), so a row keeps its place while others come after
 * it, and the QML keeps what the user set on each row by request id
 * (Permissions.qml, `edits`), so a rebuilt row starts from that, not
 * from the request.
 */
module protocolwindow

sig Param {}
sig Lease {}
// A pending request: the parameters and lease it asks for.
sig Req { params: one Param, proposed: one Lease }
// A row of the list, top to bottom.
sig Slot {}

one sig Win {
  var at: Req -> lone Slot,
  var edited: Req -> lone Param,
  var leaseSel: Req -> lone Lease,
  // where the pointer is, which request the user means there, and what
  // they set on it
  var aim: lone Slot,
  var meant: lone Req,
  var chose: Req -> Param -> Lease,
  // the answer sent: request, parameters, lease
  var sent: lone Req,
  var sentParams: lone Param,
  var sentLease: lone Lease
}

fun shown: set Req { Win.at.Slot }

pred keepView { at' = at and edited' = edited and leaseSel' = leaseSel }
pred keepUser { aim' = aim and meant' = meant and chose' = chose }
pred noSend { no sent' and no sentParams' and no sentLease' }

pred init {
  all r: shown | r.(Win.edited) = r.params and r.(Win.leaseSel) = r.proposed
  Win.at in Req lone -> Slot
  no Win.aim and no Win.meant and no Win.chose and no Win.sent
}

// The user narrows a request and picks a lease.
pred edit[r: Req, p: Param, ls: Lease] {
  r in shown
  edited' = edited - Win -> r -> Param + Win -> r -> p
  leaseSel' = leaseSel - Win -> r -> Lease + Win -> r -> ls
  chose' = chose - Win -> r -> Param -> Lease + Win -> r -> p -> ls
  at' = at and aim' = aim and meant' = meant and noSend
}

// The user moves to Allow on a row.
pred look[r: Req] {
  r in shown
  aim' = Win -> r.(Win.at) and meant' = Win -> r
  chose' = chose and keepView and noSend
}

// A watch event: state again. Rows already shown keep their place and
// what the user set; new requests come in free rows, from their own
// parameters and lease.
pred refresh {
  Win.at' in Req lone -> Slot
  all r: shown | r.(Win.at') = r.(Win.at)
  all r: shown | r.(Win.edited') = r.(Win.edited) and r.(Win.leaseSel') = r.(Win.leaseSel)
  all r: Win.at'.Slot - shown | r.(Win.edited') = r.params and r.(Win.leaseSel') = r.proposed
  keepUser and noSend
}

// Allow on the row under the pointer sends that row's request with its
// fields as they are now (Permissions.qml:146-152).
pred click {
  some Win.aim
  let r = (Win.at).(Win.aim) {
    one r
    sent' = Win -> r and sentParams' = Win -> r.(Win.edited) and sentLease' = Win -> r.(Win.leaseSel)
  }
  keepView and keepUser
}

pred skip { keepView and keepUser and noSend }

fact traces {
  init
  always Win.at in Req lone -> lone Slot
  always (skip or refresh or click or (some r: Req | look[r]) or (some r: Req, p: Param, ls: Lease | edit[r, p, ls]))
}

// The window's Allow answers the request the user aimed at. Holds with
// the rows in arrival order. Revert: refresh placing shown rows anywhere
// (map order, as before the fix): a watch event between aiming and
// clicking moves another request's Allow under the pointer
// (counterexample found).
assert windowAnswersMeant {
  always (click implies after Win.sent = Win.meant)
}
check windowAnswersMeant for 3 but 1..5 steps expect 0

// The window's Allow carries the parameters and lease the user set.
// Holds with the edits kept by request id. Revert: refresh rebuilding
// shown rows from their requests (as before the fix): a watch event the
// sandbox times after the user narrowed a request makes Allow send what
// the sandbox asked for (counterexample found).
assert windowSendsChosen {
  always all r: Req, p: Param, ls: Lease |
    (click and Win.meant = r and r -> p -> ls in Win.chose and after Win.sent = r)
      implies after (Win.sentParams = p and Win.sentLease = ls)
}
check windowSendsChosen for 3 but 1..6 steps expect 0

// Both hold when nothing refreshes the window between look and click,
// which is what the counterexamples above need: the premise is reachable.
assert windowWithoutRefresh {
  always (click implies after Win.sent = Win.meant) or eventually refresh
}
check windowWithoutRefresh for 3 but 1..5 steps expect 0
run windowAnswers {
  eventually (some Win.chose and click)
} for 3 but 1..5 steps expect 1
