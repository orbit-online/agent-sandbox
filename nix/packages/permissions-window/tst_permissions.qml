import QtQuick
import QtTest

// The window's content against a mock broker, offscreen through qmltestrunner: what each action sends
TestCase {
    name: "Permissions"
    width: 640
    height: 720
    when: windowShown
    // Invisible by default, and mouseClick needs its items visible
    visible: true

    QtObject {
        id: mock
        property string state: JSON.stringify({
            pending: [{ id: "p1", capability: "folders/folder", params: { path: "/srv/notes", ro: true },
                        summary: 'a folder (path="/srv/notes", ro=true)', reason: "read the notes", lease: "PT1H" }],
            grants: [{ id: "g1", capability: "test/thing", params: {}, summary: "the test thing", lease: "session" }],
            log: [],
            capabilities: [{ id: "folders/folder", type: "attach",
                             params: { path: { type: "string" }, ro: { type: "boolean" } } }]
        })
        property string error: ""
        property string command: ""
    }

    Permissions {
        id: view
        anchors.fill: parent
        broker: mock
    }

    function sent() {
        return JSON.parse(mock.command)
    }

    // The rows arriving at the start, or a test before that changed them, leave Allow and Deny off for a second
    function init() {
        tryVerify(() => !view.settling, 3000)
    }

    function test_allow_narrowed() {
        const ro = findChild(view, "param-ro")
        verify(ro, "the ro field")
        mouseClick(ro)
        mouseClick(findChild(view, "allow"))
        const c = sent()
        compare(c.op, "answer")
        compare(c.pending, "p1")
        compare(c.allow, true)
        compare(c.lease, "PT1H")
        compare(c.params, { path: "/srv/notes", ro: false })
    }

    // A refresh, which the sandbox can cause at will, rebuilds the list: the narrowing and lease the user set stay
    function test_edit_survives_refresh() {
        const ro = findChild(view, "param-ro")
        if (!ro.checked)
            mouseClick(ro)
        mouseClick(ro)
        const lease = findChild(view, "lease")
        lease.currentIndex = 0
        lease.activated(0)
        // Another request arrives: it comes after this one, as the broker sorts them
        const st = JSON.parse(mock.state)
        const before = JSON.stringify(st)
        st.pending.push({ id: "p2", capability: "test/thing", params: {}, summary: "the test thing", reason: "more",
                          lease: "PT1H" })
        mock.state = JSON.stringify(st)
        tryVerify(() => findChild(view, "param-ro") !== ro, 1000, "the list wasn't rebuilt")
        tryVerify(() => findChild(view, "allow").enabled, 3000)
        mouseClick(findChild(view, "allow"))
        const c = sent()
        compare(c.params, { path: "/srv/notes", ro: false })
        compare(c.lease, "session")
        mock.state = before
    }

    function test_deny() {
        mouseClick(findChild(view, "deny"))
        compare(sent().op, "answer")
        compare(sent().allow, false)
    }

    function test_revoke_then_end() {
        mouseClick(findChild(view, "revoke"))
        compare(sent().op, "revoke")
        compare(sent().grant, "g1")
        const st = JSON.parse(mock.state)
        st.held = [{ grant: "g1", summary: "the test thing", why: "revoked by the user",
                     holders: [{ pid: 42, comm: "cat", start: 1 }, { pid: 43, comm: "less", start: 2, possible: true }] }]
        mock.state = JSON.stringify(st)
        const end = findChild(view, "end")
        tryVerify(() => end.visible)
        compare(findChild(view, "held").text,
                "Still open in folders no longer granted: the test thing (revoked by the user): cat (42), less (43, possibly)")
        mouseClick(end)
        compare(sent().op, "end")
        compare(sent().grants, ["g1"])
    }

    // The same action twice is still a change: each command carries its own number
    function test_repeat() {
        mouseClick(findChild(view, "deny"))
        const first = mock.command
        mouseClick(findChild(view, "deny"))
        verify(mock.command !== first)
    }

    // The sandbox's request above another ends (it timed out): the other moves up under the pointer, and a click
    // right then doesn't answer it
    function test_rows_shift() {
        const before = mock.state
        const st = JSON.parse(before)
        const second = Object.assign({}, st.pending[0], { id: "p2", summary: "another" })
        st.pending.push(second)
        mock.state = JSON.stringify(st)
        st.pending.shift()
        mock.state = JSON.stringify(st)
        const allow = findChild(view, "allow")
        const command = mock.command
        mouseClick(allow)
        compare(mock.command, command, "a click right after the rows moved answered")
        tryVerify(() => allow.enabled, 3000)
        mouseClick(allow)
        compare(sent().pending, "p2")
        mock.state = before
    }

    // A row replaced in place: the sandbox times another request for the moment its first ends, [p1] turns [p2] and
    // [p0, p1] turns [p0, p2], and nothing moves. A click right then answers neither
    function test_rows_replaced() {
        const before = mock.state
        const st = JSON.parse(before)
        const p1 = st.pending[0]
        const p0 = Object.assign({}, p1, { id: "p0", summary: "above" })
        const p2 = Object.assign({}, p1, { id: "p2", summary: "another" })
        for (const [from, to] of [[[p1], [p2]], [[p0, p1], [p0, p2]]]) {
            st.pending = from
            mock.state = JSON.stringify(st)
            tryVerify(() => !view.settling, 3000)
            st.pending = to
            mock.state = JSON.stringify(st)
            const command = mock.command
            mouseClick(findChild(view, "allow"))
            compare(mock.command, command, "a click right after a row was replaced answered")
        }
        mock.state = before
    }
}
