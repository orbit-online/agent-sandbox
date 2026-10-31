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
            always: [{ capability: "test/thing", params: { x: "y" } }],
            log: [],
            capabilities: [{ id: "folders/folder", type: "C",
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
                     holders: [{ pid: 42, comm: "cat", start: 1 }] }]
        mock.state = JSON.stringify(st)
        const end = findChild(view, "end")
        tryVerify(() => end.visible)
        mouseClick(end)
        compare(sent().op, "end")
        compare(sent().grants, ["g1"])
    }

    function test_forget() {
        mouseClick(findChild(view, "forget"))
        compare(sent().op, "forget")
        compare(sent().params, { x: "y" })
    }

    // The same action twice is still a change: each command carries its own number
    function test_repeat() {
        mouseClick(findChild(view, "deny"))
        const first = mock.command
        mouseClick(findChild(view, "deny"))
        verify(mock.command !== first)
    }
}
