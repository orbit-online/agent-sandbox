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
            grants: [{ id: "g1", capability: "test-thing", params: {}, summary: "the test thing", lease: "lock",
                       reason: "testing" },
                     { id: "g2", capability: "echo", params: {}, summary: "the echo", lease: "standing",
                       socket: "/run/permissions/sockets/echo" },
                     { id: "g3", capability: "windows-vm", params: { vm: "win11" },
                       summary: 'control the Windows VM "win11"', lease: "PT1H30M", reason: "check the VM",
                       expires: new Date(Date.now() + 90 * 60000).toISOString() }],
            calls: [{ grant: "g3", capability: "windows-vm", time: "2026-11-03T10:00:00Z", command: "exec",
                      arguments: { script: "Get-Date" }, exit: 0 },
                    { grant: "g0", capability: "windows-vm", time: "2026-11-03T10:05:00Z", command: "click",
                      arguments: { x: 5 }, exit: 1, error: "no VM" }],
            log: [],
            standing: [{ capability: "echo", params: {}, summary: "the echo", grant: "g2" },
                       { capability: "test-thing", params: {}, summary: "the test thing", ended: true }],
            overview: {
                binds: [{ path: "/home/alice", src: "/srv/home", rw: true, optional: false },
                        { path: "/srv/notes", src: "/srv/notes", rw: false, optional: true }],
                devices: ["/dev/kvm"],
                dbus: { "org.kde.StatusNotifierItem-100-1": { policy: "own" },
                        "org.freedesktop.portal.Desktop": { call: ["a@/x", "b@/x"], broadcast: ["c@/x"] },
                        "org.test.Seen": { policy: "see", call: ["d"] } },
                network: "its own",
                implicit: ["Sockets: Wayland"]
            },
            capabilities: [{ id: "folders/folder", type: "attach",
                             params: { path: { type: "string" }, ro: { type: "boolean" } } },
                           { id: "windows-vm", type: "command", title: "control the Windows VM",
                             params: { vm: { type: "string", description: "the VM" } },
                             consent: [{ consent: "Run any PowerShell, up to system level",
                                         commands: ["exec"], unrestricted: true },
                                       { consent: "Use the keyboard and type any text", commands: ["keys", "type"],
                                         unrestricted: true },
                                       { consent: "Click on the screen", commands: ["click"] },
                                       { consent: "Take screenshots", commands: ["screenshot"] }],
                             scope: [{ command: "exec", description: "Run PowerShell", argument: "script",
                                       about: "any PowerShell, as SYSTEM", allows: "any text", unrestricted: true },
                                     { command: "click", description: "Click", argument: "x", about: "column",
                                       allows: "a number within 0–99" },
                                     { command: "keys", description: "Press keys", argument: "key", about: "a key",
                                       allows: "one of 9 values" },
                                     { command: "screenshot", description: "Take a screenshot" }],
                             commands: { keys: { arguments: { key: { type: "string", description: "a key",
                                                                     enum: "abcdefghi".split("") } } } } }]
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

    // A tab brought to the front, laid out before a mouse click lands on it
    function show(page) {
        view.page = page
        waitForRendering(view)
    }

    // A toggle may sit below the visible part of the window, where a mouse click doesn't reach
    function click(name) {
        const button = findChild(view, name)
        verify(button, name)
        button.clicked()
    }

    // A test that failed halfway leaves the next the state it started with
    property string initial
    Component.onCompleted: initial = mock.state
    function cleanup() {
        mock.state = initial
        view.page = ""
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
        st.pending.push({ id: "p2", capability: "test-thing", params: {}, summary: "the test thing", reason: "more",
                          lease: "PT1H" })
        mock.state = JSON.stringify(st)
        tryVerify(() => findChild(view, "param-ro") !== ro, 1000, "the list wasn't rebuilt")
        tryVerify(() => findChild(view, "allow").enabled, 3000)
        mouseClick(findChild(view, "allow"))
        const c = sent()
        compare(c.params, { path: "/srv/notes", ro: false })
        compare(c.lease, "lock")
        mock.state = before
    }

    function test_deny() {
        mouseClick(findChild(view, "deny"))
        compare(sent().op, "answer")
        compare(sent().allow, false)
    }

    function test_revoke_then_end() {
        show("granted")
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
        waitForRendering(view)
        mouseClick(end)
        compare(sent().op, "end")
        compare(sent().grants, ["g1"])
    }

    // A standing grant shows as from the config, with no lease of its own
    function test_standing_grant() {
        compare(findChild(view, "grant-g2").text, "The echo")
        compare(findChild(view, "badge-config-g2").text, "from config")
        verify(!findChild(view, "badge-lease-g2"), "a lease badge on a standing grant")
    }

    // A grant is one line until the user expands it, which a refresh keeps
    function test_collapse_expand() {
        show("granted")
        const details = findChild(view, "details-g3")
        verify(!details.visible, "expanded at the start")
        click("toggle-g3")
        verify(details.visible, "not expanded by a click")
        const before = mock.state
        const st = JSON.parse(before)
        st.grants.push({ id: "g4", capability: "test-thing", params: {}, summary: "another", lease: "PT1H" })
        mock.state = JSON.stringify(st)
        tryVerify(() => findChild(view, "details-g3") !== details, 1000, "the list wasn't rebuilt")
        verify(findChild(view, "details-g3").visible, "a refresh collapsed it")
        click("toggle-g3")
        verify(!findChild(view, "details-g3").visible, "not collapsed by a click")
        mock.state = before
    }

    // Badges: the lease, a host command capability's free arguments with a warning for each unrestricted one
    function test_badges() {
        compare(findChild(view, "badge-lease-g1").text, "until lock")
        compare(findChild(view, "badge-lease-g3").text, "1 h 30 min")
        compare(findChild(view, "left-g3").text, "1 h 30 min left")
        verify(!findChild(view, "badge-holders-g3"))
        compare(findChild(view, "badge-free-g3").text, "3 free arguments")
        const open = findChild(view, "badge-unrestricted-g3-exec-script")
        compare(open.text, "unrestricted: exec script")
        verify(open.warning)
        verify(!findChild(view, "badge-free-g1"), "free arguments on a grant without")
    }

    // A host command capability's consent: a line per phrase, the commands sharing one on it, a warning on an
    // unrestricted one, the commands' names after it
    function consentLines(key) {
        const lines = []
        for (let i = 0; findChild(view, "consent-" + key + "-" + i); i++) {
            const open = findChild(view, "consent-unrestricted-" + key + "-" + i)
            lines.push((open.visible ? "[" + open.text + "] " : "") + findChild(view, "consent-" + key + "-" + i).text
                       + " (" + findChild(view, "consent-commands-" + key + "-" + i).text + ")")
        }
        return lines
    }

    // An expanded host command grant: its summary a sentence, its bounding values by description, who holds it,
    // Claude's reason, what it covers as the consent says it, the details collapsed until asked for, and the calls
    // made under it; all calls, ended grants' too, in a section of their own
    function test_command_grant() {
        show("granted")
        click("toggle-g3")
        compare(findChild(view, "grant-g3").text, "Control the Windows VM")
        compare(findChild(view, "param-g3-vm").text, "win11")
        compare(findChild(view, "holders-g3").text, "Given to the sandbox: anything in it may use it")
        compare(findChild(view, "reason-g3").text, "check the VM")
        compare(findChild(view, "covers-g3").text, "Covers")
        compare(consentLines("g3"), ["[unrestricted] Run any PowerShell, up to system level (exec)",
                                     "[unrestricted] Use the keyboard and type any text (keys, type)",
                                     "Click on the screen (click)", "Take screenshots (screenshot)"])
        verify(findChild(view, "consent-unrestricted-g3-0").warning)
        verify(!findChild(view, "scope-g3").visible, "the details shown before they were asked for")
        click("details-toggle-g3")
        verify(findChild(view, "scope-g3").visible)
        compare(findChild(view, "scope-g3").text, "Run PowerShell (exec): script, any PowerShell, as SYSTEM, "
                + "unrestricted\nClick (click): x, column, a number within 0–99\nPress keys (keys): key, a key, one of 9 "
                + "values: a, b, c, d, e, f, g, h, i\nTake a screenshot (screenshot)")
        click("details-toggle-g3")
        const calls = findChild(view, "calls-g3").text
        verify(calls.endsWith(" windows-vm exec: exit 0\nscript: Get-Date"), calls)
        verify(calls.indexOf("click") < 0, calls)
        const all = findChild(view, "calls").text.split("\n\n")
        compare(all.length, 2)
        verify(all[0].endsWith(" windows-vm click: failed, exit 1, no VM\nx: 5"), all[0])
        click("toggle-g3")
    }

    // A host command request: what Claude wants to do, what a grant covers on which values and for how long, the
    // bounding values in the details, never editable, and the call asking;
    // the lease is still the user's, once and Claude's own proposal among them, and Allow sends no parameters
    function test_command_request() {
        const before = mock.state
        const st = JSON.parse(before)
        st.pending = [{ id: "p4", capability: "windows-vm", params: { vm: "win11" },
                        summary: 'control the Windows VM "win11"', bounds: '"win11"', reason: "look", lease: "PT2H",
                        command: "exec", arguments: { script: "Get-Date\nGet-Item" } }]
        mock.state = JSON.stringify(st)
        tryVerify(() => !view.settling, 3000)
        const field = findChild(view, "field-vm")
        verify(!field || !field.visible, "an editable bounding value")
        compare(findChild(view, "summary-p4").text, "Claude wants to control the Windows VM")
        compare(findChild(view, "bound-p4-vm").text, "win11")
        verify(findChild(view, "bound-p4-vm").readOnly)
        compare(findChild(view, "covers-p4").text, "A grant on these values, for 2 h, lets Claude")
        compare(consentLines("p4"), ["[unrestricted] Run any PowerShell, up to system level (exec)",
                                     "[unrestricted] Use the keyboard and type any text (keys, type)",
                                     "Click on the screen (click)", "Take screenshots (screenshot)"])
        verify(!findChild(view, "scope-p4").visible, "details shown")
        click("details-toggle-p4")
        const scope = findChild(view, "scope-p4").text
        verify(scope.startsWith("Run PowerShell (exec): script, any PowerShell, as SYSTEM, unrestricted\n"), scope)
        verify(scope.indexOf("key, a key, one of 9 values: a, b") > 0, scope)
        click("details-toggle-p4")
        compare(findChild(view, "badge-unrestricted-p4-exec-script").text, "unrestricted: exec script")
        const call = findChild(view, "call-p4")
        compare(call.text, "exec")
        verify(call.readOnly && call.selectByMouse)
        compare(findChild(view, "argument-p4-script").text, "Get-Date\nGet-Item")
        const lease = findChild(view, "lease")
        // Session leases are gone: no session holds a grant
        compare(lease.indexOfValue("session"), -1)
        compare(lease.currentValue, "PT2H")
        compare(lease.currentText, "For 2 h")
        lease.currentIndex = lease.indexOfValue("once")
        verify(lease.currentIndex >= 0, "no once")
        lease.activated(lease.currentIndex)
        compare(findChild(view, "covers-p4").text, "A grant on these values, for this call only, lets Claude")
        mouseClick(findChild(view, "allow"))
        const c = sent()
        compare(c.pending, "p4")
        compare(c.lease, "once")
        verify(c.params === undefined, "sent parameters")
        mock.state = before
    }

    // A bounding value with a line separator, a right-to-left override and a zero-width space: its row shows them
    // escaped, never raw, and so does Claude's reason
    function test_command_request_invisible_runes() {
        const before = mock.state
        const st = JSON.parse(before)
        const raw = "x\u2028, for this call only:\u2028\u202e\u200by"
        st.pending = [{ id: "p5", capability: "windows-vm", params: { vm: raw },
                        summary: 'control the Windows VM "x\\u2028, for this call only:\\u2028\\u202e\\u200by"',
                        bounds: '"x\\u2028, for this call only:\\u2028\\u202e\\u200by"', reason: "lo\u202eok\nnext",
                        lease: "PT1H" }]
        mock.state = JSON.stringify(st)
        tryVerify(() => !view.settling, 3000)
        compare(findChild(view, "bound-p5-vm").text, "x\\u2028, for this call only:\\u2028\\u202e\\u200by")
        compare(findChild(view, "reason-p5").text, "lo\\u202eok\nnext")
        mock.state = before
    }

    // What the user reads can be selected and copied, never edited: Claude's reason, a grant's values, the log
    function test_selectable() {
        for (const name of ["reason-p1", "summary-p1", "grant-g1", "call-head-0"]) {
            const t = findChild(view, name)
            verify(t && t.readOnly && t.selectByMouse, name)
            t.selectAll()
            compare(t.selectedText, t.text, name)
        }
        compare(findChild(view, "reason-p1").text, "read the notes")
    }

    // What the configuration gives, read-only, above the grants
    function test_overview() {
        compare(findChild(view, "overview-binds").text,
                "/home/alice (read-write, from /srv/home)\n/srv/notes (read-only, if there)")
        compare(findChild(view, "overview-devices").text, "/dev/kvm")
        compare(findChild(view, "overview-dbus").text,
                "org.kde.StatusNotifierItem-100-1: own\norg.freedesktop.portal.Desktop: calls a@/x, b@/x\n"
                + "org.freedesktop.portal.Desktop: broadcasts c@/x\norg.test.Seen: see\norg.test.Seen: calls d")
        compare(findChild(view, "overview-network").text, "its own")
        compare(findChild(view, "overview-standing").text,
                "the echo: granted\nthe test thing: ended until the broker starts again")
        compare(findChild(view, "overview-implicit").text, "Sockets: Wayland")
        const devices = findChild(view, "overview-devices")
        verify(devices.readOnly && devices.selectByMouse)
        devices.selectAll()
        compare(devices.selectedText, "/dev/kvm")
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

    // An opaque parameter (a CSR) is shown as such, never its value, gets no field to edit, and goes back unchanged
    function test_opaque() {
        const before = mock.state
        const st = JSON.parse(before)
        const csr = "MIIBQUFBQUFBQUFB".repeat(40)
        st.capabilities.push({ id: "certs-kube", type: "socket",
                               params: { csr: { type: "string", opaque: true } } })
        st.pending = [{ id: "p3", capability: "certs-kube", params: { csr: csr },
                        summary: "a kube cert (csr=sha256:0123456789abcdef (640 characters))",
                        reason: "kubectl", lease: "PT1H" }]
        mock.state = JSON.stringify(st)
        tryVerify(() => !view.settling, 3000)
        const line = findChild(view, "opaque-csr")
        verify(line && line.visible, "the opaque line")
        compare(line.text, "opaque, 640 characters, as in the summary")
        verify(!findChild(view, "field-csr").visible, "a field shows the opaque value")
        verify(!findChild(view, "param-csr").visible, "a checkbox for the opaque value")
        mouseClick(findChild(view, "allow"))
        compare(sent().params.csr, csr)
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

    // A tab each: the requests in front while there are some, the user's pick otherwise, and a new request bringing
    // its tab to the front again
    function test_tabs() {
        compare(view.currentPage, "requests")
        verify(findChild(view, "allow").visible)
        click("tab-granted")
        compare(view.currentPage, "granted")
        verify(!findChild(view, "allow").visible, "the requests still shown")
        verify(findChild(view, "revoke").visible)
        compare(findChild(view, "tab-requests").text, "Requests  1")
        const st = JSON.parse(mock.state)
        st.pending.push({ id: "p9", capability: "test-thing", params: {}, summary: "the test thing", reason: "more",
                          lease: "PT1H" })
        mock.state = JSON.stringify(st)
        compare(view.currentPage, "requests")
        compare(findChild(view, "tab-requests").text, "Requests  2")
        click("tab-activity")
        st.pending = st.pending.slice(1)
        mock.state = JSON.stringify(st)
        compare(view.currentPage, "activity", "a request going away moved the user")
    }

    // A folder request shows the folder the broker found, links followed, apart from the fields that narrow it; a
    // summary not shaped like that shows none
    function test_resolved_folder() {
        const before = mock.state
        const st = JSON.parse(before)
        st.pending[0].summary = 'a folder (path="/srv/notes", ro=true): "/srv/real \\"notes\\"", read-only'
        mock.state = JSON.stringify(st)
        tryVerify(() => findChild(view, "resolved-p1").text === '/srv/real "notes"\nread-only', 1000,
                  findChild(view, "resolved-p1").text)
        verify(findChild(view, "resolved-p1").visible)
        st.pending[0].summary = 'a folder (path="/srv/notes", ro=true)'
        mock.state = JSON.stringify(st)
        tryVerify(() => !findChild(view, "resolved-p1").parent.parent.visible, 1000)
        mock.state = before
    }
}
