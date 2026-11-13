import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// The Permissions window's content. broker.state is the broker's state as JSON, broker.error what went wrong; actions
// go to broker.command as JSON. main.go passes a QQmlPropertyMap, tst_permissions.qml a mock. The rows are the
// broker's, in its order: the window keeps only what the user set on them (edits, what's expanded)
Item {
    id: root
    required property var broker

    readonly property var st: root.broker.state ? JSON.parse(root.broker.state) : ({})
    // Who asks, as the broker's config names it
    readonly property string agent: st.agent || "The agent"
    readonly property var pending: st.pending || []
    readonly property var grants: st.grants || []
    readonly property var log: (st.log || []).slice().reverse().slice(0, 30)
    // Host command calls, newest first, also those of grants that ended
    readonly property var calls: (st.calls || []).slice().reverse()
    // What the sandbox reaches from its start, from the launcher's config, read-only: each section a title, its items
    // (a value, monospace when it's a path or a name, its badges, and rows for what goes with it) and its text, a line an item, for copying and the tests
    readonly property var standing: st.standing || []
    readonly property var overview: {
        const o = st.overview || {}
        const d = o.dbus || {}
        const sections = []
        const add = (key, title, items, lines) => {
            if (items.length > 0)
                sections.push({ key: key, title: title, items: items, text: lines.join("\n") })
        }
        // Whether an optional bind or a device is there: the broker lists what the sandbox's mount table lacks, when it
        // could read it
        const known = Array.isArray(o.absent)
        const optional = path => !known ? "optional" : o.absent.indexOf(path) >= 0 ? "optional, missing"
                                                                                  : "optional, present"
        const plain = (list, mono) => list.map(v => ({ value: v, mono: mono, badges: [], rows: [] }))
        const binds = o.binds || []
        add("binds", "Binds", binds.map(b => ({
                value: b.path,
                mono: true,
                badges: [{ text: b.rw ? "read-write" : "read-only", warning: false }]
                        .concat(b.optional ? [{ text: optional(b.path) }] : []),
                rows: b.src && b.src !== b.path ? [{ name: "from", value: b.src }] : []
            })), binds.map(b => b.path + " (" + (b.rw ? "read-write" : "read-only")
                           + (b.src && b.src !== b.path ? ", from " + b.src : "")
                           + (b.optional ? ", " + optional(b.path) : "") + ")"))
        // Bound only where they exist, as an optional bind
        add("devices", "Devices", (o.devices || []).map(v => ({ value: v, mono: true, badges: [{ text: optional(v) }],
                                                                rows: [] })),
            (o.devices || []).map(v => known ? v + " (" + optional(v) + ")" : v))
        // The proxy's config: by name, its policy, calls and broadcasts
        const names = Object.keys(d)
        add("dbus", "D-Bus, through the proxy", names.map(n => ({
                value: n,
                mono: true,
                badges: d[n].policy ? [{ text: d[n].policy }] : [],
                rows: (d[n].call || []).map(c => ({ name: "calls", value: c }))
                      .concat((d[n].broadcast || []).map(c => ({ name: "broadcasts", value: c })))
            })), names.reduce((lines, n) => lines.concat(
                d[n].policy ? [n + ": " + d[n].policy] : [],
                (d[n].call || []).length > 0 ? [n + ": calls " + d[n].call.join(", ")] : [],
                (d[n].broadcast || []).length > 0 ? [n + ": broadcasts " + d[n].broadcast.join(", ")] : []), []))
        add("network", "Network", plain(o.network ? [o.network] : [], false), o.network ? [o.network] : [])
        const state = g => g.ended ? "ended until the broker starts again" : g.grant ? "granted" : "not granted now"
        add("standing", "Standing grants", root.standing.map(g => ({
                value: g.summary, mono: false, badges: [{ text: state(g), warning: !!g.ended }], rows: [] })),
            root.standing.map(g => g.summary + ": " + state(g)))
        add("implicit", "Also", plain(o.implicit || [], false), o.implicit || [])
        return sections
    }
    // What still holds folder grants that ended, however they ended
    readonly property var held: st.held || []
    // The capabilities by id: their parameters' declarations and, for host commands, what a grant covers
    readonly property var caps: {
        const c = {}
        for (const cap of st.capabilities || [])
            c[cap.id] = cap
        return c
    }
    // Each capability's parameter types, for the fields that narrow a request. An opaque parameter (data for a
    // host command, such as a CSR) gets no field: there's nothing to narrow, and the summary shows its digest
    readonly property var types: {
        const t = {}
        for (const c of st.capabilities || []) {
            t[c.id] = {}
            for (const k in c.params || {})
                t[c.id][k] = c.params[k].opaque ? "opaque" : c.params[k].type || "string"
        }
        return t
    }

    // Leases the user can pick
    readonly property var leases: [
        { value: "lock", text: "Until the screen locks" },
        { value: "PT1H", text: "For 1 h" },
        { value: "PT8H", text: "For 8 h" }
    ]
    // A request's leases: the usual ones, once for a call, and what Claude proposed when it's none of those
    function leasesFor(req) {
        const list = leases.slice()
        if (req.command)
            list.push({ value: "once", text: leaseText("once") })
        if (!list.some(l => l.value === req.lease))
            list.push({ value: req.lease, text: leaseText(req.lease) })
        return list
    }

    // What the user set on each pending request, by its id: the list is rebuilt on every broker event, which the
    // sandbox can cause at will, and a row must keep the user's narrowing and lease through it
    property var edits: ({})
    function editsOf(req) {
        if (!edits[req.id])
            edits[req.id] = { params: Object.assign({}, req.params), lease: req.lease }
        return edits[req.id]
    }

    // Which sections and grants the user expanded or collapsed, by key: sections start expanded, grants collapsed
    property var expanded: ({})
    function isOpen(key, open) {
        return expanded[key] === undefined ? open : expanded[key]
    }
    function toggle(key, open) {
        const e = Object.assign({}, expanded)
        e[key] = !isOpen(key, open)
        expanded = e
    }

    // Another request where a row was: one moved up, a row above it gone, or one in a row's place, [A] turned [B] or
    // [X, A] turned [X, B], or a row where there was none. When the sandbox's requests end and arrive is partly its
    // choice (they time out), and a click meant for one would land on the other. Allow and Deny stay off for a second
    // after, as the notification ignores a click right after it appears
    property var pendingIds: []
    property bool settling: false
    property int settleMs: 1000
    onPendingChanged: {
        const ids = pending.map(p => p.id)
        // A new request brings its tab to the front; Allow and Deny are off for a second then anyway
        if (ids.some(id => pendingIds.indexOf(id) < 0))
            page = "requests"
        if (ids.some((id, i) => id !== pendingIds[i])) {
            settling = true
            settle.restart()
        }
        pendingIds = ids
    }
    Timer {
        id: settle
        interval: root.settleMs
        onTriggered: root.settling = false
    }

    // The time, for what grants have left
    property double now: Date.now()
    Timer {
        interval: 30000
        running: true
        repeat: true
        onTriggered: root.now = Date.now()
    }

    // A counter in each command, so the same action twice is still a change of broker.command
    property int sent: 0
    function send(cmd) {
        cmd.seq = ++sent
        root.broker.command = JSON.stringify(cmd)
    }

    // "1 h 30 min" for PT1H30M, or "" when lease isn't a duration
    function spoken(lease) {
        const m = /^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$/.exec(lease || "")
        if (!m || !(m[1] || m[2] || m[3]))
            return ""
        const secs = Number(m[1] || 0) * 3600 + Number(m[2] || 0) * 60 + Number(m[3] || 0)
        return minutes(Math.floor(secs / 60)) || secs + " s"
    }
    function minutes(n) {
        const h = Math.floor(n / 60), m = n % 60
        return [h ? h + " h" : "", m ? m + " min" : ""].filter(s => s).join(" ")
    }
    function leaseText(lease) {
        switch (lease) {
        case "standing": return "From config"
        case "once": return "For this call only"
        }
        for (const l of leases)
            if (l.value === lease)
                return l.text
        return spoken(lease) ? "For " + spoken(lease) : lease
    }
    function timeLeft(expires) {
        if (!expires)
            return ""
        const ms = new Date(expires).getTime() - now
        return ms <= 0 ? "ending" : minutes(Math.ceil(ms / 60000)) + " left"
    }

    // A value the sandbox chose, as it is, in a box of its own: no quotes needed to see where it ends, but what would
    // break a line where it shouldn't, turn the text around or hide is escaped, and C1 controls, line and paragraph separators, bidi and other format characters. A string with line
    // breaks keeps them; another value is shown as JSON
    function shown(v) {
        const s = typeof v === "string" ? v : JSON.stringify(v)
        return String(s).replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff\ufff9-\ufffb]/g,
                                 c => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"))
    }
    // What a parameter is, from its capability's declaration
    function paramDescription(capId, key) {
        return ((((caps[capId] || {}).params || {})[key]) || {}).description || ""
    }
    // A request's heading: a host command capability's title completes "Claude wants to", the values below it; another
    // capability by its description, or the broker's summary when it has none
    function headline(req) {
        const cap = caps[req.capability] || {}
        if (cap.type === "command")
            return root.agent + " wants to " + (cap.title || req.summary)
        return root.agent + " asks for " + (cap.description || req.summary)
    }
    // A grant's line: the same words, as a sentence of its own; for a port its summary, which names it
    function grantTitle(g) {
        const cap = caps[g.capability] || {}
        const t = cap.type === "command" ? cap.title || g.summary
                                         : cap.type === "port" ? g.summary : cap.description || g.summary
        return t.charAt(0).toUpperCase() + t.slice(1)
    }
    // What the broker found an attach request's target to be, from the end of its summary (describeAttach: the
    // path quoted, then read-only or read-write), or null
    function resolvedTarget(summary) {
        const m = /: ("(?:[^"\\]|\\.)*"), (read-only|read-write)$/.exec(summary || "")
        if (!m)
            return null
        try {
            return { path: shown(JSON.parse(m[1])), access: m[2] }
        } catch (e) {
            return null
        }
    }
    // A grant's values a row each: its parameters by name, where it's mounted, its socket, where the host reaches a port
    function grantFields(g) {
        const rows = Object.keys(g.params || {}).sort().map(k => {
            const d = ((caps[g.capability] || {}).params || {})[k] || {}
            const v = g.params[k]
            return { key: k, name: k, description: d.description || "",
                     value: d.opaque && typeof v === "string" ? "opaque, " + v.length + " characters" : shown(v) }
        })
        if (g.source)
            rows.push({ key: "source", name: "on the host", value: g.source })
        if (g.path)
            rows.push({ key: "path", name: "mounted at", value: g.path })
        if (g.socket)
            rows.push({ key: "socket", name: "socket", value: g.socket })
        if (g.addresses)
            rows.push({ key: "addresses", name: "on the host at", value: g.addresses.join("\n") })
        return rows
    }
    // A call's free arguments, one a line after the call's own: the broker has opaque ones by digest
    function argumentLines(args) {
        return Object.keys(args || {}).sort().map(k => "\n" + k + ": "
                                                   + (typeof args[k] === "string" ? args[k] : JSON.stringify(args[k])))
                                          .join("")
    }
    // How long a lease lasts, after "for" or as "until": the notification's words
    function leasePhrase(lease) {
        switch (lease) {
        case "lock": return "until the screen locks"
        case "once": return "for this call only"
        }
        return "for " + (spoken(lease) || lease)
    }
    // The heading of what a host command request's grant covers, for the lease picked: its bounding values are the
    // rows above it
    function coversHeading(lease) {
        const p = leasePhrase(lease)
        return "A grant on these values, " + p + ", lets " + root.agent
    }
    // What a grant of a host command capability covers in detail, one command or free argument a line, unrestricted
    // ones first, with the values of an enum the broker counts rather than lists (more than its maxListedEnum, 8)
    function scopeText(capId) {
        const cap = caps[capId] || {}
        return (cap.scope || []).map(s => {
            if (!s.argument)
                return s.description + " (" + s.command + ")"
            const line = s.description + " (" + s.command + "): " + s.argument + ", " + s.about + ", "
                         + (s.unrestricted ? "unrestricted" : s.allows)
            const decl = ((cap.commands || {})[s.command] || {}).arguments || {}
            const arg = decl[s.argument] || {}
            const values = arg.enum || (arg.items || {}).enum || []
            return values.length > 8 ? line + ": " + values.join(", ") : line
        }).join("\n")
    }
    function callsText(list, none) {
        if (list.length === 0)
            return none
        return list.map(c => Qt.formatDateTime(new Date(c.time), "yyyy-MM-dd HH:mm:ss") + " " + c.capability + " "
                        + c.command + ": " + (c.error || c.exit ? "failed, exit " + c.exit : "exit 0")
                        + (c.error ? ", " + c.error : "") + argumentLines(c.arguments)).join("\n\n")
    }
    function holdersText(g) {
        const lines = ["Given to the sandbox: anything in it may use it"]
        if ((g.holders || []).length > 0)
            lines.push("Open in: " + g.holders.map(h => h.comm + " (" + h.pid + (h.possible ? ", possibly" : "")
                                                     + ")").join(", "))
        return lines.join("\n")
    }

    // Badges: each a name for its objectName, a text and whether it warns
    function freeBadges(capId, id) {
        const items = ((caps[capId] || {}).scope || []).filter(s => s.argument)
        const out = []
        if (items.length > 0)
            out.push({ name: "badge-free-" + id,
                       text: items.length + (items.length === 1 ? " free argument" : " free arguments") })
        for (const s of items.filter(s => s.unrestricted))
            out.push({ name: "badge-unrestricted-" + id + "-" + s.command + "-" + s.argument, warning: true,
                       text: "unrestricted: " + s.command + " " + s.argument })
        return out
    }
    function grantBadges(g) {
        const out = []
        if (g.lease === "standing")
            out.push({ name: "badge-config-" + g.id, text: "from config" })
        else
            out.push({ name: "badge-lease-" + g.id,
                       text: { lock: "until lock", once: "once" }[g.lease] || spoken(g.lease) || g.lease })
        return out.concat(freeBadges(g.capability, g.id))
    }

    // The tab shown: the user's pick, or the requests when there are some
    property string page: ""
    readonly property string currentPage: page !== "" ? page : pending.length > 0 ? "requests" : "granted"
    readonly property var pages: ["requests", "granted", "activity", "config"]

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Label {
            Layout.fillWidth: true
            Layout.margins: 12
            visible: (root.broker.error || "") !== ""
            text: root.broker.error || ""
            color: "firebrick"
            wrapMode: Text.Wrap
            renderType: Text.NativeRendering
        }

        TabBar {
            id: tabs
            Layout.fillWidth: true
            currentIndex: root.pages.indexOf(root.currentPage)
            // Declared, not repeated: the Plasma style's TabBar reads its first tab's height before a Repeater adds it
            TabButton {
                objectName: "tab-requests"
                text: "Requests" + (root.pending.length > 0 ? "  " + root.pending.length : "")
                font.bold: root.pending.length > 0
                onClicked: root.page = "requests"
            }
            TabButton {
                objectName: "tab-granted"
                text: "Granted" + (root.grants.length > 0 ? "  " + root.grants.length : "")
                onClicked: root.page = "granted"
            }
            TabButton {
                objectName: "tab-activity"
                text: "Activity"
                onClicked: root.page = "activity"
            }
            TabButton {
                objectName: "tab-config"
                text: "Configuration"
                onClicked: root.page = "config"
            }
        }

        StackLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: tabs.currentIndex

            TabPage {
                objectName: "page-requests"
                Label {
                    objectName: "no-requests"
                    visible: root.pending.length === 0
                    text: "Nothing waiting for your answer"
                    opacity: 0.7
                    renderType: Text.NativeRendering
                }
                Repeater {
                    model: root.pending
                    delegate: RequestRow {
                        view: root
                    }
                }
            }

            TabPage {
                objectName: "page-granted"
                Card {
                    visible: root.held.length > 0
                    RowLayout {
                        Layout.fillWidth: true
                        ReadOnlyText {
                            objectName: "held"
                            Layout.fillWidth: true
                            // A folder grant that ended is unmounted, but what's open in it stays readable to whoever
                            // holds it
                            text: "Still open in folders no longer granted: "
                                  + root.held.map(g => g.summary + " (" + g.why + "): "
                                                  + g.holders.map(h => h.comm + " (" + h.pid
                                                                  + (h.possible ? ", possibly" : "") + ")").join(", "))
                                            .join("; ")
                        }
                        Button {
                            objectName: "end"
                            text: "End them"
                            onClicked: root.send({ op: "end", grants: root.held.map(g => g.grant) })
                        }
                    }
                }
                Label {
                    objectName: "no-grants"
                    visible: root.grants.length === 0
                    text: "Nothing granted right now"
                    opacity: 0.7
                    renderType: Text.NativeRendering
                }
                Repeater {
                    model: root.grants
                    delegate: GrantRow {
                        view: root
                    }
                }
            }

            TabPage {
                objectName: "page-activity"
                Section {
                    key: "calls"
                    title: "Host command calls"
                    info: root.calls.length > 0 ? String(root.calls.length) : "none yet"
                    CallList {
                        objectName: "calls"
                        view: root
                        calls: root.calls
                    }
                }
                Section {
                    key: "log"
                    title: "Recent decisions"
                    info: root.log.length > 0 ? "" : "none yet"
                    Repeater {
                        model: root.log
                        delegate: ColumnLayout {
                            id: entry
                            required property var modelData
                            Layout.fillWidth: true
                            spacing: 4
                            RowLayout {
                                Layout.fillWidth: true
                                spacing: 8
                                Label {
                                    text: Qt.formatDateTime(new Date(entry.modelData.time), "yyyy-MM-dd HH:mm")
                                    font.family: "monospace"
                                    opacity: 0.7
                                    renderType: Text.NativeRendering
                                }
                                Badge {
                                    text: entry.modelData.decision
                                    warning: entry.modelData.decision.startsWith("denied")
                                }
                            }
                            ReadOnlyText {
                                Layout.fillWidth: true
                                Layout.leftMargin: 12
                                text: root.shown(entry.modelData.summary)
                            }
                            Quote {
                                agent: root.agent
                                Layout.leftMargin: 12
                                visible: !!entry.modelData.reason
                                text: root.shown(entry.modelData.reason || "")
                            }
                        }
                    }
                    // The log as plain text, for the tests
                    property string text: root.log.map(e => Qt.formatDateTime(new Date(e.time), "yyyy-MM-dd HH:mm")
                                                       + ": " + e.decision + ", " + e.summary
                                                       + (e.reason ? ". " + root.agent + "'s reason: " + JSON.stringify(e.reason)
                                                                   : "")).join("\n")
                    objectName: "log"
                }
            }

            TabPage {
                objectName: "page-config"
                Label {
                    Layout.fillWidth: true
                    text: "What the sandbox gets from its start, from the launcher's configuration. Read-only here."
                    wrapMode: Text.Wrap
                    opacity: 0.7
                    renderType: Text.NativeRendering
                }
                Repeater {
                    model: root.overview
                    delegate: Section {
                        id: part
                        required property var modelData
                        key: "overview-" + modelData.key
                        title: modelData.title
                        info: modelData.items.length > 1 ? String(modelData.items.length) : ""
                        Card {
                            objectName: "overview-" + part.modelData.key
                            readonly property string text: part.modelData.text
                            padding: 10
                            Repeater {
                                model: part.modelData.items
                                delegate: ColumnLayout {
                                    id: item
                                    required property var modelData
                                    required property int index
                                    Layout.fillWidth: true
                                    spacing: 4
                                    Rectangle {
                                        Layout.fillWidth: true
                                        Layout.bottomMargin: 4
                                        visible: item.index > 0
                                        implicitHeight: 1
                                        color: palette.midlight
                                    }
                                    RowLayout {
                                        Layout.fillWidth: true
                                        spacing: 8
                                        ReadOnlyText {
                                            objectName: "overview-" + part.modelData.key + "-" + item.index
                                            Layout.fillWidth: true
                                            text: item.modelData.value
                                            font.family: item.modelData.mono ? "monospace" : Qt.application.font.family
                                        }
                                        Badges {
                                            Layout.alignment: Qt.AlignTop
                                            model: item.modelData.badges.map(b => ({ name: "", text: b.text,
                                                                                     warning: b.warning === true }))
                                        }
                                    }
                                    Repeater {
                                        model: item.modelData.rows
                                        delegate: FieldRow {
                                            required property var modelData
                                            Layout.leftMargin: -40
                                            name: modelData.name
                                            value: modelData.value
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
