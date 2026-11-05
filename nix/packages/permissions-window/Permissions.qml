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
    readonly property var pending: st.pending || []
    readonly property var grants: st.grants || []
    readonly property var log: (st.log || []).slice().reverse().slice(0, 30)
    // Host command calls, newest first, also those of grants that ended
    readonly property var calls: (st.calls || []).slice().reverse()
    // What the sandbox reaches from its start, from the launcher's config, read-only: each section a title and its lines
    readonly property var standing: st.standing || []
    readonly property var overview: {
        const o = st.overview || {}
        const d = o.dbus || {}
        const sections = []
        const add = (key, title, lines) => {
            if (lines.length > 0)
                sections.push({ key: key, title: title, text: lines.join("\n") })
        }
        add("binds", "Binds", (o.binds || []).map(b => b.path + " (" + (b.rw ? "read-write" : "read-only")
                                                   + (b.src && b.src !== b.path ? ", from " + b.src : "")
                                                   + (b.optional ? ", if there" : "") + ")"))
        add("devices", "Devices, if there", o.devices || [])
        // The proxy's config: by name, its policy, calls and broadcasts
        add("dbus", "D-Bus, through the proxy", Object.keys(d).reduce((lines, n) => lines.concat(
            d[n].policy ? [n + ": " + d[n].policy] : [],
            (d[n].call || []).length > 0 ? [n + ": calls " + d[n].call.join(", ")] : [],
            (d[n].broadcast || []).length > 0 ? [n + ": broadcasts " + d[n].broadcast.join(", ")] : []), []))
        add("network", "Network", o.network ? [o.network] : [])
        add("standing", "Standing grants", root.standing.map(g => g.summary + ": "
                                                             + (g.ended ? "ended until the broker starts again"
                                                                        : g.grant ? "granted" : "not granted now")))
        add("implicit", "Also", o.implicit || [])
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

    // A capability's parameter values, one a line, each by its declaration's description
    function paramLines(capId, params) {
        const decl = (caps[capId] || {}).params || {}
        return Object.keys(params || {}).sort().map(k => {
            const d = decl[k] || {}
            const v = params[k]
            const shown = d.opaque && typeof v === "string" ? "opaque, " + v.length + " characters"
                                                            : typeof v === "string" ? v : JSON.stringify(v)
            return (d.description ? d.description + " (" + k + ")" : k) + ": " + shown
        }).join("\n")
    }
    function grantParams(g) {
        const lines = [paramLines(g.capability, g.params)]
        if (g.path)
            lines.push("Mounted at " + g.path + (g.source ? ", from " + g.source : ""))
        if (g.socket)
            lines.push("Socket at " + g.socket)
        return lines.filter(l => l).join("\n")
    }
    // A call's free arguments, one a line after the call's own: the broker has opaque ones by digest
    function argumentLines(args) {
        return Object.keys(args || {}).sort().map(k => "\n" + k + ": "
                                                   + (typeof args[k] === "string" ? args[k] : JSON.stringify(args[k])))
                                          .join("")
    }
    // A host command capability's bounding values as the consent's summary has them: a value alone, quoted, or with
    // several, each after its name
    function boundValues(capId, params) {
        const decl = (caps[capId] || {}).params || {}
        const keys = Object.keys(params || {}).sort()
        return keys.map(k => {
            const v = params[k]
            const shown = (decl[k] || {}).opaque && typeof v === "string" ? "opaque, " + v.length + " characters"
                                                                          : JSON.stringify(v)
            return keys.length > 1 ? k + " " + shown : shown
        }).join(", ")
    }
    // How long a lease lasts, after "for" or as "until": the notification's words
    function leasePhrase(lease) {
        switch (lease) {
        case "lock": return "until the screen locks"
        case "once": return "for this call only"
        }
        return "for " + (spoken(lease) || lease)
    }
    // The heading of what a host command request's grant covers: on its bounding values, for the lease picked
    function coversHeading(capId, params, lease) {
        const on = boundValues(capId, params)
        return "A grant covers" + (on ? ", on " + on : "") + ", " + leasePhrase(lease) + ":"
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

    ScrollView {
        anchors.fill: parent
        contentWidth: availableWidth

        ColumnLayout {
            width: parent.width
            spacing: 12

            Item {
                Layout.preferredHeight: 0
            }

            Label {
                Layout.fillWidth: true
                Layout.margins: 12
                visible: (root.broker.error || "") !== ""
                text: root.broker.error || ""
                color: "firebrick"
                wrapMode: Text.Wrap
            }

            Section {
                key: "pending"
                title: "Waiting for your answer"
                info: String(root.pending.length)
                visible: root.pending.length > 0
                expanded: root.isOpen("section:" + key, true)
                onToggled: root.toggle("section:" + key, true)
                Repeater {
                    model: root.pending
                    delegate: RequestRow {
                        view: root
                    }
                }
            }

            Section {
                key: "held"
                title: "Still open"
                visible: root.held.length > 0
                expanded: root.isOpen("section:" + key, true)
                onToggled: root.toggle("section:" + key, true)
                RowLayout {
                    Layout.fillWidth: true
                    ReadOnlyText {
                        objectName: "held"
                        Layout.fillWidth: true
                        // A folder grant that ended is unmounted, but what's open in it stays readable to whoever holds it
                        text: "Still open in folders no longer granted: "
                              + root.held.map(g => g.summary + " (" + g.why + "): "
                                              + g.holders.map(h => h.comm + " (" + h.pid + (h.possible ? ", possibly" : "")
                                                              + ")").join(", ")).join("; ")
                    }
                    Button {
                        objectName: "end"
                        text: "End them"
                        onClicked: root.send({ op: "end", grants: root.held.map(g => g.grant) })
                    }
                }
            }

            Section {
                key: "config"
                title: "From the configuration"
                info: "read-only"
                visible: root.overview.length > 0
                expanded: root.isOpen("section:" + key, true)
                onToggled: root.toggle("section:" + key, true)
                Repeater {
                    model: root.overview
                    delegate: ColumnLayout {
                        required property var modelData
                        Layout.fillWidth: true
                        spacing: 2
                        Label {
                            text: modelData.title
                            font.italic: true
                        }
                        ReadOnlyText {
                            objectName: "overview-" + modelData.key
                            Layout.fillWidth: true
                            Layout.leftMargin: 12
                            text: modelData.text
                        }
                    }
                }
            }

            Section {
                key: "granted"
                title: "Granted"
                info: root.grants.length > 0 ? String(root.grants.length) : "nothing right now"
                expanded: root.isOpen("section:" + key, true)
                onToggled: root.toggle("section:" + key, true)
                Repeater {
                    model: root.grants
                    delegate: GrantRow {
                        view: root
                    }
                }
            }

            Section {
                key: "calls"
                title: "Host command calls"
                info: String(root.calls.length)
                visible: root.calls.length > 0
                expanded: root.isOpen("section:" + key, true)
                onToggled: root.toggle("section:" + key, true)
                ReadOnlyText {
                    objectName: "calls"
                    Layout.fillWidth: true
                    text: root.callsText(root.calls, "")
                }
            }

            Section {
                key: "log"
                title: "Recent decisions"
                visible: root.log.length > 0
                expanded: root.isOpen("section:" + key, true)
                onToggled: root.toggle("section:" + key, true)
                ReadOnlyText {
                    objectName: "log"
                    Layout.fillWidth: true
                    text: root.log.map(e => Qt.formatDateTime(new Date(e.time), "yyyy-MM-dd HH:mm") + ": " + e.decision
                                       + ", " + e.summary
                                       + (e.reason ? ". Claude's reason: " + JSON.stringify(e.reason) : "")).join("\n")
                }
            }
        }
    }
}
