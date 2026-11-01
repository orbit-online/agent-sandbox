import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// The Permissions window's content. broker.state is the broker's state as JSON, broker.error what went wrong; actions
// go to broker.command as JSON. main.go passes a QQmlPropertyMap, tst_permissions.qml a mock
Item {
    id: root
    required property var broker

    readonly property var st: root.broker.state ? JSON.parse(root.broker.state) : ({})
    readonly property var pending: st.pending || []
    readonly property var grants: st.grants || []
    readonly property var log: (st.log || []).slice().reverse().slice(0, 30)
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
        add("dbus", "D-Bus, through the proxy", [].concat(
            Object.keys(d.policies || {}).map(n => n + ": " + d.policies[n]),
            Object.keys(d.call || {}).map(n => n + ": calls " + d.call[n].join(", ")),
            Object.keys(d.broadcast || {}).map(n => n + ": broadcasts " + d.broadcast[n].join(", "))))
        add("network", "Network", o.network ? [o.network] : [])
        add("standing", "Standing grants", root.standing.map(g => g.summary + ": "
                                                             + (g.ended ? "ended until the broker starts again"
                                                                        : g.grant ? "granted" : "not granted now")))
        add("implicit", "Also", o.implicit || [])
        return sections
    }
    // What still holds folder grants that ended, however they ended
    readonly property var held: st.held || []
    // Each capability's parameter types, for the fields that narrow a request
    readonly property var types: {
        const t = {}
        for (const c of st.capabilities || []) {
            t[c.id] = {}
            for (const k in c.params || {})
                t[c.id][k] = c.params[k].type || "string"
        }
        return t
    }

    // Leases the user can pick
    readonly property var leases: [
        { value: "session", text: "Until this Claude session ends" },
        { value: "lock", text: "Until the screen locks" },
        { value: "PT1H", text: "For an hour" },
        { value: "PT8H", text: "For eight hours" }
    ]

    // What the user set on each pending request, by its id: the list is rebuilt on every broker event, which the
    // sandbox can cause at will, and a row must keep the user's narrowing and lease through it
    property var edits: ({})
    function editsOf(req) {
        if (!edits[req.id])
            edits[req.id] = { params: Object.assign({}, req.params), lease: req.lease }
        return edits[req.id]
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

    // A counter in each command, so the same action twice is still a change of broker.command
    property int sent: 0
    function send(cmd) {
        cmd.seq = ++sent
        root.broker.command = JSON.stringify(cmd)
    }

    function leaseText(lease) {
        if (lease === "standing")
            return "From config"
        for (const l of leases)
            if (l.value === lease)
                return l.text
        return lease
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

            Label {
                Layout.leftMargin: 12
                text: "Waiting for your answer"
                font.bold: true
                visible: root.pending.length > 0
            }
            Repeater {
                model: root.pending
                delegate: Frame {
                    id: request
                    required property var modelData
                    // The request's parameters, as the fields below narrow them, kept across refreshes
                    readonly property var edited: root.editsOf(modelData).params
                    readonly property var paramTypes: root.types[modelData.capability] || {}
                    Layout.fillWidth: true
                    Layout.leftMargin: 12
                    Layout.rightMargin: 12

                    ColumnLayout {
                        anchors.fill: parent
                        Label {
                            Layout.fillWidth: true
                            text: request.modelData.summary
                            textFormat: Text.PlainText
                            wrapMode: Text.Wrap
                            font.bold: true
                        }
                        Label {
                            Layout.fillWidth: true
                            text: "Claude's reason, in its own words: " + JSON.stringify(request.modelData.reason)
                            textFormat: Text.PlainText
                            wrapMode: Text.Wrap
                        }
                        Repeater {
                            model: Object.keys(request.paramTypes)
                            delegate: RowLayout {
                                id: param
                                required property string modelData
                                readonly property string kind: request.paramTypes[modelData]
                                Label { text: param.modelData }
                                CheckBox {
                                    objectName: "param-" + param.modelData
                                    visible: param.kind === "boolean"
                                    checked: request.edited[param.modelData] === true
                                    onToggled: request.edited[param.modelData] = checked
                                }
                                TextField {
                                    visible: param.kind !== "boolean"
                                    Layout.fillWidth: true
                                    text: request.edited[param.modelData] !== undefined ? String(request.edited[param.modelData]) : ""
                                    onEditingFinished: {
                                        if (text === "")
                                            delete request.edited[param.modelData]
                                        else
                                            request.edited[param.modelData] = param.kind === "string" ? text : Number(text)
                                    }
                                }
                            }
                        }
                        RowLayout {
                            ComboBox {
                                id: lease
                                objectName: "lease"
                                textRole: "text"
                                valueRole: "value"
                                model: root.leases
                                Component.onCompleted: currentIndex = Math.max(0, indexOfValue(root.editsOf(request.modelData).lease))
                                onActivated: root.editsOf(request.modelData).lease = currentValue
                            }
                            Item { Layout.fillWidth: true }
                            Button {
                                objectName: "deny"
                                text: "Deny"
                                enabled: !root.settling
                                onClicked: root.send({ op: "answer", pending: request.modelData.id, allow: false })
                            }
                            Button {
                                objectName: "allow"
                                text: "Allow"
                                highlighted: true
                                enabled: !root.settling
                                onClicked: root.send({ op: "answer", pending: request.modelData.id, allow: true,
                                                       lease: lease.currentValue, params: request.edited })
                            }
                        }
                    }
                }
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.leftMargin: 12
                Layout.rightMargin: 12
                visible: root.held.length > 0
                Label {
                    objectName: "held"
                    Layout.fillWidth: true
                    // A folder grant that ended is unmounted, but what's open in it stays readable to whoever holds it
                    text: "Still open in folders no longer granted: "
                          + root.held.map(g => g.summary + " (" + g.why + "): "
                                          + g.holders.map(h => h.comm + " (" + h.pid + (h.possible ? ", possibly" : "")
                                                          + ")").join(", ")).join("; ")
                    textFormat: Text.PlainText
                    wrapMode: Text.Wrap
                }
                Button {
                    objectName: "end"
                    text: "End them"
                    onClicked: root.send({ op: "end", grants: root.held.map(g => g.grant) })
                }
            }

            Label {
                Layout.leftMargin: 12
                text: "From the configuration"
                font.bold: true
                visible: root.overview.length > 0
            }
            Repeater {
                model: root.overview
                delegate: ColumnLayout {
                    required property var modelData
                    Layout.fillWidth: true
                    Layout.leftMargin: 12
                    Layout.rightMargin: 12
                    spacing: 2
                    Label {
                        text: modelData.title
                        font.italic: true
                    }
                    // Selectable, so its paths and rules can be copied
                    TextArea {
                        objectName: "overview-" + modelData.key
                        Layout.fillWidth: true
                        Layout.leftMargin: 12
                        text: modelData.text
                        textFormat: Text.PlainText
                        wrapMode: Text.Wrap
                        readOnly: true
                        selectByMouse: true
                        background: null
                        padding: 0
                    }
                }
            }

            Label {
                Layout.leftMargin: 12
                text: "Granted"
                font.bold: true
            }
            Label {
                Layout.leftMargin: 12
                visible: root.grants.length === 0
                text: "Nothing right now."
            }
            Repeater {
                model: root.grants
                delegate: RowLayout {
                    required property var modelData
                    Layout.fillWidth: true
                    Layout.leftMargin: 12
                    Layout.rightMargin: 12
                    Label {
                        objectName: "grant-" + modelData.id
                        Layout.fillWidth: true
                        text: modelData.summary + ", " + root.leaseText(modelData.lease).toLowerCase()
                              + (modelData.expires ? ", until " + Qt.formatDateTime(new Date(modelData.expires), "HH:mm") : "")
                        textFormat: Text.PlainText
                        wrapMode: Text.Wrap
                    }
                    Button {
                        objectName: "revoke"
                        text: "Revoke"
                        onClicked: root.send({ op: "revoke", grant: modelData.id })
                    }
                }
            }

            Label {
                Layout.leftMargin: 12
                text: "Recent decisions"
                font.bold: true
                visible: root.log.length > 0
            }
            Repeater {
                model: root.log
                delegate: Label {
                    required property var modelData
                    Layout.fillWidth: true
                    Layout.leftMargin: 12
                    Layout.rightMargin: 12
                    text: Qt.formatDateTime(new Date(modelData.time), "yyyy-MM-dd HH:mm") + ": " + modelData.decision + ", "
                          + modelData.summary
                    textFormat: Text.PlainText
                    wrapMode: Text.Wrap
                }
            }
        }
    }
}
