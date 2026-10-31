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
    readonly property var always: st.always || []
    readonly property var log: (st.log || []).slice().reverse().slice(0, 30)
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

    // Leases the user can pick, always only here
    readonly property var leases: [
        { value: "session", text: "For this session" },
        { value: "lock", text: "Until the screen locks" },
        { value: "PT1H", text: "For an hour" },
        { value: "PT8H", text: "For eight hours" },
        { value: "always", text: "Always" }
    ]

    // A counter in each command, so the same action twice is still a change of broker.command
    property int sent: 0
    function send(cmd) {
        cmd.seq = ++sent
        root.broker.command = JSON.stringify(cmd)
    }

    function leaseText(lease) {
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
                    // The request's parameters, as the fields below narrow them
                    property var edited: Object.assign({}, modelData.params)
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
                                textRole: "text"
                                valueRole: "value"
                                model: root.leases
                                Component.onCompleted: currentIndex = Math.max(0, indexOfValue(request.modelData.lease))
                            }
                            Item { Layout.fillWidth: true }
                            Button {
                                objectName: "deny"
                                text: "Deny"
                                onClicked: root.send({ op: "answer", pending: request.modelData.id, allow: false })
                            }
                            Button {
                                objectName: "allow"
                                text: "Allow"
                                highlighted: true
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
                    Layout.fillWidth: true
                    // A folder grant that ended is unmounted, but what's open in it stays readable to whoever holds it
                    text: "Still open in folders no longer granted: "
                          + root.held.map(g => g.summary + " (" + g.why + "): "
                                          + g.holders.map(h => h.comm + " (" + h.pid + ")").join(", ")).join("; ")
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
                text: "Always granted"
                font.bold: true
                visible: root.always.length > 0
            }
            Repeater {
                model: root.always
                delegate: RowLayout {
                    required property var modelData
                    Layout.fillWidth: true
                    Layout.leftMargin: 12
                    Layout.rightMargin: 12
                    Label {
                        Layout.fillWidth: true
                        text: modelData.capability + " " + JSON.stringify(modelData.params || {})
                        textFormat: Text.PlainText
                        wrapMode: Text.Wrap
                    }
                    Button {
                        objectName: "forget"
                        text: "Forget"
                        onClicked: root.send({ op: "forget", capability: modelData.capability, params: modelData.params || {} })
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
