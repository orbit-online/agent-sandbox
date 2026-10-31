import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ApplicationWindow {
    id: root
    required property var broker
    width: 640
    height: 720
    visible: true

    // Leases the user can pick, always only here
    readonly property var leases: [
        { value: "session", text: "For this session" },
        { value: "lock", text: "Until the screen locks" },
        { value: "PT1H", text: "For an hour" },
        { value: "PT8H", text: "For eight hours" },
        { value: "always", text: "Always" }
    ]

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
                visible: root.broker.error !== ""
                text: root.broker.error
                color: "firebrick"
                wrapMode: Text.Wrap
            }

            Label {
                Layout.leftMargin: 12
                text: "Waiting for your answer"
                font.bold: true
                visible: root.broker.pending.length > 0
            }
            Repeater {
                model: root.broker.pending
                delegate: Frame {
                    id: request
                    required property var modelData
                    // The request's parameters, as the fields below narrow them
                    property var edited: Object.assign({}, modelData.params)
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
                            model: Object.keys(request.modelData.types)
                            delegate: RowLayout {
                                id: param
                                required property string modelData
                                readonly property string kind: request.modelData.types[modelData]
                                Label { text: param.modelData }
                                CheckBox {
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
                                text: "Deny"
                                onClicked: root.broker.answer(request.modelData.id, false, "", "")
                            }
                            Button {
                                text: "Allow"
                                highlighted: true
                                onClicked: root.broker.answer(request.modelData.id, true, lease.currentValue,
                                                              JSON.stringify(request.edited))
                            }
                        }
                    }
                }
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.leftMargin: 12
                Layout.rightMargin: 12
                visible: root.broker.holders.length > 0
                Label {
                    Layout.fillWidth: true
                    // Revoking unmounts a folder, but what's open in it stays readable to whoever holds it
                    text: "Still open in what you revoked: "
                          + root.broker.holders.map(h => h.comm + " (" + h.pid + ")").join(", ")
                    textFormat: Text.PlainText
                    wrapMode: Text.Wrap
                }
                Button {
                    text: "End them"
                    onClicked: root.broker.endHolders()
                }
            }

            Label {
                Layout.leftMargin: 12
                text: "Granted"
                font.bold: true
            }
            Label {
                Layout.leftMargin: 12
                visible: root.broker.grants.length === 0
                text: "Nothing right now."
            }
            Repeater {
                model: root.broker.grants
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
                        text: "Revoke"
                        onClicked: root.broker.revoke(modelData.id)
                    }
                }
            }

            Label {
                Layout.leftMargin: 12
                text: "Always granted"
                font.bold: true
                visible: root.broker.always.length > 0
            }
            Repeater {
                model: root.broker.always
                delegate: RowLayout {
                    required property var modelData
                    Layout.fillWidth: true
                    Layout.leftMargin: 12
                    Layout.rightMargin: 12
                    Label {
                        Layout.fillWidth: true
                        text: modelData.capability + " " + modelData.paramsJson
                        textFormat: Text.PlainText
                        wrapMode: Text.Wrap
                    }
                    Button {
                        text: "Forget"
                        onClicked: root.broker.forget(modelData.capability, modelData.paramsJson)
                    }
                }
            }

            Label {
                Layout.leftMargin: 12
                text: "Recent decisions"
                font.bold: true
                visible: root.broker.log.length > 0
            }
            Repeater {
                model: root.broker.log
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
