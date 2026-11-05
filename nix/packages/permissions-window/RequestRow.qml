import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// A request waiting for the user's answer: what it asks for, what that covers (for a host command capability, a line
// per consent phrase, then Details), the call asking and Claude's reason,
// fields that narrow it, its lease, Allow and Deny. A host command grant has only its lease to change: its bounding
// values are what the call needs, and the broker refuses others
Frame {
    id: request
    required property var modelData
    required property var view
    readonly property var cap: view.caps[modelData.capability] || {}
    readonly property bool isCommand: cap.type === "command"
    // The request's parameters, as the fields below narrow them, and its lease, kept across refreshes
    readonly property var edits: view.editsOf(modelData)
    readonly property var paramTypes: isCommand ? ({}) : view.types[modelData.capability] || {}
    Layout.fillWidth: true

    ColumnLayout {
        anchors.fill: parent
        ReadOnlyText {
            objectName: "summary-" + request.modelData.id
            Layout.fillWidth: true
            // A host command capability's summary completes the sentence, as in the notification
            text: (request.isCommand ? "Claude wants to " : "") + request.modelData.summary
            font.bold: true
        }
        Badges {
            model: request.view.freeBadges(request.modelData.capability, request.modelData.id)
            visible: model.length > 0
        }
        CommandScope {
            visible: request.isCommand
            view: request.view
            key: request.modelData.id
            capability: request.modelData.capability
            heading: request.view.coversHeading(request.modelData.capability, request.modelData.params,
                                                lease.currentValue || request.modelData.lease)
            boundsText: request.view.paramLines(request.modelData.capability, request.modelData.params)
        }
        ReadOnlyText {
            objectName: "call-" + request.modelData.id
            Layout.fillWidth: true
            visible: (request.modelData.command || "") !== ""
            text: "The call asking: " + request.modelData.command
                  + request.view.argumentLines(request.modelData.arguments)
        }
        ReadOnlyText {
            objectName: "reason-" + request.modelData.id
            Layout.fillWidth: true
            text: "Claude's reason, in its own words: " + JSON.stringify(request.modelData.reason)
        }
        Repeater {
            model: Object.keys(request.paramTypes)
            delegate: RowLayout {
                id: param
                required property string modelData
                readonly property string kind: request.paramTypes[modelData]
                Label { text: param.modelData }
                Label {
                    objectName: "opaque-" + param.modelData
                    visible: param.kind === "opaque"
                    readonly property var value: request.edits.params[param.modelData]
                    text: value === undefined ? "not given"
                                              : "opaque, " + String(value).length + " characters, as in the summary"
                    font.italic: true
                }
                CheckBox {
                    objectName: "param-" + param.modelData
                    visible: param.kind === "boolean"
                    checked: request.edits.params[param.modelData] === true
                    onToggled: request.edits.params[param.modelData] = checked
                }
                TextField {
                    objectName: "field-" + param.modelData
                    visible: param.kind !== "boolean" && param.kind !== "opaque"
                    Layout.fillWidth: true
                    text: request.edits.params[param.modelData] !== undefined
                          ? String(request.edits.params[param.modelData]) : ""
                    onEditingFinished: {
                        if (text === "")
                            delete request.edits.params[param.modelData]
                        else
                            request.edits.params[param.modelData] = param.kind === "string" ? text : Number(text)
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
                model: request.view.leasesFor(request.modelData)
                Component.onCompleted: currentIndex = Math.max(0, indexOfValue(request.edits.lease))
                onActivated: request.edits.lease = currentValue
            }
            Item { Layout.fillWidth: true }
            Button {
                objectName: "deny"
                text: "Deny"
                enabled: !request.view.settling
                onClicked: request.view.send({ op: "answer", pending: request.modelData.id, allow: false })
            }
            Button {
                objectName: "allow"
                text: "Allow"
                highlighted: true
                enabled: !request.view.settling
                onClicked: {
                    const answer = { op: "answer", pending: request.modelData.id, allow: true,
                                     lease: lease.currentValue }
                    if (!request.isCommand)
                        answer.params = request.edits.params
                    request.view.send(answer)
                }
            }
        }
    }
}
