import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// A request waiting for the user's answer, as a card: what Claude asks for as a heading, then its values one a row
// (fields that narrow it, or for a host command capability its bounding values, never editable: the broker refuses
// others), what a grant covers (a line per consent phrase, then Details), the call asking, Claude's reason, and the
// lease, Deny and Allow at the bottom
Card {
    id: request
    required property var modelData
    required property var view
    readonly property var cap: view.caps[modelData.capability] || {}
    readonly property bool isCommand: cap.type === "command"
    // The request's parameters, as the fields below narrow them, and its lease, kept across refreshes
    readonly property var edits: view.editsOf(modelData)
    readonly property var paramTypes: isCommand ? ({}) : view.types[modelData.capability] || {}
    readonly property var resolved: view.resolvedTarget(modelData.summary)

    RowLayout {
        Layout.fillWidth: true
        ReadOnlyText {
            objectName: "summary-" + request.modelData.id
            Layout.fillWidth: true
            text: request.view.headline(request.modelData)
            font.bold: true
            font.pointSize: request.font.pointSize * 1.1
        }
        Badges {
            Layout.alignment: Qt.AlignTop
            model: request.view.freeBadges(request.modelData.capability, request.modelData.id)
            visible: model.length > 0
        }
    }

    // A host command's bounding values
    Repeater {
        model: request.isCommand ? Object.keys(request.modelData.params || {}).sort() : []
        delegate: FieldRow {
            required property string modelData
            name: modelData
            valueName: "bound-" + request.modelData.id + "-" + modelData
            description: request.view.paramDescription(request.modelData.capability, modelData)
            value: request.view.shown(request.modelData.params[modelData])
        }
    }

    // Fields that narrow the request
    Repeater {
        model: Object.keys(request.paramTypes).sort()
        delegate: FieldRow {
            id: param
            required property string modelData
            readonly property string kind: request.paramTypes[modelData]
            name: modelData
            description: request.view.paramDescription(request.modelData.capability, modelData)
            Label {
                objectName: "opaque-" + param.modelData
                visible: param.kind === "opaque"
                readonly property var value: request.edits.params[param.modelData]
                text: value === undefined ? "not given"
                                          : "opaque, " + String(value).length + " characters, as in the summary"
                font.italic: true
                renderType: Text.NativeRendering
            }
            CheckBox {
                objectName: "param-" + param.modelData
                visible: param.kind === "boolean"
                checked: request.edits.params[param.modelData] === true
                onToggled: request.edits.params[param.modelData] = checked
                padding: 0
            }
            TextField {
                objectName: "field-" + param.modelData
                visible: param.kind !== "boolean" && param.kind !== "opaque"
                Layout.fillWidth: true
                font.family: "monospace"
                renderType: Text.NativeRendering
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
    // What the broker found the request's folder to be, links followed, as it asked: a narrowed field asks anew
    FieldRow {
        visible: request.resolved !== null
        name: "resolves to"
        valueName: "resolved-" + request.modelData.id
        value: request.resolved ? request.resolved.path + "\n" + request.resolved.access : ""
    }

    CommandScope {
        visible: request.isCommand
        view: request.view
        key: request.modelData.id
        capability: request.modelData.capability
        heading: request.view.coversHeading(lease.currentValue || request.modelData.lease)
    }

    // The call asking
    ColumnLayout {
        Layout.fillWidth: true
        visible: (request.modelData.command || "") !== ""
        spacing: 4
        Label {
            text: "The call asking"
            opacity: 0.7
            renderType: Text.NativeRendering
        }
        FieldRow {
            name: "command"
            valueName: "call-" + request.modelData.id
            value: request.modelData.command || ""
        }
        Repeater {
            model: Object.keys(request.modelData.arguments || {}).sort()
            delegate: FieldRow {
                required property string modelData
                name: modelData
                valueName: "argument-" + request.modelData.id + "-" + modelData
                value: request.view.shown(request.modelData.arguments[modelData])
            }
        }
    }

    Quote {
        agent: request.view.agent
        textName: "reason-" + request.modelData.id
        text: request.view.shown(request.modelData.reason)
    }

    RowLayout {
        Layout.fillWidth: true
        Layout.topMargin: 4
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
