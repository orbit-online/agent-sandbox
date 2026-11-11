import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// A live grant, as a card: one line (what's granted, its badges, the time it has left, Revoke) that expands to its
// parameters, who may use it, Claude's reason, and for a host command capability what it covers and the calls made
// under it
Card {
    id: grant
    required property var modelData
    required property var view
    readonly property string gid: modelData.id
    readonly property bool isCommand: (view.caps[modelData.capability] || {}).type === "command"
    readonly property bool expanded: view.isOpen("grant:" + gid, false)
    padding: 8

    RowLayout {
        Layout.fillWidth: true
        ToolButton {
            objectName: "toggle-" + grant.gid
            text: grant.expanded ? "▾" : "▸"
            onClicked: grant.view.toggle("grant:" + grant.gid, false)
        }
        ReadOnlyText {
            objectName: "grant-" + grant.gid
            Layout.fillWidth: true
            Layout.minimumWidth: 120
            text: grant.view.grantTitle(grant.modelData)
            font.bold: true
        }
        Label {
            objectName: "left-" + grant.gid
            visible: text !== ""
            text: grant.view.timeLeft(grant.modelData.expires)
            opacity: 0.7
            renderType: Text.NativeRendering
        }
        Button {
            objectName: "revoke"
            text: "Revoke"
            onClicked: grant.view.send({ op: "revoke", grant: grant.gid })
        }
    }
    Badges {
        Layout.leftMargin: 40
        model: grant.view.grantBadges(grant.modelData)
    }
    ColumnLayout {
        objectName: "details-" + grant.gid
        Layout.fillWidth: true
        Layout.leftMargin: 6
        Layout.rightMargin: 6
        Layout.bottomMargin: 6
        visible: grant.expanded
        spacing: 8
        Repeater {
            model: grant.view.grantFields(grant.modelData)
            delegate: FieldRow {
                required property var modelData
                name: modelData.name
                valueName: "param-" + grant.gid + "-" + modelData.key
                description: modelData.description || ""
                value: modelData.value
            }
        }
        ReadOnlyText {
            objectName: "holders-" + grant.gid
            Layout.fillWidth: true
            text: grant.view.holdersText(grant.modelData)
            opacity: 0.8
        }
        Quote {
            agent: grant.view.agent
            visible: grant.modelData.lease !== "standing"
            textName: "reason-" + grant.gid
            text: grant.modelData.reason ? grant.view.shown(grant.modelData.reason) : "No reason recorded"
        }
        CommandScope {
            visible: grant.isCommand
            view: grant.view
            key: grant.gid
            capability: grant.modelData.capability
        }
        Label {
            visible: grant.isCommand
            text: "Calls"
            opacity: 0.7
            renderType: Text.NativeRendering
        }
        CallList {
            objectName: "calls-" + grant.gid
            visible: grant.isCommand
            view: grant.view
            calls: grant.view.calls.filter(c => c.grant === grant.gid)
            none: "No calls yet"
        }
    }
}
