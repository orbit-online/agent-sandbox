import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// A live grant: one line (what's granted, its badges, the time it has left, Revoke) that expands to its parameters,
// who may use it, Claude's reason, and for a host command capability what it covers and the calls made under it
ColumnLayout {
    id: grant
    required property var modelData
    required property var view
    readonly property string gid: modelData.id
    readonly property bool isCommand: (view.caps[modelData.capability] || {}).type === "command"
    readonly property bool expanded: view.isOpen("grant:" + gid, false)
    Layout.fillWidth: true
    spacing: 2

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
            // A host command capability's summary completes "Claude wants to": a sentence of its own here
            text: grant.isCommand ? grant.modelData.summary.charAt(0).toUpperCase() + grant.modelData.summary.slice(1)
                                  : grant.modelData.summary
        }
        Badges {
            model: grant.view.grantBadges(grant.modelData)
        }
        Label {
            objectName: "left-" + grant.gid
            visible: text !== ""
            text: grant.view.timeLeft(grant.modelData.expires)
            opacity: 0.7
        }
        Button {
            objectName: "revoke"
            text: "Revoke"
            onClicked: grant.view.send({ op: "revoke", grant: grant.gid })
        }
    }
    ColumnLayout {
        objectName: "details-" + grant.gid
        Layout.fillWidth: true
        Layout.leftMargin: 32
        visible: grant.expanded
        spacing: 6
        ReadOnlyText {
            objectName: "params-" + grant.gid
            Layout.fillWidth: true
            visible: text !== ""
            text: grant.view.grantParams(grant.modelData)
        }
        ReadOnlyText {
            objectName: "holders-" + grant.gid
            Layout.fillWidth: true
            text: grant.view.holdersText(grant.modelData)
        }
        ReadOnlyText {
            objectName: "reason-" + grant.gid
            Layout.fillWidth: true
            text: grant.modelData.lease === "standing" ? "From the configuration, without asking"
                  : grant.modelData.reason ? "Claude's reason, in its own words: " + JSON.stringify(grant.modelData.reason)
                  : "No reason recorded"
        }
        CommandScope {
            visible: grant.isCommand
            view: grant.view
            key: grant.gid
            capability: grant.modelData.capability
        }
        ReadOnlyText {
            objectName: "calls-" + grant.gid
            Layout.fillWidth: true
            visible: grant.isCommand
            text: grant.view.callsText(grant.view.calls.filter(c => c.grant === grant.gid), "No calls yet")
        }
    }
}
