import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// What a grant of a host command capability covers, as the consent says it: a heading, then a line per phrase the
// declaration gives its commands (commands sharing one share the line), with a warning badge where one of them takes
// any text and their names dim after it. Below, collapsed, Details: every command and free argument with what its
// schema lets through
ColumnLayout {
    id: scope
    required property var view
    // The request's or grant's id: the objectNames' suffix, and the key of Details' expanded state
    required property string key
    required property string capability
    property string heading: "Covers"
    readonly property var cap: view.caps[capability] || {}
    readonly property bool detailsOpen: view.isOpen("details:" + key, false)
    Layout.fillWidth: true
    spacing: 4

    Label {
        objectName: "covers-" + scope.key
        text: scope.heading
        opacity: 0.7
        renderType: Text.NativeRendering
    }
    Repeater {
        model: scope.cap.consent || []
        delegate: RowLayout {
            id: line
            required property var modelData
            required property int index
            Layout.fillWidth: true
            Layout.leftMargin: 8
            spacing: 6
            Label {
                text: "•"
                renderType: Text.NativeRendering
            }
            ReadOnlyText {
                objectName: "consent-" + scope.key + "-" + line.index
                Layout.fillWidth: false
                text: line.modelData.consent
            }
            Badge {
                objectName: "consent-unrestricted-" + scope.key + "-" + line.index
                visible: line.modelData.unrestricted === true
                warning: true
                text: "unrestricted"
            }
            Label {
                objectName: "consent-commands-" + scope.key + "-" + line.index
                Layout.fillWidth: true
                text: line.modelData.commands.join(", ")
                font.family: "monospace"
                opacity: 0.6
                elide: Text.ElideRight
                renderType: Text.NativeRendering
            }
        }
    }
    ToolButton {
        objectName: "details-toggle-" + scope.key
        Layout.leftMargin: 2
        text: (scope.detailsOpen ? "▾" : "▸") + " Details"
        onClicked: scope.view.toggle("details:" + scope.key, false)
    }
    ReadOnlyText {
        objectName: "scope-" + scope.key
        Layout.fillWidth: true
        Layout.leftMargin: 20
        visible: scope.detailsOpen
        text: scope.view.scopeText(scope.capability)
    }
}
