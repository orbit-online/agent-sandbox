import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// Host command calls, newest first: a line each (when, which command, how it ended) and its arguments a row each.
// text is the whole list as plain text, for copying and the tests
ColumnLayout {
    id: list
    required property var view
    required property var calls
    property string none: ""
    readonly property string text: view.callsText(calls, none)
    Layout.fillWidth: true
    spacing: 10

    Label {
        visible: list.calls.length === 0 && list.none !== ""
        text: list.none
        opacity: 0.7
        renderType: Text.NativeRendering
    }
    Repeater {
        model: list.calls
        delegate: ColumnLayout {
            id: call
            required property var modelData
            required property int index
            readonly property bool failed: !!(modelData.error || modelData.exit)
            Layout.fillWidth: true
            spacing: 4
            RowLayout {
                Layout.fillWidth: true
                spacing: 8
                ReadOnlyText {
                    objectName: "call-head-" + call.index
                    Layout.fillWidth: false
                    text: Qt.formatDateTime(new Date(call.modelData.time), "yyyy-MM-dd HH:mm:ss")
                    font.family: "monospace"
                    opacity: 0.7
                }
                ReadOnlyText {
                    Layout.fillWidth: false
                    text: call.modelData.capability + " " + call.modelData.command
                    font.bold: true
                }
                Badge {
                    text: call.failed ? "exit " + call.modelData.exit : "ok"
                    warning: call.failed
                }
                ReadOnlyText {
                    Layout.fillWidth: true
                    visible: text !== ""
                    text: list.view.shown(call.modelData.error || "")
                    opacity: 0.8
                }
            }
            Repeater {
                model: Object.keys(call.modelData.arguments || {}).sort()
                delegate: FieldRow {
                    required property string modelData
                    name: modelData
                    value: list.view.shown(call.modelData.arguments[modelData])
                }
            }
        }
    }
}
