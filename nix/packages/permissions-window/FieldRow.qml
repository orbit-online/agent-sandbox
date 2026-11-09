import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// A name and its value on a line of their own: the name dim on the left, the value in a box of its own, so where a
// value the sandbox chose starts and ends is plain. Without value, the row holds what's put in it (a field to edit)
RowLayout {
    id: row
    required property string name
    property string value: ""
    // The value's objectName, for the tests
    property string valueName: ""
    // What the name means, from the declaration, on hover
    property string description: ""
    property bool mono: true
    default property alias editor: slot.data
    Layout.fillWidth: true
    spacing: 10

    Label {
        Layout.preferredWidth: 96
        Layout.alignment: Qt.AlignTop
        Layout.topMargin: 3
        horizontalAlignment: Text.AlignRight
        text: row.name
        opacity: 0.7
        elide: Text.ElideRight
        renderType: Text.NativeRendering
        ToolTip.visible: row.description !== "" && hover.hovered
        ToolTip.text: row.description
        HoverHandler {
            id: hover
        }
    }
    Rectangle {
        Layout.fillWidth: true
        visible: slot.children.length === 0
        implicitHeight: valueText.implicitHeight + 6
        color: row.palette.alternateBase
        border.color: row.palette.midlight
        radius: 3
        ReadOnlyText {
            id: valueText
            objectName: row.valueName
            anchors.fill: parent
            anchors.margins: 3
            anchors.leftMargin: 6
            text: row.value
            font.family: row.mono ? "monospace" : Qt.application.font.family
        }
    }
    RowLayout {
        id: slot
        Layout.fillWidth: true
        visible: children.length > 0
    }
}
