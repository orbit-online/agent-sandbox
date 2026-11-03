import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// A section of the window: a header line that collapses it, and its content below while expanded. Whether it's
// expanded is the user's, kept by the window under its key
ColumnLayout {
    id: section
    required property string key
    required property string title
    // After the title on its line: how many, or what's there
    property string info: ""
    property bool expanded: true
    signal toggled
    default property alias content: body.data

    Layout.fillWidth: true
    Layout.leftMargin: 12
    Layout.rightMargin: 12
    spacing: 4

    RowLayout {
        Layout.fillWidth: true
        ToolButton {
            objectName: "section-" + section.key
            text: section.expanded ? "▾" : "▸"
            onClicked: section.toggled()
        }
        Label {
            text: section.title
            font.bold: true
        }
        Label {
            Layout.fillWidth: true
            text: section.info
            opacity: 0.7
            elide: Text.ElideRight
        }
    }
    ColumnLayout {
        id: body
        objectName: "body-" + section.key
        Layout.fillWidth: true
        Layout.leftMargin: 12
        visible: section.expanded
        spacing: 8
    }
}
