import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// A part of a page: a heading, with how many or what's there dim after it, and its content below
ColumnLayout {
    id: section
    required property string key
    required property string title
    property string info: ""
    default property alias content: body.data

    Layout.fillWidth: true
    spacing: 8

    RowLayout {
        objectName: "section-" + section.key
        Layout.fillWidth: true
        Label {
            text: section.title
            font.bold: true
            renderType: Text.NativeRendering
        }
        Label {
            Layout.fillWidth: true
            text: section.info
            opacity: 0.7
            elide: Text.ElideRight
            renderType: Text.NativeRendering
        }
    }
    ColumnLayout {
        id: body
        objectName: "body-" + section.key
        Layout.fillWidth: true
        spacing: 8
    }
}
