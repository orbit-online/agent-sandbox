import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// Claude's words, set apart: a caption, then the text beside a bar, so it never reads as the window's own
ColumnLayout {
    id: quote
    property string caption: "Claude's reason, in its own words"
    property string text: ""
    property string textName: ""
    Layout.fillWidth: true
    spacing: 4

    Label {
        text: quote.caption
        opacity: 0.7
        renderType: Text.NativeRendering
    }
    RowLayout {
        Layout.fillWidth: true
        spacing: 8
        Rectangle {
            Layout.fillHeight: true
            implicitWidth: 3
            color: quote.palette.highlight
            radius: 1
        }
        ReadOnlyText {
            objectName: quote.textName
            Layout.fillWidth: true
            text: quote.text
            font.italic: true
        }
    }
}
