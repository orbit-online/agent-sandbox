import QtQuick
import QtQuick.Controls

// Text the user can select and copy and never edit: the broker's words and Claude's, as plain text
TextArea {
    readOnly: true
    selectByMouse: true
    textFormat: Text.PlainText
    wrapMode: Text.Wrap
    background: null
    padding: 0
}
