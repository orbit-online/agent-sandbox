import QtQuick
import QtQuick.Controls

// Text the user can select and copy and never edit: the broker's words and Claude's, as plain text. Native rendering:
// Qt Quick's default, distance fields, smears small text, bold most, at fractional scales
TextArea {
    readOnly: true
    selectByMouse: true
    textFormat: Text.PlainText
    wrapMode: Text.Wrap
    renderType: Text.NativeRendering
    background: null
    padding: 0
}
