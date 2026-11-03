import QtQuick
import QtQuick.Layouts

// A row's badges, from the window's badges(): each a name (its objectName), a text and whether it warns
RowLayout {
    id: badges
    required property var model
    spacing: 4
    Repeater {
        model: badges.model
        delegate: Badge {
            required property var modelData
            objectName: modelData.name
            text: modelData.text
            warning: modelData.warning === true
        }
    }
}
