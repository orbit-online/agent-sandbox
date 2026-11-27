import QtQuick
import QtQuick.Layouts

// A card's badges, from the window's badges(): each a name (its objectName), a text and whether it warns. They wrap,
// however many: on a line beside other items they squeezed those or pushed the card past the window
Flow {
    id: badges
    required property var model
    Layout.fillWidth: true
    // As wide as the card gives, never wider
    Layout.preferredWidth: 0
    visible: model.length > 0
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
