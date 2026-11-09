import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// A request or a grant: a box in the base colour with its content in a column
Pane {
    id: card
    default property alias content: column.data
    Layout.fillWidth: true
    padding: 12
    contentHeight: column.implicitHeight
    background: Rectangle {
        color: card.palette.base
        border.color: card.palette.mid
        radius: 6
    }

    ColumnLayout {
        id: column
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: 8
    }
}
