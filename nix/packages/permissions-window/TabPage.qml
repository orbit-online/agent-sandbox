import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// A tab's content, scrolling on its own, with what's put in it in a column within the window's margins
ScrollView {
    id: page
    default property alias content: column.data
    contentWidth: availableWidth
    contentHeight: column.implicitHeight + 14
    clip: true

    ColumnLayout {
        id: column
        x: 14
        width: page.availableWidth - 28
        spacing: 14
        Item {
            implicitHeight: 0
        }
    }
}
