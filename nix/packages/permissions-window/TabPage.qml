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

    // Our own, shown while the page overflows: Plasma's style drew a white handle on a near-white track, Fusion's only
    // shows while scrolling
    ScrollBar.vertical: ScrollBar {
        id: bar
        parent: page
        x: page.mirrored ? 0 : page.width - width
        y: page.topPadding
        height: page.availableHeight
        policy: size < 1 ? ScrollBar.AlwaysOn : ScrollBar.AlwaysOff
        padding: 2
        contentItem: Rectangle {
            implicitWidth: 8
            implicitHeight: 32
            radius: width / 2
            color: bar.pressed ? bar.palette.windowText : bar.palette.mid
            opacity: bar.pressed || bar.hovered ? 0.8 : 0.6
        }
        background: Item {}
    }

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
