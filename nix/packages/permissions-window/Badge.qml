import QtQuick
import QtQuick.Controls

// A short tag on a row: its lease, from config, free arguments, who holds it. A warning stands out
Label {
    id: badge
    property bool warning: false
    leftPadding: 6
    rightPadding: 6
    topPadding: 1
    bottomPadding: 1
    color: warning ? "white" : palette.windowText
    font.bold: warning
    background: Rectangle {
        radius: 3
        color: badge.warning ? "firebrick" : "transparent"
        border.color: badge.warning ? "firebrick" : badge.palette.mid
    }
}
