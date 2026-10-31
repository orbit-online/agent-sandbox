import QtQuick
import QtQuick.Controls

// brokerMap and windowTitle are context properties from main.go: miqt can't hand a QObject over as a property value
ApplicationWindow {
    width: 640
    height: 720
    visible: true
    title: windowTitle

    Permissions {
        anchors.fill: parent
        broker: brokerMap
    }
}
