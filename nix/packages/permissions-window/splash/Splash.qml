import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// splash, windowTitle, logo, logoDark and agentLogo are context properties from main.go. While the sandbox starts: the
// main logo with the agent's beside it, a bit smaller, the step and its progress. When the start fails: why, and the
// app's last output, until the user closes it. Light or dark as the desktop is
ApplicationWindow {
    id: root
    readonly property bool failed: splash.error !== ""
    readonly property color bgColor: splash.dark ? "#1f1f22" : "#fafafa"
    readonly property color fgColor: splash.dark ? "#ececee" : "#1d1d1f"
    readonly property color mutedColor: splash.dark ? "#a1a1a6" : "#6e6e73"

    width: failed ? 640 : 460
    height: failed ? 480 : 260
    visible: true
    title: windowTitle
    color: bgColor
    // The controls (the progress bar, the log, the button) follow the splash, which follows the desktop
    palette.window: bgColor
    palette.windowText: fgColor
    palette.base: splash.dark ? "#2a2a2e" : "#ffffff"
    palette.text: fgColor
    palette.button: splash.dark ? "#3a3a3e" : "#f0f0f0"
    palette.buttonText: fgColor
    palette.mid: splash.dark ? "#4a4a4f" : "#c8c8cc"
    flags: failed ? Qt.Window : (Qt.SplashScreen | Qt.FramelessWindowHint)

    ColumnLayout {
        anchors.fill: parent
        // Brand logos want clear space of half their symbol's height around them: about 29 px at 64
        anchors.margins: 32
        spacing: 18

        RowLayout {
            objectName: "logos"
            Layout.alignment: Qt.AlignHCenter
            spacing: 32

            Image {
                objectName: "logo"
                visible: logo !== ""
                source: splash.dark ? logoDark : logo
                Layout.preferredHeight: 64
                Layout.preferredWidth: implicitHeight > 0 ? 64 * implicitWidth / implicitHeight : 0
                fillMode: Image.PreserveAspectFit
                sourceSize.height: 128
            }
            Image {
                objectName: "agentLogo"
                visible: agentLogo !== ""
                source: agentLogo
                Layout.preferredHeight: 44
                Layout.preferredWidth: implicitHeight > 0 ? 44 * implicitWidth / implicitHeight : 0
                Layout.alignment: Qt.AlignVCenter
                fillMode: Image.PreserveAspectFit
                sourceSize.height: 88
            }
        }

        Label {
            objectName: "step"
            visible: !root.failed
            text: splash.text
            color: root.mutedColor
            Layout.alignment: Qt.AlignHCenter
        }
        ProgressBar {
            objectName: "progress"
            visible: !root.failed
            Layout.fillWidth: true
            indeterminate: splash.progress < 0
            value: Math.max(splash.progress, 0)
        }

        Label {
            objectName: "error"
            visible: root.failed
            text: splash.error
            color: root.fgColor
            font.bold: true
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
        ScrollView {
            visible: root.failed && splash.log !== ""
            Layout.fillWidth: true
            Layout.fillHeight: true

            TextArea {
                objectName: "log"
                text: splash.log
                readOnly: true
                selectByMouse: true
                wrapMode: Text.WrapAnywhere
                font.family: "monospace"
                color: root.fgColor
                background: Rectangle { color: splash.dark ? "#2a2a2e" : "#ffffff" }
            }
        }
        Button {
            objectName: "close"
            visible: root.failed
            text: "Close"
            Layout.alignment: Qt.AlignRight
            onClicked: root.close()
        }
    }
}
