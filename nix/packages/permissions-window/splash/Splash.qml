import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// splash, windowTitle, logo, logoDark, agentLogo and titleFont are context properties from main.go. While the sandbox starts: the
// title, the main logo, the step and its progress, the agent's logo small at the right over the bar. When the start fails: why,
// the launcher's warnings and the app's last output, until the user closes it. Light or dark as the desktop is
ApplicationWindow {
    id: root
    readonly property bool failed: splash.error !== ""
    // The button offers Abort after 10 s; clicked, the step says so at once while the launcher tears the start down
    property bool canAbort: false
    property bool aborting: false
    readonly property color bgColor: splash.dark ? "#1f1f22" : "#fafafa"
    readonly property color fgColor: splash.dark ? "#ececee" : "#1d1d1f"
    readonly property color mutedColor: splash.dark ? "#a1a1a6" : "#6e6e73"
    // The launcher asks for the window at the front when the app is launched again while this shows
    property int activations: splash.activations
    onActivationsChanged: root.requestActivate()
    Timer {
        interval: 10000
        running: !root.failed
        onTriggered: root.canAbort = true
    }
    // The title's font, from the package (--title-font), not whatever the host has
    FontLoader {
        id: titleFontLoader
        source: titleFont
    }
    // Brand logos want clear space of half their symbol's height around them: about 29 px at 64
    readonly property int clear: 32

    width: failed ? 640 : 460
    height: failed ? 600 : 380
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
        anchors.margins: root.clear
        spacing: 18

        Label {
            objectName: "title"
            text: "Agent Sandbox"
            color: root.fgColor
            font.family: titleFontLoader.status === FontLoader.Ready ? titleFontLoader.font.family : root.font.family
            font.pixelSize: 30
            font.weight: Font.DemiBold
            Layout.alignment: Qt.AlignHCenter
        }
        Image {
            objectName: "logo"
            visible: logo !== ""
            source: splash.dark ? logoDark : logo
            Layout.topMargin: root.clear - parent.spacing
            Layout.bottomMargin: root.clear - parent.spacing
            Layout.alignment: Qt.AlignHCenter
            Layout.preferredHeight: 64
            Layout.preferredWidth: implicitHeight > 0 ? 64 * implicitWidth / implicitHeight : 0
            fillMode: Image.PreserveAspectFit
            sourceSize.height: 128
        }

        // The step, centred, and the agent's logo small at the right, over the progress bar or beside the error
        Item {
            Layout.fillWidth: true
            Layout.preferredHeight: root.failed ? Math.max(24, errorLabel.implicitHeight) : 24

            Label {
                objectName: "step"
                visible: !root.failed
                text: root.aborting ? "Aborting startup" : splash.text
                color: root.mutedColor
                anchors.centerIn: parent
            }
            Label {
                id: errorLabel
                objectName: "error"
                visible: root.failed
                text: splash.error
                color: root.fgColor
                font.bold: true
                wrapMode: Text.Wrap
                anchors.left: parent.left
                anchors.right: agentIcon.left
                anchors.rightMargin: 12
                anchors.verticalCenter: parent.verticalCenter
            }
            Image {
                id: agentIcon
                objectName: "agentLogo"
                visible: agentLogo !== ""
                source: agentLogo
                width: 24
                height: 24
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                fillMode: Image.PreserveAspectFit
                sourceSize.height: 48
            }
        }
        ProgressBar {
            objectName: "progress"
            visible: !root.failed
            Layout.fillWidth: true
            indeterminate: splash.progress < 0
            value: Math.max(splash.progress, 0)
        }
        // The launcher's warnings, from the host side's helpers, apart from the app's output: the sandbox wrote that, so
        // nothing in it may pass for the launcher's
        Label {
            visible: root.failed && splash.host !== ""
            text: "From the launcher"
            color: root.mutedColor
            Layout.bottomMargin: -12
        }
        ScrollView {
            visible: root.failed && splash.host !== ""
            Layout.fillWidth: true
            Layout.preferredHeight: Math.min(hostLog.implicitHeight, 110)

            TextArea {
                id: hostLog
                objectName: "host"
                text: splash.host
                readOnly: true
                selectByMouse: true
                wrapMode: Text.WrapAnywhere
                font.family: "monospace"
                color: root.fgColor
                background: Rectangle { color: splash.dark ? "#2a2a2e" : "#ffffff" }
            }
        }
        Label {
            visible: root.failed && splash.log !== ""
            text: "The app's output"
            color: root.mutedColor
            Layout.bottomMargin: -12
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
        // Abort while the sandbox starts, its place kept from the start so the window doesn't grow when it shows; Close
        // once the start failed
        Button {
            objectName: "action"
            opacity: root.failed || root.canAbort ? 1 : 0
            enabled: root.failed || (root.canAbort && !root.aborting)
            text: root.failed ? "Close" : "Abort"
            Layout.alignment: Qt.AlignRight
            onClicked: {
                if (root.failed) {
                    root.close()
                    return
                }
                root.aborting = true
                splash.command = "abort"
            }
        }
    }
}
