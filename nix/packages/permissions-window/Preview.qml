import QtQuick
import QtQuick.Controls

// The Permissions window against a mock broker, for working on its looks: the state from a JSON file, actions applied
// to it (an answer takes the request away, a revoke the grant) and printed. preview.sh runs it with qml; with
// --screenshot it saves the window's content to a PNG and quits
ApplicationWindow {
    id: win
    width: Number(arg("--width", "640"))
    height: Number(arg("--height", "720"))
    visible: true
    title: "Claude permissions"

    function arg(name, fallback) {
        const args = Qt.application.arguments
        const i = args.indexOf(name)
        return i >= 0 && i + 1 < args.length ? args[i + 1] : fallback
    }

    QtObject {
        id: mock
        property string state: ""
        property string error: ""
        property string command: ""
        onCommandChanged: {
            if (command === "")
                return
            console.log("command:", command)
            const c = JSON.parse(command)
            const st = JSON.parse(state)
            if (c.op === "answer")
                st.pending = st.pending.filter(p => p.id !== c.pending)
            if (c.op === "revoke")
                st.grants = st.grants.filter(g => g.id !== c.grant)
            state = JSON.stringify(st)
        }
        Component.onCompleted: {
            const xhr = new XMLHttpRequest()
            xhr.open("GET", Qt.resolvedUrl("file://" + win.arg("--state", "")), false)
            xhr.send()
            // A lease that hasn't run out: 42 minutes left, whenever the preview runs
            const st = JSON.parse(xhr.responseText)
            for (const g of st.grants || [])
                if (g.expires)
                    g.expires = new Date(Date.now() + 42 * 60000).toISOString()
            state = JSON.stringify(st)
        }
    }

    Rectangle {
        id: content
        anchors.fill: parent
        color: win.palette.window
        Permissions {
            id: view
            anchors.fill: parent
            broker: mock
            // Allow and Deny enabled right away in a screenshot
            settleMs: 0
            // Expanded at the start, by key: grant:<id>, details:<id>
            expanded: {
                const e = {}
                for (const k of win.arg("--expand", "").split(",").filter(k => k))
                    e[k] = true
                return e
            }
        }
    }

    // The tab asked for, once the requests arrived: they bring theirs to the front
    Timer {
        interval: 100
        running: win.arg("--page", "") !== ""
        onTriggered: view.page = win.arg("--page", "")
    }

    Timer {
        interval: 500
        running: win.arg("--screenshot", "") !== ""
        onTriggered: content.grabToImage(r => {
            r.saveToFile(win.arg("--screenshot", ""))
            Qt.quit()
        })
    }
}
