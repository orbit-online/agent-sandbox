"""The Permissions window: what a launcher's permissions broker has granted and is asked for.

Usage: permissions-window CONTROL_SOCKET [TITLE]

A client of the broker's control.sock (docs/permissions.md): shows pending requests to answer, live grants to
revoke, always grants to forget and the recent decisions, and refreshes on the broker's watch events. Without a
running broker it says so.
"""

import json
import os
import socket
import sys

from PySide6.QtCore import Property, QObject, QUrl, Signal, Slot
from PySide6.QtGui import QGuiApplication
from PySide6.QtNetwork import QLocalSocket
from PySide6.QtQml import QQmlApplicationEngine

# How long a call may take: state runs the plugins' list commands
CALL_TIMEOUT = 15


def call(path, request):
    """Sends one request to control.sock and returns the answer, raising its error."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(CALL_TIMEOUT)
        s.connect(path)
        s.sendall(json.dumps(request).encode() + b"\n")
        data = b""
        while chunk := s.recv(65536):
            data += chunk
    answer = json.loads(data)
    if answer.get("error"):
        raise RuntimeError(answer["error"])
    return answer


class Broker(QObject):
    changed = Signal()

    def __init__(self, path):
        super().__init__()
        self._path = path
        self._state = {}
        self._error = ""
        # What still held files on the grant revoked last, which the user may end
        self._holders = []
        self._watch = QLocalSocket(self)
        # Bound methods, not lambdas: Qt disconnects those when the Broker goes
        self._watch.readyRead.connect(self._event)
        self._watch.connected.connect(self._subscribe)
        self._watch.disconnected.connect(self._stopped)
        self.refresh()
        self._watch.connectToServer(path)

    def _subscribe(self):
        self._watch.write(b'{"op": "watch"}\n')

    def _stopped(self):
        self._set_error("The permissions broker stopped")

    def _event(self):
        self._watch.readAll()
        self.refresh()

    def _set_error(self, error):
        self._error = error
        self.changed.emit()

    def _call(self, request):
        try:
            answer = call(self._path, request)
        except (OSError, ValueError, RuntimeError) as e:
            if isinstance(e, (FileNotFoundError, ConnectionRefusedError)):
                e = "The permissions broker isn't running: start the sandbox first"
            self._set_error(str(e))
            return None
        self._error = ""
        return answer

    @Slot()
    def refresh(self):
        state = self._call({"op": "state"})
        if state is not None:
            self._state = state
        self.changed.emit()

    @Slot(str, bool, str, str)
    def answer(self, pending, allow, lease, params):
        request = {"op": "answer", "pending": pending, "allow": allow, "lease": lease}
        if params:
            request["params"] = json.loads(params)
        self._call(request)
        self.refresh()

    @Slot(str)
    def revoke(self, grant):
        answer = self._call({"op": "revoke", "grant": grant})
        self._holders = (answer or {}).get("holders") or []
        self.refresh()

    @Slot()
    def endHolders(self):
        self._call({"op": "end", "pids": [h["pid"] for h in self._holders]})
        self._holders = []
        self.refresh()

    @Property("QVariantList", notify=changed)
    def holders(self):
        return self._holders

    @Slot(str, str)
    def forget(self, capability, params):
        self._call({"op": "forget", "capability": capability, "params": json.loads(params)})
        self.refresh()

    def _list(self, key):
        return self._state.get(key) or []

    @Property("QVariantList", notify=changed)
    def pending(self):
        caps = {c["id"]: c for c in self._list("capabilities")}
        # The capability's parameter types, for the fields that narrow a request
        return [dict(p, types={k: v.get("type", "string")
                               for k, v in (caps.get(p["capability"], {}).get("params") or {}).items()})
                for p in self._list("pending")]

    @Property("QVariantList", notify=changed)
    def grants(self):
        return self._list("grants")

    @Property("QVariantList", notify=changed)
    def always(self):
        return [dict(a, paramsJson=json.dumps(a.get("params") or {})) for a in self._list("always")]

    @Property("QVariantList", notify=changed)
    def log(self):
        return list(reversed(self._list("log")))[:30]

    @Property("QVariantList", notify=changed)
    def capabilities(self):
        return self._list("capabilities")

    @Property(str, notify=changed)
    def error(self):
        return self._error


def main(argv):
    if len(argv) not in (2, 3):
        sys.exit(__doc__)
    app = QGuiApplication(argv)
    app.setApplicationName("Claude permissions")
    app.setDesktopFileName("claude-permissions")
    broker = Broker(argv[1])
    engine = QQmlApplicationEngine()
    engine.setInitialProperties({"broker": broker, "title": argv[2] if len(argv) == 3 else "Claude permissions"})
    engine.load(QUrl.fromLocalFile(os.path.join(os.path.dirname(os.path.abspath(__file__)), "Main.qml")))
    if not engine.rootObjects():
        sys.exit("The window didn't load")
    sys.exit(app.exec())


if __name__ == "__main__":
    main(sys.argv)
