"""Tests of the Permissions window against a fake control.sock, the window offscreen."""

import json
import os
import socket
import sys
import tempfile
import threading
import unittest

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtCore import QPointF, Qt, QUrl  # noqa: E402
from PySide6.QtGui import QGuiApplication  # noqa: E402
from PySide6.QtQml import QQmlApplicationEngine  # noqa: E402
from PySide6.QtQuick import QQuickItem  # noqa: E402
from PySide6.QtTest import QTest  # noqa: E402

import permissions_window  # noqa: E402

STATE = {
    "pending": [{"id": "p1", "capability": "folders/folder", "params": {"path": "/srv/notes", "ro": True},
                 "summary": 'a folder (path="/srv/notes", ro=true)', "reason": "read the notes", "lease": "PT1H",
                 "options": True}],
    "grants": [{"id": "g1", "capability": "test/thing", "params": {}, "summary": "the test thing", "lease": "session",
                "granted": "2026-10-31T10:00:00Z"}],
    "always": [{"capability": "test/thing", "params": {"x": "y"}, "granted": "2026-10-31T10:00:00Z"}],
    "log": [{"time": "2026-10-31T10:00:00Z", "summary": "the test thing", "decision": "allowed (session)"}],
    "capabilities": [{"id": "folders/folder", "type": "C", "description": "a folder",
                      "params": {"path": {"type": "string"}, "ro": {"type": "boolean"}}}],
}


class FakeBroker:
    """Serves control.sock: answers state with STATE and records every other request."""

    def __init__(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "control.sock")
        self.requests = []
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.path)
        self.sock.listen()
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def handle(self, conn):
        with conn:
            line = conn.makefile().readline()
            if not line:  # a watch the window closed before subscribing
                return
            request = json.loads(line)
            if request["op"] == "watch":
                conn.recv(1)  # held open until the window closes it
                return
            if request["op"] != "state":
                self.requests.append(request)
            answers = {"state": STATE, "revoke": {"holders": [{"pid": 42, "comm": "cat"}]}}
            conn.sendall(json.dumps(answers.get(request["op"], {})).encode())

    def close(self):
        self.sock.close()


app = QGuiApplication.instance() or QGuiApplication(sys.argv)


class TestBroker(unittest.TestCase):
    def setUp(self):
        self.fake = FakeBroker()
        self.addCleanup(self.fake.close)

    def test_state(self):
        b = permissions_window.Broker(self.fake.path)
        self.assertEqual(b.error, "")
        self.assertEqual(b.pending[0]["types"], {"path": "string", "ro": "boolean"})
        self.assertEqual(b.grants[0]["id"], "g1")
        self.assertEqual(b.always[0]["paramsJson"], '{"x": "y"}')

    def test_operations(self):
        b = permissions_window.Broker(self.fake.path)
        b.answer("p1", True, "always", '{"path": "/srv/notes", "ro": true}')
        b.revoke("g1")
        b.forget("test/thing", '{"x": "y"}')
        self.assertEqual(self.fake.requests, [
            {"op": "answer", "pending": "p1", "allow": True, "lease": "always",
             "params": {"path": "/srv/notes", "ro": True}},
            {"op": "revoke", "grant": "g1"},
            {"op": "forget", "capability": "test/thing", "params": {"x": "y"}},
        ])

    def test_no_broker(self):
        b = permissions_window.Broker(os.path.join(self.fake.dir, "missing.sock"))
        self.assertIn("isn't running", b.error)


def find(item, predicate):
    """The first item below item, depth first, for which predicate holds."""
    for child in item.childItems():
        if predicate(child):
            return child
        if found := find(child, predicate):
            return found
    return None


class TestWindow(unittest.TestCase):
    def test_allow_narrowed(self):
        fake = FakeBroker()
        self.addCleanup(fake.close)
        broker = permissions_window.Broker(fake.path)
        engine = QQmlApplicationEngine()
        warnings = []
        engine.warnings.connect(lambda ws: warnings.extend(w.toString() for w in ws))
        engine.setInitialProperties({"broker": broker, "title": "test"})
        engine.load(QUrl.fromLocalFile(os.path.join(os.path.dirname(os.path.abspath(__file__)), "Main.qml")))
        self.assertTrue(engine.rootObjects(), warnings)
        window = engine.rootObjects()[0]
        QTest.qWait(200)
        self.assertEqual(warnings, [])

        def button(text):
            item = find(window.contentItem(), lambda i: i.property("text") == text and i.metaObject().className()
                        .startswith("Button"))
            self.assertIsNotNone(item, f"No {text} button")
            return item

        def click(item):
            pos = item.mapToScene(QPointF(item.width() / 2, item.height() / 2)).toPoint()
            QTest.mouseClick(window, Qt.LeftButton, Qt.NoModifier, pos)
            QTest.qWait(100)

        # Narrow the request to read-only... it is already: untick and tick again leaves it as asked
        ro = find(window.contentItem(), lambda i: i.metaObject().className().startswith("CheckBox") and i.isVisible())
        self.assertIsNotNone(ro)
        click(ro)
        click(button("Allow"))
        self.assertEqual(fake.requests, [{"op": "answer", "pending": "p1", "allow": True, "lease": "PT1H",
                                          "params": {"path": "/srv/notes", "ro": False}}])
        click(button("Revoke"))
        self.assertEqual(fake.requests[-1], {"op": "revoke", "grant": "g1"})
        # What still held the revoked grant, to end
        click(button("End them"))
        self.assertEqual(fake.requests[-1], {"op": "end", "pids": [42]})


if __name__ == "__main__":
    unittest.main()
