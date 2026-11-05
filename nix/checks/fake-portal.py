# The settings part of xdg-desktop-portal, for the VM test: the color scheme starts dark, and SetColorScheme
# (a test hook) changes it and emits SettingChanged as the portal would; its notifications and OpenURI, which name the
# calling app. And the parts of Plasma next to objects the sandbox mustn't reach: plasmashell's notification server,
# which the sandbox mustn't reach either, with its clipboard (klipper) on one connection, kded's StatusNotifierWatcher
# with another module's object on a second
import asyncio
import json
import os

from dbus_next import Message, MessageType, Variant
from dbus_next.aio import MessageBus
from dbus_next.constants import PropertyAccess
from dbus_next.service import ServiceInterface, dbus_property, method, signal


class Settings(ServiceInterface):
    def __init__(self):
        super().__init__("org.freedesktop.portal.Settings")
        self.scheme = 1

    @method()
    def ReadOne(self, namespace: "s", key: "s") -> "v":
        return Variant("u", self.scheme)

    @method()
    def SetColorScheme(self, scheme: "u"):
        self.scheme = scheme
        self.SettingChanged("org.freedesktop.appearance", "color-scheme", Variant("u", scheme))

    @signal()
    def SettingChanged(self, namespace, key, value) -> "ssv":
        return [namespace, key, value]


class PortalNotification(ServiceInterface):
    """The portal's notifications, which the app's libnotify uses (NOTIFY_FORCE_PORTAL). AddNotification is
    Caller's"""

    def __init__(self):
        super().__init__("org.freedesktop.portal.Notification")

    @method()
    def RemoveNotification(self, id: "s"):
        pass

    @dbus_property(access=PropertyAccess.READ)
    def version(self) -> "u":
        return 2

    @signal()
    def ActionInvoked(self, id, action, parameter) -> "ssav":
        return [id, action, parameter]


def record(name, entry):
    path = os.path.join(os.environ["XDG_RUNTIME_DIR"], name)
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")


class Caller:
    """The portal's calls that name the app, as xdg-desktop-portal does, by the caller's process while the call is
    on: the pid behind the sender's connection, its /.flatpak-info. OpenURI, which the sandbox's xdg-open calls: each
    URI and that app go to $XDG_RUNTIME_DIR/fake-portal-uris; so would SchemeSupported, which no rule of the
    sandbox's lets through. AddNotification: each notification's id, its string, number and boolean fields, and that
    app go to $XDG_RUNTIME_DIR/fake-portal-notifications, the app as gnome-shell gets it, which looks it up as
    <app>.desktop. A message handler, since dbus-next's service methods can't wait on a call of their own"""

    calls = {
        ("org.freedesktop.portal.OpenURI", "OpenURI"),
        ("org.freedesktop.portal.OpenURI", "SchemeSupported"),
        ("org.freedesktop.portal.Notification", "AddNotification"),
    }

    def __init__(self, bus):
        self.bus = bus

    def handle(self, msg):
        if msg.message_type != MessageType.METHOD_CALL or msg.path != "/org/freedesktop/portal/desktop":
            return None
        if (msg.interface, msg.member) not in self.calls:
            return None
        asyncio.ensure_future(self.answer(msg))
        return True

    async def answer(self, msg):
        reply = await self.bus.call(Message(
            destination="org.freedesktop.DBus", path="/org/freedesktop/DBus", interface="org.freedesktop.DBus",
            member="GetConnectionUnixProcessID", signature="s", body=[msg.sender]))
        app = None
        if reply.message_type == MessageType.METHOD_RETURN:
            try:
                with open(f"/proc/{reply.body[0]}/root/.flatpak-info") as f:
                    app = next((ln.strip()[5:] for ln in f if ln.startswith("name=")), None)
            except OSError:
                pass
        if msg.member == "OpenURI":
            record("fake-portal-uris", {"uri": msg.body[1], "app": app})
            self.bus.send(Message.new_method_return(msg, "o", ["/org/freedesktop/portal/desktop/request/1_1/t"]))
        elif msg.member == "SchemeSupported":
            record("fake-portal-uris", {"scheme": msg.body[0], "app": app})
            self.bus.send(Message.new_method_return(msg, "b", [True]))
        else:
            id, notification = msg.body
            fields = {k: v.value for k, v in notification.items() if isinstance(v.value, (str, int, bool))}
            record("fake-portal-notifications", {"id": id, **fields, "app": app})
            self.bus.send(Message.new_method_return(msg))


class Notifications(ServiceInterface):
    def __init__(self):
        super().__init__("org.freedesktop.Notifications")

    @method()
    def Notify(self, app: "s", replaces: "u", icon: "s", summary: "s", body: "s", actions: "as", hints: "a{sv}",
               timeout: "i") -> "u":
        return 7

    @method()
    def GetCapabilities(self) -> "as":
        return ["body", "actions"]


class Klipper(ServiceInterface):
    def __init__(self):
        super().__init__("org.kde.klipper.klipper")

    @method()
    def getClipboardContents(self) -> "s":
        return "secret-clipboard"


class Watcher(ServiceInterface):
    def __init__(self):
        super().__init__("org.kde.StatusNotifierWatcher")
        self.items = []

    @method()
    def RegisterStatusNotifierItem(self, service: "s"):
        self.items.append(service)

    @dbus_property(access=PropertyAccess.READ)
    def RegisteredStatusNotifierItems(self) -> "as":
        return self.items

    @dbus_property(access=PropertyAccess.READ)
    def IsStatusNotifierHostRegistered(self) -> "b":
        return True


class Kded(ServiceInterface):
    def __init__(self):
        super().__init__("org.kde.kded6")

    @method()
    def unloadModule(self, name: "s") -> "b":
        return True


async def main():
    bus = await MessageBus().connect()
    bus.export("/org/freedesktop/portal/desktop", Settings())
    bus.export("/org/freedesktop/portal/desktop", PortalNotification())
    bus.add_message_handler(Caller(bus).handle)
    await bus.request_name("org.freedesktop.portal.Desktop")
    shell = await MessageBus().connect()
    shell.export("/org/freedesktop/Notifications", Notifications())
    shell.export("/klipper", Klipper())
    await shell.request_name("org.freedesktop.Notifications")
    await shell.request_name("org.kde.klipper")
    kded = await MessageBus().connect()
    kded.export("/StatusNotifierWatcher", Watcher())
    kded.export("/kded", Kded())
    await kded.request_name("org.kde.StatusNotifierWatcher")
    await kded.request_name("org.kde.kded6")
    await bus.wait_for_disconnect()


asyncio.run(main())
