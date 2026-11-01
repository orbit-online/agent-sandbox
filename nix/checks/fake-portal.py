# The settings part of xdg-desktop-portal, for the VM test: the color scheme starts dark, and SetColorScheme
# (a test hook) changes it and emits SettingChanged as the portal would; and its notifications. And the parts of Plasma
# next to objects the sandbox mustn't reach: plasmashell's notification server, which the sandbox mustn't reach either,
# with its clipboard (klipper) on one connection, kded's StatusNotifierWatcher with another module's object on a second
import asyncio
import json
import os

from dbus_next import Variant
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
    """The portal's notifications, which the app's libnotify uses (NOTIFY_FORCE_PORTAL): each one is appended to
    $XDG_RUNTIME_DIR/fake-portal-notifications as JSON"""

    def __init__(self):
        super().__init__("org.freedesktop.portal.Notification")

    @method()
    def AddNotification(self, id: "s", notification: "a{sv}"):
        fields = {k: v.value for k, v in notification.items() if isinstance(v.value, (str, int, bool))}
        path = os.path.join(os.environ["XDG_RUNTIME_DIR"], "fake-portal-notifications")
        with open(path, "a") as f:
            f.write(json.dumps({"id": id, **fields}) + "\n")

    @method()
    def RemoveNotification(self, id: "s"):
        pass

    @dbus_property(access=PropertyAccess.READ)
    def version(self) -> "u":
        return 2

    @signal()
    def ActionInvoked(self, id, action, parameter) -> "ssav":
        return [id, action, parameter]


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
