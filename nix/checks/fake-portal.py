# The settings part of xdg-desktop-portal, for the VM test: the color scheme starts dark, and SetColorScheme
# (a test hook) changes it and emits SettingChanged as the portal would. And the parts of Plasma the sandbox talks to,
# each next to an object it mustn't reach: plasmashell's notification server with its clipboard (klipper) on one
# connection, kded's StatusNotifierWatcher with another module's object on a second
import asyncio

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
