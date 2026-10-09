# The settings part of xdg-desktop-portal, for the VM test: the color scheme starts dark, and SetColorScheme
# (a test hook) changes it and emits SettingChanged as the portal would
import asyncio

from dbus_next import Variant
from dbus_next.aio import MessageBus
from dbus_next.service import ServiceInterface, method, signal


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


async def main():
    bus = await MessageBus().connect()
    bus.export("/org/freedesktop/portal/desktop", Settings())
    await bus.request_name("org.freedesktop.portal.Desktop")
    await bus.wait_for_disconnect()


asyncio.run(main())
