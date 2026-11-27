// The Paseo stub's main.js, in place of Paseo's packages/desktop/dist/main.js, which the module's index.js requires.
// As Paseo's does: sets the desktop name Paseo.desktop, takes the single-instance lock, and opens a window once the
// app is ready. A first instance logs what it got (its pid and namespaces as the stub app of Claude Desktop logs them,
// its effective capabilities, argv, PATH, the desktop name after its own set and the version) and every second
// instance's command line; a second instance logs its argv and quits
"use strict";
const fs = require("node:fs");
const { app, BrowserWindow } = require("electron");
const { log } = global.paseoStub;

app.setDesktopName("Paseo.desktop");
if (!app.requestSingleInstanceLock()) {
  log({ event: "second", argv: process.argv });
  app.quit();
}
const ns = (name) => fs.readlinkSync(`/proc/self/ns/${name}`);
const capEff = fs.readFileSync("/proc/self/status", "utf8").match(/^CapEff:\s*(\S+)$/m)[1];
log({
  event: "start",
  pid: process.pid,
  net: ns("net"),
  mnt: ns("mnt"),
  pidns: ns("pid"),
  capEff,
  argv: process.argv,
  path: process.env.PATH,
  desktopName: app.desktopName,
  version: app.getVersion(),
});
app.on("second-instance", (_event, argv, cwd) => log({ event: "second-instance", argv, cwd }));
app.whenReady().then(() => new BrowserWindow({ show: true }));
