// The Electron of the Paseo stub (paseo-stub.nix), in node: node paseo-stub-electron.js EXE ROOT [ARGS...] runs the app
// root ROOT (the module's own: package.json, index.js) as Electron's default_app does, with process.argv
// [EXE, ROOT, ARGS...] and `electron` a fake: an app whose ready event comes after the app root loaded, a BrowserWindow
// that is visible and loads 100 ms after it's created, the desktop name and version from ROOT's package.json, and a
// single-instance lock. A first instance listens on ~/paseo-stub.sock; a second one hands it its command line and
// working directory there, which the first emits as second-instance, as Chromium's singleton does. The stub's main.js
// (paseo-stub-main.js) writes what it sees to ~/paseo-stub.log through global.paseoStub.log
"use strict";
const childProcess = require("node:child_process");
const EventEmitter = require("node:events");
const fs = require("node:fs");
const Module = require("node:module");
const net = require("node:net");
const path = require("node:path");

const [exe, root, ...args] = process.argv.slice(2);
const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
process.argv = [exe, root, ...args];
const home = process.env.HOME;
const sock = path.join(home, "paseo-stub.sock");
global.paseoStub = {
  log: (entry) => fs.appendFileSync(path.join(home, "paseo-stub.log"), JSON.stringify(entry) + "\n"),
};

// Hands argv[2] to the socket at argv[1]: exit 0 once it's delivered, 1 when no first instance listens there
const handOver = `
const c = require("node:net").createConnection(process.argv[1]);
c.on("error", () => process.exit(1));
c.on("connect", () => c.end(process.argv[2]));
c.on("close", (failed) => process.exit(failed ? 1 : 0));
`;

const app = new EventEmitter();
app.desktopName = pkg.desktopName;
app.setDesktopName = (name) => {
  app.desktopName = name;
};
app.getVersion = () => pkg.version;
app.quit = () => process.exit(0);
app.whenReady = () => new Promise((resolve) => setImmediate(resolve));
app.requestSingleInstanceLock = () => {
  const command = JSON.stringify({ argv: process.argv, cwd: process.cwd() });
  if (childProcess.spawnSync(process.execPath, ["-e", handOver, sock, command], { stdio: "inherit" }).status === 0) {
    return false;
  }
  fs.rmSync(sock, { force: true });
  net
    .createServer((conn) => {
      let data = "";
      conn.setEncoding("utf8");
      conn.on("data", (chunk) => (data += chunk));
      conn.on("end", () => {
        const { argv, cwd } = JSON.parse(data);
        app.emit("second-instance", {}, argv, cwd);
      });
    })
    .listen(sock);
  return true;
};

class BrowserWindow extends EventEmitter {
  constructor() {
    super();
    this.webContents = new EventEmitter();
    app.emit("browser-window-created", {}, this);
    setTimeout(() => this.webContents.emit("did-finish-load"), 100);
  }
  isDestroyed() {
    return false;
  }
  isVisible() {
    return true;
  }
}

const resolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  return request === "electron" ? "electron" : resolve.call(this, request, ...rest);
};
require.cache.electron = { id: "electron", filename: "electron", loaded: true, exports: { app, BrowserWindow } };

require(path.join(root, pkg.main));
