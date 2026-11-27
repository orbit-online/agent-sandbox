// The Paseo app root's index.js (nix/home/paseo) against a fake Electron, in node: node paseo-app-root.js DIR, DIR
// holding index.js with its require of Paseo's main.js pointed at ./stub-main.js. Checks the ready line (once, only
// for a window visible once loaded or when shown), that main.js can't set the desktop name, and that a second
// instance's command line reaches main.js without the app root, the rest kept
"use strict";
const assert = require("node:assert/strict");
const EventEmitter = require("node:events");
const Module = require("node:module");
const path = require("node:path");

const dir = path.resolve(process.argv[2]);
const app = new EventEmitter();
app.setDesktopName = (name) => {
  app.desktopName = name;
};
const electron = { app };
const resolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  return request === "electron" ? "electron" : resolve.call(this, request, ...rest);
};
require.cache.electron = { id: "electron", filename: "electron", loaded: true, exports: electron };

const out = [];
const write = process.stdout.write;
process.stdout.write = (chunk) => out.push(String(chunk));

require(path.join(dir, "index.js"));
assert.equal(app.desktopName, undefined, "main.js set the desktop name");
assert.equal(global.stubMainLoaded, true, "main.js wasn't required");

const win = (visible) => {
  const w = new EventEmitter();
  w.webContents = new EventEmitter();
  w.isDestroyed = () => false;
  w.isVisible = () => visible;
  return w;
};
const hidden = win(false);
app.emit("browser-window-created", {}, hidden);
hidden.webContents.emit("did-finish-load");
assert.deepEqual(out, [], "ready printed for a hidden window");
hidden.isVisible = () => true;
hidden.emit("show");
assert.deepEqual(out, ["agent-sandbox: ready\n"], "no ready line once the window showed");
const second = win(true);
app.emit("browser-window-created", {}, second);
second.webContents.emit("did-finish-load");
assert.equal(out.length, 1, "ready printed twice");

app.emit("second-instance", {}, ["/x/Paseo", "--no-sandbox", dir, "/srv/project"], "/cwd");
assert.deepEqual(global.secondArgv, ["/x/Paseo", "--no-sandbox", "/srv/project"], "the app root reached main.js");
assert.equal(global.secondCwd, "/cwd");
app.emit("second-instance", {}, ["/x/Paseo", dir, "paseo://h/s/agent/a"], "/cwd");
assert.deepEqual(global.secondArgv, ["/x/Paseo", "paseo://h/s/agent/a"]);

process.stdout.write = write;
console.log("paseo-app-root: ok");
