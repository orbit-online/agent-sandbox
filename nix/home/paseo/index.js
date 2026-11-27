// The app root the sandbox runs Paseo from (app.nix): its package.json names this file and the launcher's app ID as
// desktopName. Before Paseo's own main.js:
// - the ready line, the first time one of the app's windows is visible once its page loaded or when it's shown (as
//   Claude Desktop's asar hook has it: not ready-to-show, which skips a window shown at creation), through stdout's
//   write as it is at startup, whatever the app does to the console later. The launcher waits for it to end its splash
// - app.setDesktopName made a no-op: main.js sets "Paseo.desktop" on Linux whatever package.json says, which would
//   give every launcher's windows the app ID Paseo
"use strict";
const { app } = require("electron");
{
  const write = process.stdout.write.bind(process.stdout);
  let done = false;
  const ready = (win) => {
    if (done || win.isDestroyed() || !win.isVisible()) return;
    done = true;
    write(@ready@ + "\n");
  };
  app.on("browser-window-created", (_event, win) => {
    win.webContents.once("did-finish-load", () => ready(win));
    win.on("show", () => ready(win));
  });
}
app.setDesktopName = () => {};
// A second instance's command line, which main.js reads as a packaged app's (desktop/src/main.ts, isDefaultApp false):
// this directory, the app root default_app runs, would be the first absolute directory in it, and the project to open
// whatever path came after. Without it a path after it opens, and a paseo:// link, which main.js finds anywhere, goes
// on as it does
{
  const on = app.on.bind(app);
  app.on = (event, listener) =>
    event === "second-instance"
      ? on(event, (e, argv, ...rest) => listener(e, argv.filter((a) => a !== __dirname), ...rest))
      : on(event, listener);
}
require(@main@);
