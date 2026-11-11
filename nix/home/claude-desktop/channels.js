// Delivers notifications/claude/channel ({content, meta: {session}}) from the local MCP servers in mcpChannels into the
// Code session meta.session names, as a turn the way the app wakes a session for its CI monitor: an archived one is
// unarchived first, and one the app no longer has or can't deliver to gets a new session in its folder. patch-asar.sh
// copies this next to the app's session manager chunk (@chunk@, exported as @export@) and calls it on each client the
// app's session-side MCP host (LocalMcpServerManager) makes. The chat's copy of a server never gets the handler
"use strict";
const { randomUUID } = require("node:crypto");
const { homedir } = require("node:os");
const servers = new Set(@servers@);

async function deliver(server, { content, meta } = {}) {
  const session = meta?.session;
  // The wrapper is the event's only markup, so the content may hold none
  if (typeof session !== "string" || !/^local_[0-9a-f-]{36}$/.test(session) || typeof content !== "string" ||
    content.length > 2000 || /[<>]/.test(content))
    return console.warn(`[agent-sandbox] ${server}: dropped a malformed channel notification`);
  const sessions = require("./@chunk@").@export@.claudeCodeSessionManager;
  const text = `<mcp-event server="${server}">\n${content}\n</mcp-event>`;
  const s = await sessions.getSession(session);
  if (s) {
    if (s.isArchived) sessions.unarchiveSession(session);
    const send = () => sessions.sendMessage(session, text, undefined, {
      origin: { kind: "auto-continuation" },
      messageUuid: randomUUID(),
    });
    // A session without a process answers retryable, and the second send takes the cold-start path
    let r = await send();
    if (!r.delivered && r.retryable) r = await send();
    if (r.delivered) return;
    console.warn(`[agent-sandbox] ${server}: ${session} didn't take the event (${r.reason}); starting a new session`);
  }
  await sessions.startSession({ cwd: s?.cwd ?? homedir(), title: `${server} event`, message: text });
}

module.exports = (client, server) => {
  if (servers.has(server))
    client.setNotificationHandler("notifications/claude/channel", ({ params }) =>
      deliver(server, params).catch((e) => console.warn(`[agent-sandbox] ${server}: delivering an event failed:`, e)));
};
