/**
 * Code Guardian v2 — stdio MCP server
 *
 * Entry point for Claude Code plugin installation.
 * Reads JSON-RPC messages from stdin and responds on stdout.
 * Also works with Cursor, Windsurf, Devin, Codex, Gemini, Antigravity and any MCP-capable agent.
 */

import { TOOLS, dispatchTool } from "./tool-registry.js";
import { EventEmitter } from "node:events";
import { createRequire } from "node:module";

const _require = createRequire(import.meta.url);
const VERSION = _require("../package.json").version;

// ─── MCP protocol helpers ───────────────────────────────────────────────────

function lineReader(stream) {
  const ee = new EventEmitter();
  let buf = "";
  stream.on("data", (chunk) => {
    buf += chunk;
    let idx;
    while ((idx = buf.indexOf("\n")) !== -1) {
      const line = buf.slice(0, idx).trim();
      buf = buf.slice(idx + 1);
      if (line) ee.emit("line", line);
    }
  });
  stream.on("end", () => {
    if (buf.trim()) ee.emit("line", buf.trim());
    ee.emit("end");
  });
  return ee;
}

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

// ─── Request handler ────────────────────────────────────────────────────────

async function handleRequest(msg) {
  const { method, params, id } = msg;
  switch (method) {
    case "initialize": {
      const clientVersion = params?.protocolVersion || "2024-11-05";
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: clientVersion,
          capabilities: { tools: {} },
          serverInfo: { name: "code-guardian", version: VERSION },
        },
      };
    }
    case "ping":
      return { jsonrpc: "2.0", id, result: {} };
    case "tools/list":
      return { jsonrpc: "2.0", id, result: { tools: TOOLS } };
    case "tools/call": {
      const { name, arguments: args } = params;
      try {
        const result = await dispatchTool(name, args);
        return {
          jsonrpc: "2.0",
          id,
          result: { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] },
        };
      } catch (err) {
        return { jsonrpc: "2.0", id, error: { code: -32603, message: err.message } };
      }
    }
    default:
      return { jsonrpc: "2.0", id, error: { code: -32601, message: "Method not found: " + method } };
  }
}

// ─── Entry point ────────────────────────────────────────────────────────────

async function main() {
  console.error("[code-guardian v" + VERSION + "] stdio server started");
  console.error("[code-guardian] Tools: " + TOOLS.map((t) => t.name).join(", "));
  const reader = lineReader(process.stdin);
  reader.on("line", async (line) => {
    try {
      const msg = JSON.parse(line);
      // MCP notifications have no "id" — they do not get a response
      if (msg.id === undefined || msg.id === null) return;
      const resp = await handleRequest(msg);
      if (resp) send(resp);
    } catch (err) {
      send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: err.message } });
    }
  });
  reader.on("end", () => process.exit(0));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
