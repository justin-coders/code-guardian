/**
 * Code Guardian v2 — HTTP/SSE MCP server
 *
 * Listens on port 8765 by default and serves the same MCP tools over HTTP
 * with Server-Sent Events for streaming and POST for requests.
 * Cross-agent: Claude Code, Cursor, Windsurf, Devin, Codex, Gemini, Antigravity.
 *
 * Security: bound to 127.0.0.1 by default, requires CODE_GUARDIAN_TOKEN env var,
 * caps request body at 1MB, validates cwd paths against traversal attacks.
 */

import { createServer } from "node:http";
import { createRequire } from "node:module";
import { resolve, dirname } from "node:path";
import { TOOLS, dispatchTool as dispatchToolRaw } from "./tool-registry.js";

const _require = createRequire(import.meta.url);
const VERSION = _require("../package.json").version;

const BODY_LIMIT = 1024 * 1024; // 1 MB
const ALLOWED_ROOTS = process.env.CODE_GUARDIAN_ALLOWED_ROOTS
  ? process.env.CODE_GUARDIAN_ALLOWED_ROOTS.split(",").map((r) => resolve(r.trim()))
  : [process.cwd()];

// ─── Helpers ────────────────────────────────────────────────────────────────

function jsonResponse(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

function sseResponse(res) {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });
  return res;
}

function sendSSE(res, event, data) {
  res.write("event: " + event + "\ndata: " + JSON.stringify(data) + "\n\n");
}

function validateCwd(args) {
  if (!args || !args.cwd) return { ok: true, cwd: process.cwd() };
  const cwd = resolve(args.cwd);
  // Prevent path traversal: cwd must be under one of the allowed roots
  const isAllowed = ALLOWED_ROOTS.some((root) => cwd.startsWith(root + "/") || cwd === root);
  if (!isAllowed) {
    return { ok: false, error: "cwd is not within allowed roots: " + ALLOWED_ROOTS.join(", ") };
  }
  return { ok: true, cwd };
}

// ─── Tool dispatch (wraps registry dispatch with cwd validation) ────────────

async function dispatchTool(name, args) {
  // Validate cwd before dispatch
  const cwdCheck = validateCwd(args);
  if (!cwdCheck.ok) {
    throw new Error(cwdCheck.error);
  }
  const resolvedArgs = args ? { ...args, cwd: cwdCheck.cwd } : { cwd: cwdCheck.cwd };
  return await dispatchToolRaw(name, resolvedArgs);
}

// ─── Auth check ─────────────────────────────────────────────────────────────

function checkAuth(req, res) {
  const token = process.env.CODE_GUARDIAN_TOKEN;
  if (!token) return true; // no auth required when env var is not set
  const authHeader = req.headers.authorization || "";
  const provided = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
  if (provided !== token) {
    jsonResponse(res, 401, { error: "Unauthorized" });
    return false;
  }
  return true;
}

// ─── Routes ─────────────────────────────────────────────────────────────────

const server = createServer(async (req, res) => {
  const { method, url: rawUrl } = req;
  const url = new URL(rawUrl, "http://" + req.headers.host);
  const path = url.pathname;

  // CORS — restrict origins when auth is enabled
  const allowedOrigin = process.env.CODE_GUARDIAN_TOKEN ? (req.headers.origin || "") : "*";
  res.setHeader("Access-Control-Allow-Origin", allowedOrigin);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  // GET / — info
  if (method === "GET" && path === "/") {
    return jsonResponse(res, 200, {
      name: "code-guardian",
      version: VERSION,
      description: "Cross-agent production-readiness enforcer for AI coding tools",
      supportsAgents: ["claude-code", "cursor", "windsurf", "devin", "codex", "gemini", "antigravity"],
      transports: ["stdio", "http-sse"],
      tools: TOOLS.map((t) => t.name),
    });
  }

  // GET /health
  if (method === "GET" && path === "/health") {
    return jsonResponse(res, 200, { status: "ok", uptime: process.uptime(), version: VERSION });
  }

  // POST /mcp — JSON-RPC over HTTP
  if (method === "POST" && path === "/mcp") {
    if (!checkAuth(req, res)) return;

    let body = "";
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > BODY_LIMIT) {
        res.destroy();
        return;
      }
      body += chunk;
    });
    req.on("error", () => {
      jsonResponse(res, 400, { jsonrpc: "2.0", error: { code: -32700, message: "Request body read error" }, id: null });
    });
    req.on("end", async () => {
      if (size > BODY_LIMIT) {
        jsonResponse(res, 413, { jsonrpc: "2.0", error: { code: -32000, message: "Payload too large (max 1MB)" }, id: null });
        return;
      }
      let id = null;
      try {
        const msg = JSON.parse(body);
        id = msg.id ?? null;
        const { method: m, params, __protocolVersion } = msg;
        let result;

        if (m === "initialize") {
          result = {
            protocolVersion: __protocolVersion || "2024-11-05",
            capabilities: { tools: {} },
            serverInfo: { name: "code-guardian", version: VERSION },
          };
        } else if (m === "ping") {
          result = {};
        } else if (m === "tools/list") {
          result = { tools: TOOLS };
        } else if (m === "tools/call") {
          const { name, arguments: args } = params;
          const toolResult = await dispatchTool(name, args);
          result = { content: [{ type: "text", text: JSON.stringify(toolResult, null, 2) }] };
        } else {
          jsonResponse(res, 400, { jsonrpc: "2.0", error: { code: -32601, message: "Unknown method: " + m }, id });
          return;
        }

        jsonResponse(res, 200, { jsonrpc: "2.0", result, id });
      } catch (err) {
        jsonResponse(res, 400, { jsonrpc: "2.0", error: { code: -32700, message: err.message }, id });
      }
    });
    return;
  }

  // GET /sse — Server-Sent Events stream
  if (method === "GET" && path === "/sse") {
    if (!checkAuth(req, res)) return;

    const resStream = sseResponse(res);
    sendSSE(resStream, "endpoint", { endpoint: "/mcp" });

    res.on("close", () => resStream.destroy());

    const ping = setInterval(() => sendSSE(resStream, "ping", { time: new Date().toISOString() }), 15000);
    res.on("close", () => clearInterval(ping));
    return;
  }

  jsonResponse(res, 404, { error: "Not found" });
});

const PORT = Number(process.env.CODE_GUARDIAN_PORT || 8765);
const HOST = process.env.CODE_GUARDIAN_HOST || "127.0.0.1";
server.listen(PORT, HOST, () => {
  console.error("[code-guardian v" + VERSION + "] HTTP server listening on http://" + HOST + ":" + PORT);
  console.error("[code-guardian] Tools: " + TOOLS.map((t) => t.name).join(", "));
  console.error("[code-guardian] Agents: claude-code, cursor, windsurf, devin, codex, gemini, antigravity");
  console.error("[code-guardian] Auth: " + (process.env.CODE_GUARDIAN_TOKEN ? "enabled" : "disabled (set CODE_GUARDIAN_TOKEN to enable)"));
  console.error("[code-guardian] CWD roots: " + ALLOWED_ROOTS.join(", "));
});

process.on("SIGINT", () => {
  console.error("[code-guardian] Shutting down...");
  server.close(() => process.exit(0));
});
