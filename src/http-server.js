/**
 * Code Guardian v2 — HTTP/SSE MCP server
 *
 * Listens on port 8765 by default and serves the same MCP tools over HTTP
 * with Server-Sent Events for streaming and POST for requests.
 * Cross-agent: Claude Code, Cursor, Windsurf, Devin, Codex, Emni, Antigravity.
 */

import { createServer } from "node:http";

import {
  toolAuditCodebase,
  toolCheckBranch,
  toolCheckTests,
  toolCheckCICD,
  toolCheckLinting,
  toolCheckSecurity,
  toolCheckArchitecture,
  toolProductionReadiness,
  toolGenerateProductionCode,
  toolGetIndustryPatterns,
  toolGenerateSecurityChecklist,
  toolGenerateGitHubWorkflow,
  toolDetectAgent,
  toolGetAgentGuidance,
  toolGenerateStarterRepo,
} from "./tools.js";

const TOOLS = [
  {
    name: "audit_codebase",
    description:
      "Full audit of a codebase against industry standards: linting, TypeScript, testing, CI/CD, docs, dependencies. Includes actionable guidance.",
    inputSchema: {
      type: "object",
      properties: {
        cwd: { type: "string", description: "Project root directory (defaults to current working directory)" },
        depth: { type: "integer", description: "Directory scan depth (default: 3)" },
      },
    },
  },
  {
    name: "check_branch",
    description: "Check that the current git branch follows conventional naming (feature/, bugfix/, hotfix/, release/, main, master, develop).",
    inputSchema: { type: "object", properties: { cwd: { type: "string", description: "Git repository root" } } },
  },
  {
    name: "check_tests",
    description: "Discover test files, detect test framework, and run a quick test execution check.",
    inputSchema: { type: "object", properties: { cwd: { type: "string", description: "Project root" } } },
  },
  {
    name: "check_cicd",
    description: "Detect CI/CD configuration files (GitHub Actions, GitLab CI, Jenkins, CircleCI, Docker, pre-commit).",
    inputSchema: { type: "object", properties: { cwd: { type: "string", description: "Project root" } } },
  },
  {
    name: "check_linting",
    description: "Detect installed linters (ESLint, Prettier, Biome, oxlint, stylelint) and run ESLint if available.",
    inputSchema: { type: "object", properties: { cwd: { type: "string", description: "Project root" } } },
  },
  {
    name: "check_security",
    description: "Scan for security concerns: .env files at root, dependency vulnerabilities via npm audit.",
    inputSchema: { type: "object", properties: { cwd: { type: "string", description: "Project root" } } },
  },
  {
    name: "check_architecture",
    description: "Review directory structure, monorepo indicators, and architectural conventions.",
    inputSchema: { type: "object", properties: { cwd: { type: "string" }, depth: { type: "integer" } } },
  },
  {
    name: "production_readiness",
    description:
      "Compute a production-readiness scorecard (A–F grade) across 10 dimensions with remediation guidance per item.",
    inputSchema: { type: "object", properties: { cwd: { type: "string" } } },
  },
  {
    name: "generate_production_code",
    description:
      "Generate production-ready code templates with industry-standard patterns. Supports api, auth, database, testing, error_handling, logging, security, ci_cd, docker.",
    inputSchema: {
      type: "object",
      properties: {
        feature: { type: "string", description: "Feature type" },
        stack: { type: "string", description: "Framework: nestjs, express, fastify" },
        language: { type: "string", description: "Language: typescript (default), javascript" },
      },
    },
  },
  {
    name: "get_industry_patterns",
    description: "Get full industry-standard patterns and checklists for any architectural concern.",
    inputSchema: { type: "object", properties: { category: { type: "string", description: "Pattern category (omit for all)" } } },
  },
  {
    name: "generate_security_checklist",
    description: "Generate a security checklist based on current project findings + OWASP Top 10 standards.",
    inputSchema: { type: "object", properties: { cwd: { type: "string" }, stack: { type: "string" } } },
  },
  {
    name: "generate_github_workflow",
    description: "Generate a production-ready GitHub Actions CI/CD workflow YAML.",
    inputSchema: {
      type: "object",
      properties: {
        stack: { type: "string" },
        deployTarget: { type: "string", description: "docker (default), k8s, vercel, aws" },
        name: { type: "string", description: "Workflow name (default: ci)" },
      },
    },
  },
  {
    name: "detect_agent",
    description: "Detect which AI coding agent is in use by scanning for agent-specific config files.",
    inputSchema: { type: "object", properties: { cwd: { type: "string" } } },
  },
  {
    name: "get_agent_guidance",
    description: "Get agent-specific best practices. Supported: claude-code, cursor, windsurf, devin, codex, emni, antigravity.",
    inputSchema: { type: "object", properties: { agent: { type: "string" } } },
  },
  {
    name: "generate_starter_repo",
    description: "Generate a complete starter project structure with production-ready defaults.",
    inputSchema: {
      type: "object",
      properties: {
        framework: { type: "string", description: "nestjs (default), express, fastify" },
        language: { type: "string", description: "typescript (default), javascript" },
      },
    },
  },
];

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

// ─── Tool dispatch ──────────────────────────────────────────────────────────

async function dispatchTool(name, args) {
  switch (name) {
    case "audit_codebase":
      return await toolAuditCodebase(args);
    case "check_branch":
      return await toolCheckBranch(args);
    case "check_tests":
      return await toolCheckTests(args);
    case "check_cicd":
      return await toolCheckCICD(args);
    case "check_linting":
      return await toolCheckLinting(args);
    case "check_security":
      return await toolCheckSecurity(args);
    case "check_architecture":
      return await toolCheckArchitecture(args);
    case "production_readiness":
      return await toolProductionReadiness(args);
    case "generate_production_code":
      return await toolGenerateProductionCode(args);
    case "get_industry_patterns":
      return await toolGetIndustryPatterns(args);
    case "generate_security_checklist":
      return await toolGenerateSecurityChecklist(args);
    case "generate_github_workflow":
      return await toolGenerateGitHubWorkflow(args);
    case "detect_agent":
      return await toolDetectAgent(args);
    case "get_agent_guidance":
      return await toolGetAgentGuidance(args);
    case "generate_starter_repo":
      return await toolGenerateStarterRepo(args);
    default:
      throw new Error("Unknown tool: " + name);
  }
}

// ─── Routes ─────────────────────────────────────────────────────────────────

const server = createServer(async (req, res) => {
  const { method, url: rawUrl } = req;
  const url = new URL(rawUrl, "http://" + req.headers.host);
  const path = url.pathname;

  // CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  // GET / — info
  if (method === "GET" && path === "/") {
    return jsonResponse(res, 200, {
      name: "code-guardian",
      version: "2.0.0",
      description: "Cross-agent production-readiness enforcer for AI coding tools",
      supportsAgents: ["claude-code", "cursor", "windsurf", "devin", "codex", "emni", "antigravity"],
      transports: ["stdio", "http-sse"],
      tools: TOOLS.map((t) => t.name),
    });
  }

  // GET /health
  if (method === "GET" && path === "/health") {
    return jsonResponse(res, 200, { status: "ok", uptime: process.uptime(), version: "2.0.0" });
  }

  // POST /mcp — JSON-RPC over HTTP
  if (method === "POST" && path === "/mcp") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", async () => {
      try {
        const msg = JSON.parse(body);
        const { method: m, params, id } = msg;
        let result;

        if (m === "initialize") {
          result = {
            protocolVersion: "2024-11-05",
            capabilities: { tools: {} },
            serverInfo: { name: "code-guardian", version: "2.0.0" },
          };
        } else if (m === "tools/list") {
          result = { tools: TOOLS };
        } else if (m === "tools/call") {
          const { name, arguments: args } = params;
          const toolResult = await dispatchTool(name, args);
          result = { content: [{ type: "text", text: JSON.stringify(toolResult, null, 2) }] };
        } else {
          return jsonResponse(res, 400, { jsonrpc: "2.0", error: { code: -32601, message: "Unknown method: " + m }, id });
        }

        jsonResponse(res, 200, { jsonrpc: "2.0", result, id });
      } catch (err) {
        jsonResponse(res, 400, { jsonrpc: "2.0", error: { code: -32700, message: err.message }, id: null });
      }
    });
    return;
  }

  // GET /sse — Server-Sent Events stream
  if (method === "GET" && path === "/sse") {
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
server.listen(PORT, () => {
  console.error("[code-guardian v2.0.0] HTTP server listening on port " + PORT);
  console.error("[code-guardian] Tools: " + TOOLS.map((t) => t.name).join(", "));
  console.error("[code-guardian] Agents: claude-code, cursor, windsurf, devin, codex, emni, antigravity");
  console.error("[code-guardian] Open http://localhost:" + PORT + " for info");
});

process.on("SIGINT", () => {
  console.error("[code-guardian] Shutting down...");
  server.close(() => process.exit(0));
});
