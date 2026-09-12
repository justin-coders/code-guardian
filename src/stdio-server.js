/**
 * Code Guardian — stdio MCP server
 *
 * Entry point for Claude Code plugin installation.
 * Reads JSON-RPC messages from stdin and responds on stdout.
 */

import {
  toolAuditCodebase,
  toolCheckBranch,
  toolCheckTests,
  toolCheckCICD,
  toolCheckLinting,
  toolCheckSecurity,
  toolCheckArchitecture,
  toolProductionReadiness,
} from "./tools.js";
import { EventEmitter } from "node:events";

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

let _id = 0;
function uid() {
  return ++_id;
}

// ─── Tool definitions ───────────────────────────────────────────────────────

const TOOLS = [
  {
    name: "audit_codebase",
    description:
      "Full audit of a codebase against industry standards: linting, TypeScript, testing, CI/CD, docs, dependencies.",
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
    description:
      "Check that the current git branch follows conventional naming (feature/, bugfix/, hotfix/, release/, main, master, develop).",
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
    inputSchema: {
      type: "object",
      properties: { cwd: { type: "string" }, depth: { type: "integer" } },
    },
  },
  {
    name: "production_readiness",
    description:
      "Compute a production-readiness scorecard (A–F grade) covering: package.json, lock file, README, .gitignore, ESLint, TypeScript strict mode, tests, CI/CD, .env safety, build script.",
    inputSchema: { type: "object", properties: { cwd: { type: "string" } } },
  },
];

// ─── Request handler ────────────────────────────────────────────────────────

async function handleRequest(msg) {
  const { method, params, id } = msg;
  switch (method) {
    case "initialize":
      return {
        id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: { name: "code-guardian", version: "1.0.0" },
        },
      };
    case "tools/list":
      return { id, result: { tools: TOOLS } };
    case "tools/call": {
      const { name, arguments: args } = params;
      try {
        let result;
        switch (name) {
          case "audit_codebase":
            result = await toolAuditCodebase(args);
            break;
          case "check_branch":
            result = await toolCheckBranch(args);
            break;
          case "check_tests":
            result = await toolCheckTests(args);
            break;
          case "check_cicd":
            result = await toolCheckCICD(args);
            break;
          case "check_linting":
            result = await toolCheckLinting(args);
            break;
          case "check_security":
            result = await toolCheckSecurity(args);
            break;
          case "check_architecture":
            result = await toolCheckArchitecture(args);
            break;
          case "production_readiness":
            result = await toolProductionReadiness(args);
            break;
          default:
            throw new Error(`Unknown tool: ${name}`);
        }
        return {
          id,
          result: { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] },
        };
      } catch (err) {
        return { id, error: { code: -32603, message: err.message } };
      }
    }
    default:
      return { id, error: { code: -32601, message: `Method not found: ${method}` } };
  }
}

// ─── Entry point ────────────────────────────────────────────────────────────

async function main() {
  const reader = lineReader(process.stdin);
  reader.on("line", async (line) => {
    try {
      const msg = JSON.parse(line);
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
