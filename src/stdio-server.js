/**
 * Code Guardian v2 — stdio MCP server
 *
 * Entry point for Claude Code plugin installation.
 * Reads JSON-RPC messages from stdin and responds on stdout.
 * Also works with Cursor, Windsurf, Devin, Codex, Gemini, Antigravity and any MCP-capable agent.
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
  toolGenerateProductionCode,
  toolGetIndustryPatterns,
  toolGenerateSecurityChecklist,
  toolGenerateGitHubWorkflow,
  toolDetectAgent,
  toolGetAgentGuidance,
  toolGenerateStarterRepo,
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

// ─── Tool definitions ───────────────────────────────────────────────────────

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
    inputSchema: { type: "object", properties: { cwd: { type: "string" }, depth: { type: "integer" } } },
  },
  {
    name: "production_readiness",
    description:
      "Compute a production-readiness scorecard (A–F grade) across 10 dimensions: package.json, lock file, README, .gitignore, ESLint, TypeScript strict mode, tests, CI/CD, .env safety, build script. Includes remediation guidance per item.",
    inputSchema: { type: "object", properties: { cwd: { type: "string" } } },
  },
  {
    name: "generate_production_code",
    description:
      "Generate production-ready code templates with industry-standard patterns. Supports: api, auth, database, testing, error_handling, logging, security, ci_cd, docker, branch_strategy. Specify stack (nestjs, express, fastify) and feature type.",
    inputSchema: {
      type: "object",
      properties: {
        feature: { type: "string", description: "Feature type: api, auth, database, testing, error_handling, logging, security, ci_cd, docker" },
        stack: { type: "string", description: "Framework: nestjs, express, fastify, default" },
        language: { type: "string", description: "Language: typescript (default), javascript" },
      },
    },
  },
  {
    name: "get_industry_patterns",
    description:
      "Get full industry-standard patterns and checklists for any architectural concern: api, auth, database, testing, error_handling, logging, security, ci_cd, docker, branch_strategy.",
    inputSchema: {
      type: "object",
      properties: {
        category: { type: "string", description: "Pattern category (omit for all patterns)" },
      },
    },
  },
  {
    name: "generate_security_checklist",
    description:
      "Generate a security checklist based on current project findings + OWASP Top 10 standards. Detects stack and tailors recommendations.",
    inputSchema: { type: "object", properties: { cwd: { type: "string" }, stack: { type: "string" } } },
  },
  {
    name: "generate_github_workflow",
    description: "Generate a production-ready GitHub Actions CI/CD workflow YAML. Supports custom name, stack, and deploy target (docker, k8s, vercel, aws).",
    inputSchema: {
      type: "object",
      properties: {
        stack: { type: "string", description: "Tech stack name" },
        deployTarget: { type: "string", description: "Deployment target: docker (default), k8s, vercel, aws" },
        name: { type: "string", description: "Workflow name (default: ci)" },
      },
    },
  },
  {
    name: "detect_agent",
    description:
      "Detect which AI coding agent is in use (Claude Code, Cursor, Windsurf, Devin, Codex, Gemini, Antigravity) by scanning for agent-specific config files (.cursorrules, .windsurfrules, CLAUDE.md, AGENTS.md). Returns detected agents and all supported agents with best practices.",
    inputSchema: { type: "object", properties: { cwd: { type: "string" } } },
  },
  {
    name: "get_agent_guidance",
    description:
      "Get agent-specific best practices and configuration guidance. Supported agents: claude-code, cursor, windsurf, devin, codex, gemini, antigravity.",
    inputSchema: {
      type: "object",
      properties: {
        agent: { type: "string", description: "Agent name: claude-code, cursor, windsurf, devin, codex, gemini, antigravity" },
      },
    },
  },
  {
    name: "generate_starter_repo",
    description:
      "Generate a complete starter project structure with production-ready defaults: directory layout, essential packages, eslint/prettier/tsconfig/jest configs. Supports nestjs, express, fastify frameworks.",
    inputSchema: {
      type: "object",
      properties: {
        framework: { type: "string", description: "Framework: nestjs (default), express, fastify" },
        language: { type: "string", description: "Language: typescript (default), javascript" },
      },
    },
  },
];

// ─── Request handler ────────────────────────────────────────────────────────

async function handleRequest(msg) {
  const { method, params, id } = msg;
  switch (method) {
    case "initialize":
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: { name: "code-guardian", version: "2.0.0" },
        },
      };
    case "tools/list":
      return { jsonrpc: "2.0", id, result: { tools: TOOLS } };
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
          case "generate_production_code":
            result = await toolGenerateProductionCode(args);
            break;
          case "get_industry_patterns":
            result = await toolGetIndustryPatterns(args);
            break;
          case "generate_security_checklist":
            result = await toolGenerateSecurityChecklist(args);
            break;
          case "generate_github_workflow":
            result = await toolGenerateGitHubWorkflow(args);
            break;
          case "detect_agent":
            result = await toolDetectAgent(args);
            break;
          case "get_agent_guidance":
            result = await toolGetAgentGuidance(args);
            break;
          case "generate_starter_repo":
            result = await toolGenerateStarterRepo(args);
            break;
          default:
            throw new Error("Unknown tool: " + name);
        }
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
  console.error("[code-guardian v2.0.0] stdio server started");
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
