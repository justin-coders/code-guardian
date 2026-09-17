/**
 * Code Guardian v2 — Tool Registry
 *
 * Single source of truth for all 15 MCP tool definitions and dispatch.
 * Imported by both stdio-server.js and http-server.js.
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

// ─── Tool definitions ────────────────────────────────────────────────────────

export const TOOLS = [
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

// ─── Dispatch map ────────────────────────────────────────────────────────────

const HANDLERS = {
  audit_codebase: toolAuditCodebase,
  check_branch: toolCheckBranch,
  check_tests: toolCheckTests,
  check_cicd: toolCheckCICD,
  check_linting: toolCheckLinting,
  check_security: toolCheckSecurity,
  check_architecture: toolCheckArchitecture,
  production_readiness: toolProductionReadiness,
  generate_production_code: toolGenerateProductionCode,
  get_industry_patterns: toolGetIndustryPatterns,
  generate_security_checklist: toolGenerateSecurityChecklist,
  generate_github_workflow: toolGenerateGitHubWorkflow,
  detect_agent: toolDetectAgent,
  get_agent_guidance: toolGetAgentGuidance,
  generate_starter_repo: toolGenerateStarterRepo,
};

/**
 * Dispatch a tool call by name. Resolves `args.cwd` if omitted.
 * @param {string} name
 * @param {object} args
 * @returns {Promise<object>}
 */
export async function dispatchTool(name, args) {
  const handler = HANDLERS[name];
  if (!handler) throw new Error("Unknown tool: " + name);
  return await handler(args);
}
