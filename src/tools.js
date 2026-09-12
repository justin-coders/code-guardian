/**
 * Code Guardian v2 — Tools Module
 *
 * Production-readiness enforcer for all AI coding agents.
 * Works with: Claude Code, Cursor, Windsurf, Devin, Codex, Emni, Antigravity, and any MCP-capable agent.
 */

import { spawn } from "node:child_process";
import { readdir, readFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const PLUGIN_DIR = process.env.PLUGIN_DIR || dirname(fileURLToPath(import.meta.url));

// ─── IO helpers ─────────────────────────────────────────────────────────────

export function run(cmd, args = [], cwd = process.cwd()) {
  return new Promise((resolve) => {
    const proc = spawn(cmd, args, { cwd, stdio: ["ignore", "pipe", "pipe"], shell: true });
    let out = "",
      err = "";
    proc.stdout.on("data", (d) => (out += d.toString()));
    proc.stderr.on("data", (d) => (err += d.toString()));
    proc.on("close", (code) => resolve({ stdout: out, stderr: err, code: code ?? 1 }));
  });
}

export async function tryRead(path) {
  try {
    return await readFile(path, "utf8");
  } catch {
    return null;
  }
}

export async function listFiles(dir, max = 200) {
  try {
    const entries = await readdir(dir, { withFileTypes: true });
    return entries.filter((e) => e.isFile()).map((e) => e.name).slice(0, max);
  } catch {
    return [];
  }
}

export async function listDirs(dir, max = 100) {
  try {
    const entries = await readdir(dir, { withFileTypes: true });
    return entries.filter((e) => e.isDirectory()).map((e) => e.name).slice(0, max);
  } catch {
    return [];
  }
}

// ─── Industry Standard Patterns ─────────────────────────────────────────────

const INDUSTRY_PATTERNS = {
  api: {
    name: "REST API",
    description: "Industry-standard REST API with proper error handling, validation, and logging",
    checklist: [
      "Use HTTP status codes correctly (200, 201, 400, 401, 403, 404, 422, 500)",
      "Validate all input with a schema validator (Joi, Zod, Yup)",
      "Centralized error handler with consistent error response format",
      "Request logging with correlation IDs",
      "Rate limiting on public endpoints",
      "Input sanitization to prevent injection attacks",
      "Pagination, filtering, and sorting for list endpoints",
      "OpenAPI/Swagger documentation for all endpoints",
    ],
    stack: { nestjs: "Use @nestjs/swagger for OpenAPI docs + ValidationPipe with whitelist+forbidNonWhitelisted+transform", express: "Use express-validator + helmet + express-rate-limit", fastify: "Use @fastify/swagger + @fastify/jwt + @fastify/rate-limit" },
  },
  auth: {
    name: "Authentication & Authorization",
    description: "Production-grade auth following OWASP guidelines",
    checklist: [
      "Use JWT with short expiry (15min access, 7day refresh)",
      "Store tokens in HttpOnly cookies, never in localStorage",
      "Implement RBAC or ABAC for authorization",
      "Rate limit login attempts (brute-force protection)",
      "Implement account lockout after N failed attempts",
      "Use bcrypt/scrypt/argon2 for password hashing (cost >= 10)",
      "Support refresh token rotation and revocation",
      "Implement MFA/2FA for sensitive operations",
      "Log all auth events with IP and user-agent",
      "CSRF protection on state-changing endpoints",
    ],
    stack: { nestjs: "Use @nestjs/jwt + @nestjs/passport with JWT strategy + bcrypt", express: "Use express-jwt + passport-jwt + bcrypt + csurf", fastify: "Use @fastify/jwt + @fastify/passport + bcrypt" },
  },
  database: {
    name: "Database Layer",
    description: "Production database patterns with migrations and connection management",
    checklist: [
      "Use an ORM or query builder (Prisma, TypeORM, Knex)",
      "Database migrations must be versioned and reversible",
      "Connection pooling with proper min/max settings",
      "Seed data for development/testing environments only",
      "Index foreign keys and frequently queried columns",
      "Use transactions for multi-step writes",
      "Avoid N+1 queries — use eager loading or DataLoader",
      "Implement soft deletes for audit trails",
      "Use read replicas for heavy read workloads",
      "Encrypt sensitive columns at rest (AES-256)",
    ],
    stack: { prisma: "Use schema.prisma with relations, migrations, and seed.ts", typeorm: "Use Entity decorators with migrations CLI", knex: "Use migration files with up/down functions" },
  },
  testing: {
    name: "Testing Strategy",
    description: "Industry-standard testing pyramid",
    checklist: [
      "Unit tests: 80%+ coverage on business logic",
      "Integration tests: API endpoints with real DB (testcontainers)",
      "E2E tests: Critical user journeys (Playwright/Cypress)",
      "Use test naming: describe('Feature', () => { it('should...', () => {}) })",
      "Arrange-Act-Assert pattern in every test",
      "Mock external services (HTTP, DB, queues)",
      "Test edge cases: empty inputs, null values, concurrent requests",
      "Snapshot tests for complex output formats",
      "CI must run all tests before merge",
      "Track test flakiness and fix/retry with backoff",
    ],
    stack: { jest: "jest.config.ts with coverage thresholds, workers: 'auto'", vitest: "vitest.config.ts with coverage reporter: 'v8'", playwright: "e2e tests in tests/e2e/ with CI integration" },
  },
  error_handling: {
    name: "Error Handling",
    description: "Centralized, structured error handling",
    checklist: [
      "Global error handler middleware (not per-route)",
      "Custom error classes: AppError, NotFoundError, ValidationError, AuthError",
      "Consistent error response shape: { code, message, details?, stack? }",
      "Log errors with context (request ID, user ID, endpoint, payload)",
      "Never expose internal stack traces to clients in production",
      "Use Sentry/Datadog for production error tracking",
      "Implement graceful degradation for non-critical failures",
      "Circuit breaker pattern for downstream service calls",
    ],
    stack: { nestjs: "Use ExceptionFilter + @HttpException", express: "Use express-error-handler middleware", fastify: "Use fastify.setErrorHandler()" },
  },
  logging: {
    name: "Logging & Observability",
    description: "Production logging with structured format",
    checklist: [
      "Use structured logging (JSON format) — logfmt or JSON",
      "Include correlation/request ID in every log line",
      "Log levels: ERROR, WARN, INFO, DEBUG (configured per env)",
      "Never log sensitive data (passwords, tokens, PII)",
      "Centralized log aggregation (ELK, Datadog, CloudWatch, Loki)",
      "Metrics: request count, latency p99, error rate, throughput",
      "Distributed tracing (OpenTelemetry) for microservices",
      "Health check endpoint at /health with dependency status",
    ],
    stack: { winston: "winston with JSON transport + daily rotate", pino: "pino-http for Express/Fastify with target: 'pino-pretty' in dev", nestjs: "@nestjs/common Logger + winston module" },
  },
  security: {
    name: "Security Hardening",
    description: "OWASP Top 10 compliance checklist",
    checklist: [
      "Helmet.js middleware for security headers (CSP, HSTS, X-Frame)",
      "CORS: whitelist specific origins, never use '*' in production",
      "Input validation on every endpoint (never trust client)",
      "SQL injection: parameterized queries only, no string concatenation",
      "XSS prevention: sanitize output, use templating engine escapes",
      "Rate limiting: express-rate-limit or similar on all public endpoints",
      "HTTPS-only in production (HSTS header)",
      "No debug endpoints in production",
      "Regular dependency audits: npm audit, Dependabot, Snyk",
      "Security headers: X-Content-Type-Options, X-Download-Options, X-DNS-Prefetch-Control",
    ],
    stack: { nestjs: "Use @nestjs/Throttler + helmet + cors with config", express: "helmet + cors + express-rate-limit + express-mongo-sanitize", fastify: "fastify-helmet + fastify-rate-limit + fastify-cors" },
  },
  ci_cd: {
    name: "CI/CD Pipeline",
    description: "GitHub Actions production pipeline template",
    checklist: [
      "Push to main/master: lint -> test -> build -> push image -> deploy staging",
      "PR: lint -> test -> type-check (block merge on failure)",
      "Cache node_modules between runs (actions/cache)",
      "Parallel test execution (jest --maxWorkers, vitest --pool=forks)",
      "Secrets: never commit; use GitHub Actions secrets",
      "Environment-specific configs (dev/staging/prod)",
      "Blue-green or rolling deployment strategy",
      "Rollback script available and tested",
      "Post-deploy health check verification",
      "Notifications on failure (Slack, Discord, Email)",
    ],
    stack: { github_actions: ".github/workflows/ci.yml + .github/workflows/cd.yml", docker: "Multi-stage Dockerfile with Alpine base, non-root user" },
  },
  docker: {
    name: "Docker & Containerization",
    description: "Production Dockerfile and compose patterns",
    checklist: [
      "Multi-stage builds to minimize image size",
      "Use Alpine or Distroless base images",
      "Run as non-root user inside container",
      "COPY not ADD for source files",
      "Use .dockerignore to exclude node_modules, .git",
      "Pin base image tags (node:20-alpine, not node:alpine)",
      "Healthcheck instruction in Dockerfile",
      "Environment variables via docker-compose or secrets",
      "Restart policy: unless-stopped or on-failure",
      "Resource limits in docker-compose (mem_limit, cpus)",
    ],
    stack: { dockerfile: "FROM node:20-alpine, RUN apk add --no-cache curl, USER node", compose: "services: app, db, redis with healthchecks and depends_on" },
  },
  branch_strategy: {
    name: "Branch Strategy",
    description: "Git flow / trunk-based development conventions",
    checklist: [
      "Main/master is always deployable (protected branch)",
      "Feature branches: feature/xxx (one feature per branch)",
      "Bugfix branches: bugfix/xxx (linked to issue number)",
      "Hotfix branches: hotfix/xxx (urgent production fixes)",
      "Release branches: release/v1.x.x (for release prep)",
      "Pull requests required for all merges to main",
      "At least one reviewer approval required",
      "All checks must pass before merge (status checks)",
      "Squash merge for features, merge commit for releases",
      "Semantic versioning for tags: v1.0.0, v1.1.0, v2.0.0",
    ],
  },
};

// ─── Cross-Agent Configs ────────────────────────────────────────────────────

const AGENT_CONFIGS = {
  "claude-code": {
    name: "Claude Code",
    pluginSystem: true,
    mcpSupport: true,
    pluginDir: "~/.claude/plugins/",
    skillFormat: "SKILL.md frontmatter",
    bestPractices: [
      "Use MCP tools for external integrations",
      "Structure skills in ~/.claude/skills/",
      "Use hooks in settings.json for automation",
      "Add project-specific instructions in AGENTS.md or CLAUDE.md",
    ],
  },
  cursor: {
    name: "Cursor",
    pluginSystem: false,
    mcpSupport: true,
    pluginDir: null,
    skillFormat: ".cursorrules file",
    bestPractices: [
      "Add project rules to .cursorrules at repo root",
      "Use @mentions to reference files in prompts",
      "Configure custom instructions in Cursor settings",
      "Use Composer mode for multi-file changes",
    ],
  },
  windsurf: {
    name: "Windsurf (Codeium)",
    pluginSystem: false,
    mcpSupport: true,
    pluginDir: null,
    skillFormat: ".windsurfrules file",
    bestPractices: [
      "Add project rules to .windsurfrules at repo root",
      "Use Cascade for multi-step workflows",
      "Configure custom instructions in Windsurf settings",
    ],
  },
  devin: {
    name: "Devin",
    pluginSystem: false,
    mcpSupport: false,
    pluginDir: null,
    skillFormat: "Context instructions in prompt",
    bestPractices: [
      "Provide complete context in initial prompt",
      "Specify tech stack and architecture upfront",
      "Request incremental commits for large tasks",
      "Use Devin's planning phase for complex features",
    ],
  },
  codex: {
    name: "OpenAI Codex",
    pluginSystem: false,
    mcpSupport: false,
    pluginDir: null,
    skillFormat: "CLI flags or config.yaml",
    bestPractices: [
      "Use --memory-file for persistent context",
      "Specify model via --model flag",
      "Provide clear system prompts for role definition",
      "Use --diff for reviewing changes",
    ],
  },
  gemini: {
    name: "Google Gemini",
    pluginSystem: false,
    mcpSupport: false,
    pluginDir: null,
    skillFormat: "Context instructions in prompt",
    bestPractices: [
      "Set clear expectations in system prompt",
      "Request production-ready code with error handling",
      "Ask for tests alongside implementation",
    ],
  },
  antigravity: {
    name: "Antigravity",
    pluginSystem: false,
    mcpSupport: false,
    pluginDir: null,
    skillFormat: "Context instructions",
    bestPractices: [
      "Define production requirements explicitly",
      "Request compliance with industry standards",
      "Ask for documentation updates with code",
    ],
  },
};

// ─── Tool: audit_codebase ───────────────────────────────────────────────────

export async function toolAuditCodebase(args) {
  const cwd = (args.cwd || process.cwd()).toString();
  const depth = Number(args.depth || 3);
  const reports = [];

  const pkg = await tryRead(cwd + "/package.json");
  const pkgData = pkg ? JSON.parse(pkg) : null;
  reports.push({
    area: "package.json",
    severity: pkgData ? "info" : "warn",
    message: pkgData
      ? "Found package.json — name: " + pkgData.name + ", scripts: " + (Object.keys(pkgData.scripts || {}).join(", ") || "none")
      : "No package.json found. Add one with name, scripts, and engine requirements.",
  });

  const readme = await tryRead(cwd + "/README.md");
  reports.push({
    area: "documentation",
    severity: readme ? "info" : "warn",
    message: readme ? "README.md present." : "No README.md found. Add one with: setup instructions, architecture diagram, API docs link, contribution guide.",
  });

  const gitignore = await tryRead(cwd + "/.gitignore");
  reports.push({
    area: "source-control",
    severity: gitignore ? "info" : "warn",
    message: gitignore ? ".gitignore present." : "No .gitignore found. Add one excluding: node_modules, dist, .env, IDE configs, OS files.",
  });

  const eslintFiles = await listFiles(cwd);
  const hasEslint = eslintFiles.some(
    (f) => f.startsWith(".eslintrc") || f === "eslint.config.js" || f === "eslint.config.mjs" || f === "eslint.config.ts",
  );
  reports.push({
    area: "linting",
    severity: hasEslint ? "info" : "warn",
    message: hasEslint ? "ESLint config detected." : "No ESLint config found. Add eslint.config.js with: strict mode, no-unused-vars, prefer-const, no-console in prod.",
  });

  const tsconfig = await tryRead(cwd + "/tsconfig.json");
  const tsStrict = tsconfig ? JSON.parse(tsconfig).compilerOptions?.strict : false;
  reports.push({
    area: "typescript",
    severity: tsStrict ? "info" : "warn",
    message: tsStrict
      ? "tsconfig.json present with strict mode enabled."
      : "No tsconfig.json or strict mode not enabled. Add: strict: true, noUncheckedIndexedAccess: true, exactOptionalPropertyTypes: true.",
  });

  const hasTestConfig =
    (await tryRead(cwd + "/jest.config.js")) !== null ||
    (await tryRead(cwd + "/jest.config.ts")) !== null ||
    (await tryRead(cwd + "/vitest.config.ts")) !== null;
  const hasTests = eslintFiles.some((f) => f.endsWith(".test.ts") || f.endsWith(".test.tsx") || f.endsWith(".spec.ts"));
  reports.push({
    area: "testing",
    severity: hasTestConfig || hasTests ? "info" : "warn",
    message: hasTestConfig
      ? "Test config (Jest/Vitest) detected."
      : hasTests
        ? "Test files found but no config detected. Add jest.config.ts or vitest.config.ts with coverage thresholds."
        : "No test files or config found. Production projects need tests. Add jest or vitest with 80%+ coverage threshold.",
  });

  const hasCI = (await tryRead(cwd + "/.github/workflows/ci.yml")) !== null;
  reports.push({
    area: "ci-cd",
    severity: hasCI ? "info" : "warn",
    message: hasCI ? "GitHub Actions CI workflow detected." : "No .github/workflows/ci.yml found. Add CI with: lint -> test -> build on PR, deploy on main merge.",
  });

  const lockfile =
    (await tryRead(cwd + "/package-lock.json")) !== null ||
    (await tryRead(cwd + "/yarn.lock")) !== null ||
    (await tryRead(cwd + "/bun.lockb")) !== null;
  reports.push({
    area: "dependencies",
    severity: lockfile ? "info" : "warn",
    message: lockfile ? "Lock file present." : "No lock file found. Pin dependencies for reproducible builds.",
  });

  let lintResult = null;
  if (hasEslint) {
    const lint = await run("npx", ["eslint", "--max-warnings=0", "."], cwd);
    lintResult = lint.code === 0 ? { ok: true, message: "ESLint passed with no errors." } : { ok: false, message: lint.stdout || lint.stderr };
  }

  let typeResult = null;
  if (tsconfig) {
    const tsc = await run("npx", ["tsc", "--noEmit"], cwd);
    typeResult = tsc.code === 0 ? { ok: true, message: "TypeScript type-check passed." } : { ok: false, message: tsc.stdout || tsc.stderr };
  }

  return {
    tool: "audit_codebase",
    version: "2.0.0",
    reports,
    lint: lintResult,
    typescript: typeResult,
    summary: {
      totalChecks: reports.length,
      warnings: reports.filter((r) => r.severity === "warn").length,
      info: reports.filter((r) => r.severity === "info").length,
      lintPassed: lintResult?.ok,
      typescriptPassed: typeResult?.ok,
    },
    guidance: reports
      .filter((r) => r.severity === "warn")
      .map((r) => ({
        area: r.area,
        action: r.message,
        industryReference: "See patterns in " + r.area + " for production-ready examples.",
      })),
  };
}

// ─── Tool: check_branch ─────────────────────────────────────────────────────

export async function toolCheckBranch(args) {
  const cwd = (args.cwd || process.cwd()).toString();
  try {
    const { stdout } = await run("git", ["branch", "--list", "--format=%(refname:short)"], cwd);
    const branches = stdout.trim().split("\n").filter(Boolean);
    const current = branches.find((b) => b.startsWith("*"));
    const currentBranch = current ? current.replace("* ", "").trim() : null;

    const patterns = [
      { name: "feature", regex: /^feature\//, description: "New feature development" },
      { name: "bugfix", regex: /^bugfix\//, description: "Bug fixes" },
      { name: "hotfix", regex: /^hotfix\//, description: "Urgent production fixes" },
      { name: "release", regex: /^release\//, description: "Release preparation" },
      { name: "main", regex: /^(main|master)$/, description: "Production branch" },
      { name: "develop", regex: /^develop$/, description: "Integration branch" },
    ];

    const violations = [];
    if (currentBranch && currentBranch !== "main" && currentBranch !== "master" && currentBranch !== "develop") {
      const matched = patterns.some((p) => p.regex.test(currentBranch));
      if (!matched) {
        violations.push({
          branch: currentBranch,
          issue: 'Branch "' + currentBranch + '" does not match conventional patterns.',
          suggestion: "Rename to: feature/<description> or bugfix/<issue-id>",
        });
      }
    }

    return {
      tool: "check_branch",
      version: "2.0.0",
      currentBranch,
      allBranches: branches,
      patterns,
      violations,
      compliant: violations.length === 0,
      guidance: violations.map((v) => ({ ...v, industryReference: "Git Flow / Trunk-Based Development — Atlassian Git Tutorial" })),
    };
  } catch (err) {
    return { tool: "check_branch", version: "2.0.0", error: err.message };
  }
}

// ─── Tool: check_tests ──────────────────────────────────────────────────────

export async function toolCheckTests(args) {
  const cwd = (args.cwd || process.cwd()).toString();
  const reports = [];

  const { execSync } = await import("node:child_process");
  try {
    const testFiles = execSync(
      'find . -type f \\( -name "*.test.ts" -o -name "*.test.tsx" -o -name "*.spec.ts" -o -name "*.spec.tsx" \\) 2>/dev/null | head -50',
      { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
    );
    const files = testFiles.trim().split("\n").filter(Boolean);
    reports.push({ area: "test-files", count: files.length, message: "Found " + files.length + " test/spec file(s)." });

    const hasJest = (await tryRead(cwd + "/jest.config.js")) !== null || (await tryRead(cwd + "/jest.config.ts")) !== null;
    const hasVitest = (await tryRead(cwd + "/vitest.config.ts")) !== null || (await tryRead(cwd + "/vitest.config.tsx")) !== null;
    reports.push({
      area: "test-config",
      message: hasJest ? "Jest config found." : hasVitest ? "Vitest config found." : "No test framework config detected.",
      guidance: "Add coverage thresholds: collectCoverageFrom: ['src/**/*.{ts,tsx}'], coverageThreshold: { global: { branches: 80, functions: 80, lines: 80, statements: 80 } }",
    });

    let testRun = null;
    if (hasJest) {
      const r = await run("npx", ["jest", "--listTests", "--passWithNoTests"], cwd);
      testRun = { ok: r.code === 0, output: (r.stdout || r.stderr).slice(0, 500) };
    } else if (hasVitest) {
      const r = await run("npx", ["vitest", "run", "--reporter=verbose"], cwd);
      testRun = { ok: r.code === 0, output: (r.stdout || r.stderr).slice(0, 500) };
    }

    if (testRun) reports.push({ area: "test-execution", passed: testRun.ok, output: testRun.output });

    return { tool: "check_tests", version: "2.0.0", reports, passed: !reports.some((r) => r.area === "test-execution" && !r.passed) };
  } catch (err) {
    return { tool: "check_tests", version: "2.0.0", error: err.message, reports };
  }
}

// ─── Tool: check_cicd ───────────────────────────────────────────────────────

export async function toolCheckCICD(args) {
  const cwd = (args.cwd || process.cwd()).toString();
  const reports = [];

  const checks = [
    { path: ".github/workflows/ci.yml", name: "GitHub Actions CI" },
    { path: ".github/workflows/cd.yml", name: "GitHub Actions CD" },
    { path: ".github/workflows/deploy.yml", name: "GitHub Actions Deploy" },
    { path: ".gitlab-ci.yml", name: "GitLab CI" },
    { path: "Jenkinsfile", name: "Jenkinsfile" },
    { path: ".circleci/config.yml", name: "CircleCI" },
    { path: "Dockerfile", name: "Dockerfile" },
    { path: "docker-compose.yml", name: "docker-compose.yml" },
    { path: ".pre-commit-config.yaml", name: "Pre-commit hooks" },
  ];

  for (const { path: p, name } of checks) {
    const exists = (await tryRead(cwd + "/" + p)) !== null;
    reports.push({
      name,
      present: exists,
      severity: exists ? "info" : "warn",
      guidance: exists ? null : "Add " + name + ": See industry-standard template at references/ci/" + p.replace("/", "_") + ".md",
    });
  }

  const pkg = JSON.parse((await tryRead(cwd + "/package.json")) || "{}");
  const hasBuild = !!pkg.scripts?.build;
  const hasTest = !!pkg.scripts?.test;
  const hasLint = !!pkg.scripts?.lint;
  reports.push({
    name: "package-scripts",
    build: hasBuild,
    test: hasTest,
    lint: hasLint,
    severity: hasBuild && hasTest && hasLint ? "info" : "warn",
    guidance: hasBuild && hasTest && hasLint
      ? null
      : 'Add build, test, and lint scripts to package.json. Example: "build": "tsc --noEmit", "test": "jest --coverage", "lint": "eslint . --max-warnings=0"',
  });

  return { tool: "check_cicd", version: "2.0.0", reports };
}

// ─── Tool: check_linting ────────────────────────────────────────────────────

export async function toolCheckLinting(args) {
  const cwd = (args.cwd || process.cwd()).toString();
  const { execSync } = await import("node:child_process");

  const lintCmds = [
    { name: "eslint", cmd: ["npx", "eslint", "--version"] },
    { name: "prettier", cmd: ["npx", "prettier", "--version"] },
    { name: "biome", cmd: ["npx", "@biomejs/biome", "--version"] },
    { name: "oxlint", cmd: ["npx", "oxlint", "--version"] },
    { name: "stylelint", cmd: ["npx", "stylelint", "--version"] },
  ];

  const results = [];
  for (const { name, cmd } of lintCmds) {
    try {
      const ver = execSync(cmd.join(" "), { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
      results.push({ tool: name, installed: true, version: ver });
    } catch {
      results.push({ tool: name, installed: false });
    }
  }

  let eslintResults = null;
  const eslintInstalled = results.find((r) => r.tool === "eslint" && r.installed);
  if (eslintInstalled) {
    const r = await run("npx", ["eslint", ".", "--format", "compact"], cwd);
    eslintResults = { passed: r.code === 0, output: (r.stdout || r.stderr).slice(0, 2000) };
  }

  return { tool: "check_linting", version: "2.0.0", linterVersions: results, eslint: eslintResults };
}

// ─── Tool: check_security ───────────────────────────────────────────────────

export async function toolCheckSecurity(args) {
  const cwd = (args.cwd || process.cwd()).toString();
  const reports = [];

  const envFiles = await listFiles(cwd);
  const hasEnv = envFiles.some((f) => f === ".env" || f.startsWith(".env."));
  reports.push({
    area: "secret-management",
    severity: hasEnv ? "warn" : "info",
    message: hasEnv ? ".env file(s) found at project root. Ensure they are in .gitignore." : "No .env files at project root.",
    guidance: hasEnv ? "Add .env to .gitignore immediately. Use dotenv-safe or similar for env validation." : null,
  });

  const gitLog = await run("git", ["log", "--oneline", "-20"], cwd);
  reports.push({
    area: "git-history",
    recentCommits: gitLog.stdout.trim().split("\n").filter(Boolean).length,
    message: gitLog.stdout.trim().split("\n").filter(Boolean).length + " recent commit(s) found.",
  });

  const pkg = await tryRead(cwd + "/package.json");
  if (pkg) {
    const audit = await run("npm", ["audit", "--production"], cwd);
    const parsed = (() => {
      try {
        return JSON.parse(audit.stdout);
      } catch {
        return null;
      }
    })();
    if (parsed) {
      const totalVulns = (parsed.fine || 0) + (parsed.low || 0) + (parsed.moderate || 0) + (parsed.high || 0) + (parsed.critical || 0);
      reports.push({
        area: "dependency-security",
        vulnerabilities: totalVulns,
        fine: parsed.fine || 0,
        low: parsed.low || 0,
        moderate: parsed.moderate || 0,
        high: parsed.high || 0,
        critical: parsed.critical || 0,
        severity: totalVulns === 0 ? "info" : totalVulns <= 5 ? "warn" : "error",
        guidance: totalVulns > 0 ? "Fix " + totalVulns + " vulnerabilities: npm audit fix (low), manual review required for high/critical." : null,
      });
    } else {
      reports.push({ area: "dependency-security", rawOutput: audit.stdout.slice(0, 500) });
    }
  }

  return { tool: "check_security", version: "2.0.0", reports };
}

// ─── Tool: check_architecture ───────────────────────────────────────────────

export async function toolCheckArchitecture(args) {
  const cwd = (args.cwd || process.cwd()).toString();
  const depth = Number(args.depth || 2);
  const reports = [];

  try {
    const { execSync } = await import("node:child_process");
    const tree = execSync("find . -maxdepth " + depth + " -type d | grep -v node_modules | grep -v '.git' | sort", { cwd, encoding: "utf8" });
    const dirs = tree.trim().split("\n").filter(Boolean);
    reports.push({ area: "directory-structure", directories: dirs.slice(0, 30) });

    const hasSrc = dirs.some((d) => d.includes("/src") || d === "./src");
    const hasTests = dirs.some((d) => d.includes("test") || d.includes("spec") || d.includes("__tests__"));
    const hasDist = dirs.some((d) => d.includes("dist") || d.includes("build"));
    const hasDocs = dirs.some((d) => d.includes("docs") || d === "./docs");

    const structureReport = {
      area: "structure-convention",
      hasSrc,
      hasTests,
      hasDist,
      hasDocs,
      warnings: [],
    };
    if (!hasSrc) structureReport.warnings.push("No src/ directory found — consider organizing source code into src/ with subdirectories: src/controllers, src/services, src/middleware, src/types, src/utils.");
    if (!hasTests) structureReport.warnings.push("No test directory found. Add tests/ or __tests__/ at project root.");
    if (!hasDocs) structureReport.warnings.push("No docs/ directory found. Add docs/ for architecture docs, API reference, deployment guide.");
    reports.push(structureReport);
  } catch (err) {
    reports.push({ area: "architecture", error: err.message });
  }

  const workspacePkg = await tryRead(cwd + "/package.json");
  const hasWorkspaces = workspacePkg ? JSON.parse(workspacePkg).workspaces !== undefined : false;
  const hasNx = (await tryRead(cwd + "/nx.json")) !== null;
  const hasLerna = (await tryRead(cwd + "/lerna.json")) !== null;
  reports.push({
    area: "monorepo",
    workspacePackageJson: hasWorkspaces,
    nxConfigured: hasNx,
    lernaConfigured: hasLerna,
    guidance: hasWorkspaces ? null : "For multi-package projects, consider Turborepo or Nx for build caching and task orchestration.",
  });

  return { tool: "check_architecture", version: "2.0.0", reports };
}

// ─── Tool: production_readiness ─────────────────────────────────────────────

export async function toolProductionReadiness(args) {
  const cwd = (args.cwd || process.cwd()).toString();
  const items = [];
  const add = (check, passed, detail, guidance = null) => items.push({ check, passed, detail, guidance });

  const pkg = await tryRead(cwd + "/package.json");
  add(
    "package.json exists",
    !!pkg,
    pkg ? "name: " + JSON.parse(pkg).name : "missing",
    "Add package.json with name, version, scripts (build, test, lint, start), and engines (node >= 18).",
  );

  const hasLock =
    (await tryRead(cwd + "/package-lock.json")) !== null ||
    (await tryRead(cwd + "/yarn.lock")) !== null ||
    (await tryRead(cwd + "/bun.lockb")) !== null;
  add("Lock file present", hasLock, hasLock ? "dependency versions pinned" : "dependencies not pinned", "Run npm install to generate package-lock.json for reproducible builds.");

  const readme = await tryRead(cwd + "/README.md");
  add("README.md present", !!readme, readme ? "project documented" : "no documentation", "Add README with: project description, quickstart, architecture overview, API docs link, contribution guide.");

  const gitignore = await tryRead(cwd + "/.gitignore");
  add(".gitignore present", !!gitignore, gitignore ? "build artifacts excluded" : "risk of committing sensitive files", "Add .gitignore excluding: node_modules/, dist/, .env*, *.log, .DS_Store.");

  const eslintFiles = await listFiles(cwd);
  const hasEslint = eslintFiles.some((f) => f.startsWith(".eslintrc") || f === "eslint.config.js" || f === "eslint.config.mjs");
  add("ESLint configured", hasEslint, hasEslint ? "code quality enforced" : "no linter", "Add eslint.config.js with strict mode, no-unused-vars, prefer-const, no-console in prod.");

  const tsconfig = await tryRead(cwd + "/tsconfig.json");
  const strict = tsconfig ? JSON.parse(tsconfig).compilerOptions?.strict : false;
  add(
    "TypeScript strict mode",
    !!strict,
    strict ? "strict type checking enabled" : "strict mode not enabled",
    "Enable strict: true, noUncheckedIndexedAccess: true, exactOptionalPropertyTypes: true in tsconfig.json.",
  );

  const hasTests = eslintFiles.some((f) => f.endsWith(".test.ts") || f.endsWith(".spec.ts"));
  add("Test files present", hasTests, hasTests ? "tests exist" : "no tests found", "Add tests with 80%+ coverage. Use Arrange-Act-Assert pattern. Mock external dependencies.");

  const hasCI = (await tryRead(cwd + "/.github/workflows/ci.yml")) !== null;
  add("CI/CD pipeline", hasCI, hasCI ? "GitHub Actions CI detected" : "no CI pipeline", "Add .github/workflows/ci.yml with: lint, test, type-check on PR. Deploy on main merge.");

  const hasEnv = eslintFiles.some((f) => f === ".env" || f.startsWith(".env."));
  add("No .env at root", !hasEnv, hasEnv ? "WARNING: .env files should not be committed" : "clean", hasEnv ? "Add .env to .gitignore immediately. Use dotenv-safe for env validation." : null);

  const pkgData = pkg ? JSON.parse(pkg) : {};
  add("Build script defined", !!pkgData.scripts?.build, pkgData.scripts?.build ? pkgData.scripts.build : "missing", 'Add "build": "tsc --noEmit" or framework-specific build command to package.json scripts.');

  const total = items.length;
  const passed = items.filter((i) => i.passed).length;
  const pct = total > 0 ? Math.round((passed / total) * 100) : 0;
  const grade = pct >= 90 ? "A" : pct >= 75 ? "B" : pct >= 60 ? "C" : pct >= 40 ? "D" : "F";

  return {
    tool: "production_readiness",
    version: "2.0.0",
    score: { total, passed, percentage: pct, grade },
    items,
    gradeExplanation: {
      A: "Production-ready. Minor improvements may exist.",
      B: "Good. Address warnings before shipping.",
      C: "Partial. Significant gaps need remediation.",
      D: "Below standard. Major improvements required.",
      F: "Not production-ready. Comprehensive remediation needed.",
    }[grade],
  };
}

// ─── Tool: generate_production_code ─────────────────────────────────────────

export async function toolGenerateProductionCode(args = {}) {
  const { feature, stack, language = "typescript" } = args;
  const pattern = INDUSTRY_PATTERNS[feature];

  if (!pattern) {
    return {
      tool: "generate_production_code",
      version: "2.0.0",
      error: "Unknown feature: " + feature + ". Available: " + Object.keys(INDUSTRY_PATTERNS).join(", "),
    };
  }

  const stackKey = stack
    ? Object.keys(pattern.stack || {}).find((k) => stack.toLowerCase().includes(k))
    : Object.keys(pattern.stack || {})[0];
  const stackGuidance = stackKey ? pattern.stack[stackKey] : null;

  return {
    tool: "generate_production_code",
    version: "2.0.0",
    feature,
    pattern: pattern.name,
    industryStandard: pattern.description,
    checklist: pattern.checklist,
    stackGuidance,
    template: getProductionTemplate(feature, stack || "default", language),
  };
}

// ─── Tool: get_industry_patterns ────────────────────────────────────────────

export async function toolGetIndustryPatterns(args = {}) {
  const { category } = args;
  if (category && INDUSTRY_PATTERNS[category]) {
    const p = INDUSTRY_PATTERNS[category];
    return { tool: "get_industry_patterns", version: "2.0.0", category, pattern: p };
  }
  return {
    tool: "get_industry_patterns",
    version: "2.0.0",
    patterns: Object.entries(INDUSTRY_PATTERNS).map(([key, p]) => ({ key, name: p.name, description: p.description })),
  };
}

// ─── Tool: generate_security_checklist ──────────────────────────────────────

export async function toolGenerateSecurityChecklist(args = {}) {
  const cwd = (args.cwd || process.cwd()).toString();
  const stack = await detectStack(cwd);
  const security = INDUSTRY_PATTERNS.security;
  const report = await toolCheckSecurity({ cwd });

  return {
    tool: "generate_security_checklist",
    version: "2.0.0",
    stack,
    checklist: security.checklist,
    currentFindings: report.reports,
    recommendations: generateSecurityRecommendations(report.reports, stack),
  };
}

// ─── Tool: generate_github_workflow ─────────────────────────────────────────

export async function toolGenerateGitHubWorkflow(args = {}) {
  const { stack, deployTarget = "docker", name = "ci" } = args;
  return { tool: "generate_github_workflow", version: "2.0.0", workflow: generateGitHubWorkflow(stack, deployTarget, name), filename: ".github/workflows/" + name + ".yml" };
}

// ─── Tool: detect_agent ─────────────────────────────────────────────────────

export async function toolDetectAgent(args = {}) {
  const cwd = (args.cwd || process.cwd()).toString();
  const agents = [];

  const cursorRules = await tryRead(cwd + "/.cursorrules");
  if (cursorRules) agents.push({ name: "cursor", detected: true, configPresent: true });

  const windsurfRules = await tryRead(cwd + "/.windsurfrules");
  if (windsurfRules) agents.push({ name: "windsurf", detected: true, configPresent: true });

  const claudeMd = await tryRead(cwd + "/CLAUDE.md") || (await tryRead(cwd + "/AGENTS.md"));
  if (claudeMd) agents.push({ name: "claude-code", detected: true, configPresent: true });

  return { tool: "detect_agent", version: "2.0.0", detectedAgents: agents, allSupportedAgents: Object.keys(AGENT_CONFIGS).map((k) => ({ name: k, ...AGENT_CONFIGS[k] })) };
}

// ─── Tool: get_agent_guidance ───────────────────────────────────────────────

export async function toolGetAgentGuidance(args = {}) {
  const { agent } = args;
  const config = AGENT_CONFIGS[agent];
  if (!config) {
    return { tool: "get_agent_guidance", version: "2.0.0", error: "Unknown agent: " + agent + ". Supported: " + Object.keys(AGENT_CONFIGS).join(", ") };
  }
  return { tool: "get_agent_guidance", version: "2.0.0", agent, config };
}

// ─── Tool: generate_starter_repo ────────────────────────────────────────────

export async function toolGenerateStarterRepo(args = {}) {
  const { framework = "nestjs", language = "typescript" } = args;
  return {
    tool: "generate_starter_repo",
    version: "2.0.0",
    framework,
    language,
    recommendedStructure: getRecommendedStructure(framework, language),
    essentialPackages: getEssentialPackages(framework, language),
    productionConfig: getProductionConfig(framework, language),
  };
}

// ─── Helpers ────────────────────────────────────────────────────────────────

async function detectStack(cwd) {
  const hasNest = (await tryRead(cwd + "/nest-cli.json")) !== null;
  const pkgData = JSON.parse((await tryRead(cwd + "/package.json")) || "{}");
  const hasExpress = !!pkgData.dependencies?.express;
  const hasFastify = !!pkgData.dependencies?.fastify;
  if (hasNest) return "nestjs";
  if (hasFastify) return "fastify";
  if (hasExpress) return "express";
  return "unknown";
}

function getProductionTemplate(feature, stack, language) {
  const snippets = {
    api_nestjs: [
      "import { Controller, Get, Post, Put, Delete, Param, Body, Query, HttpCode, HttpStatus, UseInterceptors, ClassSerializerInterceptor } from '@nestjs/common';",
      "import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';",
      "import { ValidationPipe } from '@nestjs/common';",
      "@ApiTags('tests')",
      "@Controller('tests')",
      "@UseInterceptors(ClassSerializerInterceptor)",
      "export class TestsController {",
      "  constructor(private readonly testsService: TestsService) {}",
      "  @Post()",
      "  @HttpCode(HttpStatus.CREATED)",
      "  @ApiOperation({ summary: 'Create a new test' })",
      "  @ApiResponse({ status: 201, description: 'Test created successfully' })",
      "  @ApiResponse({ status: 400, description: 'Bad request' })",
      "  @ApiBearerAuth()",
      "  async create(@Body(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true })) dto: CreateTestDto) {",
      "    return this.testsService.create(dto);",
      "  }",
      "}",
    ],
    api_express: [
      "import { Router, Request, Response, NextFunction } from 'express';",
      "import { z } from 'zod';",
      "import { celebrate, Segments, Joi } from 'celebrate';",
      "import { AppError } from '../../errors/AppError';",
      "const router = Router();",
      "const createTestSchema = z.object({",
      "  title: z.string().min(1).max(255),",
      "  description: z.string().min(1),",
      "  durationMinutes: z.number().int().positive(),",
      "});",
      "router.post('/tests', celebrate({ [Segments.BODY]: createTestSchema.shape }), async (req, res, next) => {",
      "  try {",
      "    const data = createTestSchema.parse(req.body);",
      "    const test = await testsService.create(data);",
      "    res.status(201).json({ data: test });",
      "  } catch (error) {",
      "    if (error instanceof z.ZodError) return next(new AppError('Validation failed', 400, error.errors));",
      "    next(error);",
      "  }",
      "});",
    ],
    auth_nestjs: [
      "import { Injectable, UnauthorizedException } from '@nestjs/common';",
      "import { PassportStrategy } from '@nestjs/passport';",
      "import { ExtractJwt, Strategy } from 'passport-jwt';",
      "@Injectable()",
      "export class JwtStrategy extends PassportStrategy(Strategy) {",
      "  constructor(private authService: AuthService) {",
      "    super({",
      "      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),",
      "      ignoreExpiration: false,",
      "      secretOrKey: process.env.JWT_SECRET,",
      "    });",
      "  }",
      "  async validate(payload) {",
      "    const user = await this.authService.validatePayload(payload);",
      "    if (!user) throw new UnauthorizedException('Invalid token');",
      "    return user;",
      "  }",
      "}",
    ],
    auth_express: [
      "const jwt = require('jsonwebtoken');",
      "const JWT_SECRET = process.env.JWT_SECRET;",
      "const JWT_EXPIRES_IN = '15m';",
      "function generateTokens(userId, email) {",
      "  const accessToken = jwt.sign({ sub: userId, email }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });",
      "  const refreshToken = jwt.sign({ sub: userId, email }, JWT_SECRET, { expiresIn: '7d' });",
      "  return { accessToken, refreshToken };",
      "}",
      "function authMiddleware(req, res, next) {",
      "  const authHeader = req.headers.authorization;",
      "  if (!authHeader?.startsWith('Bearer ')) return next(new UnauthorizedError('Missing auth header'));",
      "  const token = authHeader.split(' ')[1];",
      "  try { req.user = jwt.verify(token, JWT_SECRET); next(); }",
      "  catch (err) { next(err.name === 'TokenExpiredError' ? new UnauthorizedError('Token expired') : new UnauthorizedError('Invalid token')); }",
      "}",
    ],
    error_nestjs: [
      "import { ExceptionFilter, Catch, ArgumentsHost, HttpException } from '@nestjs/common';",
      "import { Request, Response } from 'express';",
      "@Catch()",
      "export class AllExceptionsFilter implements ExceptionFilter {",
      "  catch(exception: unknown, host: ArgumentsHost) {",
      "    const ctx = host.switchToHttp();",
      "    const response = ctx.getResponse<Response>();",
      "    const status = exception instanceof HttpException ? exception.getStatus() : 500;",
      "    const message = exception instanceof HttpException ? exception.message : 'Internal server error';",
      "    response.status(status).json({ statusCode: status, message, timestamp: new Date().toISOString() });",
      "  }",
      "}",
    ],
    error_express: [
      "function errorMiddleware(err, req, res, next) {",
      "  const status = err.status || 500;",
      "  const message = process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message;",
      "  console.error('[ERROR]', { requestId: req.id, message, stack: err.stack });",
      "  res.status(status).json({ code: status, message, details: process.env.NODE_ENV !== 'production' ? err.details : undefined });",
      "}",
    ],
    logging_winston: [
      "const winston = require('winston');",
      "const logger = winston.createLogger({",
      "  level: 'info',",
      "  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),",
      "  defaultMeta: { service: 'api' },",
      "  transports: [",
      "    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),",
      "    new winston.transports.File({ filename: 'logs/combined.log' }),",
      "  ],",
      "});",
      "if (process.env.NODE_ENV !== 'production') {",
      "  logger.add(new winston.transports.Console({ format: winston.format.simple() }));",
      "}",
    ],
    logging_pino: [
      "const pino = require('pino');",
      "const logger = pino({",
      "  level: process.env.LOG_LEVEL || 'info',",
      "  formatters: { level: (label) => ({ level: label }) },",
      "  timestamp: pino.stdTimeFunctions.isoTime,",
      "});",
      "// With express:",
      "const pinoHttp = require('pino-http')({ logger });",
    ],
    dockerfile: [
      "FROM node:20-alpine AS builder",
      "WORKDIR /app",
      "COPY package*.json ./",
      "RUN npm ci --only=production",
      "COPY . .",
      "RUN npm run build",
      "",
      "FROM node:20-alpine AS runner",
      "WORKDIR /app",
      "RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001",
      "COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist",
      "COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules",
      "COPY --from=builder --chown=nodejs:nodejs /app/package.json ./",
      "USER nodejs",
      "EXPOSE 3001",
      "HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost:3001/health || exit 1",
      "CMD [\"node\", \"dist/main\"]",
    ],
    dockercompose: [
      "version: '3.8'",
      "services:",
      "  app:",
      "    build: .",
      "    ports: ['3001:3001']",
      "    environment:",
      "      - NODE_ENV=production",
      "      - DATABASE_URL=${DATABASE_URL}",
      "    depends_on:",
      "      db:",
      "        condition: service_healthy",
      "    restart: unless-stopped",
      "    mem_limit: 512m",
      "    cpus: 1.0",
      "  db:",
      "    image: postgres:16-alpine",
      "    environment:",
      "      - POSTGRES_USER=${PG_USER}",
      "      - POSTGRES_PASSWORD=${PG_PASSWORD}",
      "      - POSTGRES_DB=${PG_DB}",
      "    volumes: ['pgdata:/var/lib/postgresql/data']",
      "    healthcheck: { test: ['CMD-SHELL', 'pg_isready -U $$POSTGRES_USER'], interval: 10s, timeout: 5s, retries: 5 }",
      "volumes: { pgdata: }",
    ],
    github_ci: [
      "name: CI",
      "on:",
      "  push: { branches: [main, master, develop] }",
      "  pull_request: { branches: [main, master] }",
      "jobs:",
      "  lint:",
      "    runs-on: ubuntu-latest",
      "    steps: [{ uses: actions/checkout@v4 }, { uses: actions/setup-node@v4, with: { node-version: '20', cache: 'npm' } }, { run: npm ci }, { run: npm run lint }]",
      "  type-check:",
      "    runs-on: ubuntu-latest",
      "    steps: [{ uses: actions/checkout@v4 }, { uses: actions/setup-node@v4, with: { node-version: '20', cache: 'npm' } }, { run: npm ci }, { run: npx tsc --noEmit }]",
      "  test:",
      "    runs-on: ubuntu-latest",
      "    needs: [lint, type-check]",
      "    steps:",
      "      - { uses: actions/checkout@v4 }",
      "      - { uses: actions/setup-node@v4, with: { node-version: '20', cache: 'npm' } }",
      "      - { run: npm ci }",
      "      - { run: npm test -- --coverage }",
      "      - { uses: codecov/codecov-action@v3 }",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    needs: [test]",
      "    steps:",
      "      - { uses: actions/checkout@v4 }",
      "      - { uses: actions/setup-node@v4, with: { node-version: '20', cache: 'npm' } }",
      "      - { run: npm ci }",
      "      - { run: npm run build }",
    ],
    prisma_schema: [
      "generator client { provider = 'prisma-client-js' }",
      "datasource db { provider = 'postgresql', url = env('DATABASE_URL') }",
      "model User {",
      "  id        String   @id @default(cuid())",
      "  email     String   @unique",
      "  password  String",
      "  role      String   @default('user')",
      "  createdAt DateTime @default(now())",
      "  updatedAt DateTime @updatedAt",
      "  tests     Test[]",
      "}",
      "model Test {",
      "  id            String   @id @default(cuid())",
      "  title         String",
      "  description   String",
      "  durationMinutes Int    @default(60)",
      "  isActive      Boolean  @default(true)",
      "  createdAt     DateTime @default(now())",
      "  updatedAt     DateTime @updatedAt",
      "  createdBy     String",
      "}",
    ],
    jest_config: [
      "export default {",
      "  testEnvironment: 'node',",
      "  testMatch: ['**/*.test.ts', '**/*.spec.ts'],",
      "  collectCoverageFrom: ['src/**/*.{ts,tsx}'],",
      "  coverageThreshold: {",
      "    global: { branches: 80, functions: 80, lines: 80, statements: 80 },",
      "  },",
      "  moduleNameMapper: { '^@/(.*)$': '<rootDir>/src/$1' },",
      "  setupFilesAfterEnv: ['<rootDir>/test/setup.ts'],",
      "};",
    ],
    eslint_config: [
      "import tseslint from 'eslint-plugin-typescript-eslint';",
      "export default [",
      "  { ignores: ['dist/', 'node_modules/'] },",
      "  { files: ['**/*.ts', '**/*.tsx'] },",
      "  tseslint.configs.recommended,",
      "  {",
      "    rules: {",
      "      '@typescript-eslint/no-unused-vars': 'error',",
      "      '@typescript-eslint/require-await': 'error',",
      "      '@typescript-eslint/no-non-null-assertion': 'warn',",
      "      'no-console': process.env.NODE_ENV === 'production' ? 'error' : 'warn',",
      "      'prefer-const': 'error',",
      "    },",
      "  },",
      "];",
    ],
    prettier_config: [
      "{",
      "  semi: true,",
      "  trailingComma: 'es5',",
      "  singleQuote: true,",
      "  printWidth: 120,",
      "  tabWidth: 2,",
      "}",
    ],
    swagger_config: [
      "import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';",
      "export function setupSwagger(app) {",
      "  const config = new DocumentBuilder()",
      "    .setTitle('API')",
      "    .setDescription('Production API')",
      "    .setVersion('1.0')",
      "    .addBearerAuth()",
      "    .build();",
      "  const document = SwaggerModule.createDocument(app, config);",
      "  SwaggerModule.setup('/api', app, document);",
      "}",
    ],
    health_check: [
      "import { Controller, Get } from '@nestjs/common';",
      "import { HealthCheck, HealthCheckService, SqlHealthIndicator, HttpHealthIndicator } from '@nestjs/terminus';",
      "@Controller('health')",
      "export class HealthController {",
      "  constructor(private health: HealthCheckService, private db: SqlHealthIndicator, private http: HttpHealthIndicator) {}",
      "  @Get()",
      "  @HealthCheck()",
      "  check() {",
      "    return this.health.check([",
      "      () => this.db.checkDatabase('db', { timeout: 3000 }),",
      "      () => this.http.pingCheck('api', 'https://api.example.com/health'),",
      "    ]);",
      "  }",
      "}",
    ],
  };

  const key = feature + "_" + stack;
  return snippets[key] || snippets[feature] || ["// Production-ready " + feature + " template for " + stack, "// Follow industry checklist:"];
}

function generateSecurityRecommendations(reports, stack) {
  const recs = [];
  const vulnReport = reports.find((r) => r.area === "dependency-security");
  if (vulnReport && vulnReport.critical > 0) recs.push({ severity: "critical", action: "Fix " + vulnReport.critical + " critical vulnerability(ies) immediately. Do not ship until resolved." });
  if (vulnReport && vulnReport.high > 0) recs.push({ severity: "high", action: "Review and fix " + vulnReport.high + " high-severity vulnerability(ies)." });
  recs.push({ severity: "info", action: "Add helmet middleware for security headers.", stack });
  recs.push({ severity: "info", action: "Configure CORS with specific origins (never '*').", stack });
  recs.push({ severity: "info", action: "Add rate limiting on all public endpoints.", stack });
  recs.push({ severity: "info", action: "Use parameterized queries only (no string concatenation for SQL).", stack });
  recs.push({ severity: "info", action: "Implement CSRF protection for state-changing operations.", stack });
  return recs;
}

function getRecommendedStructure(framework, language) {
  const base = { "src/": "Application source code", "tests/": "Test files (unit, integration, e2e)", "docs/": "Documentation", ".github/workflows/": "CI/CD pipelines" };
  if (framework === "nestjs") {
    base["src/controllers/"] = "Route handlers";
    base["src/services/"] = "Business logic";
    base["src/middleware/"] = "Middleware";
    base["src/types/"] = "TypeScript type definitions";
    base["src/utils/"] = "Utility functions";
    base["src/decorators/"] = "Custom decorators";
    base["src/filters/"] = "Exception filters";
    base["src/guards/"] = "Auth guards";
    base["src/interceptors/"] = "Request interceptors";
    base["src/modules/"] = "NestJS modules";
    base["src/dto/"] = "Data Transfer Objects";
    base["src/entities/"] = "Database entities/models";
  }
  return base;
}

function getEssentialPackages(framework, language) {
  const base = { dev: ["typescript", "eslint", "prettier", "jest", "ts-jest", "@types/node"], prod: [] };
  if (framework === "nestjs") {
    base.prod = ["@nestjs/core", "@nestjs/common", "@nestjs/platform-express", "@nestjs/jwt", "@nestjs/passport", "passport", "class-validator", "class-transformer", "zod", "prisma", "@prisma/client", "winston", "helmet", "cors", "express-rate-limit"];
    base.dev = [...base.dev, "@nestjs/cli", "@nestjs/schematics", "@nestjs/testing", "@types/jest", "supertest", "jest-environment-node"];
  }
  return base;
}

function getProductionConfig(framework, language) {
  return {
    node: { engine: ">=18.0.0", pm2: true },
    typescript: { strict: true, noUncheckedIndexedAccess: true, exactOptionalPropertyTypes: true },
    eslint: { extends: ["eslint:recommended", "plugin:@typescript-eslint/recommended"], rules: { "no-console": "warn", "prefer-const": "error" } },
    prettier: { semi: true, trailingComma: "es5", singleQuote: true, printWidth: 120 },
    jest: { testEnvironment: "node", collectCoverageFrom: ["src/**/*.{ts,tsx}"], coverageThreshold: { global: { branches: 80, functions: 80, lines: 80, statements: 80 } } },
  };
}

function generateGitHubWorkflow(stack, deployTarget, name) {
  return `name: ${name}

on:
  push:
    branches: [main, master, develop]
  pull_request:
    branches: [main, master]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      - run: npm ci
      - run: npm run lint

  type-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      - run: npm ci
      - run: npx tsc --noEmit

  test:
    runs-on: ubuntu-latest
    needs: [lint, type-check]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      - run: npm ci
      - run: npm test -- --coverage
      - name: Upload coverage
        uses: codecov/codecov-action@v3

  build:
    runs-on: ubuntu-latest
    needs: [test]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      - run: npm ci
      - run: npm run build`;
}
