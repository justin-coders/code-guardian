# Code Guardian

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js >= 18](https://img.shields.io/badge/node-%3E%3D18-green.svg)](https://nodejs.org)
[![Tests](https://img.shields.io/badge/tests-46_passing-brightgreen.svg)](tests/)
[![MCP Ready](https://img.shields.io/badge/MCP-compatible-blue.svg)](https://modelcontextprotocol.io)

> **Stop shipping code that isn't ready for production.** Code Guardian audits your project against industry standards, generates production-ready patterns, and enforces quality gates — across every AI coding agent.

## What is this?

You're building an app. You ask an AI agent to write code. It delivers something that *works* — but doesn't have tests, error handling, CI/CD, security headers, or proper logging. You ship it, and three days later production burns down.

**Code Guardian exists to fix that.**

It's an MCP plugin that gives every AI coding agent (Claude Code, Cursor, Windsurf, Devin, Codex, Gemini, Antigravity) built-in knowledge of **what production-ready code actually looks like**. Before any feature is implemented, it audits the project. After any change, it checks whether it meets industry standards. And when you need to start fresh, it generates complete project scaffolds with zero guesswork.

Think of it as a senior engineer who reviews every line of code the AI writes — but automated, instant, and consistent.

## Supported Agents

Works with every major AI coding agent out of the box:

| Agent | Integration | How it works |
|---|---|---|
| [**Claude Code**](https://claude.ai/code) | Plugin | Auto-installed, zero config |
| [**Cursor**](https://cursor.sh) | MCP Server | Add to `~/.cursor/mcp.json` |
| [**Windsurf**](https://windsurf.com) | MCP Server | Add to `~/.windsurf/mcp.json` |
| [**Devin**](https://devin.ai) | Context | Follow agent-specific guidance |
| [**Codex**](https://openai.com/index/codex/) | CLI | Use with memory files & flags |
| [**Gemini**](https://gemini.google.com) | Context | Set expectations in system prompt |
| [**Antigravity**](https://antigravity.sh) | Context | Define requirements explicitly |

## Quick Start

### Claude Code — Step-by-step install

Code Guardian ships as a Claude Code plugin. Here's how to get it working:

**1. Clone this repo**
```bash
git clone https://github.com/justin-coders/code-guardian.git
cd code-guardian
```

**2. Copy the plugin into Claude Code's cache**
```bash
cp -r v1 ~/.claude/plugins/cache/claude-plugins-official/code-guardian/v1
```

**3. Register the plugin**
Add this entry to `~/.claude/plugins/installed_plugins.json`:
```json
{
  "code-guardian": [
    {
      "scope": "user",
      "installPath": "~/.claude/plugins/cache/claude-plugins-official/code-guardian/v1",
      "version": "2.0.0"
    }
  ]
}
```

**4. Restart Claude Code**

Close all Claude Code windows and reopen. The plugin loads automatically.

**5. Start using it**
Just ask naturally:
```
"Audit this project for production readiness"
"Generate a production REST API with NestJS and Zod validation"
"Show me the industry standard for JWT authentication"
"Create a GitHub Actions CI/CD pipeline for my Express app"
```

### Cursor — Quick add

Add one entry to your `~/.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "code-guardian": {
      "command": "node",
      "args": ["/absolute/path/to/code-guardian/v1/src/stdio-server.js"]
    }
  }
}
```
Restart Cursor. The tools are now available in your prompts.

### Windsurf — Same as Cursor

Add the same MCP config to `~/.windsurf/mcp.json`.

### Other agents (Devin, Codex, Gemini, Antigravity)

These agents don't support MCP plugins directly. Use Code Guardian as a standalone tool — clone the repo and run it, then paste the output into your agent's context, or follow the agent-specific guidance in [INSTALLATION.md](INSTALLATION.md).

## What It Does

### 1. Audit Everything

Run a full production-readiness audit on any project in seconds:

```
> "Audit this project"
```

Covers 10 dimensions and gives you an **A–F grade** with specific remediation steps for every failure:

| Dimension | What it checks |
|---|---|
| `package.json` | Scripts, engines, name, version |
| Lock file | Dependency pinning for reproducible builds |
| README | Documentation quality |
| `.gitignore` | Sensitive files excluded |
| ESLint | Code quality enforcement |
| TypeScript strict mode | Type safety settings |
| Tests | Coverage and framework config |
| CI/CD | Pipeline detection |
| `.env` safety | Secret management |
| Build script | Deployment readiness |

### 2. Generate Production-Ready Code

Stop copying Stack Overflow snippets. Get templates that follow industry conventions:

```
> "Generate a production REST API with NestJS"
> "Create a JWT auth module for Express"
> "Generate a Dockerfile for my NestJS app"
```

Available templates:

| Feature | Frameworks | What's included |
|---|---|---|
| **REST API** | NestJS, Express, Fastify | Controllers, DTOs, validation, Swagger docs, pagination |
| **Authentication** | NestJS, Express | JWT, refresh tokens, RBAC, MFA, brute-force protection |
| **Database** | Prisma, TypeORM, Knex | Migrations, connection pooling, soft deletes, indexing |
| **Error Handling** | All frameworks | Global handlers, custom error classes, structured logging |
| **Logging** | Winston, Pino | JSON structured logs, correlation IDs, log levels |
| **Security** | All frameworks | OWASP Top 10, helmet, CORS, rate limiting, input sanitization |
| **CI/CD** | GitHub Actions | Lint → test → build → deploy pipeline with caching |
| **Docker** | Docker | Multi-stage builds, non-root user, healthchecks, compose |
| **Testing** | Jest, Vitest | 80% coverage thresholds, Arrange-Act-Assert, mock strategies |
| **Branch Strategy** | Git | Feature/bugfix/hotfix/release patterns, PR requirements |

### 3. Enforce Standards

Every tool includes **remediation guidance** — not just "you failed X", but "here's exactly how to fix it":

```
❌ Missing ESLint
→ Add eslint.config.js with: strict mode, no-unused-vars, prefer-const, no-console in prod

❌ No TypeScript strict mode
→ Enable: strict: true, noUncheckedIndexedAccess: true, exactOptionalPropertyTypes: true

❌ No CI pipeline
→ Add .github/workflows/ci.yml with: lint → test → type-check on PR, deploy on main merge
```

### 4. Know Your Agent

Auto-detects which AI agent you're using and surfaces the right best practices:

```
> "What's the best way to use Code Guardian with Cursor?"
> "Detect which agent I'm using"
```

Each agent gets tailored guidance on plugin structure, configuration files, and workflows.

## 10 Industry Pattern Categories

Built-in knowledge of production standards across every major concern:

1. **REST API** — Correct HTTP status codes, schema validation, pagination, OpenAPI/Swagger docs
2. **Authentication** — JWT with short expiry, RBAC, MFA, token rotation, CSRF protection, brute-force mitigation
3. **Database** — Versioned migrations, connection pooling, N+1 query prevention, soft deletes, read replicas
4. **Testing** — 80%+ coverage targets, test pyramid (unit/integration/E2E), Arrange-Act-Assert, mock strategies
5. **Error Handling** — Centralized global handlers, custom error classes, consistent response shape, Sentry integration
6. **Logging** — Structured JSON logs, correlation/request IDs, log levels per environment, centralized aggregation
7. **Security** — OWASP Top 10 compliance, helmet.js, CORS whitelists, rate limiting, parameterized queries only
8. **CI/CD** — Parallel jobs, node_modules caching, blue-green deployment, rollback scripts, failure notifications
9. **Docker** — Multi-stage builds, Alpine/Distroless bases, non-root user, healthchecks, resource limits
10. **Branch Strategy** — Git Flow / trunk-based conventions, PR requirements, semantic versioning, squash vs merge rules

## File Structure

```
code-guardian/
├── src/
│   ├── tools.js              # 15 tools + 10 industry patterns + code templates
│   ├── stdio-server.js       # stdio MCP server (Claude Code, Cursor, Windsurf)
│   └── http-server.js        # HTTP/SSE server (port 8765)
├── tests/
│   ├── tools.test.js         # 28 unit tests
│   └── integration.test.js   # 18 integration tests
├── .claude-plugin/
│   └── plugin.json           # Plugin manifest
├── .mcp.json                 # Dual transport config (stdio + HTTP)
├── package.json              # Zero dependencies
├── LICENSE                   # MIT
├── README.md
├── INSTALLATION.md
├── CONTRIBUTING.md
└── CHANGELOG.md
```

**Zero dependencies.** Pure ESM Node.js. No `npm install` required.

## Complete Tool Reference

| Tool | Command | Description |
|---|---|---|
| `audit_codebase` | `audit_codebase({ cwd })` | Full 10-dimension audit with A-F grade and remediation |
| `check_branch` | `check_branch({ cwd })` | Verify git branch naming conventions |
| `check_tests` | `check_tests({ cwd })` | Discover test framework and run execution check |
| `check_cicd` | `check_cicd({ cwd })` | Detect CI/CD configs and package scripts |
| `check_linting` | `check_linting({ cwd })` | Find linters and run ESLint if present |
| `check_security` | `check_security({ cwd })` | Scan for secrets + run `npm audit` |
| `check_architecture` | `check_architecture({ cwd, depth })` | Review directory structure and monorepo setup |
| `production_readiness` | `production_readiness({ cwd })` | A-F scorecard with per-item guidance |
| `generate_production_code` | `generate_production_code({ feature, stack })` | Production-ready code templates |
| `get_industry_patterns` | `get_industry_patterns({ category })` | Full checklist for any architectural concern |
| `generate_security_checklist` | `generate_security_checklist({ cwd })` | OWASP Top 10 tailored to your project |
| `generate_github_workflow` | `generate_github_workflow({ stack, deployTarget })` | CI/CD YAML generation |
| `detect_agent` | `detect_agent({ cwd })` | Auto-detect your AI coding agent |
| `get_agent_guidance` | `get_agent_guidance({ agent })` | Agent-specific best practices |
| `generate_starter_repo` | `generate_starter_repo({ framework })` | Complete project scaffold with production defaults |

## Production Readiness Grading

| Grade | Score | What it means |
|---|---|---|
| **A** | 90–100% | Production-ready. Ship it. |
| **B** | 75–89% | Good. Address the warnings before deploying. |
| **C** | 60–74% | Partial. Significant gaps need fixing. |
| **D** | 40–59% | Below standard. Don't ship without major work. |
| **F** | 0–39% | Not production-ready. Comprehensive remediation needed. |

## Development

```bash
# Run all tests
node --test tests/**/*.test.js

# Run with coverage report
node --test --experimental-test-coverage tests/**/*.test.js

# Syntax check
node --check src/tools.js
node --check src/stdio-server.js
node --check src/http-server.js
```

**46 tests passing.** 28 unit tests + 18 integration tests covering all 15 tools.

## Adding a New Tool

1. Implement in `src/tools.js` with defensive args (`args = {}`)
2. Add to `TOOLS` array in both `src/stdio-server.js` and `src/http-server.js`
3. Add switch case in `handleRequest()` / `dispatchTool()`
4. Write unit tests in `tests/tools.test.js` and integration tests in `tests/integration.test.js`
5. Document in README.md tools table

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

## License

[MIT](LICENSE) — use it freely in personal and commercial projects.

## Built With

- [Model Context Protocol](https://modelcontextprotocol.io) — open standard for AI tool integration
- [Node.js](https://nodejs.org) — runtime (ESM, zero dependencies)
- [GitHub Actions](https://github.com/features/actions) — CI reference templates

---

**Made with care by [justin-coders](https://github.com/justin-coders). Questions? Open an issue.**
