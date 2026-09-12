# Code Guardian

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node >= 18](https://img.shields.io/badge/node-%3E%3D18-green.svg)](https://nodejs.org)
[![Claude Code Plugin](https://img.shields.io/badge/Claude_Code-plugin-blue.svg)](https://claude.ai/code)

**Production-readiness enforcer for AI coding agents.**

Audits codebases against industry standards, generates production-grade code with reference patterns, enforces quality gates, and works across **all major AI coding agents**.

## Supported Agents

| Agent | Status | MCP Support |
|---|---|---|
| [Claude Code](https://claude.ai/code) | Full plugin | Yes |
| [Cursor](https://cursor.sh) | Full support | Yes |
| [Windsurf](https://windsurf.com) | Full support | Yes |
| [Devin](https://devin.ai) | Context guidance | No |
| [OpenAI Codex](https://openai.com/index codex/) | CLI guidance | No |
| [Google Gemini](https://gemini.google.com) | Context guidance | No |
| [Antigravity](https://antigravity.sh) | Context guidance | No |

## Features

### 15 MCP Tools

| Tool | What it does |
|---|---|
| `audit_codebase` | Full audit: linting, TypeScript, testing, CI/CD, docs, dependencies — with remediation guidance |
| `check_branch` | Verify git branch naming follows conventions (feature/, bugfix/, hotfix/, release/, main) |
| `check_tests` | Discover test files/frameworks, run quick test execution check |
| `check_cicd` | Detect CI/CD configs (GitHub Actions, GitLab CI, Jenkins, CircleCI, Docker, pre-commit) |
| `check_linting` | Find installed linters (ESLint, Prettier, Biome, oxlint, stylelint) and run ESLint |
| `check_security` | Scan for .env leaks, run `npm audit` for dependency vulnerabilities |
| `check_architecture` | Review directory structure, monorepo indicators, architectural conventions |
| `production_readiness` | Compute A–F grade scorecard across 10 dimensions with per-item remediation guidance |
| `generate_production_code` | Generate production-ready code templates (api, auth, database, testing, error_handling, logging, security, ci_cd, docker) for NestJS, Express, Fastify |
| `get_industry_patterns` | Get full industry-standard checklists for any architectural concern |
| `generate_security_checklist` | OWASP Top 10 security checklist tailored to your stack and current findings |
| `generate_github_workflow` | Production-ready GitHub Actions CI/CD workflow YAML |
| `detect_agent` | Auto-detect which AI agent is in use and surface relevant best practices |
| `get_agent_guidance` | Agent-specific best practices and configuration guidance |
| `generate_starter_repo` | Complete starter project structure with production defaults |

### 10 Industry Pattern Categories

1. **REST API** — status codes, Zod/Joi validation, pagination, OpenAPI/Swagger docs
2. **Authentication** — JWT with short expiry, RBAC, MFA, token rotation, CSRF protection
3. **Database** — Prisma/TypeORM/Knex migrations, connection pooling, N+1 prevention
4. **Testing** — 80%+ coverage, test pyramid, Arrange-Act-Assert, mock strategies
5. **Error Handling** — global handlers, custom error classes, structured logging
6. **Logging** — JSON structured logs, correlation IDs, centralized aggregation
7. **Security** — OWASP Top 10, helmet, CORS, rate limiting, SQL injection prevention
8. **CI/CD** — parallel jobs, caching, blue-green deployment, rollback scripts
9. **Docker** — multi-stage builds, Alpine base, non-root user, healthchecks
10. **Branch Strategy** — Git Flow / trunk-based, PR requirements, semantic versioning

## Quick Start

### Using in Claude Code

The plugin is already registered in your Claude Code installation. Simply ask:

```
"Audit this project for production readiness"
"Generate a production REST API with NestJS"
"Show me the auth industry patterns"
"Create a GitHub Actions CI workflow"
"Check my security"
```

Claude will automatically invoke the appropriate code-guardian tools.

### Using as a Standalone MCP Server

```bash
# Clone the repo
git clone https://github.com/justin-coders/code-guardian.git
cd code-guardian

# Install (no dependencies needed — pure Node.js)
# Start the stdio server
node src/stdio-server.js

# Or start the HTTP/SSE server
CODE_GUARDIAN_TRANSPORT=http node src/stdio-server.js
# Listens on http://localhost:8765
```

### Adding to Other Agents

**Cursor:** Add to your `~/.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "code-guardian": {
      "command": "node",
      "args": ["/path/to/code-guardian/src/stdio-server.js"]
    }
  }
}
```

**Windsurf:** Add to your `~/.windsurf/mcp.json` (same format as Cursor).

**Any MCP-compatible agent:** Point it at the stdio server.

## Installation

### From Source

```bash
git clone https://github.com/justin-coders/code-guardian.git
cd code-guardian
# No npm install needed — pure ESM Node.js, zero dependencies
node src/stdio-server.js
```

### For Claude Code (from installed location)

The plugin lives at:
```
~/.claude/plugins/cache/claude-plugins-official/code-guardian/v1/
```

It is auto-loaded on next Claude Code restart.

### Running Tests

```bash
# Run all tests
node --test tests/**/*.test.js

# Run with coverage
node --test --experimental-test-coverage tests/**/*.test.js
```

## Project Structure

```
code-guardian/
├── .claude-plugin/
│   └── plugin.json           # Plugin manifest
├── .mcp.json                 # MCP server config (stdio + HTTP)
├── .gitignore
├── LICENSE                   # MIT License
├── README.md                 # This file
├── INSTALLATION.md           # Detailed installation guide
├── CONTRIBUTING.md           # Contribution guidelines
├── CHANGELOG.md              # Version history
├── package.json
└── src/
    ├── tools.js              # All 15 tool implementations + patterns
    ├── stdio-server.js       # stdio entry point
    └── http-server.js        # HTTP/SSE entry point
└── tests/
    ├── tools.test.js         # Unit tests for individual tools
    └── integration.test.js   # Integration tests via MCP protocol
```

## Usage Examples

### Audit a Project
```
> "Audit this project for production readiness"
> "Run the full codebase audit"
> "Check my branch naming compliance"
```

### Generate Code Templates
```
> "Generate a production REST API with NestJS"
> "Create a JWT auth module with Express"
> "Generate a Dockerfile for my NestJS app"
> "Show me the industry standard for error handling"
```

### Security & CI/CD
```
> "Run a security scan on this project"
> "Generate a GitHub Actions CI workflow"
> "Generate a security checklist based on OWASP"
```

### Agent-Specific
```
> "Detect which agent I'm using and give me best practices"
> "What are the best practices for Cursor?"
> "How do I configure code-guardian for Windsurf?"
```

### Starter Projects
```
> "Generate a production-ready NestJS starter project"
> "Create an Express project structure with testing"
```

## Production Readiness Scorecard

The `production_readiness` tool scores projects on a 10-point scale:

| Grade | Range | Meaning |
|---|---|---|
| **A** | 90–100% | Production-ready. Minor improvements may exist. |
| **B** | 75–89% | Good. Address warnings before shipping. |
| **C** | 60–74% | Partial. Significant gaps need remediation. |
| **D** | 40–59% | Below standard. Major improvements required. |
| **F** | 0–39% | Not production-ready. Comprehensive remediation needed. |

**Dimensions checked:** package.json, lock file, README, .gitignore, ESLint, TypeScript strict mode, test files, CI/CD pipeline, .env safety, build script.

## Cross-Agent Patterns

Each supported agent has agent-specific best practices surfaced via `get_agent_guidance`:

- **Claude Code**: Use MCP tools, structure skills in `~/.claude/skills/`, add project rules to `AGENTS.md` or `CLAUDE.md`
- **Cursor**: Add rules to `.cursorrules`, use `@` mentions, enable Composer mode for multi-file changes
- **Windsurf**: Add rules to `.windsurfrules`, use Cascade for multi-step workflows
- **Devin**: Provide complete context upfront, request incremental commits for large tasks
- **Codex**: Use `--memory-file` for persistent context, `--diff` for reviewing changes
- **Gemini**: Set clear expectations in system prompt, request production-ready code with tests
- **Antigravity**: Define production requirements explicitly, ask for compliance with industry standards

## License

[MIT](LICENSE) — Free to use, modify, and distribute.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.
