# Code Guardian — Production Readiness Plugin for Claude Code

A cross-agent production-readiness enforcer for **Claude Code, Cursor, Windsurf, Devin, Codex, Emni, Antigravity**, and any MCP-capable AI coding agent.

Audits codebases against industry standards, generates production-grade code with reference patterns, enforces quality gates, and ensures every change ships at production quality.

## v2.0.0 — What's New

| Feature | Description |
|---|---|
| **Cross-agent support** | Works with Claude Code, Cursor, Windsurf, Devin, Codex, Emni, Antigravity |
| **15 tools** (up from 8) | Added: `generate_production_code`, `get_industry_patterns`, `generate_security_checklist`, `generate_github_workflow`, `detect_agent`, `get_agent_guidance`, `generate_starter_repo` |
| **Production code templates** | Ready-to-use templates for REST APIs, auth, error handling, logging, Docker, CI/CD |
| **Industry pattern library** | 10 pattern categories with full checklists (REST API, Auth, Database, Testing, Security, etc.) |
| **Remediation guidance** | Every audit finding includes actionable guidance on how to fix it |
| **Agent detection** | Automatically detects which AI agent is being used and provides tailored best practices |
| **Starter repo generator** | Generates complete production-ready project structure for NestJS, Express, or Fastify |

## All Tools

### Audit & Quality Gates

| Tool | Description |
|---|---|
| `audit_codebase` | Full audit: linting, TypeScript, testing, CI/CD, docs, dependencies. Includes remediation guidance. |
| `check_branch` | Verify git branch naming follows conventions (feature/, bugfix/, hotfix/, release/, main, master, develop) |
| `check_tests` | Discover test files/frameworks, run quick test execution check |
| `check_cicd` | Detect CI/CD configs (GitHub Actions, GitLab CI, Jenkins, CircleCI, Docker, pre-commit) |
| `check_linting` | Find installed linters (ESLint, Prettier, Biome, oxlint, stylelint) and run ESLint |
| `check_security` | Scan for .env leaks and run `npm audit` for dependency vulnerabilities |
| `check_architecture` | Review directory structure, monorepo indicators, architectural conventions |
| `production_readiness` | Compute A-F grade scorecard across 10 dimensions with remediation per item |

### Code Generation & Patterns

| Tool | Description |
|---|---|
| `generate_production_code` | Generate production-ready code templates. Features: api, auth, database, testing, error_handling, logging, security, ci_cd, docker. Stacks: nestjs, express, fastify |
| `get_industry_patterns` | Get full industry-standard checklists for any architectural concern |
| `generate_security_checklist` | OWASP Top 10 security checklist tailored to your stack and current findings |
| `generate_github_workflow` | Production-ready GitHub Actions CI/CD workflow YAML |
| `generate_starter_repo` | Complete starter project structure with production defaults |

### Agent Support

| Tool | Description |
|---|---|
| `detect_agent` | Detect which AI coding agent is in use (.cursorrules, .windsurfrules, CLAUDE.md, AGENTS.md) |
| `get_agent_guidance` | Get agent-specific best practices and configuration guidance |

## Supported Agents

| Agent | MCP Support | Plugin System | Best Practice File |
|---|---|---|---|
| Claude Code | Yes | Yes | `CLAUDE.md` / `AGENTS.md` |
| Cursor | Yes | No | `.cursorrules` |
| Windsurf | Yes | No | `.windsurfrules` |
| Devin | No | No | Context instructions |
| Codex | No | No | CLI flags / config.yaml |
| Emni | No | No | Context instructions |
| Antigravity | No | No | Context instructions |

## Usage

Once installed, Claude Code will automatically load the plugin. Invoke naturally:

```
"Audit this project for production readiness"
"Check my branch naming compliance"
"Generate a production REST API with NestJS"
"Show me the industry pattern for authentication"
"Generate a security checklist for this project"
"Create a GitHub Actions CI workflow"
"Detect which agent I'm using and give me best practices"
"Generate a starter NestJS project with production defaults"
```

## Transports

- **stdio** — runs as a subprocess (Claude Code default plugin transport)
- **HTTP/SSE** — listens on `http://localhost:8765` for direct MCP protocol access

## Project Structure

```
code-guardian/
├── .claude-plugin/
│   └── plugin.json        # Plugin manifest (name, description, author)
├── .mcp.json              # MCP server config (stdio + HTTP transports)
├── package.json           # Node.js package
├── README.md
└── src/
    ├── tools.js           # All 15 tool implementations + industry patterns
    ├── stdio-server.js    # stdio entry point for Claude Code
    └── http-server.js     # HTTP/SSE entry point (port 8765)
```

## Versioning

Bump version in `package.json` and `.claude-plugin/plugin.json`, then:

```bash
git add -A
git commit -m "feat: <description>"
git tag v2.1.0
git push origin v2.1.0
gh release create v2.1.0 --title "v2.1.0" --notes "<release notes>"
```

## Industry Patterns Covered

10 pattern categories with full checklists:

1. **REST API** — status codes, validation, pagination, HATEOAS, OpenAPI docs
2. **Authentication** — JWT, RBAC, MFA, token rotation, CSRF, brute-force protection
3. **Database** — Prisma/TypeORM/Knex, migrations, connection pooling, N+1 prevention, soft deletes
4. **Testing** — 80%+ coverage, test pyramid, Arrange-Act-Assert, mock strategies
5. **Error Handling** — global handlers, custom error classes, structured logging, circuit breakers
6. **Logging** — structured JSON, correlation IDs, log levels, centralized aggregation, OpenTelemetry
7. **Security** — OWASP Top 10, helmet, CORS, rate limiting, SQL injection prevention
8. **CI/CD** — GitHub Actions, parallel jobs, caching, blue-green deployment, rollback
9. **Docker** — multi-stage builds, Alpine/Distroless, non-root user, healthchecks, resource limits
10. **Branch Strategy** — Git Flow / trunk-based, PR requirements, semantic versioning

## License

MIT
