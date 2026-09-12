# Code Guardian — Production Readiness Plugin for Claude Code

A Claude Code plugin that enforces production-readiness standards across any project. Audits codebases against industry best practices, checks branch strategy, validates testing and CI/CD setup, and computes a quality scorecard.

## Features

| Tool | What it does |
|---|---|
| `audit_codebase` | Full audit: linting, TypeScript, testing, CI/CD, docs, dependencies |
| `check_branch` | Verifies git branch naming follows conventions (feature/, bugfix/, etc.) |
| `check_tests` | Discovers test files/frameworks and runs a quick test execution check |
| `check_cicd` | Detects CI/CD configs (GitHub Actions, GitLab CI, Jenkins, CircleCI, Docker) |
| `check_linting` | Finds installed linters (ESLint, Prettier, Biome, oxlint, stylelint) and runs ESLint |
| `check_security` | Scans for .env leaks and runs `npm audit` for dependency vulnerabilities |
| `check_architecture` | Reviews directory structure and monorepo indicators |
| `production_readiness` | Computes an A–F grade scorecard across 10 quality dimensions |

## Transports

- **stdio** — Runs as a subprocess (Claude Code's default plugin transport)
- **HTTP/SSE** — Listens on `http://localhost:8765` for direct MCP protocol access

## Installation

The plugin is already installed at:

```
~/.claude/plugins/cache/claude-plugins-official/code-guardian/v1/
```

To install manually:

```bash
cp -r ~/.claude/plugins/cache/claude-plugins-official/code-guardian/v1 \
       ~/.claude/plugins/cache/claude-plugins-official/code-guardian/<version>/
```

Then register it in `~/.claude/plugins/installed_plugins.json`.

## Usage

Once installed, Claude Code will automatically load the plugin. The tools are available as MCP tools — invoke them directly or ask Claude to run an audit:

> "Run code-guardian and audit this project"
> "Check my production readiness score"
> "Is my branch naming compliant?"
> "Run a security scan with npm audit"

## Project structure

```
code-guardian/
├── .claude-plugin/
│   └── plugin.json        # Plugin manifest (name, description, author)
├── .mcp.json              # MCP server config (stdio + HTTP transports)
├── package.json           # Node.js package
└── src/
    ├── tools.js           # All tool implementations (shared)
    ├── stdio-server.js    # stdio entry point for Claude Code
    └── http-server.js     # HTTP/SSE entry point (port 8765)
```

## Extending

Add a new tool by:

1. Implementing the function in [src/tools.js](src/tools.js)
2. Adding it to the `TOOLS` array and dispatch switch in [src/stdio-server.js](src/stdio-server.js) and [src/http-server.js](src/http-server.js)
3. Updating `.mcp.json` if a new transport config is needed
