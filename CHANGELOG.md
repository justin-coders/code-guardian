# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- 15 MCP tools covering full production-readiness workflow
- Industry-standard pattern library (10 categories)
- Production code templates for NestJS, Express, Fastify
- Cross-agent support: Claude Code, Cursor, Windsurf, Devin, Codex, Gemini, Antigravity
- Remediation guidance on every audit finding
- Defensive args handling (empty args default gracefully)
- Comprehensive test suite (unit + integration)
- MIT License
- Full documentation: README, INSTALLATION, CONTRIBUTING, CHANGELOG

### Changed
- Bumped version from 1.0.0 to 2.0.0
- All tool responses now include `version` field
- `production_readiness` now includes per-item `guidance` field
- `audit_codebase` now includes `guidance` array for actionable fixes
- Added Gemini agent support (replaced incorrect "Emni")

## [1.0.0] — 2026-09-12

### Added
- Initial release with 8 MCP tools
- `audit_codebase` — full codebase audit
- `check_branch` — branch naming compliance
- `check_tests` — test discovery and execution
- `check_cicd` — CI/CD config detection
- `check_linting` — linter detection and ESLint runs
- `check_security` — security scan with npm audit
- `check_architecture` — directory structure review
- `production_readiness` — A-F grade scorecard
- Dual transport: stdio + HTTP/SSE
- Registered in Claude Code plugin system
- GitHub repository with MIT license

---

## Versioning

- **Major** (2.x.0): Breaking changes, new tool categories
- **Minor** (x.1.x): New tools, new patterns, new agent support
- **Patch** (x.y.z): Bug fixes, test improvements, documentation
