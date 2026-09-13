# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Released] - 2026-09-13

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
- Bumped version from 2.0.1 to 2.0.2
- All tool responses now include `version` field
- `production_readiness` now includes per-item `guidance` field
- `audit_codebase` now includes `guidance` array for actionable fixes
- Added Gemini agent support (replaced incorrect "Emni")


## [2.0.2] — 2026-09-13

### Fixed
- Fixed a bug where the plugin wouldn't load in Claude Code

### Changed
- Updated the plugin manifest to include `version` field


## [2.0.1] — 2026-09-13


### Added
- Added `check_code_quality` tool to check code quality metrics


### 🐛 Fixes & Improvements
* **Windows Support:** Improved cross-platform file path resolution to ensure seamless operation on Windows environments.
* **Test & Execution Stability:** Enhanced command execution resilience and timeouts, preventing false-positive failures during longer-running project checks.
* **Dual Transport Compatibility:** Resolved an issue where JSON-RPC responses were missing protocol headers, ensuring smooth server communication across standard I/O connections without unexpected crashes.

---

### ✅ Compatibility & Reliability
* **Cross-Platform Verified:** Validated full feature functionality and suite pass rates across Linux, macOS, and Windows.


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
