# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.4] — 2026-09-17

### Fixed
- Fixed GitHub Packages publish step: `NODE_AUTH_TOKEN` now correctly references `${{ secrets.GITHUB_TOKEN }}` (was broken, causing publish to fail)

---

## [2.0.3] — 2026-09-17

### Fixed
- Removed dead `PLUGIN_DIR` constant and orphaned imports from `src/tools.js`
- Removed unused `depth` variable in `toolAuditCodebase`
- Added `express` and `fastify` cases to `getEssentialPackages` with meaningful production dependency arrays
- Replaced hardcoded Windows path in `.mcp.json` with `${workspaceFolder}` placeholder
- Added `.mcp.json` to `.gitignore` (contains local paths); removed `.claude-plugin/` so `plugin.json` stays tracked
- Softened agent support claims in README for Devin, Codex, Gemini, Antigravity to reflect reality
- Rewrote README install section — removed ZIP upload fiction and `v1/` cache references
- Updated all version assertions in tests from `2.0.2` to `2.0.3`

### Changed
- Bumped version from `2.0.2` to `2.0.3`
- Fixed `.gitignore` to properly track `plugin.json` while ignoring `.mcp.json`

### Docs
- Created `UPCOMING_FEATURES.md` tracking all future work (Streamable HTTP, secret scanning, write mode, non-JS stacks, monolith refactor, score weights)
- Updated `INSTALLATION.md` — removed stale ZIP upload and `v1/` cache instructions; added npm link method

---

## [2.0.2] — 2026-09-13

### Fixed
- Fixed a bug where the plugin wouldn't load in Claude Code

### Changed
- Updated the plugin manifest to include `version` field

---

## [2.0.1] — 2026-09-13

### Added
- Added `check_code_quality` tool to check code quality metrics

### Fixed
- **Windows Support:** Improved cross-platform file path resolution to ensure seamless operation on Windows environments.
- **Test & Execution Stability:** Enhanced command execution resilience and timeouts, preventing false-positive failures during longer-running project checks.
- **Dual Transport Compatibility:** Resolved an issue where JSON-RPC responses were missing protocol headers, ensuring smooth server communication across standard I/O connections without unexpected crashes.

---

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
