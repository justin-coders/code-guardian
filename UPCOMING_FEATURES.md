# Upcoming Features — Code Guardian v2.1.0+

This document tracks planned features, enhancements, and known limitations for future releases of Code Guardian. All items below are tracked as future work and are **not** implemented in v2.0.3.

---

## Roadmap Overview

| Category | Item | Priority | Target Version |
|---|---|---|---|
| Transport | Streamable HTTP (2024-11-05 spec) | Medium | v2.1.0 |
| Architecture | `tools.js` monolith refactor | Low | v2.2.0 |
| Security | Real secret scanning | Medium | v2.1.0 |
| Tooling | Write mode (`--fix` / `apply`) | Medium | v2.2.0 |
| Ecosystem | Non-JS stack support (Python, Go, Rust) | Low | v2.3.0 |
| Config | Score weights configuration | Low | v2.2.0 |

---

## P5 — Streamable HTTP Transport (2024-11-05)

**Priority:** Medium  
**Status:** Known Limitation  
**Target:** v2.1.0

### Current State

The HTTP transport (`src/http-server.js`) uses a simplified POST/SSE approach. It handles single requests and stream responses, but does not implement the full [MCP 2024-11-05 Streamable HTTP spec](https://spec.modelcontextprotocol.io/specification/2024-11-05/basic/transports/#streamable-http).

### What's Missing

| Spec Requirement | Current Behavior | Gap |
|---|---|---|
| Session management (`sessionId` header) | Stateless — no session tracking | Clients cannot maintain state across requests |
| HTTP DELETE for session termination | Not implemented | No way to explicitly close an MCP session |
| `text/event-stream` with proper SSE events | Basic SSE output only | Missing `id`, `event`, `data` framing per spec |
| JSON-RPC batch support | Single-request only | No `BatchNotification` or batch response handling |
| Session persistence across restarts | Not supported | Sessions lost on server restart |

### Implementation Plan

1. Add in-memory session store keyed by `sessionId`
2. Parse `Session-Id` request header; emit it in responses
3. Implement `DELETE /` to terminate sessions and free resources
4. Refactor SSE response writer to emit properly framed events
5. Support JSON-RPC batch requests (`[request1, request2, ...]`)
6. Add session timeout / idle cleanup (e.g., 30 min)

### Acceptance Criteria

- [ ] `/POST` and `/GET` endpoints match spec exactly
- [ ] `Session-Id` header round-trips correctly
- [ ] `DELETE` terminates session and returns `202 Accepted`
- [ ] Batch JSON-RPC requests resolved and returned as batch response
- [ ] Existing stdio transport unaffected

---

## Security — Real Secret Scanning

**Priority:** Medium  
**Status:** Not Implemented  
**Target:** v2.1.0

### Current State

`check_security` currently:
- Scans for `.env`, `.env.local`, `.env.production` files
- Checks if `package.json` lists secret-related dependencies
- Runs `npm audit` for known vulnerabilities

This is **file presence detection**, not actual secret scanning.

### What's Missing

| Capability | Current | Needed |
|---|---|---|
| Pattern-based secret detection | None | Regex matching for API keys, tokens, passwords (e.g., `AKIA[0-9A-Z]{16}`, `sk-live-[0-9a-zA-Z]{20}`) |
| Entropy analysis | None | Detect high-entropy strings that look like secrets |
| Gitleaks / trufflehog integration | None | Integrate existing OSS secret scanners |
| Secret classification | None | Categorize by type (AWS, Stripe, GitHub, database URI) |
| Exclusion rules | None | Allow `.gitignore`-based or manual ignore lists |

### Implementation Plan

1. Add regex-based pattern library (ported from [gitleaks detect rules](https://github.com/gitleaks/gitleaks))
2. Scan file contents (not just names) against secret patterns
3. Classify detected secrets by type and severity
4. Support an ignore list via `.codeguardianignore` or `package.json#codeGuardian.secretScanning.ignorePatterns`
5. Report structured findings: `{ path, line, pattern, severity, category }`

### Acceptance Criteria

- [ ] Detects AWS access keys, GitHub tokens, Stripe keys, generic API keys
- [ ] Reports line number and file path for each match
- [ ] Skips `node_modules`, `.git`, `coverage/` automatically
- [ ] `npm audit` output still included (complementary, not replaced)

---

## Tooling — Write Mode (`--fix` / `apply`)

**Priority:** Medium  
**Status:** Not Implemented  
**Target:** v2.2.0

### Current State

All 15 generators (`generate_production_code`, `generate_github_workflow`, `generate_security_checklist`, `generate_starter_repo`) are **read-only text dumps**. They return YAML/JSON/code strings — they never write files.

### What's Missing

| Capability | Current | Needed |
|---|---|---|
| File writing | Returns text | Writes to `cwd` |
| Dry-run mode | N/A | `--dry-run` flag to preview changes before applying |
| Patch-style output | Full file rewrites | Unified diffs when modifying existing files |
| Conflict detection | N/A | Warn when target file already exists with content |
| Selective generation | All-or-nothing | Generate only the requested subset (e.g., CI only) |

### Implementation Plan

1. Add optional `write: boolean` and `targetDir: string` to generator tool args
2. When `write: true`, serialize output to disk under `targetDir` (default: `cwd`)
3. Add `--dry-run` in CLI (`bin/cli.js`) to print diff preview without writing
4. For existing files, compute a diff and present it as part of the response
5. Guard writes with existence checks; warn on overwrite rather than clobbering

### Acceptance Criteria

- [ ] `generate_github_workflow({ write: true, targetDir: ".github/workflows" })` creates the YAML file
- [ ] `generate_starter_repo({ framework: "nestjs", write: true })` scaffolds a complete project
- [ ] Dry-run mode shows what would change without touching the filesystem
- [ ] Overwrite protection prevents accidental data loss

---

## Ecosystem — Non-JS Stack Support (Python, Go, Rust)

**Priority:** Low  
**Status:** Not Implemented  
**Target:** v2.3.0

### Current State

Code Guardian is Node.js-only. Framework detection and templates cover:
- NestJS, Express, Fastify (Node.js/TypeScript)
- Prisma, TypeORM, Knex (Node.js ORMs)
- Jest, Vitest, node --test (Node.js test runners)
- ESLint, Prettier, Biome (Node.js linters)

### What's Missing

| Stack | Missing Capability |
|---|---|
| **Python** | `requirements.txt` / `pyproject.toml` parsing, `pytest`/`tox` detection, `pip-audit` integration, Django/FastAPI templates |
| **Go** | `go.mod` parsing, `golangci-lint` detection, `go test` integration, Gin/Echo templates |
| **Rust** | `Cargo.toml` parsing, `cargo clippy`/`cargo test` integration, structural patterns |
| **General** | Cross-language project detection (e.g., monorepo with multiple languages) |

### Implementation Plan

1. Add language detection module — inspect root for `package.json`, `pyproject.toml`, `go.mod`, `Cargo.toml`
2. For each language, add a framework-detection function that maps to known production patterns
3. Implement language-specific security checklists (Python: Bandit; Go: gosec; Rust: cargo-audit)
4. Add code templates for each language's web framework

### Acceptance Criteria

- [ ] `audit_codebase` on a Python project reports pytest, black, ruff status
- [ ] `generate_security_checklist({ stack: "python" })` returns OWASP + Bandit recommendations
- [ ] `generate_production_code({ feature: "rest_api", stack: "fastapi" })` returns valid FastAPI code

---

## Architecture — `tools.js` Monolith Refactor

**Priority:** Low  
**Status:** Not Started  
**Target:** v2.2.0

### Current State

`src/tools.js` is ~1,391 lines containing:
- 15 tool implementations
- 10 industry pattern libraries
- Code templates for NestJS / Express / Fastify
- Security checklist templates
- CI/CD workflow templates

### Proposed Structure

```
src/
├── tools.js                 # Thin dispatcher (~200 lines)
├── tool-registry.js         # Tool definitions (unchanged)
├── stdio-server.js          # stdio transport (unchanged)
├── http-server.js           # HTTP transport (unchanged)
├── audit/
│   ├── index.js             # audit_codebase orchestration
│   ├── dimensions.js        # 10 production-readiness dimension logic
│   └── scoring.js           # A-F grading logic
├── patterns/
│   ├── rest-api.js          # REST API pattern data
│   ├── auth.js              # Authentication pattern data
│   ├── security.js          # Security pattern data
│   └── index.js             # Re-exports all
├── templates/
│   ├── nestjs.js
│   ├── express.js
│   ├── fastify.js
│   ├── github-workflow.js
│   └── docker.js
└── config/
    ├── score-weights.js     # Configurable scoring weights
    └── ignore-patterns.js   # Default skip patterns
```

### Expected Impact

- `tools.js`: ~1,391 → ~200 lines
- Readability: each module focused on one concern
- Testability: unit tests can target individual modules
- Zero behavioral change — all exports preserved via re-exports

### Acceptance Criteria

- [ ] All 15 tools produce identical output after refactor
- [ ] 83 existing tests pass without modification
- [ ] No new public API surface added or removed

---

## Config — Score Weights Configuration

**Priority:** Low  
**Status:** Not Implemented  
**Target:** v2.2.0

### Current State

`production_readiness` applies equal weight (10 points each) to all 10 dimensions:

| Dimension | Weight |
|---|---|
| `package.json` | 10 |
| Lock file | 10 |
| README | 10 |
| `.gitignore` | 10 |
| ESLint | 10 |
| TypeScript strict | 10 |
| Tests | 10 |
| CI/CD | 10 |
| `.env` safety | 10 |
| Build script | 10 |

### What's Missing

- Per-project weight overrides (e.g., a frontend project may care more about README than ESLint)
- Environment-specific weights (dev vs. production audits)
- Custom dimension registration

### Implementation Plan

1. Extract weight map to `src/config/score-weights.js`
2. Accept optional `weights` object in `production_readiness` args
3. Validate custom weights (must sum to 100, all positive)
4. Default to current equal-weighting for backward compatibility

### Acceptance Criteria

- [ ] `production_readiness({ weights: { tests: 30, readme: 5 } })` uses custom weights
- [ ] Invalid weights rejected with a clear error message
- [ ] Score grades (A–F) still map correctly to the new total

---

## Tracking

This document is reviewed and updated at the start of each release cycle. Items may move between priorities based on community feedback and usage patterns.

**Last updated:** 2026-09-17  
**Next review:** v2.1.0 planning
