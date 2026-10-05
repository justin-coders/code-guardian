# Phase 17 — Reliability Analyzer (architectural decisions)

Official roadmap Phase 17 (`docs/ROADMAPS/Code Guardian — Long-Term Development Roadmap.md`, §21)
asks for a **Reliability Analyzer** over ten domains:

```
timeouts · retry behavior · circuit breaking · graceful shutdown · health checks ·
failure handling · resource cleanup · transaction handling · queue behavior · observability
```

"especially useful for backend/service repositories." All ten are implemented, one-to-one, in
`src/rules/reliability-analysis/`. This file records the decisions the implementation encodes.

## 1. The question every rule must answer

For each domain: *what exact reliability claim is being made, and what repository fact
establishes it?* The model this build ships (Phases 8–16) establishes **structure**, not
runtime behaviour. It reads no handler body, no inline option object, boots no server, connects
to no database, and sends no probe. So an honest reliability claim can only rest on one of three
facts the model actually records:

1. **A structural model fact** — an API route, a container definition, a Dockerfile healthcheck,
   a middleware registration the middleware graph classified.
2. **A package-usage fact** — a module *imports* a known reliability package **and** the symbol
   graph observed the module *using* the imported binding (calling or constructing it). This is
   stronger than a `package.json` dependency: it is an import plus an observed occurrence.
3. **A local-symbol fact** — a module-scope *callable* symbol whose name matches a closed,
   conservative vocabulary is called/referenced (e.g. a function named `withTransaction` that the
   file invokes). Name-derived, reported at the weakest confidence, and worded as such.

Anything else is `unknown` with a reason. Nothing is inferred from a bare dependency name in
`package.json`, from a string, or from a comment (the symbol graph never reads comments).

## 2. The evidence substrate — reuse, no new acquisition

No new scanner was added. Phase 17 is a pure consumer of facts the accepted model already
exposes:

| Fact | Source (existing) | Used for |
| --- | --- | --- |
| API routes (`route:METHOD:/path`) | `query.apiGraph()` / `query.routes()` (Phase 18 substrate) | health checks |
| Route/API coverage | `query.apiCoverage()` | absence gating |
| Middleware classification (name-derived) | `query.middlewareGraph()` (Phase 19) | observability (logging dimension) |
| Imported-binding symbols with `binding.specifier` + observed occurrences | `query.symbolGraph()` (Phase 17 substrate) | timeouts/retry/circuit-breaking/shutdown/queue/transaction/cleanup/observability |
| Unresolved symbol occurrences (`callee-not-established`, kind `call`/`construct`) | `query.unresolvedSymbolReferences()` | package **usage**, not mere import |
| Dockerfile healthcheck + container definitions | `query.productionSection("container")` (Phase 20 inventory) | health checks |
| Test-file identities | `query.listEntities("test")` | exclude test-only usage |

The symbol graph records imported bindings as symbols carrying `binding.specifier` (the module
specifier exactly as written). It withholds a `calls`/`construct` **edge** for an imported
binding (its value shape is not established), but it *does* record the occurrence as an
unresolved record (`reason: callee-not-established`, `kind: call|construct`). Joining the two —
"this file imports `Queue` from `bullmq` **and** the file constructs something named `Queue`" —
is genuine usage evidence, established entirely from the existing model.

**Decision:** no new detector, no new model fact, no new query method, no new acquisition. The
roadmap's new acquisition is *justified only when the model cannot establish a domain*; for
Phase 17 the existing symbol/API/middleware/container substrates establish the domains that are
establishable at all, and the rest are honestly `unknown`.

## 3. Applicability — a repository is not assumed to be a service

`reliabilitySubject(query)`:

- **applicable** — a container definition is declared, **or** the API graph declares ≥ 1 route,
  **or** the module graph uses a service-runtime package (express, fastify, koa, hapi, restify,
  `@nestjs/core`, `http`/`https` server, or a queue/worker package).
- **unknown** — the substrate needed to decide is not established (no semantic graph; an
  unsupported source format; an unestablished API graph with route-shaped occurrences; an
  incomplete scan).
- **not_applicable** — the scan is complete, the graphs are established, and none of the signals
  above exists (a CLI tool, a pure library). Only claimed over an established, complete model.

An unsupported framework or ecosystem is `unknown`, never `not_applicable` (§56). A library
package is not a shutdown subject (§51).

## 4. States, severity, confidence, absence

- Domain `state` vocabulary: `established` (a mechanism is observed), `detected` (a gap is
  established over sufficient coverage), `unknown` (the repo does not establish enough — never
  read as clean), `not_applicable` (no reliability subject).
- **Severity** follows the exact claim: `info` for an established mechanism, `low`/`medium` for a
  gap whose relevance the repository establishes. Nothing is `high` unless the evidence shows a
  consequential failure; Phase 17 produces no `high`.
- **Confidence** = evidence strength: `0.9` observed artifact (Dockerfile healthcheck), `0.8`
  established structure (API route), `0.7` package usage (import + observed occurrence), `0.5`
  name-derived (local-symbol vocabulary, middleware classification).
- **Absence claims** are gated: a domain only concludes an absence over a complete route set / a
  complete container read. Where the model cannot conclude an absence, the domain is `unknown`
  with the reason — never `clean`. Timeout/retry/shutdown/etc. absence is *not* claimed at all,
  because inline configuration and handler bodies are unread (§16–§22, §40).

## 5. Boundaries (no duplicate semantics)

- **Not security** (no `security.*` restated), **not CI/CD** (rollback/deployment stay in
  CICDAnalyzer), **not testing** (test retry/sleep/network stay in the Testing analyzer; test
  files are excluded from application usage), **not `execution/runner.js`** (Code Guardian's own
  timeout is never application timeout evidence).
- Observability does **not** re-report the Phase 16 `api.logging` request-lifecycle gap: it
  reports separate dimensions (logging packages, metrics, tracing, error reporting) plus the
  existing middleware `logging` classification as one dimension, and produces no gap.

## 6. Fingerprints, determinism, bounds

Route-level subjects reuse `route:METHOD:/path`; service subjects use the symbol id
`symbol:<path>#<name>`; container subjects use the file path. Keys are sanitized into the
Finding Engine's `fingerprintKey` charset. Everything is sorted by a documented key; no array
index, no clock, no RNG, no filesystem order. Output is bounded (`MAX_FINDINGS`,
`MAX_USAGES`) with the cap recorded in `metadata.capped` and surfaced as `unknown`/truncation —
never silently dropped.

## 7. Known limitations

- Inline/framework-configured timeouts, retry policies, transaction scopes and cleanup calls are
  method calls (`server.setTimeout`, `db.transaction`, `stream.close`) and stay unresolved; those
  domains are `established` only when a package-usage or local-symbol fact exists, else `unknown`.
- A repository that imports a reliability package but whose usage the symbol graph cannot resolve
  is reported at "imported" strength only where an import is itself the fact.
- Framework coverage: JavaScript/TypeScript (the symbol graph's own supported set). Other
  ecosystems are `unknown`.

## 8. Explicit stop

No official Phase 18+ work (Rule Registry redesign, Guardian Engine, production-readiness
rebuild, MCP modernization, remediation, generation, verification, baselines, CLI, CI-native
mode, benchmarks, LLM assistance, agent-native workflow) is started here.
