# Phase 19 — Canonical Analysis Engine (architectural decisions)

Official roadmap Phase 19 (`docs/ROADMAPS/Code Guardian — Long-Term Development Roadmap.md`, §23)
asks to unify the independent analyzers under one engine:

```
GuardianEngine
guardian.audit(repository, options)

1. load configuration
2. build RepositoryModel
3. select analyzers
4. determine applicable rules
5. run analyzers
6. collect evidence
7. aggregate findings
8. calculate risk
9. generate canonical result
```

This file records the decisions behind `src/guardian/`. The phase is **additive**: no analyzer,
rule pack, scanner, model projection, transport, tool or CLI is modified, and no accepted contract
is replaced.

## 1. Where the Core lives, and the dependency direction

A new layer, not a new contract in an existing one:

```
interface (MCP · CLI · CI · HTTP)          future adapters (Phase 21+)
        │
        ▼
guardian  (Phase 19 — this layer)   orchestration only
        │
        ├──► rules        (Phase 10/18)   rule engine · registry · applicability
        ├──► analysis     (Phase 9)       AnalysisContext · Analyzer Engine · Finding Engine
        ├──► repository   (Phase 8C/8D)   scanner · model builder
        └──► core                              contracts · errors · validation
```

It is a separate directory (`src/guardian/`) rather than an addition to `src/core/` because
`src/core/` is the *contract* layer and must never import the scanner, the model or the analysis
framework. The Guardian Core is the first layer *above* those, and the only one that may drive all
of them.

The direction is enforced by an architectural test in `tests/guardian-engine.test.js`:

- the Core imports only `./*`, `../core/index.js`, `../repository/model/index.js`,
  `../repository/scanner/index.js`, `../analysis/index.js` and `../rules/index.js`;
- it never imports `node:fs`, `child_process`, `node:net`, `node:http`, `node:https`, the Phase 8A
  filesystem boundary, the execution layer, `tools.js`, `tool-registry`, `stdio-server` or
  `http-server`;
- no file under `src/analysis/` or `src/rules/` references `guardian` — analyzers orchestrate
  nothing and never call back into the Core.

## 2. `GuardianEngine` ownership

`createGuardianEngine({ registry, analyzers, failFast, clock, fingerprintAlgorithm })` returns a
frozen handle whose single operation is `audit(repository, options)`.

The Core owns **the pipeline and nothing the layers below already own**:

| Stage | Owner |
| --- | --- |
| load configuration | Guardian Core (`resolveAuditOptions`) |
| build RepositoryModel | scanner (8C) + model builder (8D) |
| select analyzers | analyzer registry (9) — selection policy in the Core |
| determine applicable rules | Rule Engine + `evaluateRuleApplicability` (10) |
| run analyzers | Analyzer Engine (9) |
| collect evidence | Analyzer Engine / Rule Engine (9/10) |
| aggregate findings | Finding Engine (9) |
| calculate risk | **Guardian Core** (new — see §8) |
| generate canonical result | **Guardian Core** (new — see §9) |

`GuardianEngine` never calls `analyzer.analyze()` directly, never re-implements applicability, never
fingerprints or deduplicates a finding, and never rescans the repository.

## 3. Audit contract

```js
guardian.audit(repository, options)
```

- `repository` is **one** of:
  - a repository root path → `scanRepository(root, scanOptions)` → `buildRepositoryModel`;
  - a `ScanResult` → `buildRepositoryModel`;
  - a built `RepositoryModel` → used as-is (validated).
- `options` is a closed object; an unknown key is an error, never silently ignored.

The two-argument form is the roadmap's signature. The architecture specification's
`guardian.audit({ cwd, analyzers, rules, options })` sketch is a *conceptual* shape; a single
request object was rejected because a `RepositoryModel` is also a plain object, and shape-sniffing
the first argument would make the API ambiguous. Every field the sketch lists has a home in the
canonical form.

## 4. Configuration ownership

`resolveAuditOptions(options)` is the only configuration authority. Recognized keys
(`AUDIT_OPTION_KEYS`):

| Key | Meaning | Validation |
| --- | --- | --- |
| `analyzers` | analyzer ids, or `"all"` (default) | array of non-empty strings, `≤ 1000`; de-duplicated and sorted |
| `rules` | Rule contracts on the `AnalysisContext` | passed through; validated by the context validator |
| `evidence` | Evidence contracts carried into the run | passed through; validated by the context validator |
| `configuration` | declarative data → `context.configuration` | declarative-data validation |
| `execution` | execution policy descriptor → `context.execution` | declarative-data validation |
| `analysis` | declarative data → `context.options` | declarative-data validation |
| `failFast` | stop at the first analyzer failure | boolean; left `undefined` when absent so an engine default survives |
| `scan` | scanner options (path inputs only) | `SCAN_OPTION_KEYS` (`maxFiles`, `maxDepth`) |
| `clock` | millisecond clock (metadata only) | function; a **runtime** dependency, never serialized |

Configuration is **data, and only data**: no expression language, no `eval`, no dynamic module
load, no network-loaded configuration. `configuration`/`execution`/`analysis` are validated with
the accepted `declarativeDataIssues` (bounds, unsafe keys, cycles) and then call
`buildAnalysisContext`, which is the authority on the context contract. The resolved shape is
frozen and deterministic (selection sorted), so two callers that described the same audit get the
same configuration object.

Rule configuration stays where Phase 18 put it: on a rule registry, applied through the
`AnalysisContext` / Rule Engine boundary. The Core does not reach into an analyzer's private rule
registry.

## 5. Repository-model construction

`resolveRepositoryModel` reuses the accepted pipeline only, and never implements a scanner, a walk,
manifest detection, dependency acquisition, graph construction or evidence collection. A path input
is the only input that reaches the filesystem, through `scanRepository`; a `ScanResult` goes
straight to `buildRepositoryModel`; a `RepositoryModel` is validated by `validateRepositoryModel`.
The model layer itself never touches the filesystem.

Detection/validation of the three input forms is shape-based (`identity` discriminates a model from
a scan result) but the Core validators remain the authority: `validateRepositoryModel` /
`validateScanResult` decide validity.

## 6. Analyzer selection

`selectAnalyzers(registry, selection)` is built entirely on `createAnalyzerRegistry`:

- `"all"` → `registry.ids()`; explicit ids → the list (already sorted/de-duplicated by §4);
- `registry.select(...)` is the single authority for de-duplication, ordering and
  unknown-id rejection, so selection never depends on registration order or the caller's order;
- an **unknown** explicitly requested id fails through the registry (`CG_ANALYZER_UNKNOWN`), never
  a silent empty audit;
- an **empty** selection (empty registry or explicit `[]`) fails with
  `CG_GUARDIAN_SELECTION_EMPTY`, because a run that analysed nothing must never read as a run that
  found nothing wrong.

## 7. Applicability and execution ownership

Both are **reused, not duplicated**:

- **rules** — `evaluateRuleApplicability` (and Phase 18's `registry.evaluateApplicability`
  delegate) remain the only applicability authority; `unknown` from incomplete coverage is never
  turned into `not-applicable`. The Core does not evaluate selectors.
- **analyzers** — the Core builds the context with `buildAnalysisContext` and runs the selection
  with `createAnalyzerEngine`. Analyzer applicability, isolation, failure capture, evidence
  provenance enforcement, finding normalization/fingerprinting/deduplication and deterministic
  ordering all stay in the accepted engine. The Core consumes the resulting `AnalysisRunResult`.

"Determine applicable rules" is therefore satisfied *through* the accepted engines: the Core hands
the same validated `AnalysisContext` to every analyzer and lets the rule/analyzer engines decide
applicability. No second decision path exists.

## 8. Risk semantics (the phase's explicit decision)

Risk is the first Guardian-level interpretation the architecture permits, so the phase makes the
contract explicit instead of inventing a formula.

**Risk is a profile, not a number.** The architecture specification (§22) requires risk to consider
severity, confidence, impact, scope, exploitability and evidence completeness, and to avoid
pretending these reduce to one objective number, with the dimensions still visible. The profile:

```js
risk = {
  version: "1.0.0",            // RISK_CONTRACT_VERSION
  highestSeverity,             // max severity present, or null when there are none
  counts: { total, info, low, medium, high, critical },
  complete,                    // see below
  coverage: {
    repository: { complete, truncated, guarantee },
    analysis:   { selected, completed, notApplicable, failed, skipped },
  },
  limitations: [ ...sorted reason codes... ],
}
```

Decision by decision:

- **Risk inputs.** The canonical findings (severity), the analyzer-stage statuses, and the model's
  scan coverage. Nothing else — no clock, no I/O, no randomness.
- **Risk semantics.** `highestSeverity` is a *fact about the finding set* — `max(severity)` — not a
  verdict, not a percentage and not a score. `counts` exposes the distribution.
- **Aggregation rules.** Counts iterate the closed severity vocabulary; `highestSeverity` is the
  highest severity with a non-zero count; `limitations` is sorted and de-duplicated. No
  time-weighted, no size-weighted and no arbitrary numeric combination is applied.
- **Relationship between severity and confidence.** They are independent and are never combined.
  `highestSeverity` reads only severity; every finding keeps its own `confidence` (0–1) on the
  canonical result, and the profile deliberately contains **no** aggregated confidence. A consumer
  that wants to combine them does so explicitly on data the Core did not pre-combine, because a
  Core that combined them would have made a policy decision the architecture says is not objective.
- **Incomplete analysis.** `complete` is `false` when the repository scan was not complete, when it
  was truncated, or when any analyzer failed or was skipped, and `limitations` records why. An
  incomplete run is **never** presented as clean: a zero-finding profile from an incomplete scan
  carries `complete: false` and a non-empty `limitations` list.
- **Failed analyzers.** Each failure contributes `analyzer-failed:<id>` and makes `complete` false;
  the failure also stays visible at `analyzers[].status`/`analyzers[].errors`.
- **Unknown / not-applicable analyzers.** `not-applicable` is a normal outcome and does **not** make
  the run incomplete. Absence of evidence is never converted into a risk conclusion. Rule-level
  `unknown` outcomes remain visible in the producing analyzer's metadata, which the result carries.
- **Determinism.** The profile is a pure function of the findings and the coverage facts; severity
  counts, limitation ordering and the coverage block are all sorted/closed-vocabulary, so the
  profile does not depend on finding order, analyzer scheduling or key order.
- **Versioning.** `RISK_CONTRACT_VERSION` is recorded on the profile, separate from the result
  schema version, so a consumer baselining risk detects a semantic change without a shape change.

## 9. Canonical result schema

`createGuardianResult` + `validateGuardianResult` define a new, higher-level contract. The accepted
`AnalysisRunResult` is **not** corrupted: it deliberately rejects judgment keys (`score`, `grade`,
`verdict`, `productionReady`, `risk`, `quality`), and the Guardian Core is the first layer permitted
a documented risk profile, so it needs its own result rather than a modified lower one.

The shape follows the architecture specification §43:

```js
{
  schemaVersion: "1.0.0",
  engine:     { name, version, fingerprintAlgorithm },
  repository: { repositoryId, root, modelVersion, coverage, fileCount, evidenceCount },
  scan:       { complete, truncated, guarantee },
  analyzers:  [ { id, name, version, scope, status, applicability,
                  findings: [fingerprint…], evidence: [id…], metrics, errors } ],
  analysis:   { complete, selectedAnalyzers, analyzers: { selected, completed,
                notApplicable, failed, skipped }, failFast, durationMs },
  findings:   [ canonical Finding … ],
  evidence:   [ resolved Evidence record … ],
  metrics:    { analyzers, findings: { total, duplicates }, evidence: { total } },
  risk:       { …see §8… },
}
```

- `schemaVersion` is semver, validated with the accepted `VERSION_PATTERN` (matching
  `AnalysisRunResult.version`), not the sketch's `"1"`.
- The result is **validated**, **deeply frozen**, **serializable**, **versioned** and independent of
  MCP/CLI/HTTP — no transport type appears anywhere in it.
- It distinguishes **facts** (`repository`, `scan`, `analysis`, `metrics`), **findings**
  (`findings`, `analyzers`), **risk** (`risk`), **coverage/unknowns** (`scan`, `risk.coverage`,
  `risk.limitations`) and **failures** (`analyzers[].errors`, `risk.limitations`).
- Evidence is resolved to whole records: every finding's references are carried in `evidence`, so a
  finding can be traced back to its observation without a lookup. The validator enforces that every
  finding reference resolves.
- **No wall-clock timestamps.** `durationMs` is the only non-deterministic field and is metadata
  only; `stableGuardianView` removes it (recursively) so two runs of the same model, analyzers and
  configuration compare byte for byte. The sketch's `startedAt`/`completedAt` were deliberately not
  adopted, to match the accepted analysis results' determinism convention.
- The validator rejects the collapsed-judgment keys (`score`, `grade`, `verdict`,
  `productionReady`, `quality`) and pins the coherence of the analysis counts, the `complete` flag,
  the selection, the risk counts vs. the findings, and the evidence references.

## 10. Error semantics

Two classes, mirroring the layers below:

- **Thrown (no meaningful audit possible):** `GuardianConfigurationError` for an unknown option key,
  a malformed option, an invalid repository input, or an empty selection
  (`CG_GUARDIAN_CONFIGURATION_INVALID`, `CG_GUARDIAN_REPOSITORY_INVALID`,
  `CG_GUARDIAN_SELECTION_EMPTY`); the analysis framework's `AnalyzerConfigurationError`
  (`CG_ANALYZER_UNKNOWN`) for an unknown analyzer id; `GuardianValidationError`
  (`CG_GUARDIAN_RESULT_INVALID`) for a result the Core assembled but could not validate.
- **Recorded, never thrown:** an analyzer failure. It stays inside the run
  (`analyzers[].status`, `analyzers[].errors`) and in `risk.limitations`. Throwing it would erase the
  other analyzers' work and the failure's own visibility.

All errors carry a stable `code` and serializable `details`; no stack, `cause` chain or host detail
is exposed.

## 11. Incomplete-analysis semantics

The distinctions the framework established are preserved end to end:

`completed` · `not-applicable` · `failed` · `skipped` · repository coverage
`complete`/`partial`/`truncated`.

If the model is incomplete, `result.scan.complete === false`, `result.repository.coverage.complete
=== false` and `result.risk.complete === false`, with `risk.limitations` naming the reason. A
partial scan is never presented as a complete or clean audit. `not-applicable` remains a normal
outcome that neither fails nor limits the run.

## 12. Determinism

- selection: registry-sorted, de-duplicated;
- execution: Analyzer Engine's own deterministic ordering;
- findings: the Finding Engine's canonical ordering and fingerprints (unchanged);
- risk: closed-vocabulary counts and sorted limitations;
- result: sorted analyzers/evidence, sorted limitations, no timestamps;
- the only non-deterministic field is `analysis.durationMs`, removed by `stableGuardianView`.

## 13. Security boundaries

- No configuration-supplied code; no `eval`, dynamic import or module load; no network-loaded
  configuration.
- The only filesystem access is a path input reaching the accepted scanner; the model layer and the
  Core never touch the filesystem.
- The context handed to analyzers exposes data only (the frozen model, declarative configuration, an
  execution *policy descriptor*) — no `fs`, no `spawn`, no `fetch`, no transport; the Core adds no
  capability the analyzer framework did not already grant.
- Evidence provenance is enforced by the accepted engines and re-checked by the result validator: an
  analyzer may not forge or duplicate an evidence id, and cannot point outside the repository.
- No rule of the result may carry a collapsed judgment; the Core emits facts, findings and a
  documented risk profile.

## 14. Compatibility boundaries (what Phase 19 deliberately did not do)

- **No MCP/legacy-tool migration** (official Phase 21). `tools.js`, `tool-registry`, the stdio/http
  servers and the CLI are untouched; `audit_codebase`, `production_readiness`, `check_security`,
  `check_tests`, `check_linting`, `check_cicd` and `check_architecture` behave exactly as before and
  keep passing their existing suites. The canonical engine sits *underneath* the future adapters.
- **No Audit Tool Rebuild** (official Phase 22).
- **No Production Readiness Rebuild** (official Phase 20): the engine provides the canonical inputs
  Phase 20 needs (findings, risk, coverage, limitations) but implements no readiness product, no
  grade and no percentage.
- **No remediation / verification**, no CLI expansion, no CI-native mode, no baseline/incremental
  analysis, no HTTP rebuild, no LLM assistance.
- **No analyzer, rule, scanner or model change.** The phase only adds a layer.

## 15. Tests

`tests/guardian-engine.test.js` (48 tests) covers configuration (default/explicit/invalid/
deterministic), repository-model resolution (path / ScanResult / prebuilt / invalid / incomplete
visible), analyzer selection (default/explicit/ordering/unknown/duplicate/empty), applicability
(not-applicable distinguishable; the accepted evaluator reused), execution (isolation, fail-fast
skips, attribution), evidence (model, derived, forged-id refusal, reference resolution), findings
(canonical, stable fingerprints, dedup, ordering), risk (versioned, deterministic, severity/confidence
independent, failure/incomplete handling), the canonical result (versioned/validated/frozen/sections/
deterministic/transport-independent) and the architectural boundary (imports, forbidden accesses,
analyzers never depending on the Core). It is part of the hosted CI named suite.

## 16. Known limitations

- The Core does not aggregate per-finding confidence into the risk profile by design; a consumer
  wanting a combined view must compute it (§8).
- `analyzers[].findings` records fingerprints for attribution, and the full canonical findings live
  in `findings`; a consumer resolves a fingerprint against that list. This avoids duplicating whole
  finding objects per analyzer.
- Rule configuration remains a property of a rule registry (Phase 18). The Core passes the context
  through; it does not configure an analyzer's internal rule registry.
- The result has no wall-clock timestamps (documented deviation from the specification sketch) to
  preserve the accepted determinism convention.
