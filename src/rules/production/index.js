/**
 * Code Guardian — Production Rule Pack Boundary (Phase 20)
 *
 * The stable import surface for the production domain. Consumers — an MCP tool, the CLI, a
 * CI job, a future aggregate analyzer — should import from here rather than reaching into
 * the individual rule modules.
 *
 * Phase 20 adds six informational rules, one per audit domain of the ProductionReport:
 * environment configuration, container configuration, CI configuration, API exposure,
 * dependency inventory and architecture. Together they inventory what the repository establishes in
 * each domain and cite the evidence behind every statement. None of them scores the
 * repository: there is no readiness verdict, no grade, no percentage, no traffic light, no
 * severity above `info` and no environment to compare against.
 *
 * Dependency direction, unchanged from Phase 10 and enforced by an architectural test in
 * `tests/production-report.test.js`:
 *
 *   core ← repository/model (8D … 20) ← analysis (9) ← rules (10) ← rules/production (20)
 *
 * The pack reads the frozen RepositoryModel through the Phase 11 query API and nothing else.
 * It must never import `node:fs`, `node:path`, `child_process`, `node:net`, `node:http`,
 * `node:https`, `node:dns`, `node:worker_threads`, the Phase 8A filesystem boundary, the
 * Phase 8B execution boundary, `src/tools.js`, `tool-registry`, a transport, an MCP/CLI
 * module, or the scanner/acquisition layer that produced the observations. It reads no
 * source file, starts no container, resolves no dependency, runs no process, contacts no
 * network or registry, consults no vulnerability database, and never reads a clock, a random
 * source or the environment: production findings in this phase are deterministic,
 * evidence-first, and scoped to what the repository model can prove.
 */

export {
  MAX_PRODUCTION_FINDINGS,
  PRODUCTION_ABSTENTION_WORDING,
  PRODUCTION_ANALYZER_ID,
  PRODUCTION_ANALYZER_NAME,
  PRODUCTION_ANALYZER_SCOPE,
  PRODUCTION_BASIS,
  PRODUCTION_CATEGORY,
  PRODUCTION_CONFIDENCE,
  PRODUCTION_OBSERVATION_WORDING,
  PRODUCTION_RULE_ID_PREFIX,
  PRODUCTION_RULE_IDS,
  PRODUCTION_RULE_PACK_VERSION,
  PRODUCTION_RULE_VERSION,
  PRODUCTION_SECTION_WORDING,
  PRODUCTION_STATE_WORDING,
} from "./contracts.js";

export {
  PRODUCTION_DESCRIBED_ABSTENTIONS,
  PRODUCTION_DESCRIBED_OBSERVATIONS,
  PRODUCTION_DESCRIBED_SECTIONS,
  PRODUCTION_DESCRIBED_STATES,
  PRODUCTION_SECTIONS,
  PRODUCTION_SECTION_TITLES,
  productionAbsence,
  productionCoverage,
  productionSection,
  productionSections,
  queryFor,
} from "./signals.js";

export { productionInventoryRules, productionRules } from "./rules/index.js";

export { createProductionRuleRegistry, productionRuleSetIssues } from "./registry.js";

export { createProductionAnalyzer } from "./analyzer.js";

// Phase 21 — the `production.risk.*` sub-pack: the same domain, read for the engineering gaps
// the inventory report's own evidence proves. It lives beside the inventory pack rather than
// inside it so neither pack's rule set moves when the other grows; the rule namespace is still
// one (`production.`), and both are wired through this module's boundary.
export * from "./risk/index.js";
