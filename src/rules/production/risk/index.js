/**
 * Code Guardian — Production Risk Rule Pack Boundary (Phase 21)
 *
 * The stable import surface for the `production.risk.*` domain. Consumers — an MCP tool, the
 * CLI, a CI job, a future aggregate analyzer — should import from here rather than reaching into
 * the individual rule modules.
 *
 * Phase 21 adds six rules, one per audit domain of the ProductionRiskReport: environment
 * configuration, container configuration, CI configuration, route protection, dependency
 * hygiene and architecture integrity. Together they report the engineering gaps the repository's
 * own evidence proves, cite the evidence behind every statement, and name what the report could
 * not establish. None of them scores the repository: there is no readiness verdict, no grade, no
 * percentage, no traffic light, and no severity above `medium`.
 *
 * Dependency direction, unchanged from Phase 10 and enforced by an architectural test in
 * `tests/production-risk.test.js`:
 *
 *   core ← repository/model (8D … 21) ← analysis (9) ← rules (10) ← rules/production/risk (21)
 *
 * The pack reads the frozen RepositoryModel through the Phase 11 query API and nothing else. It
 * must never import `node:fs`, `node:path`, `child_process`, `node:net`, `node:http`,
 * `node:https`, `node:dns`, `node:worker_threads`, the Phase 8A filesystem boundary, the Phase
 * 8B execution boundary, `src/tools.js`, `tool-registry`, a transport, an MCP/CLI module, or the
 * scanner/acquisition layer that produced the observations. It reads no source file, starts no
 * container, resolves no dependency, runs no process, contacts no network or registry, consults
 * no vulnerability database, and never reads a clock, a random source or the environment.
 */

export {
  MAX_PRODUCTION_RISK_FINDINGS,
  PRODUCTION_RISK_ABSTENTION_WORDING,
  PRODUCTION_RISK_ANALYZER_ID,
  PRODUCTION_RISK_ANALYZER_NAME,
  PRODUCTION_RISK_ANALYZER_SCOPE,
  PRODUCTION_RISK_BASIS,
  PRODUCTION_RISK_CATEGORY,
  PRODUCTION_RISK_CLASSIFICATION_WORDING,
  PRODUCTION_RISK_CONFIDENCE,
  PRODUCTION_RISK_CONFIDENCE_WORDING,
  PRODUCTION_RISK_FINDING_WORDING,
  PRODUCTION_RISK_RULE_ID_PREFIX,
  PRODUCTION_RISK_RULE_IDS,
  PRODUCTION_RISK_RULE_PACK_VERSION,
  PRODUCTION_RISK_RULE_SEVERITIES,
  PRODUCTION_RISK_RULE_VERSION,
  PRODUCTION_RISK_SECTION_WORDING,
  PRODUCTION_RISK_SEVERITY_WORDING,
  PRODUCTION_RISK_STATE_WORDING,
} from "./contracts.js";

export {
  PRODUCTION_RISK_DESCRIBED_ABSTENTIONS,
  PRODUCTION_RISK_DESCRIBED_CLASSIFICATIONS,
  PRODUCTION_RISK_DESCRIBED_CONFIDENCES,
  PRODUCTION_RISK_DESCRIBED_KINDS,
  PRODUCTION_RISK_DESCRIBED_SECTIONS,
  PRODUCTION_RISK_DESCRIBED_SEVERITIES,
  PRODUCTION_RISK_DESCRIBED_STATES,
  PRODUCTION_RISK_SECTIONS,
  PRODUCTION_RISK_SECTION_TITLES,
  productionRiskAbsence,
  productionRiskCoverage,
  productionRiskSection,
  productionRiskSections,
  queryFor,
} from "./signals.js";

export { productionRiskAuditRules, productionRiskRules } from "./rules/index.js";

export {
  createProductionRiskRuleRegistry,
  productionRiskRuleSetIssues,
} from "./registry.js";

export { createProductionRiskAnalyzer } from "./analyzer.js";
