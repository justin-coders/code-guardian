/**
 * Code Guardian — Compliance Rule Pack Boundary (Phase 22)
 *
 * The stable import surface for the `compliance.*` domain. Consumers — an MCP tool, the CLI, a CI
 * job, a future aggregate analyzer — should import from here rather than reaching into the
 * individual rule modules.
 *
 * Phase 22 adds six rules, one per policy domain of the ComplianceReport: environment configuration,
 * container configuration, CI configuration, route middleware, dependency manifests and architecture
 * entrypoints. Together they measure the requirements the repository's own policy declares, cite the
 * repository observation **and** the policy declaration behind every violation, and abstain where
 * nothing could be measured. None of them scores the repository: there is no compliance percentage,
 * no grade, no traffic light, and no severity above `medium`.
 *
 * Dependency direction, unchanged from Phase 10 and enforced by an architectural test in
 * `tests/compliance.test.js`:
 *
 *   core ← repository/model (8D … 22) ← analysis (9) ← rules (10) ← rules/compliance (22)
 *
 * The pack reads the frozen RepositoryModel through the Phase 11 query API and nothing else. It must
 * never import `node:fs`, `node:path`, `child_process`, `node:net`, `node:http`, `node:https`,
 * `node:dns`, `node:worker_threads`, the Phase 8A filesystem boundary, the Phase 8B execution
 * boundary, `src/tools.js`, `tool-registry`, a transport, an MCP/CLI module, or the
 * scanner/acquisition layer that produced the observations. It reads no source file, starts no
 * container, resolves no dependency, runs no process, contacts no network or registry, consults no
 * vulnerability database, and never reads a clock, a random source or the environment.
 */

export {
  COMPLIANCE_ABSTENTION_WORDING,
  COMPLIANCE_ANALYZER_ID,
  COMPLIANCE_ANALYZER_NAME,
  COMPLIANCE_ANALYZER_SCOPE,
  COMPLIANCE_BASIS,
  COMPLIANCE_CATEGORY,
  COMPLIANCE_CONFIDENCE,
  COMPLIANCE_POLICY_STATE_WORDING,
  COMPLIANCE_RULE_ID_PREFIX,
  COMPLIANCE_RULE_IDS,
  COMPLIANCE_RULE_PACK_VERSION,
  COMPLIANCE_RULE_SEVERITIES,
  COMPLIANCE_RULE_VERSION,
  COMPLIANCE_SECTION_WORDING,
  COMPLIANCE_SEVERITY_VALUES,
  COMPLIANCE_STATE_WORDING,
  COMPLIANCE_STATUS_WORDING,
  MAX_COMPLIANCE_FINDINGS,
} from "./contracts.js";

export {
  COMPLIANCE_DESCRIBED_ABSTENTIONS,
  COMPLIANCE_DESCRIBED_POLICY_STATES,
  COMPLIANCE_DESCRIBED_SECTIONS,
  COMPLIANCE_DESCRIBED_STATES,
  COMPLIANCE_DESCRIBED_STATUSES,
  COMPLIANCE_SECTIONS,
  COMPLIANCE_SECTION_TITLES,
  complianceAbsence,
  complianceCoverage,
  compliancePolicy,
  complianceSection,
  complianceSections,
  complianceUnmeasuredReason,
  queryFor,
} from "./signals.js";

export { complianceDomainRules, complianceRules } from "./rules/index.js";

export { createComplianceRuleRegistry, complianceRuleSetIssues } from "./registry.js";

export { createComplianceAnalyzer } from "./analyzer.js";
