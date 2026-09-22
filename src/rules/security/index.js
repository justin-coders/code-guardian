/**
 * Code Guardian — Security Rule Pack Boundary (Phase 12)
 *
 * The stable import surface for the security domain. Consumers — an MCP tool, the
 * CLI, a CI job, a future aggregate analyzer — should import from here rather than
 * reaching into the individual rule modules.
 *
 * Dependency direction, unchanged from Phase 10 and enforced by an architectural
 * test in `tests/security-rules.test.js`:
 *
 *   core ← repository/model (8D, 11) ← analysis (9) ← rules (10) ← rules/security (12)
 *
 * The pack reads the frozen RepositoryModel through the Phase 11 query API and
 * nothing else. It must never import `node:fs`, `node:path`, `child_process`,
 * `node:net`, `node:http`, `node:https`, `node:dns`, `node:worker_threads`, the
 * Phase 8A filesystem boundary, the Phase 8B execution boundary, `src/tools.js`,
 * `tool-registry`, a transport, or an MCP/CLI module. It reads no file contents, runs
 * no command, and consults no clock, random source or environment: security findings
 * in this phase are deterministic, evidence-first, and scoped to what the repository
 * model can actually prove.
 */

export {
  CONFIGURATION_SIGNALS,
  FINDING_BASIS,
  SECURITY_ANALYZER_ID,
  SECURITY_ANALYZER_NAME,
  SECURITY_ANALYZER_SCOPE,
  SECURITY_CATEGORY,
  SECURITY_CONFIDENCE,
  SECURITY_RULE_ID_PREFIX,
  SECURITY_RULE_IDS,
  SECURITY_RULE_PACK_VERSION,
  SECURITY_RULE_VERSION,
  SENSITIVE_FILE_SPECS,
} from "./contracts.js";

export { FILE_SPEC_CRITERIA, defineFileSpec, matchesFileSpec } from "./matching.js";

export {
  configurationEntities,
  fileInventory,
  filesMatching,
  inventoryAbsence,
  queryFor,
} from "./signals.js";

export { securityRules } from "./rules/index.js";

export { createSecurityRuleRegistry, securityRuleSetIssues } from "./registry.js";

export { createSecurityAnalyzer } from "./analyzer.js";
