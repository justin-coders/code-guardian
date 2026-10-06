/**
 * Code Guardian — Guardian Core Boundary (Official Roadmap Phase 19)
 *
 * Stable import surface for the canonical analysis engine. Interface layers — an
 * MCP adapter, a CLI, a CI job, an HTTP handler — should import from here rather
 * than reaching into individual files, exactly as they do for the Core, the model
 * and the analyzer framework.
 *
 * Dependency direction, enforced by an architectural test in
 * `tests/guardian-engine.test.js`:
 *
 *   interface  →  guardian (19)  →  rules (10)  →  analysis (9)
 *                                              →  repository/model (8D)
 *                                              →  core
 *
 * The Guardian Core consumes the Core contracts, the repository scanner/model
 * boundary, the analysis framework and the rule layer. It must never import
 * `src/tools.js`, `tool-registry`, a transport, an MCP/CLI module, or the Phase 8A
 * filesystem boundary directly (only a path input reaches the scanner, which owns
 * filesystem access). Analyzers must never import this layer: the Core orchestrates
 * analyzers, and an analyzer that called back into the Core would invert the
 * dependency the architecture fixes.
 */

export {
  AUDIT_OPTION_KEYS,
  DECLARATIVE_AUDIT_KEYS,
  FORBIDDEN_GUARDIAN_RESULT_KEYS,
  GUARDIAN_ANALYZER_SUMMARY_FIELDS,
  GUARDIAN_ENGINE_NAME,
  GUARDIAN_ENGINE_VERSION,
  GUARDIAN_RESULT_FIELDS,
  GUARDIAN_RESULT_SCHEMA_VERSION,
  GUARDIAN_SELECTION_ALL,
  MAX_AUDIT_ANALYZERS,
  MAX_LIMITATION_LENGTH,
  RISK_CONTRACT_VERSION,
  RISK_LIMITATION_KINDS,
  RISK_SEVERITIES,
} from "./contracts.js";

export {
  GUARDIAN_FAILURE_CODES,
  GuardianConfigurationError,
  GuardianValidationError,
} from "./errors.js";

export { resolveAuditOptions } from "./configuration.js";

export { isRepositoryModel, isScanResult, resolveRepositoryModel } from "./repository.js";

export { selectAnalyzers } from "./selection.js";

export { calculateRisk } from "./risk.js";

export {
  createGuardianResult,
  freezeGuardianResult,
  guardianEngineIdentity,
  stableGuardianView,
  validateGuardianResult,
} from "./result.js";

export { createGuardianEngine } from "./engine.js";
