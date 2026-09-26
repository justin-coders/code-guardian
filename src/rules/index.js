/**
 * Code Guardian — Rule Engine Boundary (Phase 10)
 *
 * Stable import boundary for the rule engine. Future domain analyzers and
 * interface layers should import from here rather than reaching into individual
 * files.
 *
 * Dependency direction, enforced by an architectural test in
 * `tests/rule-engine.test.js`:
 *
 *   core  ←  repository/model (8D)  ←  analysis (9)  ←  rules (10)
 *
 * This layer consumes Core contracts, the frozen RepositoryModel and the Phase 9
 * framework. It must never import `node:fs`, `node:fs/promises`, `child_process`,
 * `node:net`, `node:http`, `node:https`, `node:dns`, `node:worker_threads`, the
 * Phase 8A filesystem boundary, the Phase 8B execution boundary, `src/tools.js`,
 * `tool-registry`, a transport, or an MCP/CLI module.
 *
 * Rules are **trusted programmatic contracts** in this phase: there is no
 * expression language, no configuration-supplied code, no `eval` and no
 * network-loaded rule. A rule is a JavaScript object with a `detect` function,
 * registered by the process itself.
 */

export {
  APPLICABILITY_COVERAGE,
  ABNORMAL_RULE_STATUSES,
  MAX_ERROR_MESSAGE_LENGTH,
  MAX_IDENTIFIER_LENGTH,
  RULE_CAPABILITIES,
  RULE_ENGINE_VERSION,
  RULE_FAILURE_CODES,
  RULE_FAILURE_KINDS,
  RULE_ID_PATTERN,
  RULE_OUTCOME_STATUSES,
  RULE_OUTCOME_STATUS_VALUES,
  RULE_SELECTOR_KEYS,
} from "./contracts.js";

export {
  FAILURE_CODE_BY_KIND,
  RuleConfigurationError,
  RuleFrameworkError,
  RuleRegistrationError,
  ruleFailureEntry,
  sanitizeMessage,
  sanitizeRuleFailure,
} from "./errors.js";

export {
  applicabilitySelectorIssues,
  createRuleRegistry,
  ruleDescriptorIssues,
} from "./registry.js";

export { evaluateRuleApplicability } from "./applicability.js";

export { createRuleDetection, evaluateRule, ruleSummary } from "./evaluation.js";

export {
  RULE_EVALUATION_FIELDS,
  RULE_RUN_FIELDS,
  createRuleEvaluationResult,
  createRuleRunResult,
  stableAnalysisView,
  validateRuleEvaluationResult,
  validateRuleRunResult,
} from "./results.js";

export {
  DEFAULT_RULE_ENGINE_OPTIONS,
  createRuleEngine,
  findingsForRule,
  isRuleRunComplete,
} from "./engine.js";

export { createRuleAnalyzer } from "./analyzer.js";

// Phase 12 — the first domain rule pack. Purely additive: the Rule Engine above is
// unchanged, and the security pack is a *consumer* of it (rules, registry, analyzer
// adapter), so a single import boundary still covers the whole rules layer.
export {
  CONFIGURATION_SIGNALS,
  CONTENT_CANDIDATE_FILES,
  CONTENT_PATTERNS,
  FINDING_BASES,
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
  FILE_SPEC_CRITERIA,
  configurationEntities,
  contentInspectionFor,
  createSecurityAnalyzer,
  createSecurityRuleRegistry,
  defineFileSpec,
  fileInventory,
  filesMatching,
  inventoryAbsence,
  isCompleteContentInspection,
  matchesFileSpec,
  queryFor,
  securityRuleSetIssues,
  securityRules,
  symlinkInventory,
  symlinkTargets,
} from "./security/index.js";

// Phase 15 — the architecture rule pack. The minimum integration that proves the
// Phase 15 architecture graph is consumable through the accepted Rule Engine: one
// informational inventory rule, its own registry and analyzer adapter. Purely
// additive — the Rule Engine is unchanged, the other packs are untouched, and all
// three are consumers of the same generic framework.
export {
  ARCHITECTURE_ANALYZER_ID,
  ARCHITECTURE_ANALYZER_NAME,
  ARCHITECTURE_ANALYZER_SCOPE,
  ARCHITECTURE_BASIS,
  ARCHITECTURE_CATEGORY,
  ARCHITECTURE_CONFIDENCE,
  ARCHITECTURE_DESCRIBED_EDGE_TYPES,
  ARCHITECTURE_RULE_ID_PREFIX,
  ARCHITECTURE_RULE_IDS,
  ARCHITECTURE_RULE_PACK_VERSION,
  ARCHITECTURE_RULE_VERSION,
  EDGE_WORDING,
  MAX_ARCHITECTURE_FINDINGS,
  architectureAbsence,
  architectureCoverage,
  architectureInventoryRules,
  architectureRelationships,
  architectureRuleSetIssues,
  architectureRules,
  createArchitectureAnalyzer,
  createArchitectureRuleRegistry,
} from "./architecture/index.js";

// Phase 16 — the import rule pack. The minimum integration that proves the Phase 16
// import graph is consumable through the accepted Rule Engine: one informational
// inventory rule, its own registry and analyzer adapter. Purely additive — the Rule
// Engine is unchanged, the other packs are untouched, and all four are consumers of
// the same generic framework.
export {
  IMPORT_ANALYZER_ID,
  IMPORT_ANALYZER_NAME,
  IMPORT_ANALYZER_SCOPE,
  IMPORT_BASIS,
  IMPORT_CATEGORY,
  IMPORT_CONFIDENCE,
  IMPORT_DESCRIBED_UNRESOLVED_REASONS,
  IMPORT_RULE_ID_PREFIX,
  IMPORT_RULE_IDS,
  IMPORT_RULE_PACK_VERSION,
  IMPORT_RULE_VERSION,
  KIND_WORDING,
  MAX_IMPORT_FINDINGS,
  UNRESOLVED_REASON_WORDING,
  createImportAnalyzer,
  createImportRuleRegistry,
  importCoverage,
  importInventoryRules,
  importRelationships,
  importRuleSetIssues,
  importRules,
  importUnresolved,
  importsAbsence,
} from "./imports/index.js";

// Phase 13/14 — the dependency rule pack. The minimum integration that proves
// dependency intelligence is consumable through the accepted Rule Engine: two
// inventory rules (declarations and the Phase 14 dependency graph), their own registry
// and analyzer adapter. Purely additive — the Rule Engine is unchanged, the security
// pack is untouched, and both packs are consumers of the same generic framework.
export {
  DEPENDENCY_ANALYZER_ID,
  DEPENDENCY_ANALYZER_NAME,
  DEPENDENCY_ANALYZER_SCOPE,
  DEPENDENCY_BASIS,
  DEPENDENCY_CATEGORY,
  DEPENDENCY_CONFIDENCE,
  DEPENDENCY_GRAPH_BASIS,
  DEPENDENCY_RULE_ID_PREFIX,
  DEPENDENCY_RULE_IDS,
  DEPENDENCY_RULE_PACK_VERSION,
  DEPENDENCY_RULE_VERSION,
  DEPENDENCY_SIGNALS,
  MAX_DECLARATION_FINDINGS,
  MAX_GRAPH_FINDINGS,
  createDependencyAnalyzer,
  createDependencyRuleRegistry,
  dependencyAbsence,
  dependencyAcquisitionCoverage,
  dependencyDeclarations,
  dependencyGraphAbsence,
  dependencyGraphCoverage,
  dependencyGraphEdges,
  dependencyGraphRules,
  dependencyObservations,
  dependencyRuleSetIssues,
  dependencyRules,
} from "./dependency/index.js";

// Phase 17 — the symbol rule pack. The minimum integration that proves the semantic
// graph is consumable through the accepted Rule Engine: one informational inventory
// rule, its own registry and analyzer adapter. Purely additive — the Rule Engine is
// unchanged and every other pack is untouched.
export {
  EDGE_TYPE_WORDING,
  MAX_SYMBOL_FINDINGS,
  SYMBOL_ANALYZER_ID,
  SYMBOL_ANALYZER_NAME,
  SYMBOL_ANALYZER_SCOPE,
  SYMBOL_BASIS,
  SYMBOL_CATEGORY,
  SYMBOL_CONFIDENCE,
  SYMBOL_DESCRIBED_EDGE_TYPES,
  SYMBOL_DESCRIBED_UNRESOLVED_REASONS,
  SYMBOL_GRAPH_STATES,
  SYMBOL_KIND_WORDING,
  SYMBOL_RULE_ID_PREFIX,
  SYMBOL_RULE_IDS,
  SYMBOL_RULE_PACK_VERSION,
  SYMBOL_RULE_VERSION,
  UNRESOLVED_SYMBOL_REASON_WORDING,
  createSymbolAnalyzer,
  createSymbolRuleRegistry,
  symbolCoverage,
  symbolInventoryRules,
  symbolRelationships,
  symbolRuleSetIssues,
  symbolRules,
  symbolUnresolved,
  symbolsAbsence,
} from "./symbols/index.js";

// Phase 18 — the API rule pack. The minimum integration that proves the API & Service
// graph is consumable through the accepted Rule Engine: one informational inventory
// rule, its own registry and analyzer adapter. Purely additive — the Rule Engine is
// unchanged and every other pack is untouched.
export {
  API_ANALYZER_ID,
  API_ANALYZER_NAME,
  API_ANALYZER_SCOPE,
  API_BASIS,
  API_CATEGORY,
  API_CONFIDENCE,
  API_DESCRIBED_EDGE_TYPES,
  API_DESCRIBED_UNRESOLVED_REASONS,
  API_EDGE_TYPE_WORDING,
  API_GRAPH_STATES,
  API_RULE_ID_PREFIX,
  API_RULE_IDS,
  API_RULE_PACK_VERSION,
  API_RULE_VERSION,
  API_UNRESOLVED_REASON_WORDING,
  MAX_API_FINDINGS,
  apiAbsence,
  apiCoverage,
  apiInventoryRules,
  apiRoutes,
  apiRuleSetIssues,
  apiRules,
  apiUnresolved,
  createApiAnalyzer,
  createApiRuleRegistry,
} from "./api/index.js";
