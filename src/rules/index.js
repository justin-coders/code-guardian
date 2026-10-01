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
  AUTHORIZING_CLASSIFICATIONS,
  CONFIGURATION_SIGNALS,
  CONTENT_CANDIDATE_FILES,
  CONTENT_PATTERNS,
  DIAGNOSTIC_ROUTE_SEGMENTS,
  FINDING_BASES,
  FINDING_BASIS,
  PRIVILEGED_ROUTE_SEGMENTS,
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
  matchesRoutePath,
  middlewareSourceEvidenceId,
  queryFor,
  routeInventory,
  routeProtections,
  routeRules,
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

// Phase 19 — the middleware rule pack. The minimum integration that proves the middleware &
// authorization graph is consumable through the accepted Rule Engine: one informational
// inventory rule, its own registry and analyzer adapter. Purely additive — the Rule Engine
// is unchanged and every other pack is untouched.
export {
  MAX_MIDDLEWARE_FINDINGS,
  MIDDLEWARE_ANALYZER_ID,
  MIDDLEWARE_ANALYZER_NAME,
  MIDDLEWARE_ANALYZER_SCOPE,
  MIDDLEWARE_BASIS,
  MIDDLEWARE_CATEGORY,
  MIDDLEWARE_CLASSIFICATION_WORDING,
  MIDDLEWARE_CONFIDENCE,
  MIDDLEWARE_DESCRIBED_EDGE_TYPES,
  MIDDLEWARE_DESCRIBED_UNRESOLVED_REASONS,
  MIDDLEWARE_EDGE_TYPE_WORDING,
  MIDDLEWARE_GRAPH_STATES,
  MIDDLEWARE_PROTECTION_WORDING,
  MIDDLEWARE_RULE_ID_PREFIX,
  MIDDLEWARE_RULE_IDS,
  MIDDLEWARE_RULE_PACK_VERSION,
  MIDDLEWARE_RULE_VERSION,
  MIDDLEWARE_UNRESOLVED_REASON_WORDING,
  createMiddlewareAnalyzer,
  createMiddlewareRuleRegistry,
  middlewareAbsence,
  middlewareCoverage,
  middlewareInventoryRules,
  middlewareNodes,
  middlewareRouteViews,
  middlewareRuleSetIssues,
  middlewareRules,
  middlewareUnresolved,
} from "./middleware/index.js";

// Phase 20 — the production rule pack. Six informational rules, one per audit domain of the
// ProductionReport, proving the report is consumable through the accepted Rule Engine.
// Purely additive — the Rule Engine is unchanged and every other pack is untouched.
export {
  MAX_PRODUCTION_FINDINGS,
  PRODUCTION_ABSTENTION_WORDING,
  PRODUCTION_ANALYZER_ID,
  PRODUCTION_ANALYZER_NAME,
  PRODUCTION_ANALYZER_SCOPE,
  PRODUCTION_BASIS,
  PRODUCTION_CATEGORY,
  PRODUCTION_CONFIDENCE,
  PRODUCTION_DESCRIBED_ABSTENTIONS,
  PRODUCTION_DESCRIBED_OBSERVATIONS,
  PRODUCTION_DESCRIBED_SECTIONS,
  PRODUCTION_DESCRIBED_STATES,
  PRODUCTION_OBSERVATION_WORDING,
  PRODUCTION_RULE_ID_PREFIX,
  PRODUCTION_RULE_IDS,
  PRODUCTION_RULE_PACK_VERSION,
  PRODUCTION_RULE_VERSION,
  PRODUCTION_SECTIONS,
  PRODUCTION_SECTION_TITLES,
  PRODUCTION_SECTION_WORDING,
  PRODUCTION_STATE_WORDING,
  createProductionAnalyzer,
  createProductionRuleRegistry,
  productionAbsence,
  productionCoverage,
  productionInventoryRules,
  productionRules,
  productionRuleSetIssues,
  productionSection,
  productionSections,
  // Phase 21 — the `production.risk.*` sub-pack. Six rules, one per audit domain of the
  // ProductionRiskReport, proving that report is consumable through the accepted Rule Engine.
  // Purely additive — the Rule Engine is unchanged and every other pack is untouched.
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
  PRODUCTION_RISK_DESCRIBED_ABSTENTIONS,
  PRODUCTION_RISK_DESCRIBED_CLASSIFICATIONS,
  PRODUCTION_RISK_DESCRIBED_CONFIDENCES,
  PRODUCTION_RISK_DESCRIBED_KINDS,
  PRODUCTION_RISK_DESCRIBED_SECTIONS,
  PRODUCTION_RISK_DESCRIBED_SEVERITIES,
  PRODUCTION_RISK_DESCRIBED_STATES,
  PRODUCTION_RISK_FINDING_WORDING,
  PRODUCTION_RISK_RULE_ID_PREFIX,
  PRODUCTION_RISK_RULE_IDS,
  PRODUCTION_RISK_RULE_PACK_VERSION,
  PRODUCTION_RISK_RULE_SEVERITIES,
  PRODUCTION_RISK_RULE_VERSION,
  PRODUCTION_RISK_SECTIONS,
  PRODUCTION_RISK_SECTION_TITLES,
  PRODUCTION_RISK_SECTION_WORDING,
  PRODUCTION_RISK_SEVERITY_WORDING,
  PRODUCTION_RISK_STATE_WORDING,
  createProductionRiskAnalyzer,
  createProductionRiskRuleRegistry,
  productionRiskAbsence,
  productionRiskAuditRules,
  productionRiskCoverage,
  productionRiskRules,
  productionRiskRuleSetIssues,
  productionRiskSection,
  productionRiskSections,
} from "./production/index.js";

// Phase 22 — the `compliance.*` pack. Six rules, one per policy domain of the ComplianceReport,
// proving that report is consumable through the accepted Rule Engine: a rule reports the
// requirements the repository's own policy contradicts, cites both the repository observation and
// the policy declaration behind each finding, and abstains where nothing could be measured.
// Purely additive — the Rule Engine is unchanged and every other pack is untouched.
export {
  COMPLIANCE_ABSTENTION_WORDING,
  COMPLIANCE_ANALYZER_ID,
  COMPLIANCE_ANALYZER_NAME,
  COMPLIANCE_ANALYZER_SCOPE,
  COMPLIANCE_BASIS,
  COMPLIANCE_CATEGORY,
  COMPLIANCE_CONFIDENCE,
  COMPLIANCE_DESCRIBED_ABSTENTIONS,
  COMPLIANCE_DESCRIBED_POLICY_STATES,
  COMPLIANCE_DESCRIBED_SECTIONS,
  COMPLIANCE_DESCRIBED_STATES,
  COMPLIANCE_DESCRIBED_STATUSES,
  COMPLIANCE_POLICY_STATE_WORDING,
  COMPLIANCE_RULE_ID_PREFIX,
  COMPLIANCE_RULE_IDS,
  COMPLIANCE_RULE_PACK_VERSION,
  COMPLIANCE_RULE_SEVERITIES,
  COMPLIANCE_RULE_VERSION,
  COMPLIANCE_SECTIONS,
  COMPLIANCE_SECTION_TITLES,
  COMPLIANCE_SECTION_WORDING,
  COMPLIANCE_SEVERITY_VALUES,
  COMPLIANCE_STATE_WORDING,
  COMPLIANCE_STATUS_WORDING,
  MAX_COMPLIANCE_FINDINGS,
  complianceAbsence,
  complianceCoverage,
  complianceDomainRules,
  compliancePolicy,
  complianceRules,
  complianceRuleSetIssues,
  complianceSection,
  complianceSections,
  complianceUnmeasuredReason,
  createComplianceAnalyzer,
  createComplianceRuleRegistry,
} from "./compliance/index.js";

// Phase 23 — the `policy.*` pack. One **informational** rule, `policy.preset.audit`, proving the
// preset layer is consumable through the accepted Rule Engine: it names the built-in preset a
// repository's policy applied, the keys that preset supplied and the keys the repository replaced,
// and it abstains when no preset governs anything. Purely additive — the Rule Engine is unchanged,
// every other pack is untouched, and this one carries no violation, score or recommendation.
export {
  MAX_POLICY_FINDINGS,
  POLICY_ABSTENTION_REASON_VALUES,
  POLICY_ABSTENTION_REASONS,
  POLICY_ABSTENTION_WORDING,
  POLICY_ANALYZER_ID,
  POLICY_ANALYZER_NAME,
  POLICY_ANALYZER_SCOPE,
  POLICY_BASIS,
  POLICY_CATEGORY,
  POLICY_CONFIDENCE,
  POLICY_DESCRIBED_STATES,
  POLICY_RULE_ID_PREFIX,
  POLICY_RULE_IDS,
  POLICY_RULE_PACK_VERSION,
  POLICY_RULE_SEVERITY,
  POLICY_RULE_VERSION,
  POLICY_SEVERITY_VALUES,
  POLICY_STATE_WORDING,
  activePreset,
  createPolicyAnalyzer,
  createPolicyRuleRegistry,
  effectivePolicy,
  hasPolicyArea,
  policyArea,
  policyAuditRules,
  policyProvenance,
  policyRules,
  policyRuleSetIssues,
} from "./policy/index.js";
