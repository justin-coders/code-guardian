/**
 * Code Guardian — RepositoryModel Boundary (Phase 8D)
 *
 * Stable import boundary for the repository-model layer. Analyzers (Phase 9+)
 * should import from here rather than reaching into individual files.
 *
 * Dependency direction, which the architectural test in
 * `tests/repository-model.test.js` enforces:
 *
 *   core  ←  scanner (8C)  ←  model (8D)
 *
 * The model layer consumes a **validated ScanResult** and the Core contracts. It
 * must never import `node:fs`, `node:fs/promises`, `child_process`, `node:net`,
 * `node:http`, `node:https`, the Phase 8A filesystem boundary directly, the
 * execution layer, MCP, HTTP, stdio, the CLI or `tools.js`. It is a pure
 * transformation: reading the repository is the scanner's job, and doing it twice
 * would let the model contradict the scan it claims to describe.
 *
 * The Phase 11 query layer (`createRepositoryQuery`, `query-contracts.js`,
 * `query-errors.js`) is a pure read-only view over a built model. It adds
 * `node:path` to the prohibition above: it operates on already-normalized model
 * paths and must not manipulate filesystem paths independently.
 *
 * The Phase 14 dependency graph (`dependency-graph.js`) is part of that view: it is
 * a deterministic projection of the dependency entities and `depends-on`
 * relationships, with per-edge provenance and an explicit coverage state, and it
 * imports nothing at all — no filesystem, no parser, no resolver, no clock.
 *
 * The Phase 16 import graph (`import-graph.js`) follows the same rule with one
 * addition worth naming: it *does* resolve module specifiers, but only against the
 * file paths the scan already observed. It reads no file, consults no package
 * resolver, and refuses any path that leaves the repository root instead of asking
 * the filesystem about it.
 */

export {
  MODEL_ENTITY_COLLECTIONS,
  MODEL_IMMUTABILITY,
  REPOSITORY_MODEL_BUILDER,
  REPOSITORY_MODEL_BUILDER_VERSION,
  collectModelEntities,
  // Phase 22 — the two check-table functions the contract uses to guarantee that every declared
  // policy setting has a measurement and that every measurement belongs to a declared setting.
  // Exported so the focused suite can pin the tables together; the contract itself refuses to load
  // when either direction is incomplete.
  policyKeyIds,
  unmeasuredPolicyKeys,
  unknownPolicyCheckKeys,
  validateRepositoryModelGraph,
} from "./contracts.js";

export { buildRepositoryModel } from "./builder.js";

export {
  ENTITY_KINDS,
  GIT_ENTITY_ID,
  REPOSITORY_ID_PREFIX,
  entityId,
  evidenceId,
  repositoryId,
  stabilityHash,
} from "./identity.js";

export {
  CONTAINER_SIGNALS,
  CONTENT_SIGNALS,
  CONTENT_STATUSES,
  CONTENT_UNINSPECTED_REASONS,
  DEPENDENCY_SIGNALS,
  EVIDENCE_COLLECTOR,
  EVIDENCE_SOURCE,
  EVIDENCE_SUBJECTS,
  EVIDENCE_TYPE_BY_SUBJECT,
  IMPORT_SIGNALS,
  INVENTORY_KINDS,
  MIDDLEWARE_SIGNALS,
  contentObservationKind,
  createBuildContextObservation,
  createContentInspectionObservation,
  createContentPatternObservation,
  createDependencyDeclarationObservation,
  createDependencyResolutionObservation,
  createDependencySourceObservation,
  createImportSourceObservation,
  createInventoryObservation,
  createMiddlewareSourceObservation,
  createObservation,
  createSignalObservation,
} from "./evidence.js";

export {
  DOCKERFILE_STRUCTURE_REASONS,
  emptyDockerfileStructure,
  DEPENDENCY_PROBLEM_REASONS,
  DEPENDENCY_SCOPES,
  DEPENDENCY_SOURCE_REASONS,
  DEPENDENCY_SOURCE_STATUSES,
  CI_TEST_EXECUTION_STATES,
  DEPENDENCY_SPEC_KINDS,
  GIT_HEAD_KINDS,
  IMPORT_MODULE_EXTENSIONS,
  IMPORT_PROBLEM_REASONS,
  IMPORT_SOURCE_REASONS,
  IMPORT_SOURCE_STATUSES,
  IMPORT_SPECIFIER_KINDS,
  SYMLINK_TARGET_KINDS,
  SYMLINK_TARGET_REASONS,
  TEST_FLAKY_INDICATORS,
  TEST_KINDS,
  projectDependencyName,
  projectGitHead,
  projectModuleSpecifier,
  projectSymlinkTarget,
} from "./entities.js";

// Phase 16 — the import graph: its closed vocabularies, its resolution policy and
// its bounds, plus the projection the builder materializes into
// `model.imports.graph`.
export {
  IMPORT_GRAPH_EDGE_TYPES,
  IMPORT_GRAPH_EDGE_TYPE_VALUES,
  IMPORT_GRAPH_LIMITS,
  IMPORT_GRAPH_STATES,
  IMPORT_GRAPH_STATE_VALUES,
  IMPORT_GRAPH_VERSION,
  INDEX_BASENAME,
  MODULE_EXTENSIONS,
  RESOLUTION_EXTENSIONS,
  UNRESOLVED_REFERENCE_REASONS,
  UNRESOLVED_REFERENCE_REASON_VALUES,
  buildImportGraph,
  classifySpecifier,
  importGraphState,
  isEstablishedState as isImportGraphEstablishedState,
  isSourceEstablished as isImportSourceEstablished,
  joinRelativePath,
  resolveModuleReference,
} from "./import-graph.js";

// Phase 17 — the symbol graph: its closed vocabularies, its resolution reasons, its
// bounds and its identity rule, plus the projection the builder materializes into
// `model.symbols.graph`.
export {
  SYMBOL_GRAPH_EDGE_TYPES,
  SYMBOL_GRAPH_EDGE_TYPE_VALUES,
  SYMBOL_GRAPH_LIMITS,
  SYMBOL_GRAPH_STATES,
  SYMBOL_GRAPH_STATE_VALUES,
  SYMBOL_GRAPH_VERSION,
  SYMBOL_MODULE_EXTENSIONS,
  SYMBOL_UNRESOLVED_KINDS,
  SYMBOL_UNRESOLVED_REASONS,
  SYMBOL_UNRESOLVED_REASON_VALUES,
  buildSymbolGraph,
  isEstablishedSymbolState,
  isSymbolSourceEstablished,
  isSymbolSourceResolvable,
  symbolGraphState,
  symbolIdOf,
} from "./symbol-graph.js";

// Phase 18 — the API & Service graph: its identity rule, its closed vocabularies and
// bounds, plus the projection the builder materializes into `model.api.graph`.
export {
  API_GRAPH_EDGE_TYPES,
  API_GRAPH_EDGE_TYPE_VALUES,
  API_GRAPH_LIMITS,
  API_GRAPH_STATES,
  API_GRAPH_STATE_VALUES,
  API_GRAPH_VERSION,
  API_UNRESOLVED_KINDS,
  API_UNRESOLVED_REASONS,
  API_UNRESOLVED_REASON_VALUES,
  apiRouteIdOf,
  apiGraphState,
  apiHandlerSymbolId,
  buildApiGraph,
  isApiSourceEstablished,
  isEstablishedApiState,
} from "./api-graph.js";

// Phase 19 — the middleware graph: its identity rule, its closed vocabularies (edges,
// classifications, protection states), its name-only classification function and its
// bounds, plus the projection the builder materializes into `model.middleware.graph`.
export {
  MIDDLEWARE_CLASSIFICATION_RULES,
  MIDDLEWARE_CLASSIFICATION_VALUES,
  MIDDLEWARE_CLASSIFICATIONS,
  MIDDLEWARE_EDGE_TYPES,
  MIDDLEWARE_EDGE_TYPE_VALUES,
  MIDDLEWARE_GRAPH_LIMITS,
  MIDDLEWARE_GRAPH_STATES,
  MIDDLEWARE_GRAPH_STATE_VALUES,
  MIDDLEWARE_GRAPH_VERSION,
  MIDDLEWARE_PROTECTION_STATES,
  MIDDLEWARE_PROTECTION_VALUES,
  // The graph's own scope and registration-kind vocabularies are a documented superset of the
  // acquisition layer's (they add `route`, the registration a route declaration's own argument
  // list states), so they are exported under graph-qualified names rather than shadowing the
  // acquisition values the block below re-declares.
  MIDDLEWARE_REGISTRATIONS as MIDDLEWARE_GRAPH_REGISTRATIONS,
  MIDDLEWARE_ROUTE_REASON_MAP,
  MIDDLEWARE_ROUTE_REGISTRATION,
  MIDDLEWARE_ROUTE_SCOPE,
  MIDDLEWARE_SCOPES as MIDDLEWARE_GRAPH_SCOPES,
  MIDDLEWARE_UNRESOLVED_KINDS,
  MIDDLEWARE_UNRESOLVED_REASONS,
  MIDDLEWARE_UNRESOLVED_REASON_VALUES,
  buildMiddlewareGraph,
  classifyMiddlewareName,
  isEstablishedMiddlewareState,
  isMiddlewareSourceEstablished,
  middlewareGraphState,
  middlewareNameWords,
  middlewareRouteIdOf,
} from "./middleware-graph.js";

// Phase 17 — the semantic vocabularies the model re-declares, so a consumer of the
// model never has to import the acquisition layer.
export {
  SEMANTIC_MODULE_EXTENSIONS,
  SEMANTIC_PROBLEM_REASONS,
  SEMANTIC_SOURCE_REASONS,
  SEMANTIC_SOURCE_STATUSES as SEMANTIC_SOURCE_STATUS_VALUES,
  SYMBOL_BINDING_KINDS,
  SYMBOL_EXPORT_FORMS,
  SYMBOL_KINDS,
  SYMBOL_OCCURRENCE_FORMS,
  projectSymbolName,
} from "./entities.js";

// Phase 18 — the API vocabularies the model re-declares, so a consumer never has to
// import the acquisition layer.
export {
  API_CALLABLE_FORMS,
  API_FRAMEWORKS,
  API_PROBLEM_REASONS,
  API_RECEIVER_KINDS,
  API_ROUTE_METHODS,
  API_SHAPE_REASONS,
  API_SOURCE_REASONS,
  API_SOURCE_STATUSES,
  API_UNSUPPORTED_FRAMEWORKS,
  projectApiName,
  projectRoutePath,
} from "./entities.js";

// Phase 19 — the middleware vocabularies the model re-declares, so a consumer never has to
// import the acquisition layer.
export {
  MIDDLEWARE_CALLABLE_FORMS,
  MIDDLEWARE_FRAMEWORKS,
  MIDDLEWARE_PROBLEM_REASONS,
  MIDDLEWARE_REGISTRATIONS,
  MIDDLEWARE_SCOPES,
  MIDDLEWARE_SOURCE_REASONS,
  MIDDLEWARE_SOURCE_STATUSES,
  MIDDLEWARE_UNRESOLVED_REASONS as MIDDLEWARE_SOURCE_UNRESOLVED_REASONS,
} from "./entities.js";

// Phase 20 — the production-readiness report: its six domains, its closed observation and
// abstention vocabularies, its bounds and its coverage-state reading, plus the projection
// the builder materializes into `model.production.report`.
//
// The report is the one projection whose vocabulary is part of its interface: a consumer
// switches on a section name, an observation kind, a coverage state and an abstention
// reason, so all four are exported rather than reached for through the report object.
export {
  CI_PURPOSES,
  ENVIRONMENT_CLASSES,
  PRODUCTION_ENTRYPOINT_DIRECTORIES,
  PRODUCTION_ENTRYPOINT_NAMES,
  PRODUCTION_OBSERVATION_KINDS,
  PRODUCTION_REPORT_BUILDER,
  PRODUCTION_REPORT_LIMITS,
  PRODUCTION_REPORT_STATES,
  PRODUCTION_REPORT_STATE_VALUES,
  PRODUCTION_REPORT_VERSION,
  PRODUCTION_SECTIONS,
  PRODUCTION_SECTION_TITLES,
  PRODUCTION_UNKNOWN_REASONS,
  PRODUCTION_UNKNOWN_REASON_VALUES,
  PRODUCTION_UNSUPPORTED_REASONS,
  buildProductionReport,
  classifyEnvironmentArtifact,
  classifyWorkflowName,
  isEntrypointShapedPath,
  isEnvironmentShapedName,
  isEstablishedProductionState,
} from "./production-report.js";

// Phase 21 — the production **risk** report: the same six domains, read for the production
// conditions the inventory's own evidence proves, and for a defect only where the repository's
// own declaration proves one. Its six section names, its classification table, its three-word
// severity table, its four-word confidence vocabulary, its per-kind basis table, its abstention
// vocabulary and its bounds are all part of its interface, so all of them are exported rather
// than reached for through the report object.
export {
  PRODUCTION_RISK_BASIS_BY_KIND,
  PRODUCTION_RISK_CLASSIFICATION_BY_KIND,
  PRODUCTION_RISK_CLASSIFICATIONS,
  PRODUCTION_RISK_CLASSIFICATION_VALUES,
  PRODUCTION_RISK_CONFIDENCE_BY_KIND,
  PRODUCTION_RISK_CONFIDENCES,
  PRODUCTION_RISK_CONFIDENCE_VALUES,
  PRODUCTION_RISK_FINDING_KINDS,
  PRODUCTION_RISK_REPORT_BUILDER,
  PRODUCTION_RISK_REPORT_LIMITS,
  PRODUCTION_RISK_REPORT_VERSION,
  PRODUCTION_RISK_ROUTER_SCOPE,
  PRODUCTION_RISK_SECTIONS,
  PRODUCTION_RISK_SECTION_TITLES,
  PRODUCTION_RISK_SEVERITIES,
  PRODUCTION_RISK_SEVERITY_BY_KIND,
  PRODUCTION_RISK_SEVERITY_VALUES,
  PRODUCTION_RISK_STATES,
  PRODUCTION_RISK_STATE_VALUES,
  PRODUCTION_RISK_UNKNOWN_REASONS,
  PRODUCTION_RISK_UNSUPPORTED_REASONS,
  buildProductionRiskReport,
  isEstablishedRiskState,
  renderRiskRemediation,
  renderRiskStatement,
} from "./production-risk-report.js";

// Phase 22 — the repository policy area. The one *input* this architecture reads as a contract:
// its document path, its closed domain schema, its read statuses and refusal reasons, its five
// states and its abstention vocabulary are all part of its interface — a consumer switches on
// them — so all of them are exported rather than reached for through the area object.
export {
  MAX_RELEASE_WORKFLOWS,
  POLICY_ANSWERED_STATES,
  POLICY_BUILDER,
  POLICY_DOCUMENT_KEYS,
  POLICY_DOCUMENT_METADATA_KEYS,
  POLICY_DOCUMENT_PATH,
  POLICY_DOCUMENT_PRESET_KEY,
  POLICY_DOCUMENT_SCHEMA,
  POLICY_DOCUMENT_VERSION,
  POLICY_DOMAINS,
  POLICY_LIMITS,
  POLICY_READ_FAILURE_REASONS,
  POLICY_READ_STATUSES,
  POLICY_READ_STATUS_VALUES,
  POLICY_READ_UNSUPPORTED_REASONS,
  POLICY_STATES,
  POLICY_STATE_VALUES,
  POLICY_UNKNOWN_REASONS,
  POLICY_UNKNOWN_REASON_VALUES,
  POLICY_VERSION,
  buildPolicyArea,
  emptyPolicyArea,
  isEstablishedPolicyState,
  policyDocumentDomains,
  policyDocumentEvidenceId,
  policyDocumentPresetName,
  policyDocumentSettingCount,
} from "./policy.js";

// Phase 22 — the compliance report: one section per policy domain, each item measured against a
// declared requirement. Its six domains, its three statuses, its four section states, its five
// report states, its observed-value vocabulary, its requirement-binding table, its abstention
// vocabulary, its bounds and the rationale renderer whose output the validator recomputes are all
// part of its interface.
export {
  COMPLIANCE_BUILDER,
  COMPLIANCE_CHECK_IDS,
  COMPLIANCE_LIMITS,
  COMPLIANCE_OBSERVED_VALUES,
  COMPLIANCE_POLICY_READ_STATUSES,
  COMPLIANCE_POLICY_SCHEMA,
  COMPLIANCE_SECTIONS,
  COMPLIANCE_SECTION_STATES,
  COMPLIANCE_SECTION_STATE_VALUES,
  COMPLIANCE_SECTION_TITLES,
  COMPLIANCE_STATES,
  COMPLIANCE_STATE_VALUES,
  COMPLIANCE_STATUSES,
  COMPLIANCE_STATUS_VALUES,
  COMPLIANCE_UNKNOWN_REASONS,
  COMPLIANCE_UNKNOWN_REASON_VALUES,
  COMPLIANCE_VERSION,
  POLICY_REQUIREMENT_BINDING,
  buildComplianceReport,
  renderComplianceRationale,
} from "./compliance-report.js";

export {
  GRAPH_ENTITY_KINDS,
  GRAPH_RELATIONSHIP_TYPES,
  RELATIONSHIP_TYPES,
} from "./graph.js";

// Phase 14 — the dependency graph: its closed vocabularies, its bounds, and the
// projection the builder materializes into `model.dependencies.graph`.
export {
  DEPENDENCY_GRAPH_EDGE_TYPES,
  DEPENDENCY_GRAPH_EDGE_TYPE_VALUES,
  DEPENDENCY_GRAPH_LIMITS,
  DEPENDENCY_GRAPH_STATES,
  DEPENDENCY_GRAPH_STATE_VALUES,
  DEPENDENCY_GRAPH_VERSION,
  buildDependencyGraph,
  dependencyGraphState,
  isSourceEstablished,
  unestablishedSourceRecord,
} from "./dependency-graph.js";

// Phase 15 — the architecture graph: its closed vocabularies, its bounds, and the
// projection the builder materializes into `model.architecture.graph`.
export {
  ARCHITECTURE_EDGE_TYPES,
  ARCHITECTURE_EDGE_TYPE_VALUES,
  ARCHITECTURE_GRAPH_LIMITS,
  ARCHITECTURE_GRAPH_STATES,
  ARCHITECTURE_GRAPH_STATE_VALUES,
  ARCHITECTURE_GRAPH_VERSION,
  ARCHITECTURE_NODE_KINDS,
  REPOSITORY_NODE_KIND,
  architectureGraphState,
  buildArchitectureGraph,
  collectArchitecturalEntities,
  isArchitecturalEntity,
  isEstablishedState,
} from "./architecture-graph.js";

export {
  COVERAGE_CLASSES,
  COVERAGE_GUARANTEES,
  coverageClass,
  entityIdsForEvidence,
  getDependencyByName,
  getDirectoryByPath,
  getEntity,
  getEntityEvidence,
  getEvidence,
  getFileByPath,
  getManifestByPath,
  getSymlinkByPath,
  inspectCompleteness,
  isKnownAbsent,
  listDependencies,
  listDependenciesByEcosystem,
  listEntitiesByKind,
  listFilesByLanguage,
  listManifestsByEcosystem,
  listRelationships,
  relationshipsFrom,
  relationshipsTo,
} from "./query.js";

// Phase 11 — repository-intelligence query layer: contracts, errors and the
// read-only semantic API. `createRepositoryQuery(model)` is the entry point.
export {
  PRODUCTION_COVERAGE_RESULT_FIELDS,
  PRODUCTION_REPORT_RESULT_FIELDS,
  PRODUCTION_SECTION_RESULT_FIELDS,
  createProductionCoverageResult,
  createProductionReportResult,
  createProductionSectionResult,
  validateProductionCoverageResult,
  validateProductionReportResult,
  validateProductionSectionResult,
  PRODUCTION_RISK_COVERAGE_RESULT_FIELDS,
  PRODUCTION_RISK_FINDING_RESULT_FIELDS,
  PRODUCTION_RISK_REPORT_RESULT_FIELDS,
  PRODUCTION_RISK_SECTION_RESULT_FIELDS,
  createProductionRiskCoverageResult,
  createProductionRiskReportResult,
  createProductionRiskSectionResult,
  validateProductionRiskCoverageResult,
  validateProductionRiskReportResult,
  validateProductionRiskSectionResult,
  DEPENDENCY_EDGE_RESULT_FIELDS,
  DEPENDENCY_GRAPH_RESULT_FIELDS,
  DEPENDENCY_PATH_RESULT_FIELDS,
  DEPENDENCY_TRAVERSAL_RESULT_FIELDS,
  ENTITY_QUERY_RESULT_FIELDS,
  EVIDENCE_QUERY_RESULT_FIELDS,
  FRAMEWORK_USAGE_RESULT_FIELDS,
  IMPORT_EDGE_RESULT_FIELDS,
  IMPORT_GRAPH_RESULT_FIELDS,
  IMPORT_NODE_RESULT_FIELDS,
  API_GRAPH_RESULT_FIELDS,
  API_HANDLER_ROUTE_RESULT_FIELDS,
  API_ROUTE_HANDLER_RESULT_FIELDS,
  API_ROUTE_LOOKUP_RESULT_FIELDS,
  API_ROUTE_MIDDLEWARE_RESULT_FIELDS,
  MIDDLEWARE_CHAIN_RESULT_FIELDS,
  MIDDLEWARE_GRAPH_RESULT_FIELDS,
  MIDDLEWARE_PROTECTED_ROUTE_RESULT_FIELDS,
  MIDDLEWARE_RESULT_FIELDS,
  MIDDLEWARE_STATE_VALUES,
  MIDDLEWARE_UNRESOLVED_RESULT_FIELDS,
  API_ROUTE_RESULT_FIELDS,
  API_ROUTE_STATE_VALUES,
  API_SERVICE_RESULT_FIELDS,
  API_UNRESOLVED_ROUTE_RESULT_FIELDS,
  IMPORT_PATH_RESULT_FIELDS,
  IMPORT_TRAVERSAL_RESULT_FIELDS,
  IMPORT_UNRESOLVED_RESULT_FIELDS,
  QUERY_DIRECTIONS,
  QUERY_DIRECTION_VALUES,
  QUERY_LIMITS,
  RELATIONSHIP_QUERY_RESULT_FIELDS,
  TRAVERSAL_RESULT_FIELDS,
  createApiGraphResult,
  createApiHandlerRouteResult,
  createApiRouteHandlerResult,
  createApiRouteLookupResult,
  createApiRouteMiddlewareResult,
  createApiRouteQueryResult,
  createApiServiceResult,
  createApiUnresolvedRouteResult,
  createMiddlewareChainResult,
  createMiddlewareGraphResult,
  createMiddlewareProtectedRouteResult,
  createMiddlewareQueryResult,
  createMiddlewareUnresolvedResult,
  createDependencyEdgeQueryResult,
  createDependencyGraphResult,
  createDependencyPathResult,
  createDependencyTraversalResult,
  createEntityQueryResult,
  createEvidenceQueryResult,
  createImportEdgeQueryResult,
  createImportGraphResult,
  createImportNodeQueryResult,
  createImportPathResult,
  createImportTraversalResult,
  createImportUnresolvedQueryResult,
  createRelationshipQueryResult,
  createSymbolBindingQueryResult,
  createSymbolEdgeQueryResult,
  createSymbolGraphResult,
  createSymbolNodeQueryResult,
  createSymbolPathResult,
  createSymbolReferenceResult,
  createSymbolTraversalResult,
  createSymbolUnresolvedQueryResult,
  createTraversalResult,
  validateApiGraphResult,
  validateApiHandlerRouteResult,
  validateApiRouteHandlerResult,
  validateApiRouteLookupResult,
  validateApiRouteMiddlewareResult,
  validateApiRouteQueryResult,
  validateApiServiceResult,
  validateApiUnresolvedRouteResult,
  validateMiddlewareChainResult,
  validateMiddlewareGraphResult,
  validateMiddlewareProtectedRouteResult,
  validateMiddlewareQueryResult,
  validateMiddlewareUnresolvedResult,
  validateDependencyEdgeQueryResult,
  validateDependencyGraphResult,
  validateDependencyPathResult,
  validateDependencyTraversalResult,
  validateEntityQueryResult,
  validateEvidenceQueryResult,
  validateImportEdgeQueryResult,
  validateImportGraphResult,
  validateImportNodeQueryResult,
  validateImportPathResult,
  validateImportTraversalResult,
  validateImportUnresolvedQueryResult,
  validateRelationshipQueryResult,
  validateSymbolBindingQueryResult,
  validateSymbolEdgeQueryResult,
  validateSymbolGraphResult,
  validateSymbolNodeQueryResult,
  validateSymbolPathResult,
  validateSymbolReferenceResult,
  validateSymbolTraversalResult,
  validateSymbolUnresolvedQueryResult,
  validateTraversalResult,
  // Phase 23 — the preset, effective-policy and provenance answers.
  EFFECTIVE_POLICY_RESULT_FIELDS,
  POLICY_PRESET_RESULT_FIELDS,
  POLICY_PROVENANCE_RESULT_FIELDS,
  createEffectivePolicyResult,
  createPolicyPresetResult,
  createPolicyProvenanceResult,
  validateEffectivePolicyResult,
  validatePolicyPresetResult,
  validatePolicyProvenanceResult,
  // Phase 24 — the pack the applied preset came from.
  POLICY_PACK_RESULT_FIELDS,
  createPolicyPackResult,
  validatePolicyPackResult,
  // Phase 22's policy and provenance result contracts, exported on the same terms as the Phase 23
  // ones: a consumer validating a result it assembled itself needs the same closed contract the
  // query layer applies.
  createPolicyResult,
  validatePolicyResult,
} from "./query-contracts.js";

export {
  MAX_QUERY_TOKEN_LENGTH,
  QUERY_ERROR_CODES,
  QUERY_ERROR_KINDS,
  RepositoryQueryError,
  safeQueryToken,
} from "./query-errors.js";

export { createRepositoryQuery } from "./query-api.js";

export {
  MAX_RELATIVE_PATH_LENGTH,
  basenameOfPath,
  depthOfPath,
  isRepositoryRelativePath,
  parentPathOf,
  requireRepositoryRelativePath,
  toRepositoryRelativePath,
} from "./paths.js";
