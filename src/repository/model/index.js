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
 */

export {
  MODEL_ENTITY_COLLECTIONS,
  MODEL_IMMUTABILITY,
  REPOSITORY_MODEL_BUILDER,
  REPOSITORY_MODEL_BUILDER_VERSION,
  collectModelEntities,
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
  INVENTORY_KINDS,
  contentObservationKind,
  createBuildContextObservation,
  createContentInspectionObservation,
  createContentPatternObservation,
  createDependencyDeclarationObservation,
  createDependencyResolutionObservation,
  createDependencySourceObservation,
  createInventoryObservation,
  createObservation,
  createSignalObservation,
} from "./evidence.js";

export {
  DEPENDENCY_PROBLEM_REASONS,
  DEPENDENCY_SCOPES,
  DEPENDENCY_SOURCE_REASONS,
  DEPENDENCY_SOURCE_STATUSES,
  DEPENDENCY_SPEC_KINDS,
  GIT_HEAD_KINDS,
  SYMLINK_TARGET_KINDS,
  SYMLINK_TARGET_REASONS,
  TEST_KINDS,
  projectDependencyName,
  projectGitHead,
  projectSymlinkTarget,
} from "./entities.js";

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
  DEPENDENCY_EDGE_RESULT_FIELDS,
  DEPENDENCY_GRAPH_RESULT_FIELDS,
  DEPENDENCY_PATH_RESULT_FIELDS,
  DEPENDENCY_TRAVERSAL_RESULT_FIELDS,
  ENTITY_QUERY_RESULT_FIELDS,
  EVIDENCE_QUERY_RESULT_FIELDS,
  QUERY_DIRECTIONS,
  QUERY_DIRECTION_VALUES,
  QUERY_LIMITS,
  RELATIONSHIP_QUERY_RESULT_FIELDS,
  TRAVERSAL_RESULT_FIELDS,
  createDependencyEdgeQueryResult,
  createDependencyGraphResult,
  createDependencyPathResult,
  createDependencyTraversalResult,
  createEntityQueryResult,
  createEvidenceQueryResult,
  createRelationshipQueryResult,
  createTraversalResult,
  validateDependencyEdgeQueryResult,
  validateDependencyGraphResult,
  validateDependencyPathResult,
  validateDependencyTraversalResult,
  validateEntityQueryResult,
  validateEvidenceQueryResult,
  validateRelationshipQueryResult,
  validateTraversalResult,
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
