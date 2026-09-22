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
  CONTENT_SIGNALS,
  CONTENT_STATUSES,
  CONTENT_UNINSPECTED_REASONS,
  EVIDENCE_COLLECTOR,
  EVIDENCE_SOURCE,
  EVIDENCE_SUBJECTS,
  EVIDENCE_TYPE_BY_SUBJECT,
  INVENTORY_KINDS,
  contentObservationKind,
  createContentInspectionObservation,
  createContentPatternObservation,
  createInventoryObservation,
  createObservation,
  createSignalObservation,
} from "./evidence.js";

export {
  GIT_HEAD_KINDS,
  SYMLINK_TARGET_KINDS,
  SYMLINK_TARGET_REASONS,
  TEST_KINDS,
  projectGitHead,
  projectSymlinkTarget,
} from "./entities.js";

export {
  GRAPH_ENTITY_KINDS,
  GRAPH_RELATIONSHIP_TYPES,
  RELATIONSHIP_TYPES,
} from "./graph.js";

export {
  COVERAGE_CLASSES,
  COVERAGE_GUARANTEES,
  coverageClass,
  entityIdsForEvidence,
  getDirectoryByPath,
  getEntity,
  getEntityEvidence,
  getEvidence,
  getFileByPath,
  getManifestByPath,
  getSymlinkByPath,
  inspectCompleteness,
  isKnownAbsent,
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
  ENTITY_QUERY_RESULT_FIELDS,
  EVIDENCE_QUERY_RESULT_FIELDS,
  QUERY_DIRECTIONS,
  QUERY_DIRECTION_VALUES,
  QUERY_LIMITS,
  RELATIONSHIP_QUERY_RESULT_FIELDS,
  TRAVERSAL_RESULT_FIELDS,
  createEntityQueryResult,
  createEvidenceQueryResult,
  createRelationshipQueryResult,
  createTraversalResult,
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
