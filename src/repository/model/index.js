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
  EVIDENCE_COLLECTOR,
  EVIDENCE_SOURCE,
  EVIDENCE_SUBJECTS,
  EVIDENCE_TYPE_BY_SUBJECT,
  INVENTORY_KINDS,
  createInventoryObservation,
  createObservation,
  createSignalObservation,
} from "./evidence.js";

export { TEST_KINDS, GIT_HEAD_KINDS, projectGitHead } from "./entities.js";

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

export {
  MAX_RELATIVE_PATH_LENGTH,
  basenameOfPath,
  depthOfPath,
  isRepositoryRelativePath,
  parentPathOf,
  requireRepositoryRelativePath,
  toRepositoryRelativePath,
} from "./paths.js";
