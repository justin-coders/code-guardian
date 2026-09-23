/**
 * Code Guardian — RepositoryModel Query API (Phase 8D)
 *
 * Small, deterministic accessors over a built model. The model itself is plain
 * frozen data; these functions only read it, so an analyzer cannot corrupt another
 * analyzer's view by accident.
 *
 * Every lookup is index-backed (`O(1)` for ids and paths, `O(edges)` only where no
 * index exists), and every accessor tolerates unknown input by returning `null`
 * or `[]` rather than throwing — a query is not validation.
 *
 * ### Coverage queries
 *
 * `coverageClass` and `isKnownAbsent` are the only correct way to ask whether
 * something is missing, because they know the difference between the four ways a
 * path can be absent from the entity collections:
 *
 *   observed     the scanner saw it
 *   ignored      policy excluded it (it was seen and consciously not inventoried)
 *   unreadable   it could not be read (a permission or I/O failure)
 *   unknown      the scan did not cover it (truncation or an incomplete scan)
 *   absent       the scan covered this path and found nothing (the only case in
 *                which "does not exist" is a claim the model supports)
 *
 * A caller that asks `filesByPath[path] === undefined` instead is silently
 * conflating the last four, which is exactly the misreading Phase 8C/8D exist to
 * prevent.
 */

import { ENTITY_KINDS } from "./identity.js";
import { isRepositoryRelativePath } from "./paths.js";

/** Coverage classes reported by `coverageClass`. */
export const COVERAGE_CLASSES = Object.freeze({
  OBSERVED: "observed",
  IGNORED: "ignored",
  UNREADABLE: "unreadable",
  UNKNOWN: "unknown",
  ABSENT: "absent",
});

/** Coverage guarantees reported by `inspectCompleteness`. */
export const COVERAGE_GUARANTEES = Object.freeze({
  COMPLETE: "complete",
  PARTIAL: "partial",
});

const coverageCache = new WeakMap();

function coverageIndex(model) {
  const cached = coverageCache.get(model);
  if (cached !== undefined) return cached;

  const index = {
    ignored: new Set((model.scan.coverage.ignored.paths ?? []).map((entry) => entry.path)),
    unreadable: new Set((model.scan.coverage.unreadable.paths ?? []).map((entry) => entry.path)),
    truncated: model.scan.truncated === true,
  };
  coverageCache.set(model, index);
  return index;
}

function coversPath(set, path) {
  const segments = path.split("/");
  for (let index = 1; index <= segments.length; index += 1) {
    if (set.has(segments.slice(0, index).join("/"))) return true;
  }
  return false;
}

/** Entity by id, or `null`. */
export function getEntity(model, id) {
  if (typeof id !== "string") return null;
  return model.indexes.entitiesById[id] ?? null;
}

/** File entity by repository-relative path, or `null`. */
export function getFileByPath(model, path) {
  if (!isRepositoryRelativePath(path)) return null;
  const id = model.indexes.filesByPath[path];
  return id === undefined ? null : getEntity(model, id);
}

/** Directory entity by repository-relative path, or `null`. */
export function getDirectoryByPath(model, path) {
  if (!isRepositoryRelativePath(path)) return null;
  const id = model.indexes.directoriesByPath[path];
  return id === undefined ? null : getEntity(model, id);
}

/** Symlink entity by repository-relative path, or `null`. */
export function getSymlinkByPath(model, path) {
  if (!isRepositoryRelativePath(path)) return null;
  const id = model.indexes.symlinksByPath[path];
  return id === undefined ? null : getEntity(model, id);
}

/** Manifest entity by repository-relative path, or `null`. */
export function getManifestByPath(model, path) {
  if (!isRepositoryRelativePath(path)) return null;
  const id = model.indexes.manifestsByPath[path];
  return id === undefined ? null : getEntity(model, id);
}

/** Every entity of a kind, in id order. */
export function listEntitiesByKind(model, kind) {
  const ids = model.indexes.entityIdsByKind[kind];
  if (ids === undefined) return [];
  return ids.map((id) => getEntity(model, id)).filter((entity) => entity !== null);
}

/** File entities observed for a language id (e.g. `typescript`), in id order. */
export function listFilesByLanguage(model, languageId) {
  const ids = model.indexes.filesByLanguage[`language:${languageId}`];
  if (ids === undefined) return [];
  return ids.map((id) => getEntity(model, id)).filter((entity) => entity !== null);
}

/** Manifest entities in an ecosystem, in id order. */
export function listManifestsByEcosystem(model, ecosystemId) {
  const ids = model.indexes.manifestsByEcosystem[`ecosystem:${ecosystemId}`];
  if (ids === undefined) return [];
  return ids.map((id) => getEntity(model, id)).filter((entity) => entity !== null);
}

/**
 * Dependency entities in an ecosystem, in id order.
 *
 * @param {object} model
 * @param {string} ecosystemId Ecosystem id (`node`, `python`, `go`).
 * @returns {object[]}
 */
export function listDependenciesByEcosystem(model, ecosystemId) {
  const ids = model.indexes.dependenciesByEcosystem?.[`ecosystem:${ecosystemId}`];
  if (ids === undefined) return [];
  return ids.map((id) => getEntity(model, id)).filter((entity) => entity !== null);
}

/**
 * A dependency entity by `(ecosystem, name)` — its canonical identity, or `null`.
 *
 * The name must already be in its normalized form (see the acquisition layer's
 * `normalizeDependencyName`); the index is keyed by identity, not by spelling, so
 * `Flask` does not resolve to the `flask` entity.
 */
export function getDependencyByName(model, ecosystem, name) {
  if (typeof ecosystem !== "string" || typeof name !== "string") return null;
  const id = model.indexes.dependencyIdsByName?.[`${ecosystem}:${name}`];
  return id === undefined ? null : getEntity(model, id);
}

/** Every dependency entity, in id order. */
export function listDependencies(model) {
  return listEntitiesByKind(model, ENTITY_KINDS.DEPENDENCY);
}

/**
 * Relationships matching every supplied filter (`from`, `type`, `to`).
 *
 * The `from`/`to` indexes narrow the scan before filtering, so the common
 * "everything connected to this entity" queries do not walk the whole edge list.
 */
export function listRelationships(model, filter = {}) {
  const { from, type, to } = filter;

  let positions;
  if (typeof from === "string") {
    positions = model.indexes.relationshipsByFrom[from] ?? [];
    if (typeof to === "string") {
      const toPositions = new Set(model.indexes.relationshipsByTo[to] ?? []);
      positions = positions.filter((index) => toPositions.has(index));
    }
  } else if (typeof to === "string") {
    positions = model.indexes.relationshipsByTo[to] ?? [];
  } else {
    positions = model.relationships.map((_relationship, index) => index);
  }

  const matches = positions.map((index) => model.relationships[index]);
  if (typeof type !== "string") return matches;
  return matches.filter((relationship) => relationship.type === type);
}

/** Relationships whose `from` is an entity id. */
export function relationshipsFrom(model, entityIdValue) {
  return listRelationships(model, { from: entityIdValue });
}

/** Relationships whose `to` is an entity id (incoming edges, e.g. provenance-free reverse lookups). */
export function relationshipsTo(model, entityIdValue) {
  return listRelationships(model, { to: entityIdValue });
}

/** Evidence record by id, or `null`. */
export function getEvidence(model, id) {
  if (typeof id !== "string") return null;
  return model.indexes.evidenceById[id] ?? null;
}

/** Evidence records an entity was derived from, in id order. */
export function getEntityEvidence(model, entityIdValue) {
  const entity = getEntity(model, entityIdValue);
  if (entity === null) return [];
  return entity.evidenceIds
    .map((id) => getEvidence(model, id))
    .filter((record) => record !== null);
}

/** Entity ids that reference an evidence record, in id order. */
export function entityIdsForEvidence(model, evidenceIdValue) {
  if (typeof evidenceIdValue !== "string") return [];
  return [...(model.indexes.entityIdsByEvidence[evidenceIdValue] ?? [])];
}

/**
 * A compact, explicit statement of what the model does and does not cover.
 *
 * @returns {object} Coverage and limit state, never judgments.
 */
export function inspectCompleteness(model) {
  return {
    complete: model.scan.complete === true,
    truncated: model.scan.truncated === true,
    guarantee: model.scan.coverage.guarantee,
    limits: model.scan.limits,
    truncatedBy: model.scan.coverage.truncatedBy,
    errors: model.scan.errors,
    observed: model.scan.coverage.observed,
    ignoredCount: model.scan.coverage.ignored.count,
    unreadableCount: model.scan.coverage.unreadable.count,
  };
}

/**
 * Classify a repository-relative path against the scan's coverage.
 *
 * @returns {string} One of `COVERAGE_CLASSES`. A non-relative path is `unknown`:
 *   the model can say nothing about a path outside the repository.
 */
export function coverageClass(model, path) {
  if (!isRepositoryRelativePath(path)) return COVERAGE_CLASSES.UNKNOWN;

  if (
    path in model.indexes.filesByPath ||
    path in model.indexes.directoriesByPath ||
    path in model.indexes.symlinksByPath
  ) {
    return COVERAGE_CLASSES.OBSERVED;
  }

  const index = coverageIndex(model);
  if (coversPath(index.ignored, path)) return COVERAGE_CLASSES.IGNORED;
  if (coversPath(index.unreadable, path)) return COVERAGE_CLASSES.UNREADABLE;
  if (index.truncated || model.scan.complete !== true) return COVERAGE_CLASSES.UNKNOWN;
  return COVERAGE_CLASSES.ABSENT;
}

/**
 * Whether the model positively supports "this path does not exist".
 *
 * True only for a complete scan that covered the path and observed nothing there.
 */
export function isKnownAbsent(model, path) {
  return coverageClass(model, path) === COVERAGE_CLASSES.ABSENT;
}
