/**
 * Code Guardian — RepositoryModel Graph (Phase 8D)
 *
 * Builds the model's deterministic relationships and lookup indexes. Both are
 * derived *only* from the entity collections: no filesystem, no clock, no
 * randomness, no evaluation order that depends on object iteration.
 *
 * ### Why a relationship list and not nested objects
 *
 * If a directory embedded its children and each child embedded its directory, the
 * model would be cyclic, unserializable and would freeze badly. Relationships are
 * therefore a flat, sorted edge list (`{ from, type, to }`) referencing entity ids.
 * Every edge is *observed*: an edge is emitted only when the ScanResult already
 * established the fact (a parent path, a declared language, a declared provider).
 *
 * ### Deliberately absent relationships
 *
 * There is no import graph, no call graph, no dependency graph, no API graph and
 * no architecture graph. Those require parsing and resolution phases that have not
 * run; inventing them here would turn an inventory into a guess. The relationship
 * vocabulary below is closed for exactly that reason.
 */

import { ENTITY_KINDS } from "./identity.js";

/** Closed relationship vocabulary. */
export const RELATIONSHIP_TYPES = Object.freeze({
  /** Repository → observed or derived entity. */
  CONTAINS: "contains",
  /** Directory → its parent directory. */
  PARENT: "parent",
  /** Path-bearing entity → the directory it sits in (the repository at the root). */
  LOCATED_IN: "located_in",
  /** File → a language observed for that file. */
  SIGNALS: "signals",
  /** Manifest → a language the manifest declares. */
  DECLARES: "declares",
  /** Manifest → the ecosystem the manifest belongs to. */
  ECOSYSTEM: "ecosystem",
  /** Test evidence entity → the framework it belongs to. */
  FRAMEWORK: "framework",
  /** Manifest → a dependency that manifest declares (Phase 13). */
  DECLARES_DEPENDENCY: "declares-dependency",
  /** Dependency → a dependency a lockfile states it depends on (Phase 13). */
  DEPENDS_ON: "depends-on",
  /** Dependency → the lockfile that resolved it (Phase 13). */
  RESOLVED_BY: "resolved-by",
});

function compareRelationships(a, b) {
  if (a.from !== b.from) return a.from < b.from ? -1 : 1;
  if (a.type !== b.type) return a.type < b.type ? -1 : 1;
  if (a.to === b.to) return 0;
  return a.to < b.to ? -1 : 1;
}

function edge(from, type, to) {
  return { from, type, to };
}

/**
 * The entity collections the graph connects, in one place.
 *
 * Both the containment edges and the indexes are built from this list, so an entity
 * collection can never be contained by the repository but missing from the index (or
 * the reverse) — the failure mode that would make a query silently return nothing.
 */
function allEntities(collections) {
  return [
    ...collections.files,
    ...collections.directories,
    ...collections.symlinks,
    ...collections.languages,
    ...collections.frameworks,
    ...collections.ecosystems,
    ...collections.manifests,
    ...collections.dependencies,
    ...collections.tests,
    ...collections.cicd,
    ...collections.documentation,
    ...collections.configuration,
    collections.git,
  ];
}

/**
 * Build the relationship list.
 *
 * @param {object} collections Entity collections from `entities.js`.
 * @param {string} repositoryIdValue Repository node id.
 * @returns {object[]} Sorted relationships.
 */
export function buildRelationships(collections, repositoryIdValue) {
  const {
    files,
    symlinks,
    manifests,
    dependencies,
    dependencyEdges,
    tests,
    cicd,
    documentation,
    configuration,
    directories,
    git,
  } = collections;

  const relationships = [];

  for (const entity of allEntities(collections)) {
    relationships.push(edge(repositoryIdValue, RELATIONSHIP_TYPES.CONTAINS, entity.id));
  }

  for (const directory of directories) {
    if (directory.parentId === null) continue;
    relationships.push(edge(directory.id, RELATIONSHIP_TYPES.PARENT, directory.parentId));
  }

  for (const entity of [...files, ...symlinks, ...manifests, ...tests, ...cicd, ...documentation, ...configuration]) {
    relationships.push(edge(entity.id, RELATIONSHIP_TYPES.LOCATED_IN, entity.directoryId));
  }

  for (const file of files) {
    if (file.languageId === null) continue;
    relationships.push(edge(file.id, RELATIONSHIP_TYPES.SIGNALS, file.languageId));
  }

  for (const manifest of manifests) {
    relationships.push(edge(manifest.id, RELATIONSHIP_TYPES.ECOSYSTEM, manifest.ecosystemId));
    for (const languageId of manifest.languages) {
      relationships.push(edge(manifest.id, RELATIONSHIP_TYPES.DECLARES, languageId));
    }
  }

  for (const test of tests) {
    if (test.frameworkId === null) continue;
    relationships.push(edge(test.id, RELATIONSHIP_TYPES.FRAMEWORK, test.frameworkId));
  }

  // Dependency relationships are derived only from recorded declaration and
  // resolution facts: a manifest *declares* what its sections declared, a lockfile
  // edge *depends-on* another package, and a resolved package is *resolved-by* the
  // lockfile that pinned it. No import, call or source-level relationship is built
  // here — that requires a parsing phase this architecture does not have yet.
  const manifestIds = new Set(manifests.map((manifest) => manifest.id));
  const dependencyIds = new Set(dependencies.map((dependency) => dependency.id));
  for (const dependency of dependencies) {
    for (const declaration of dependency.declarations) {
      if (!manifestIds.has(declaration.manifestId)) continue;
      relationships.push(
        edge(declaration.manifestId, RELATIONSHIP_TYPES.DECLARES_DEPENDENCY, dependency.id),
      );
    }
    for (const resolution of dependency.resolutions) {
      if (!manifestIds.has(resolution.manifestId)) continue;
      relationships.push(edge(dependency.id, RELATIONSHIP_TYPES.RESOLVED_BY, resolution.manifestId));
    }
  }
  for (const dependencyEdge of dependencyEdges) {
    if (!dependencyIds.has(dependencyEdge.from) || !dependencyIds.has(dependencyEdge.to)) continue;
    relationships.push(
      edge(dependencyEdge.from, RELATIONSHIP_TYPES.DEPENDS_ON, dependencyEdge.to),
    );
  }

  return relationships.sort(compareRelationships);
}

function sortedRecord(entries) {
  const record = {};
  const ordered = [...entries].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  for (const [key, value] of ordered) record[key] = value;
  return record;
}

/**
 * Build the lookup indexes.
 *
 * All backed collections are stored once (in the typed areas and in
 * `evidence`); the indexes hold references and position lists so the model stays
 * a single source of truth rather than a set of duplicated copies.
 *
 * @param {object} collections Entity collections from `entities.js`.
 * @param {object[]} relationships Sorted relationship list.
 * @param {object[]} evidence Sorted evidence list.
 * @returns {object} The index record.
 */
export function buildIndexes(collections, relationships, evidence) {
  const entities = allEntities(collections);

  const entitiesById = sortedRecord(entities.map((entity) => [entity.id, entity]));

  const idsByKind = new Map();
  for (const entity of entities) {
    const bucket = idsByKind.get(entity.kind);
    if (bucket === undefined) idsByKind.set(entity.kind, [entity.id]);
    else bucket.push(entity.id);
  }
  const entityIdsByKind = sortedRecord(
    [...idsByKind.entries()].map(([kind, ids]) => [kind, [...ids].sort()]),
  );

  const pathsFor = (list) => sortedRecord(list.map((entity) => [entity.path, entity.id]));
  const filesByPath = pathsFor(collections.files);
  const directoriesByPath = pathsFor(collections.directories);
  const symlinksByPath = pathsFor(collections.symlinks);
  const manifestsByPath = pathsFor(collections.manifests);

  const languageBuckets = new Map();
  for (const file of collections.files) {
    if (file.languageId === null) continue;
    const bucket = languageBuckets.get(file.languageId);
    if (bucket === undefined) languageBuckets.set(file.languageId, [file.id]);
    else bucket.push(file.id);
  }
  const filesByLanguage = sortedRecord(
    [...languageBuckets.entries()].map(([languageId, ids]) => [languageId, [...ids].sort()]),
  );

  const ecosystemBuckets = new Map();
  for (const manifest of collections.manifests) {
    const bucket = ecosystemBuckets.get(manifest.ecosystemId);
    if (bucket === undefined) ecosystemBuckets.set(manifest.ecosystemId, [manifest.id]);
    else bucket.push(manifest.id);
  }
  const manifestsByEcosystem = sortedRecord(
    [...ecosystemBuckets.entries()].map(([ecosystemId, ids]) => [ecosystemId, [...ids].sort()]),
  );

  const dependencyBuckets = new Map();
  for (const dependency of collections.dependencies) {
    const bucket = dependencyBuckets.get(dependency.ecosystemId);
    if (bucket === undefined) dependencyBuckets.set(dependency.ecosystemId, [dependency.id]);
    else bucket.push(dependency.id);
  }
  const dependenciesByEcosystem = sortedRecord(
    [...dependencyBuckets.entries()].map(([ecosystemId, ids]) => [ecosystemId, [...ids].sort()]),
  );

  const dependencyIdsByName = sortedRecord(
    collections.dependencies.map((dependency) => [
      `${dependency.ecosystem}:${dependency.name}`,
      dependency.id,
    ]),
  );

  const evidenceById = sortedRecord(evidence.map((record) => [record.id, record]));

  const entityBuckets = new Map();
  for (const entity of entities) {
    for (const evidenceIdValue of entity.evidenceIds) {
      const bucket = entityBuckets.get(evidenceIdValue);
      if (bucket === undefined) entityBuckets.set(evidenceIdValue, [entity.id]);
      else bucket.push(entity.id);
    }
  }
  const entityIdsByEvidence = sortedRecord(
    [...entityBuckets.entries()].map(([id, ids]) => [id, [...ids].sort()]),
  );

  // Relationships are kept in one canonical sorted list; the indexes hold
  // positions into it so edges are never duplicated.
  const fromBuckets = new Map();
  const toBuckets = new Map();
  relationships.forEach((relationship, index) => {
    const from = fromBuckets.get(relationship.from);
    if (from === undefined) fromBuckets.set(relationship.from, [index]);
    else from.push(index);

    const to = toBuckets.get(relationship.to);
    if (to === undefined) toBuckets.set(relationship.to, [index]);
    else to.push(index);
  });

  return {
    entitiesById,
    entityIdsByKind,
    filesByPath,
    directoriesByPath,
    symlinksByPath,
    manifestsByPath,
    filesByLanguage,
    manifestsByEcosystem,
    dependenciesByEcosystem,
    dependencyIdsByName,
    evidenceById,
    entityIdsByEvidence,
    relationshipsByFrom: sortedRecord([...fromBuckets.entries()]),
    relationshipsByTo: sortedRecord([...toBuckets.entries()]),
  };
}

/** The relationship vocabulary as a list, for validation and documentation. */
export const GRAPH_RELATIONSHIP_TYPES = Object.freeze(Object.values(RELATIONSHIP_TYPES));

/** Entity kinds the graph can connect, exported for consumers and tests. */
export const GRAPH_ENTITY_KINDS = Object.freeze(Object.values(ENTITY_KINDS));
