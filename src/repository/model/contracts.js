/**
 * Code Guardian — RepositoryModel Contract & Invariants (Phase 8D)
 *
 * Two layers validate a built model:
 *
 *   1. `validateRepositoryModel` (Core, Phase 7) is the authority on the
 *      contracted *shape*: required areas, typed collections, nested Evidence
 *      records, and the rule that a truncated scan is never complete.
 *   2. `validateRepositoryModelGraph` (here) is the authority on the *model's own
 *      meaning*: entity identity, path relativity, parent/containment coherence,
 *      provenance, and graph reachability.
 *
 * They are separate because they answer different questions. Core must accept a
 * model produced by any scanner; this layer rejects a model that contradicts
 * itself, which is a stronger claim.
 *
 * Nothing here judges the repository. An invalid model is a *plumbing* failure,
 * not a finding: it means the builder was given an inconsistent ScanResult, or the
 * builder itself regressed.
 */

import {
  REPOSITORY_MODEL_JUDGMENT_AREAS,
  REPOSITORY_MODEL_VERSION,
  ValidationError,
} from "../../core/index.js";

import {
  DEPENDENCY_GRAPH_EDGE_TYPE_VALUES,
  DEPENDENCY_GRAPH_LIMITS,
  DEPENDENCY_GRAPH_STATES,
  DEPENDENCY_GRAPH_STATE_VALUES,
} from "./dependency-graph.js";
import { DEPENDENCY_SCOPES, DEPENDENCY_SOURCE_STATUSES, DEPENDENCY_SPEC_KINDS } from "./entities.js";
import { GRAPH_RELATIONSHIP_TYPES, RELATIONSHIP_TYPES } from "./graph.js";
import { ENTITY_KINDS } from "./identity.js";
import {
  depthOfPath,
  parentPathOf,
  requireRepositoryRelativePath,
} from "./paths.js";
import { COVERAGE_GUARANTEES } from "./query.js";

/** Builder identity recorded in `metadata`. */
export const REPOSITORY_MODEL_BUILDER = "phase-8d-repository-model";

/** Builder version, bumped when entity shapes change incompatibly. */
export const REPOSITORY_MODEL_BUILDER_VERSION = "1";

/** The builder returns a deeply frozen model; recorded for consumers. */
export const MODEL_IMMUTABILITY = "frozen";

/**
 * Entity collections the validator inspects, in a fixed order.
 *
 * A descriptor is `{ label, kind, select(model) }`, so both the validator and
 * `collectModelEntities` share one definition of "what entities this model has".
 */
export const MODEL_ENTITY_COLLECTIONS = Object.freeze([
  { label: "files.entries", kind: ENTITY_KINDS.FILE, select: (model) => model.files.entries },
  {
    label: "files.directories",
    kind: ENTITY_KINDS.DIRECTORY,
    select: (model) => model.files.directories,
  },
  {
    label: "files.symlinks",
    kind: ENTITY_KINDS.SYMLINK,
    select: (model) => model.files.symlinks,
  },
  { label: "languages", kind: ENTITY_KINDS.LANGUAGE, select: (model) => model.languages },
  { label: "frameworks", kind: ENTITY_KINDS.FRAMEWORK, select: (model) => model.frameworks },
  {
    label: "manifests.ecosystems",
    kind: ENTITY_KINDS.ECOSYSTEM,
    select: (model) => model.manifests.ecosystems,
  },
  { label: "manifests.entries", kind: ENTITY_KINDS.MANIFEST, select: (model) => model.manifests.entries },
  {
    label: "dependencies.entries",
    kind: ENTITY_KINDS.DEPENDENCY,
    select: (model) => model.dependencies.entries,
  },
  { label: "tests.entries", kind: ENTITY_KINDS.TEST, select: (model) => model.tests.entries },
  { label: "ci.entries", kind: ENTITY_KINDS.CICD, select: (model) => model.ci.entries },
  {
    label: "documentation.entries",
    kind: ENTITY_KINDS.DOCUMENTATION,
    select: (model) => model.documentation.entries,
  },
  {
    label: "configuration.entries",
    kind: ENTITY_KINDS.CONFIGURATION,
    select: (model) => model.configuration.entries,
  },
  { label: "git.entity", kind: ENTITY_KINDS.GIT, select: (model) => [model.git.entity] },
]);

/**
 * Every entity in the model, as `{ label, kind, entity }` records.
 * @param {object} model
 * @returns {Array<{ label: string, kind: string, entity: object }>}
 */
export function collectModelEntities(model) {
  const out = [];
  for (const descriptor of MODEL_ENTITY_COLLECTIONS) {
    const entities = descriptor.select(model) ?? [];
    for (const entity of entities) {
      out.push({ label: descriptor.label, kind: descriptor.kind, entity });
    }
  }
  return out;
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim() !== "";
}

function checkIndexCoverage(model, entityIds, evidenceIds, ctx) {
  const indexed = new Set(Object.keys(model.indexes.entitiesById ?? {}));
  for (const id of entityIds) {
    if (!indexed.has(id)) ctx.fail(`indexes.entitiesById`, `does not index entity "${id}"`);
  }
  for (const id of indexed) {
    if (!entityIds.has(id)) {
      ctx.fail(`indexes.entitiesById`, `indexes unknown entity "${id}"`);
    }
  }

  const indexedEvidence = new Set(Object.keys(model.indexes.evidenceById ?? {}));
  for (const id of evidenceIds) {
    if (!indexedEvidence.has(id)) {
      ctx.fail(`indexes.evidenceById`, `missing evidence "${id}"`);
    }
  }

  for (const [path, id] of Object.entries(model.indexes.filesByPath ?? {})) {
    const entity = model.indexes.entitiesById?.[id];
    if (entity === undefined || entity.path !== path || entity.kind !== ENTITY_KINDS.FILE) {
      ctx.fail(`indexes.filesByPath`, `entry "${path}" does not resolve to that file`);
    }
  }

  const relationshipCount = model.relationships.length;
  for (const key of ["relationshipsByFrom", "relationshipsByTo"]) {
    for (const positions of Object.values(model.indexes[key] ?? {})) {
      for (const position of positions) {
        if (!Number.isInteger(position) || position < 0 || position >= relationshipCount) {
          ctx.fail(`indexes.${key}`, "must hold positions inside the relationship list");
        }
      }
    }
  }
}

/**
 * Validate the model's internal coherence.
 *
 * @param {object} model A model produced by `buildRepositoryModel`.
 * @returns {object} The same model when valid.
 * @throws {ValidationError} Listing every invariant it found broken.
 */
export function validateRepositoryModelGraph(model) {
  const issues = [];
  const fail = (path, message) => issues.push(`${path}: ${message}`);

  if (!isPlainObject(model)) {
    throw new ValidationError("Invalid repository model", {
      details: { contract: "RepositoryModelGraph", issues: ["model: must be a plain object"] },
    });
  }

  // ── Identity ──────────────────────────────────────────────────────────────
  if (model.version !== REPOSITORY_MODEL_VERSION) {
    fail("version", `must be "${REPOSITORY_MODEL_VERSION}"`);
  }
  if (!isNonEmptyString(model.identity?.repositoryId)) {
    fail("identity.repositoryId", "must be a non-empty string");
  }
  if (!isNonEmptyString(model.identity?.root)) {
    fail("identity.root", "must be a non-empty string");
  }
  if (model.identity?.name !== null) {
    fail("identity.name", "must be null: the scan does not determine a repository name");
  }

  // ── Entities ──────────────────────────────────────────────────────────────
  const descriptors = collectModelEntities(model);
  const entityIds = new Set();
  const seen = new Set();
  const repositoryId = model.identity?.repositoryId;

  for (const { label, kind, entity } of descriptors) {
    if (!isPlainObject(entity)) {
      fail(`${label}`, "every entity must be a plain object");
      continue;
    }
    if (!isNonEmptyString(entity.id)) {
      fail(`${label}`, "entity id must be a non-empty string");
      continue;
    }
    if (seen.has(entity.id)) {
      fail(`${label}`, `duplicate entity id "${entity.id}"`);
      continue;
    }
    seen.add(entity.id);
    entityIds.add(entity.id);

    if (entity.kind !== kind) {
      fail(`${label}[${entity.id}]`, `entity kind must be "${kind}"`);
    }
    if (!entity.id.startsWith(`${kind}:`) && kind !== ENTITY_KINDS.GIT) {
      fail(`${label}[${entity.id}]`, `entity id must start with "${kind}:"`);
    }

    // Path-shaped entities carry a string path; value-shaped ones (language,
    // framework, ecosystem, git) carry `null`.
    if (typeof entity.path === "string") {
      try {
        requireRepositoryRelativePath(entity.path, `${label}[${entity.id}].path`);
      } catch (error) {
        fail(`${label}[${entity.id}].path`, "must be a canonical repository-relative path");
      }
      if (depthOfPath(entity.path) !== entity.depth) {
        fail(`${label}[${entity.id}].depth`, "must agree with the entity path");
      }
    }

    if (entity.evidenceIds.length === 0 && kind !== ENTITY_KINDS.GIT) {
      fail(`${label}[${entity.id}]`, "every entity must reference at least one observation");
    }
  }

  const directoryIds = new Set(
    model.files.directories.map((directory) => directory.id),
  );

  for (const file of [...model.files.entries, ...model.files.symlinks]) {
    const expected = parentPathOf(file.path);
    const expectedId =
      expected === null ? repositoryId : `${ENTITY_KINDS.DIRECTORY}:${expected}`;
    if (file.directoryId !== expectedId) {
      fail(`files[${file.path}].directoryId`, "must be the directory that contains the path");
    }
    if (file.directoryId !== repositoryId && !directoryIds.has(file.directoryId)) {
      fail(`files[${file.path}].directoryId`, "must resolve to an observed directory");
    }
  }

  for (const directory of model.files.directories) {
    const expected = parentPathOf(directory.path);
    const expectedId = expected === null ? null : `${ENTITY_KINDS.DIRECTORY}:${expected}`;
    if (directory.parentId !== expectedId) {
      fail(`files.directories[${directory.path}].parentId`, "must be the path's parent directory");
    }
    if (directory.depth > 1 && directory.parentId === null) {
      fail(`files.directories[${directory.path}].parentId`, "a nested directory must have a parent");
    }
    if (directory.parentId !== null && !directoryIds.has(directory.parentId)) {
      fail(`files.directories[${directory.path}].parentId`, "must resolve to an observed directory");
    }
  }

  for (const manifest of model.manifests.entries) {
    const expected = parentPathOf(manifest.path);
    const expectedId =
      expected === null ? repositoryId : `${ENTITY_KINDS.DIRECTORY}:${expected}`;
    if (manifest.directoryId !== expectedId) {
      fail(`manifests[${manifest.path}].directoryId`, "must be the directory that contains the path");
    }
  }

  // ── Dependency semantics ─────────────────────────────────────────────────
  //
  // A dependency is the one entity kind whose *content* is a graph: declarations
  // point at manifests, resolutions point at lockfiles, and both must resolve to
  // entities the model contains. Validating that here is what makes the dependency
  // query layer's answers traceable — an unverifiable edge would let a rule cite
  // provenance that does not exist.
  const manifestIds = new Set(model.manifests.entries.map((manifest) => manifest.id));
  const ecosystemIds = new Set(model.manifests.ecosystems.map((ecosystem) => ecosystem.id));
  const scopes = Object.values(DEPENDENCY_SCOPES);
  const specKinds = Object.values(DEPENDENCY_SPEC_KINDS);

  for (const dependency of model.dependencies.entries ?? []) {
    const at = `dependencies[${dependency?.id}]`;
    if (!isNonEmptyString(dependency?.ecosystem)) {
      fail(at, "must record the ecosystem it belongs to");
      continue;
    }
    if (!ecosystemIds.has(dependency.ecosystemId)) {
      fail(at, "must belong to an ecosystem the scan observed");
    }
    if (dependency.path !== null) {
      fail(at, "must not carry a path: a dependency is identified by (ecosystem, name)");
    }
    if (dependency.id !== `${ENTITY_KINDS.DEPENDENCY}:${dependency.ecosystem}:${dependency.name}`) {
      fail(at, "id must be derived from the ecosystem and the name");
    }

    let facts = 0;
    for (const declaration of dependency.declarations ?? []) {
      facts += 1;
      if (!manifestIds.has(declaration.manifestId)) {
        fail(at, "a declaration must cite a manifest the model contains");
      }
      if (!scopes.includes(declaration.scope)) {
        fail(at, `declaration scope must be one of: ${scopes.join(", ")}`);
      }
      if (!specKinds.includes(declaration.specKind)) {
        fail(at, `declaration specKind must be one of: ${specKinds.join(", ")}`);
      }
      if (typeof declaration.direct !== "boolean") {
        fail(at, "declaration direct must be a boolean");
      }
    }
    for (const resolution of dependency.resolutions ?? []) {
      facts += 1;
      if (!manifestIds.has(resolution.manifestId)) {
        fail(at, "a resolution must cite a lockfile the model contains");
      }
    }
    for (const path of dependency.referencedBy ?? []) {
      facts += 1;
      if (typeof path !== "string" || !manifestIds.has(`${ENTITY_KINDS.MANIFEST}:${path}`)) {
        fail(at, "a referencing edge must name a manifest the model contains");
      }
    }
    if (facts === 0) {
      fail(at, "must be declared, resolved or named by an edge somewhere in the model");
    }

    const declared = (dependency.declarations ?? []).some((entry) => entry.direct === true);
    if (dependency.direct !== declared) {
      fail(at, "direct must agree with the declarations it carries");
    }
    const resolved = (dependency.resolutions ?? []).length > 0;
    if (dependency.resolved !== resolved) {
      fail(at, "resolved must agree with the resolutions it carries");
    }
  }

  for (const source of model.dependencies.sources ?? []) {
    if (!manifestIds.has(`${ENTITY_KINDS.MANIFEST}:${source.path}`)) {
      fail(`dependencies.sources[${source.path}]`, "must name a manifest the model contains");
    }
    if (!DEPENDENCY_SOURCE_STATUSES.includes(source.status)) {
      fail(`dependencies.sources[${source.path}].status`, "must be a documented source status");
    }
    if (!isNonEmptyString(source.evidenceId)) {
      fail(`dependencies.sources[${source.path}]`, "must cite the observation it rests on");
    }
    if (typeof source.truncated !== "boolean") {
      fail(`dependencies.sources[${source.path}].truncated`, "must be a boolean");
    }
  }

  // The coverage statement may not claim more than the sources support: `complete`
  // means every dependency source in the repository was read and interpreted, which
  // is exactly what `scan.complete` plus a clean source list means.
  if (model.dependencies.coverage?.complete === true) {
    const clean = (model.dependencies.sources ?? []).every(
      (source) => source.status === "parsed" && (source.problems ?? []).length === 0,
    );
    if (!clean) {
      fail(
        "dependencies.coverage.complete",
        "cannot be true unless every dependency source was parsed without problems",
      );
    }
  }

  // ── Provenance ────────────────────────────────────────────────────────────
  const evidenceIds = new Set();
  for (const record of model.evidence) {
    if (!isPlainObject(record) || !isNonEmptyString(record.id)) {
      fail("evidence", "every observation must carry an id");
      continue;
    }
    if (evidenceIds.has(record.id)) fail("evidence", `duplicate observation id "${record.id}"`);
    evidenceIds.add(record.id);
    if (!("path" in (record.location ?? {}))) {
      fail(`evidence[${record.id}]`, "every observation must locate a repository-relative path");
    }
  }
  for (const { label, entity } of descriptors) {
    for (const id of entity.evidenceIds ?? []) {
      if (!evidenceIds.has(id)) {
        fail(`${label}[${entity.id}]`, `references unknown observation "${id}"`);
      }
    }
  }

  // ── Relationships ─────────────────────────────────────────────────────────
  const known = new Set([...entityIds, repositoryId]);
  for (const relationship of model.relationships) {
    if (!isPlainObject(relationship)) {
      fail("relationships", "every relationship must be a plain object");
      continue;
    }
    if (!GRAPH_RELATIONSHIP_TYPES.includes(relationship.type)) {
      fail("relationships", `unknown relationship type "${String(relationship.type)}"`);
    }
    if (!known.has(relationship.from)) {
      fail("relationships", `unknown relationship source "${String(relationship.from)}"`);
    }
    if (!known.has(relationship.to)) {
      fail("relationships", `unknown relationship target "${String(relationship.to)}"`);
    }
  }
  // Every entity must be connected to the repository, so a consumer can always
  // reach it without scanning the whole edge list. The containment set is built
  // once; testing it per entity would make validation quadratic.
  const contained = new Set(
    (model.indexes.relationshipsByFrom?.[repositoryId] ?? [])
      .map((position) => model.relationships[position])
      .filter((relationship) => relationship?.type === RELATIONSHIP_TYPES.CONTAINS)
      .map((relationship) => relationship.to),
  );
  for (const id of entityIds) {
    if (!contained.has(id)) fail("relationships", `"${id}" is not connected to the repository`);
  }

  // ── Dependency graph (Phase 14) ───────────────────────────────────────────
  //
  // The graph is a projection of the dependency entities and the `depends-on`
  // relationships above, so validating it here is what stops it from becoming a
  // second, disagreeing source of truth: every node must be a dependency entity the
  // model contains, every edge must be a relationship the model already states (in
  // both directions — no invented edge, no silently dropped one), and every edge's
  // provenance must resolve to real observations and real manifests.
  const graph = model.dependencies.graph;
  if (!isPlainObject(graph)) {
    fail("dependencies.graph", "must be a plain object");
  } else {
    const dependencyById = new Map(
      (model.dependencies.entries ?? []).map((dependency) => [dependency.id, dependency]),
    );

    if (!isNonEmptyString(graph.version)) {
      fail("dependencies.graph.version", "must be a non-empty string");
    }
    if (!DEPENDENCY_GRAPH_STATE_VALUES.includes(graph.state)) {
      fail(
        "dependencies.graph.state",
        `must be one of: ${DEPENDENCY_GRAPH_STATE_VALUES.join(", ")}`,
      );
    }
    if (typeof graph.established !== "boolean") {
      fail("dependencies.graph.established", "must be a boolean");
    } else if (
      graph.established !==
      (graph.state !== DEPENDENCY_GRAPH_STATES.UNKNOWN &&
        graph.state !== DEPENDENCY_GRAPH_STATES.UNSUPPORTED)
    ) {
      fail("dependencies.graph.established", "must agree with the state it reports");
    }

    const nodeIds = new Set();
    if (!Array.isArray(graph.nodes)) {
      fail("dependencies.graph.nodes", "must be an array");
    } else if (graph.nodes.length > DEPENDENCY_GRAPH_LIMITS.MAX_NODES) {
      fail("dependencies.graph.nodes", "must stay within the graph node bound");
    } else {
      graph.nodes.forEach((node, index) => {
        const at = `dependencies.graph.nodes[${index}]`;
        if (!isPlainObject(node)) {
          fail(at, "must be a plain object");
          return;
        }
        if (typeof node.id !== "string" || !dependencyById.has(node.id)) {
          fail(at, "must name a dependency entity the model contains");
          return;
        }
        if (nodeIds.has(node.id)) fail(at, `duplicate graph node "${node.id}"`);
        nodeIds.add(node.id);
        if (node.id !== `${ENTITY_KINDS.DEPENDENCY}:${node.ecosystem}:${node.name}`) {
          fail(at, "id must be derived from the ecosystem and the name");
        }
        const entity = dependencyById.get(node.id);
        for (const field of ["declared", "direct", "resolved"]) {
          if (typeof node[field] !== "boolean") {
            fail(at, `${field} must be a boolean`);
            continue;
          }
          if (node[field] !== (entity[field] === true)) {
            fail(at, `${field} must agree with the dependency entity it names`);
          }
        }
      });
      // Deterministic ordering is part of the contract, not a nicety: two builds of
      // one repository state must produce byte-identical graphs.
      for (let next = 1; next < graph.nodes.length; next += 1) {
        const previous = graph.nodes[next - 1]?.id;
        const current = graph.nodes[next]?.id;
        if (typeof previous === "string" && typeof current === "string" && !(previous < current)) {
          fail(`dependencies.graph.nodes[${next}]`, "nodes must be sorted by id and unique");
        }
      }
      if (nodeIds.size !== dependencyById.size) {
        fail(
          "dependencies.graph.nodes",
          "every dependency entity must project to exactly one node",
        );
      }
    }

    const edgeKeys = new Set();
    if (!Array.isArray(graph.edges)) {
      fail("dependencies.graph.edges", "must be an array");
    } else if (graph.edges.length > DEPENDENCY_GRAPH_LIMITS.MAX_EDGES) {
      fail("dependencies.graph.edges", "must stay within the graph edge bound");
    } else {
      graph.edges.forEach((edge, index) => {
        const at = `dependencies.graph.edges[${index}]`;
        if (!isPlainObject(edge)) {
          fail(at, "must be a plain object");
          return;
        }
        if (!DEPENDENCY_GRAPH_EDGE_TYPE_VALUES.includes(edge.type)) {
          fail(at, `type must be one of: ${DEPENDENCY_GRAPH_EDGE_TYPE_VALUES.join(", ")}`);
        }
        for (const endpoint of ["from", "to"]) {
          if (!nodeIds.has(edge[endpoint])) {
            fail(at, `${endpoint} must name a graph node`);
          }
        }
        const key = `${edge.from}\u0000${edge.type}\u0000${edge.to}`;
        if (edgeKeys.has(key)) fail(at, "must not repeat an edge the graph already states");
        edgeKeys.add(key);

        if (!Array.isArray(edge.evidenceIds) || edge.evidenceIds.length === 0) {
          fail(at, "must cite at least one observation");
        } else {
          for (const id of edge.evidenceIds) {
            if (!evidenceIds.has(id)) fail(at, `references unknown observation "${String(id)}"`);
          }
        }
        if (!Array.isArray(edge.manifestPaths) || edge.manifestPaths.length === 0) {
          fail(at, "must name the lockfile that established it");
        } else {
          for (const path of edge.manifestPaths) {
            if (
              typeof path !== "string" ||
              path.startsWith("/") ||
              !manifestIds.has(`${ENTITY_KINDS.MANIFEST}:${path}`)
            ) {
              fail(at, "provenance must name a manifest the model contains");
            }
          }
        }
      });
      for (let next = 1; next < graph.edges.length; next += 1) {
        const previous = graph.edges[next - 1];
        const current = graph.edges[next];
        if (
          isPlainObject(previous) &&
          isPlainObject(current) &&
          !(
            previous.from < current.from ||
            (previous.from === current.from && previous.to < current.to)
          )
        ) {
          fail(`dependencies.graph.edges[${next}]`, "edges must be sorted by endpoints, unique");
        }
      }
    }

    // The two views of one fact must agree exactly.
    const relationshipEdges = new Set(
      (model.relationships ?? [])
        .filter((relationship) => relationship?.type === RELATIONSHIP_TYPES.DEPENDS_ON)
        .map(
          (relationship) =>
            `${relationship.from}\u0000${relationship.type}\u0000${relationship.to}`,
        ),
    );
    for (const key of edgeKeys) {
      if (!relationshipEdges.has(key)) {
        fail("dependencies.graph.edges", "an edge must be a depends-on relationship the model states");
      }
    }
    for (const key of relationshipEdges) {
      if (!edgeKeys.has(key)) {
        fail("dependencies.graph.edges", "a depends-on relationship must appear in the graph");
      }
    }

    const graphCoverage = graph.coverage;
    if (!isPlainObject(graphCoverage)) {
      fail("dependencies.graph.coverage", "must be a plain object");
    } else {
      if (graphCoverage.state !== graph.state) {
        fail("dependencies.graph.coverage.state", "must agree with the graph state");
      }
      if (graphCoverage.nodes !== nodeIds.size) {
        fail("dependencies.graph.coverage.nodes", "must count the nodes the graph contains");
      }
      if (graphCoverage.edges !== edgeKeys.size) {
        fail("dependencies.graph.coverage.edges", "must count the edges the graph contains");
      }
      if (!Array.isArray(graphCoverage.unestablishedSources)) {
        fail("dependencies.graph.coverage.unestablishedSources", "must be an array");
      }
      const versionInstances = graphCoverage.versionInstances;
      if (!isPlainObject(versionInstances)) {
        fail("dependencies.graph.coverage.versionInstances", "must state the identity limitation");
      } else if (!Array.isArray(versionInstances.packages)) {
        fail("dependencies.graph.coverage.versionInstances.packages", "must be an array");
      } else if (
        versionInstances.packages.length > DEPENDENCY_GRAPH_LIMITS.MAX_AMBIGUOUS_PACKAGES
      ) {
        fail(
          "dependencies.graph.coverage.versionInstances.packages",
          "must stay within the graph bound",
        );
      }
    }
  }

  // ── Completeness ──────────────────────────────────────────────────────────
  if (model.scan.truncated === true && model.scan.complete === true) {
    fail("scan", "a truncated model must not be complete");
  }
  const guarantee =
    model.scan.complete === true && model.scan.truncated !== true
      ? COVERAGE_GUARANTEES.COMPLETE
      : COVERAGE_GUARANTEES.PARTIAL;
  if (model.scan.coverage?.guarantee !== guarantee) {
    fail("scan.coverage.guarantee", `must be "${guarantee}" for this scan state`);
  }
  if (model.metadata?.immutability !== MODEL_IMMUTABILITY) {
    fail("metadata.immutability", `must be "${MODEL_IMMUTABILITY}"`);
  }

  // ── No judgments ──────────────────────────────────────────────────────────
  for (const judgment of REPOSITORY_MODEL_JUDGMENT_AREAS) {
    if (judgment in model) {
      fail(judgment, "the model records facts; judgments belong to analyzers");
    }
  }

  // ── Path-like fields must stay relative ───────────────────────────────────
  for (const { label, entity } of descriptors) {
    for (const field of ["path", "directory", "root"]) {
      const value = entity[field];
      if (typeof value === "string" && value !== model.identity.root && value.startsWith("/")) {
        fail(`${label}[${entity.id}].${field}`, "must not be an absolute path");
      }
    }
  }

  checkIndexCoverage(model, entityIds, evidenceIds, { fail });

  if (issues.length > 0) {
    throw new ValidationError("Invalid repository model graph", {
      details: { contract: "RepositoryModelGraph", issues },
    });
  }

  return model;
}
