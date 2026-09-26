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
  ARCHITECTURE_EDGE_TYPES,
  ARCHITECTURE_EDGE_TYPE_VALUES,
  ARCHITECTURE_GRAPH_LIMITS,
  ARCHITECTURE_GRAPH_STATES,
  ARCHITECTURE_GRAPH_STATE_VALUES,
  ARCHITECTURE_NODE_KINDS,
  isEstablishedState,
  REPOSITORY_NODE_KIND,
} from "./architecture-graph.js";
import {
  DEPENDENCY_GRAPH_EDGE_TYPE_VALUES,
  DEPENDENCY_GRAPH_LIMITS,
  DEPENDENCY_GRAPH_STATES,
  DEPENDENCY_GRAPH_STATE_VALUES,
} from "./dependency-graph.js";
import {
  API_CALLABLE_FORMS,
  API_FRAMEWORKS,
  API_PROBLEM_REASONS,
  API_RECEIVER_KINDS,
  API_ROUTE_METHODS,
  API_SHAPE_REASONS,
  API_SOURCE_STATUSES,
  DEPENDENCY_SCOPES,
  DEPENDENCY_SOURCE_STATUSES,
  DEPENDENCY_SPEC_KINDS,
  IMPORT_MODULE_EXTENSIONS,
  IMPORT_PROBLEM_REASONS,
  IMPORT_SOURCE_REASONS,
  IMPORT_SOURCE_STATUSES as IMPORT_SOURCE_STATUS_VALUES,
  IMPORT_SPECIFIER_KINDS,
  SEMANTIC_MODULE_EXTENSIONS,
  SEMANTIC_PROBLEM_REASONS,
  SEMANTIC_SOURCE_REASONS,
  SEMANTIC_SOURCE_STATUSES as SEMANTIC_SOURCE_STATUS_VALUES,
  SYMBOL_BINDING_KINDS,
  SYMBOL_EXPORT_FORMS,
  SYMBOL_KINDS,
  SYMBOL_OCCURRENCE_FORMS,
  projectModuleSpecifier,
  projectSymbolName,
} from "./entities.js";
import {
  IMPORT_GRAPH_EDGE_TYPE_VALUES,
  IMPORT_GRAPH_LIMITS,
  IMPORT_GRAPH_STATES,
  IMPORT_GRAPH_STATE_VALUES,
  INTERPRETED_LANGUAGE_IDS,
  UNRESOLVED_REFERENCE_REASON_VALUES,
  isEstablishedState as isImportGraphEstablished,
} from "./import-graph.js";
import {
  SYMBOL_GRAPH_EDGE_TYPES,
  SYMBOL_GRAPH_EDGE_TYPE_VALUES,
  SYMBOL_GRAPH_LIMITS,
  SYMBOL_GRAPH_STATES,
  SYMBOL_GRAPH_STATE_VALUES,
  SYMBOL_UNRESOLVED_KINDS,
  SYMBOL_UNRESOLVED_REASON_VALUES,
  isEstablishedSymbolState,
  symbolIdOf,
} from "./symbol-graph.js";
import {
  API_GRAPH_EDGE_TYPES,
  API_GRAPH_EDGE_TYPE_VALUES,
  API_GRAPH_LIMITS,
  API_GRAPH_STATES,
  API_GRAPH_STATE_VALUES,
  API_UNRESOLVED_KINDS,
  API_UNRESOLVED_REASON_VALUES,
  apiRouteIdOf,
  isEstablishedApiState,
} from "./api-graph.js";
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
 * The signal a container build-context observation carries, re-declared here rather
 * than imported from the scanner (the model must not depend on the acquisition
 * layer). A test in `tests/architecture-graph.test.js` pins it against the model's
 * own `CONTAINER_SIGNALS` vocabulary, so a rename on either side fails the suite.
 */
const BUILD_CONTEXT_SIGNAL = "compose-build-context";

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

/**
 * A count the graph states. A count is a number of things that exist, so anything a
 * reader could mistake for one — a fraction, a negative, `NaN`, a numeric string — has to
 * be rejected rather than coerced, because every bound and total in the graph area is
 * compared against these.
 */
function isNonNegativeInteger(value) {
  return Number.isInteger(value) && value >= 0;
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
  const entityById = new Map();
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
    entityById.set(entity.id, entity);

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

  // ── Architecture graph (Phase 15) ─────────────────────────────────────────
  //
  // Another projection of the same model, so it is validated the same way the
  // dependency graph is: every node must be an entity the model contains (or the
  // repository node), every edge must re-state a fact the model already established
  // — a `contains`/`parent`/`located_in` containment, a `declares-dependency`, a
  // `framework` relationship, or a container declaration observation — and every
  // edge's provenance must resolve to real observations. An edge the model does not
  // support is rejected here rather than becoming a finding.
  const architectureGraph = model.architecture?.graph;
  if (!isPlainObject(architectureGraph)) {
    fail("architecture.graph", "must be a plain object");
  } else {
    if (!isNonEmptyString(architectureGraph.version)) {
      fail("architecture.graph.version", "must be a non-empty string");
    }
    if (!ARCHITECTURE_GRAPH_STATE_VALUES.includes(architectureGraph.state)) {
      fail(
        "architecture.graph.state",
        `must be one of: ${ARCHITECTURE_GRAPH_STATE_VALUES.join(", ")}`,
      );
    }
    if (typeof architectureGraph.established !== "boolean") {
      fail("architecture.graph.established", "must be a boolean");
    } else if (architectureGraph.established !== isEstablishedState(architectureGraph.state)) {
      fail("architecture.graph.established", "must agree with the state it reports");
    }

    const architectureNodeIds = new Set();
    const architectureNodeById = new Map();
    if (!Array.isArray(architectureGraph.nodes)) {
      fail("architecture.graph.nodes", "must be an array");
    } else if (architectureGraph.nodes.length > ARCHITECTURE_GRAPH_LIMITS.MAX_NODES) {
      fail("architecture.graph.nodes", "must stay within the graph node bound");
    } else {
      architectureGraph.nodes.forEach((node, index) => {
        const at = `architecture.graph.nodes[${index}]`;
        if (!isPlainObject(node)) {
          fail(at, "must be a plain object");
          return;
        }
        if (typeof node.id !== "string" || node.id.trim() === "") {
          fail(at, "must carry a non-empty id");
          return;
        }
        if (architectureNodeIds.has(node.id)) fail(at, `duplicate graph node "${node.id}"`);
        architectureNodeIds.add(node.id);
        architectureNodeById.set(node.id, node);

        if (node.id === repositoryId) {
          if (node.kind !== REPOSITORY_NODE_KIND) {
            fail(at, `the repository node must have kind "${REPOSITORY_NODE_KIND}"`);
          }
          if (node.path !== null) fail(at, "the repository node must not carry a path");
          return;
        }
        if (!ARCHITECTURE_NODE_KINDS.includes(node.kind)) {
          fail(at, `kind must be one of: ${ARCHITECTURE_NODE_KINDS.join(", ")}`);
        }
        const entity = entityById.get(node.id);
        if (entity === undefined) {
          fail(at, "must name an entity the model contains");
          return;
        }
        if (entity.kind !== node.kind) {
          fail(at, "kind must agree with the entity it names");
        }
        if (node.path !== null) {
          try {
            requireRepositoryRelativePath(node.path, `${at}.path`);
          } catch (error) {
            fail(`${at}.path`, "must be a canonical repository-relative path");
          }
          if (node.path !== entity.path) {
            fail(at, "path must agree with the entity it names");
          }
        }
      });
      // Deterministic ordering is part of the contract, not a nicety: two builds of
      // one repository state must produce byte-identical graphs.
      for (let next = 1; next < architectureGraph.nodes.length; next += 1) {
        const previous = architectureGraph.nodes[next - 1]?.id;
        const current = architectureGraph.nodes[next]?.id;
        if (typeof previous === "string" && typeof current === "string" && !(previous < current)) {
          fail(`architecture.graph.nodes[${next}]`, "nodes must be sorted by id and unique");
        }
      }
      for (const { label, entity } of descriptors) {
        if (!ARCHITECTURE_NODE_KINDS.includes(entity.kind)) continue;
        if (!architectureNodeIds.has(entity.id)) {
          fail(
            `architecture.graph.nodes`,
            `${label}[${entity.id}] must project to a graph node`,
          );
        }
      }
    }

    // The container declarations the model recorded, by observation id. Used to check
    // that a container edge is the *same* declaration it cites: an edge whose
    // endpoints disagree with the observation behind it (a different Dockerfile, a
    // different Compose file, a different context) is provenance that does not exist.
    const buildContextObservations = new Map();
    for (const record of model.evidence) {
      if (record?.data?.signal !== BUILD_CONTEXT_SIGNAL) continue;
      buildContextObservations.set(record.id, {
        path: record.location?.path ?? null,
        source: record.data.source ?? null,
        contextPath: record.data.contextPath ?? null,
      });
    }

    const architectureEdgeKeys = new Set();
    if (!Array.isArray(architectureGraph.edges)) {
      fail("architecture.graph.edges", "must be an array");
    } else if (architectureGraph.edges.length > ARCHITECTURE_GRAPH_LIMITS.MAX_EDGES) {
      fail("architecture.graph.edges", "must stay within the graph edge bound");
    } else {
      const relationshipKeys = new Set(
        (model.relationships ?? []).map(
          (relationship) =>
            `${relationship.from}\u0000${relationship.type}\u0000${relationship.to}`,
        ),
      );
      architectureGraph.edges.forEach((edge, index) => {
        const at = `architecture.graph.edges[${index}]`;
        if (!isPlainObject(edge)) {
          fail(at, "must be a plain object");
          return;
        }
        if (!ARCHITECTURE_EDGE_TYPE_VALUES.includes(edge.type)) {
          fail(at, `type must be one of: ${ARCHITECTURE_EDGE_TYPE_VALUES.join(", ")}`);
        }
        for (const endpoint of ["from", "to"]) {
          if (!architectureNodeIds.has(edge[endpoint])) {
            fail(at, `${endpoint} must name a graph node`);
          }
        }
        const key = `${edge.from}\u0000${edge.to}\u0000${edge.type}`;
        if (architectureEdgeKeys.has(key)) fail(at, "must not repeat an edge the graph already states");
        architectureEdgeKeys.add(key);

        if (!Array.isArray(edge.evidenceIds) || edge.evidenceIds.length === 0) {
          fail(at, "must cite at least one observation");
        } else {
          for (const id of edge.evidenceIds) {
            if (!evidenceIds.has(id)) fail(at, `references unknown observation "${String(id)}"`);
          }
        }
        if (!Array.isArray(edge.sourcePaths) || edge.sourcePaths.length === 0) {
          fail(at, "must name the path whose observation stated it");
        } else {
          for (const path of edge.sourcePaths) {
            if (typeof path !== "string" || path.startsWith("/")) {
              fail(at, "provenance paths must be repository-relative");
            }
          }
        }
        if (!Array.isArray(edge.services)) {
          fail(at, "services must be an array (empty for a non-container edge)");
        }

        // Every edge must re-state a fact the model already established. The three
        // containment forms are one fact stated in one direction here; the container
        // forms are established by an observation, because the model has no
        // relationship for build wiring.
        switch (edge.type) {
          case ARCHITECTURE_EDGE_TYPES.CONTAINS: {
            const forms = [
              `${edge.from}\u0000contains\u0000${edge.to}`,
              `${edge.to}\u0000located_in\u0000${edge.from}`,
              `${edge.to}\u0000parent\u0000${edge.from}`,
            ];
            if (!forms.some((form) => relationshipKeys.has(form))) {
              fail(at, "a containment edge must be containment the model already states");
            }
            break;
          }
          case ARCHITECTURE_EDGE_TYPES.DECLARES_DEPENDENCY:
          case ARCHITECTURE_EDGE_TYPES.FRAMEWORK: {
            const form = `${edge.from}\u0000${edge.type}\u0000${edge.to}`;
            if (!relationshipKeys.has(form)) {
              fail(at, `a ${edge.type} edge must be a relationship the model already states`);
            }
            break;
          }
          case ARCHITECTURE_EDGE_TYPES.DECLARES_BUILD:
          case ARCHITECTURE_EDGE_TYPES.BUILD_CONTEXT: {
            const declares = edge.type === ARCHITECTURE_EDGE_TYPES.DECLARES_BUILD;
            // The declaration's Dockerfile is the edge's `to` when a Compose file
            // declares a build, and its `from` when the Dockerfile is placed in its
            // context root.
            const dockerfilePath = declares
              ? (architectureNodeById.get(edge.to)?.path ?? null)
              : (architectureNodeById.get(edge.from)?.path ?? null);
            const sourcePath = declares ? (architectureNodeById.get(edge.from)?.path ?? null) : null;
            const contextPath = declares
              ? undefined
              : edge.to === repositoryId
                ? null
                : (architectureNodeById.get(edge.to)?.path ?? undefined);

            const matched = (edge.evidenceIds ?? []).some((id) => {
              const observation = buildContextObservations.get(id);
              if (observation === undefined) return false;
              if (observation.path !== dockerfilePath) return false;
              return declares
                ? observation.source === sourcePath
                : observation.contextPath === contextPath;
            });
            if (!matched) {
              fail(at, "must cite the container declaration that established exactly it");
            }
            break;
          }
          default:
            break;
        }
      });
      for (let next = 1; next < architectureGraph.edges.length; next += 1) {
        const previous = architectureGraph.edges[next - 1];
        const current = architectureGraph.edges[next];
        if (!isPlainObject(previous) || !isPlainObject(current)) continue;
        const orderedBefore =
          previous.from < current.from ||
          (previous.from === current.from &&
            (previous.to < current.to ||
              (previous.to === current.to && previous.type < current.type)));
        if (!orderedBefore) {
          fail(`architecture.graph.edges[${next}]`, "edges must be sorted by endpoints, unique");
        }
      }
    }

    if (!Array.isArray(architectureGraph.buildContexts)) {
      fail("architecture.graph.buildContexts", "must be an array");
    } else if (
      architectureGraph.buildContexts.length > ARCHITECTURE_GRAPH_LIMITS.MAX_BUILD_DECLARATIONS
    ) {
      fail("architecture.graph.buildContexts", "must stay within the graph bound");
    } else {
      architectureGraph.buildContexts.forEach((record, index) => {
        const at = `architecture.graph.buildContexts[${index}]`;
        if (!isPlainObject(record)) {
          fail(at, "must be a plain object");
          return;
        }
        for (const field of ["source", "service", "dockerfile"]) {
          if (!isNonEmptyString(record[field])) fail(at, `${field} must be a non-empty string`);
        }
        for (const field of ["source", "dockerfile"]) {
          if (typeof record[field] === "string" && record[field].startsWith("/")) {
            fail(at, `${field} must be repository-relative`);
          }
        }
        if (record.context !== null && !isNonEmptyString(record.context)) {
          fail(at, "context must be null (the repository root) or a repository-relative path");
        }
        if (typeof record.context === "string" && record.context.startsWith("/")) {
          fail(at, "context must be repository-relative");
        }
        if (!buildContextObservations.has(record.evidenceId)) {
          fail(at, "must cite the observation it rests on");
        }
      });
      for (let next = 1; next < architectureGraph.buildContexts.length; next += 1) {
        const previous = architectureGraph.buildContexts[next - 1];
        const current = architectureGraph.buildContexts[next];
        if (!isPlainObject(previous) || !isPlainObject(current)) continue;
        const previousKey = `${previous.source}\u0000${previous.service}\u0000${previous.dockerfile}`;
        const currentKey = `${current.source}\u0000${current.service}\u0000${current.dockerfile}`;
        if (!(previousKey < currentKey)) {
          fail(
            `architecture.graph.buildContexts[${next}]`,
            "declarations must be sorted by source, service and Dockerfile",
          );
        }
      }
    }

    const architectureCoverage = architectureGraph.coverage;
    if (!isPlainObject(architectureCoverage)) {
      fail("architecture.graph.coverage", "must be a plain object");
    } else {
      if (architectureCoverage.state !== architectureGraph.state) {
        fail("architecture.graph.coverage.state", "must agree with the graph state");
      }
      if (architectureCoverage.established !== architectureGraph.established) {
        fail("architecture.graph.coverage.established", "must agree with the graph state");
      }
      if (architectureCoverage.nodes !== architectureNodeIds.size) {
        fail("architecture.graph.coverage.nodes", "must count the nodes the graph contains");
      }
      if (architectureCoverage.edges !== architectureEdgeKeys.size) {
        fail("architecture.graph.coverage.edges", "must count the edges the graph contains");
      }
      if (!Array.isArray(architectureCoverage.unestablishedSources)) {
        fail("architecture.graph.coverage.unestablishedSources", "must be an array");
      } else if (
        architectureCoverage.unestablishedSources.length >
        ARCHITECTURE_GRAPH_LIMITS.MAX_UNESTABLISHED_SOURCES
      ) {
        fail(
          "architecture.graph.coverage.unestablishedSources",
          "must stay within the graph bound",
        );
      }
      // The state may not claim more than the scan and the sources support.
      if (architectureCoverage.state === ARCHITECTURE_GRAPH_STATES.COMPLETE) {
        if (architectureCoverage.complete !== true || architectureCoverage.truncated === true) {
          fail(
            "architecture.graph.coverage.state",
            "cannot be complete unless the scan covered the repository",
          );
        }
        if ((architectureCoverage.unestablishedSources ?? []).length > 0) {
          fail(
            "architecture.graph.coverage.state",
            "cannot be complete while an architecture source is unestablished",
          );
        }
      }
    }
  }

  // ── Import graph (Phase 16) ───────────────────────────────────────────────
  //
  // The graph's nodes must be files the model contains, its edges must join two of
  // those nodes and cite the *importing* file's own observation, and an unresolved
  // reference must be a reference that produced no edge. That last check is what
  // keeps the two halves of the projection from contradicting each other: a
  // specifier cannot be both "we established where this points" and "we could not
  // establish where this points".
  {
    const importsArea = model.imports;
    if (!isPlainObject(importsArea)) {
      fail("imports", "must be a plain object");
    } else {
      const fileIds = new Set(model.files.entries.map((file) => file.id));
      const evidenceById = new Map(
        (Array.isArray(model.evidence) ? model.evidence : []).map((record) => [record?.id, record]),
      );
      const sourceByPath = new Map();
      const entries = importsArea.entries;

      if (typeof importsArea.detected !== "boolean") {
        fail("imports.detected", "must be a boolean");
      }
      if (!Array.isArray(entries)) {
        fail("imports.entries", "must be an array");
      } else {
        for (const source of entries) {
          const at = `imports.entries[${source?.path}]`;
          if (!isPlainObject(source)) {
            fail("imports.entries", "every module source must be a plain object");
            continue;
          }
          if (!fileIds.has(`${ENTITY_KINDS.FILE}:${source.path}`)) {
            fail(at, "must name a file the model contains");
            continue;
          }
          if (sourceByPath.has(source.path)) fail(at, "must describe each module source once");
          sourceByPath.set(source.path, source);

          if (!IMPORT_MODULE_EXTENSIONS.includes(source.extension)) {
            fail(at, "must carry a module source extension");
          }
          if (!entityIds.has(source.languageId)) {
            fail(at, "language must name a language the model contains");
          }
          if (!IMPORT_SOURCE_STATUS_VALUES.includes(source.status)) {
            fail(at, `status must be one of: ${IMPORT_SOURCE_STATUS_VALUES.join(", ")}`);
          }
          if (source.reason !== null && !IMPORT_SOURCE_REASONS.includes(source.reason)) {
            fail(at, `reason must be null or one of: ${IMPORT_SOURCE_REASONS.join(", ")}`);
          }
          if (source.status === "parsed" && source.reason !== null) {
            fail(at, "a parsed module source must not carry an acquisition reason");
          }
          if (source.status !== "parsed" && source.reason === null) {
            fail(at, "a module source that was not parsed must record why");
          }
          for (const problem of source.problems ?? []) {
            if (!IMPORT_PROBLEM_REASONS.includes(problem)) {
              fail(at, `unknown import problem "${String(problem)}"`);
            }
          }
          if (!Array.isArray(source.references)) {
            fail(at, "must carry a references array");
          } else {
            for (const reference of source.references) {
              if (!isPlainObject(reference) || !IMPORT_SPECIFIER_KINDS.includes(reference.kind)) {
                fail(at, "references must carry a documented module reference kind");
                continue;
              }
              // Bounded, printable, non-empty text: the same projection the model
              // applies at build time, enforced here as a contract so a tampered
              // model cannot smuggle a control character or an unbounded string into
              // a path candidate or a consumer's output.
              if (projectModuleSpecifier(reference.specifier) === null) {
                fail(at, "references must carry bounded, printable specifier text");
              }
            }
            if (source.status !== "parsed" && source.references.length > 0) {
              fail(at, "a module source that was not parsed states no reference");
            }
          }
          if (!evidenceIds.has(source.evidenceId)) {
            fail(at, "must cite the observation that recorded it");
          }
        }
        for (let next = 1; next < entries.length; next += 1) {
          if (entries[next - 1]?.path >= entries[next]?.path) {
            fail(`imports.entries[${next}]`, "must be sorted by path and unique");
            break;
          }
        }
      }
      if (importsArea.count !== (Array.isArray(entries) ? entries.length : 0)) {
        fail("imports.count", "must count the module sources the area carries");
      }

      const graph = importsArea.graph;
      if (!isPlainObject(graph)) {
        fail("imports.graph", "must be a plain object");
      } else {
        const nodeIds = new Set();
        if (!isNonEmptyString(graph.version)) {
          fail("imports.graph.version", "must be a non-empty string");
        }
        if (!IMPORT_GRAPH_STATE_VALUES.includes(graph.state)) {
          fail("imports.graph.state", `must be one of: ${IMPORT_GRAPH_STATE_VALUES.join(", ")}`);
        }
        if (typeof graph.established !== "boolean") {
          fail("imports.graph.established", "must be a boolean");
        } else if (graph.established !== isImportGraphEstablished(graph.state)) {
          fail("imports.graph.established", "must agree with the state it reports");
        }

        if (!Array.isArray(graph.nodes)) {
          fail("imports.graph.nodes", "must be an array");
        } else if (graph.nodes.length > IMPORT_GRAPH_LIMITS.MAX_NODES) {
          fail("imports.graph.nodes", "must stay within the graph node bound");
        } else {
          graph.nodes.forEach((node, index) => {
            const at = `imports.graph.nodes[${index}]`;
            if (!isPlainObject(node)) {
              fail(at, "must be a plain object");
              return;
            }
            if (typeof node.id !== "string" || !fileIds.has(node.id)) {
              fail(at, "must name a file entity the model contains");
              return;
            }
            if (nodeIds.has(node.id)) fail(at, `duplicate graph node "${node.id}"`);
            nodeIds.add(node.id);
            const file = entityById.get(node.id);
            if (node.path !== file.path) fail(at, "path must agree with the file it names");
            if (node.module !== IMPORT_MODULE_EXTENSIONS.includes(file.extension)) {
              fail(at, "module must agree with the file's extension");
            }
            const expectedStatus = sourceByPath.get(node.path)?.status ?? null;
            if (node.status !== expectedStatus) {
              fail(at, "status must agree with the module source record it names");
            }
          });
          for (let next = 1; next < graph.nodes.length; next += 1) {
            const previous = graph.nodes[next - 1]?.id;
            const current = graph.nodes[next]?.id;
            if (typeof previous === "string" && typeof current === "string" && !(previous < current)) {
              fail(`imports.graph.nodes[${next}]`, "nodes must be sorted by id and unique");
            }
          }
          // Every module source the acquisition read is a node of this graph: a source
          // that vanished from the node set would silently remove a file from the
          // graph while its references stayed in the edge or unresolved list.
          for (const source of sourceByPath.values()) {
            if (!nodeIds.has(`${ENTITY_KINDS.FILE}:${source.path}`)) {
              fail(`imports.graph.nodes`, `must contain the module source "${source.path}"`);
              break;
            }
          }
        }

        const edgeKeys = new Set();
        const statedSpecifiers = new Set();
        if (!Array.isArray(graph.edges)) {
          fail("imports.graph.edges", "must be an array");
        } else if (graph.edges.length > IMPORT_GRAPH_LIMITS.MAX_EDGES) {
          fail("imports.graph.edges", "must stay within the graph edge bound");
        } else {
          graph.edges.forEach((edge, index) => {
            const at = `imports.graph.edges[${index}]`;
            if (!isPlainObject(edge)) {
              fail(at, "must be a plain object");
              return;
            }
            if (!IMPORT_GRAPH_EDGE_TYPE_VALUES.includes(edge.type)) {
              fail(at, `type must be one of: ${IMPORT_GRAPH_EDGE_TYPE_VALUES.join(", ")}`);
            }
            for (const endpoint of ["from", "to"]) {
              if (!nodeIds.has(edge[endpoint])) {
                fail(at, `${endpoint} must name a graph node`);
              }
            }
            const key = `${edge.from}\u0000${edge.type}\u0000${edge.to}`;
            if (edgeKeys.has(key)) fail(at, "must not repeat an edge the graph already states");
            edgeKeys.add(key);

            if (!Array.isArray(edge.specifiers) || edge.specifiers.length === 0) {
              fail(at, "must record the specifier(s) that established it");
            } else {
              for (const specifier of edge.specifiers) {
                if (typeof specifier !== "string" || specifier === "") {
                  fail(at, "specifiers must be non-empty text");
                }
                if (nodeIds.has(edge.from)) {
                  statedSpecifiers.add(`${edge.from}\u0000${specifier}`);
                }
              }
              for (let next = 1; next < edge.specifiers.length; next += 1) {
                if (edge.specifiers[next - 1] >= edge.specifiers[next]) {
                  fail(at, "specifiers must be sorted and unique");
                  break;
                }
              }
            }
            if (!Array.isArray(edge.kinds) || edge.kinds.length === 0) {
              fail(at, "must record how the reference was declared");
            } else {
              for (const kind of edge.kinds) {
                if (!IMPORT_SPECIFIER_KINDS.includes(kind)) {
                  fail(at, `unknown module reference kind "${String(kind)}"`);
                }
              }
            }
            if (!Array.isArray(edge.evidenceIds) || edge.evidenceIds.length === 0) {
              fail(at, "must cite at least one observation");
            } else {
              const ownerPath = entityById.get(edge.from)?.path;
              for (const id of edge.evidenceIds) {
                if (!evidenceIds.has(id)) {
                  fail(at, `references unknown observation "${String(id)}"`);
                  continue;
                }
                // Provenance must be the *importing* file's own observation. Any
                // other file's observation would attribute a reference to the wrong
                // source — a finding that points at a file that never stated it.
                if (evidenceById.get(id)?.location?.path !== ownerPath) {
                  fail(at, "must cite the importing file's own observation");
                }
              }
            }
            // Provenance must be the importing file itself. An edge citing another
            // file's observation would be provenance that does not exist.
            if (!Array.isArray(edge.sourcePaths) || edge.sourcePaths.length === 0) {
              fail(at, "must name the file whose observation stated it");
            } else {
              for (const path of edge.sourcePaths) {
                if (path !== entityById.get(edge.from)?.path) {
                  fail(at, "provenance must be the importing file");
                }
                if (!fileIds.has(`${ENTITY_KINDS.FILE}:${path}`)) {
                  fail(at, "provenance must name a file the model contains");
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
                (previous.from === current.from &&
                  (previous.to < current.to ||
                    (previous.to === current.to && previous.type < current.type)))
              )
            ) {
              fail(`imports.graph.edges[${next}]`, "edges must be sorted by (from, to, type)");
            }
          }
        }

        if (!Array.isArray(graph.unresolved)) {
          fail("imports.graph.unresolved", "must be an array");
        } else if (graph.unresolved.length > IMPORT_GRAPH_LIMITS.MAX_UNRESOLVED) {
          fail("imports.graph.unresolved", "must stay within the unresolved bound");
        } else {
          graph.unresolved.forEach((record, index) => {
            const at = `imports.graph.unresolved[${index}]`;
            if (!isPlainObject(record)) {
              fail(at, "must be a plain object");
              return;
            }
            if (!nodeIds.has(`${ENTITY_KINDS.FILE}:${record.path}`)) {
              fail(at, "must name a graph node");
            }
            if (sourceByPath.get(record.path)?.status !== "parsed") {
              fail(at, "must belong to a module source that was parsed");
            }
            if (typeof record.specifier !== "string" || record.specifier === "") {
              fail(at, "must carry the specifier that was written");
            }
            if (!IMPORT_SPECIFIER_KINDS.includes(record.kind)) {
              fail(at, "kind must be a documented module reference kind");
            }
            if (!UNRESOLVED_REFERENCE_REASON_VALUES.includes(record.reason)) {
              fail(at, `reason must be one of: ${UNRESOLVED_REFERENCE_REASON_VALUES.join(", ")}`);
            }
            if (!evidenceIds.has(record.evidenceId)) {
              fail(at, "must cite the observation that recorded it");
            }
            // A specifier cannot be both resolved and unresolved for one file.
            if (statedSpecifiers.has(`${ENTITY_KINDS.FILE}:${record.path}\u0000${record.specifier}`)) {
              fail(at, "must not state a reference the graph established as an edge");
            }
          });
          for (let next = 1; next < graph.unresolved.length; next += 1) {
            const previous = graph.unresolved[next - 1];
            const current = graph.unresolved[next];
            if (isPlainObject(previous) && isPlainObject(current)) {
              const key = (record) => `${record.path}\u0000${record.specifier}\u0000${record.kind}`;
              if (key(previous) > key(current)) {
                fail(`imports.graph.unresolved[${next}]`, "must be sorted deterministically");
              }
            }
          }
        }

        const graphCoverage = graph.coverage;
        if (!isPlainObject(graphCoverage)) {
          fail("imports.graph.coverage", "must be a plain object");
        } else {
          if (graphCoverage.state !== graph.state) {
            fail("imports.graph.coverage.state", "must agree with the graph state");
          }
          if (graphCoverage.established !== graph.established) {
            fail("imports.graph.coverage.established", "must agree with the graph state");
          }
          if (graphCoverage.nodes !== nodeIds.size) {
            fail("imports.graph.coverage.nodes", "must count the nodes the graph contains");
          }
          if (graphCoverage.edges !== edgeKeys.size) {
            fail("imports.graph.coverage.edges", "must count the edges the graph contains");
          }
          if (graphCoverage.sources !== (Array.isArray(entries) ? entries.length : 0)) {
            fail("imports.graph.coverage.sources", "must count the module sources acquired");
          }
          if (graphCoverage.truncated !== (graph.state === IMPORT_GRAPH_STATES.TRUNCATED)) {
            fail("imports.graph.coverage.truncated", "must agree with the graph state");
          }
          if (graphCoverage.complete !== (graph.state === IMPORT_GRAPH_STATES.COMPLETE)) {
            fail("imports.graph.coverage.complete", "must agree with the graph state");
          }
          if (Array.isArray(graph.unresolved)) {
            if (graphCoverage.unresolvedReported !== graph.unresolved.length) {
              fail(
                "imports.graph.coverage.unresolvedReported",
                "must count the unresolved references the graph carries",
              );
            }
            if (
              graphCoverage.unresolvedTruncated !== true &&
              graphCoverage.unresolved !== graph.unresolved.length
            ) {
              fail(
                "imports.graph.coverage.unresolved",
                "must count every unresolved reference when none were dropped",
              );
            }
          }
          if (Array.isArray(graph.edges)) {
            if (graphCoverage.edgesTruncated !== true && graphCoverage.edges !== graph.edges.length) {
              fail("imports.graph.coverage.edges", "must count every edge when none were dropped");
            }
          }
          if (!Array.isArray(graphCoverage.unestablishedSources)) {
            fail("imports.graph.coverage.unestablishedSources", "must be an array");
          } else if (
            graphCoverage.unestablishedSources.length >
            IMPORT_GRAPH_LIMITS.MAX_UNESTABLISHED_SOURCES
          ) {
            fail("imports.graph.coverage.unestablishedSources", "must stay within the graph bound");
          }
          // The other half of the coverage statement: source files in languages this
          // build does not read. The count is checked against the file entities the
          // model contains, so a graph cannot claim to have read every source file
          // while the inventory holds files no part of this phase reads.
          const uninterpreted = graphCoverage.uninterpretedSources;
          const uninterpretedObserved = [...entityById.values()].filter(
            (entity) =>
              entity?.kind === ENTITY_KINDS.FILE &&
              typeof entity.languageId === "string" &&
              !INTERPRETED_LANGUAGE_IDS.includes(entity.languageId),
          ).length;
          if (!Number.isInteger(uninterpreted) || uninterpreted < 0) {
            fail(
              "imports.graph.coverage.uninterpretedSources",
              "must be a non-negative integer count of source files",
            );
          } else if (uninterpreted !== uninterpretedObserved) {
            fail(
              "imports.graph.coverage.uninterpretedSources",
              "must count the source files in languages this build does not read",
            );
          }
          if (!Array.isArray(graphCoverage.uninterpretedExtensions)) {
            fail("imports.graph.coverage.uninterpretedExtensions", "must be an array");
          } else if (
            graphCoverage.uninterpretedExtensions.length >
            IMPORT_GRAPH_LIMITS.MAX_UNINTERPRETED_EXTENSIONS
          ) {
            fail(
              "imports.graph.coverage.uninterpretedExtensions",
              "must stay within the graph bound",
            );
          } else if (
            graphCoverage.uninterpretedExtensions.some(
              (extension) => typeof extension !== "string" || !/^\.[a-z0-9]+$/.test(extension),
            )
          ) {
            fail(
              "imports.graph.coverage.uninterpretedExtensions",
              "must be lower-case, dot-prefixed extensions",
            );
          }
          // The state may not claim more than the sources support.
          if (graph.state === IMPORT_GRAPH_STATES.COMPLETE) {
            if (graphCoverage.truncated === true) {
              fail("imports.graph.state", "cannot be complete and truncated at once");
            }
            if (graphCoverage.unestablishedSources.length > 0) {
              fail(
                "imports.graph.state",
                "cannot be complete while a module source is unestablished",
              );
            }
            for (const source of sourceByPath.values()) {
              if (source.status !== "parsed" || (source.problems ?? []).length > 0) {
                fail("imports.graph.state", "cannot be complete while a source has a problem");
                break;
              }
            }
          }
          if (graph.state === IMPORT_GRAPH_STATES.UNSUPPORTED) {
            // Two ways to establish nothing: every module source is a format this
            // build does not parse, or there is no module source at all because every
            // source file is in a language it does not read.
            if (sourceByPath.size > 0) {
              for (const source of sourceByPath.values()) {
                if (source.status !== "unsupported") {
                  fail(
                    "imports.graph.state",
                    "cannot be unsupported unless every module source is an unparsed format",
                  );
                  break;
                }
              }
            } else if (!(uninterpreted > 0)) {
              fail(
                "imports.graph.state",
                "cannot be unsupported without an unparsed format or an unread language",
              );
            }
          }
          if (
            graph.state === IMPORT_GRAPH_STATES.COMPLETE &&
            uninterpreted > 0 &&
            (Array.isArray(entries) ? entries.length : 0) === 0
          ) {
            fail(
              "imports.graph.state",
              "cannot be complete when every source file is in a language this build does not read",
            );
          }
        }
      }

      if (isPlainObject(importsArea.coverage) && isPlainObject(importsArea.graph?.coverage)) {
        if (importsArea.coverage.unresolved !== importsArea.graph.coverage.unresolved) {
          fail("imports.coverage.unresolved", "must agree with the graph it summarises");
        }
      }

      // The two views of one fact must agree exactly: every graph edge is an
      // `imports` relationship and every `imports` relationship is a graph edge. A
      // projection that dropped an edge (or a relationship list that invented one)
      // would make a generic graph query and an import query answer differently.
      const relationshipEdges = new Set(
        (model.relationships ?? [])
          .filter((relationship) => relationship?.type === RELATIONSHIP_TYPES.IMPORTS)
          .map(
            (relationship) =>
              `${relationship.from}\u0000${relationship.type}\u0000${relationship.to}`,
          ),
      );
      const graphEdgeKeys = new Set(
        (Array.isArray(importsArea.graph?.edges) ? importsArea.graph.edges : []).map(
          (graphEdge) => `${graphEdge?.from}\u0000${graphEdge?.type}\u0000${graphEdge?.to}`,
        ),
      );
      if (relationshipEdges.size !== graphEdgeKeys.size) {
        fail(
          "imports.graph.edges",
          "must state exactly the `imports` relationships the model records",
        );
      } else {
        for (const key of graphEdgeKeys) {
          if (!relationshipEdges.has(key)) {
            fail(
              "imports.graph.edges",
              "must state exactly the `imports` relationships the model records",
            );
            break;
          }
        }
      }
    }
  }

  // ── Symbol graph (Phase 17) ───────────────────────────────────────────────
  //
  // The semantic projection's contract. It is the strictest of the graph areas, and
  // deliberately so: a symbol graph makes *resolution* claims, so a malformed one can
  // mislead a rule into reporting a relationship the repository never established.
  //
  // Three invariants carry most of the weight:
  //
  //   - a node's id **is** the identity of the binding it describes (path + name), so a
  //     fabricated symbol cannot be smuggled in by inventing an id;
  //   - a *use* of a symbol (`declares`, `references`, `calls`) may only name a symbol
  //     declared in a file whose own observation stated the edge, while `exports` and
  //     `imports-binding` may point at another module — that is what those relations mean;
  //   - a state of `complete` requires the scan behind it to have finished, which is the
  //     one claim an empty graph must never make over an unfinished scan.
  {
    const symbolsArea = model.symbols;
    if (!isPlainObject(symbolsArea)) {
      fail("symbols", "must be a plain object");
    } else {
      const filePaths = new Set(model.files.entries.map((file) => file.path));
      const fileIds = new Set(model.files.entries.map((file) => file.id));
      const evidenceIds = new Set(
        (Array.isArray(model.evidence) ? model.evidence : []).map((record) => record?.id),
      );
      const sourceByPath = new Map();
      const entries = symbolsArea.entries;

      if (typeof symbolsArea.detected !== "boolean") {
        fail("symbols.detected", "must be a boolean");
      }
      if (!Array.isArray(entries)) {
        fail("symbols.entries", "must be an array");
      } else {
        for (const source of entries) {
          const at = `symbols.entries[${source?.path}]`;
          if (!isPlainObject(source)) {
            fail("symbols.entries", "every semantic source must be a plain object");
            continue;
          }
          if (!filePaths.has(source.path)) {
            fail(at, "must name a file the model observed");
            continue;
          }
          if (sourceByPath.has(source.path)) fail(at, "must describe each semantic source once");
          sourceByPath.set(source.path, source);

          if (!SEMANTIC_MODULE_EXTENSIONS.includes(source.extension)) {
            fail(at, "must carry a module source extension this build covers");
          }
          if (!entityIds.has(source.languageId)) {
            fail(at, "language must name a language the model contains");
          }
          if (!SEMANTIC_SOURCE_STATUS_VALUES.includes(source.status)) {
            fail(at, `status must be one of: ${SEMANTIC_SOURCE_STATUS_VALUES.join(", ")}`);
          }
          if (source.reason !== null && !SEMANTIC_SOURCE_REASONS.includes(source.reason)) {
            fail(at, `reason must be null or one of: ${SEMANTIC_SOURCE_REASONS.join(", ")}`);
          }
          if (source.status === "parsed" && source.reason !== null) {
            fail(at, "a parsed semantic source must not carry an acquisition reason");
          }
          if (source.status !== "parsed" && source.reason === null) {
            fail(at, "a semantic source that was not parsed must record why");
          }
          if (typeof source.truncated !== "boolean") {
            fail(at, "truncated must be a boolean");
          }
          for (const problem of source.problems ?? []) {
            if (!SEMANTIC_PROBLEM_REASONS.includes(problem)) {
              fail(at, `unknown semantic problem "${String(problem)}"`);
            }
          }

          const established = isPlainObject(source.established) ? source.established : null;
          if (established === null) {
            fail(at, "must state what it established");
          } else {
            for (const field of [
              "declarationsEstablished",
              "resolutionEstablished",
              "exportsEstablished",
            ]) {
              if (typeof established[field] !== "boolean") {
                fail(at, `${field} must be a boolean`);
              }
            }
            // Resolution is a claim *about* a declaration set: it cannot be established
            // where that set is not.
            if (
              established.resolutionEstablished === true &&
              established.declarationsEstablished !== true
            ) {
              fail(at, "resolution cannot be established while declarations are not");
            }
            if (source.status !== "parsed") {
              for (const field of [
                "declarationsEstablished",
                "resolutionEstablished",
                "exportsEstablished",
              ]) {
                if (established[field] !== false) {
                  fail(at, "a source that was not scanned establishes nothing");
                  break;
                }
              }
            }
          }

          if (!Array.isArray(source.declarations)) {
            fail(at, "must carry a declarations array");
          } else {
            for (const declaration of source.declarations) {
              if (!isPlainObject(declaration)) {
                fail(at, "declarations must be plain objects");
                continue;
              }
              if (projectSymbolName(declaration.name) === null) {
                fail(at, "declaration names must be bounded identifier text");
              }
              if (!Array.isArray(declaration.kinds) || declaration.kinds.length === 0) {
                fail(at, "a declaration must state at least one kind");
                continue;
              }
              for (const kind of declaration.kinds) {
                if (!SYMBOL_KINDS.includes(kind)) {
                  fail(at, `declaration kinds must be one of: ${SYMBOL_KINDS.join(", ")}`);
                  break;
                }
              }
              if (!Array.isArray(declaration.exportNames)) {
                fail(at, "a declaration must carry its exported names");
              } else {
                for (const name of declaration.exportNames) {
                  if (projectSymbolName(name) === null) {
                    fail(at, "exported names must be bounded identifier text");
                  }
                }
              }
              for (const field of ["exported", "shadowed", "reassigned"]) {
                if (typeof declaration[field] !== "boolean") {
                  fail(at, `${field} must be a boolean`);
                }
              }
              for (const field of ["callable", "constructable"]) {
                const value = declaration[field];
                if (value !== true && value !== false && value !== null) {
                  fail(at, `${field} must be true, false or null`);
                }
              }
              if (declaration.binding !== null) {
                if (!isPlainObject(declaration.binding)) {
                  fail(at, "binding must be null or a plain object");
                } else if (!SYMBOL_BINDING_KINDS.includes(declaration.binding.bindingKind)) {
                  fail(at, `binding kinds must be one of: ${SYMBOL_BINDING_KINDS.join(", ")}`);
                } else if (
                  declaration.binding.specifier !== null &&
                  projectModuleSpecifier(declaration.binding.specifier) === null
                ) {
                  fail(at, "a binding specifier must be null or bounded, printable text");
                }
              }
            }
            if (source.status !== "parsed" && source.declarations.length > 0) {
              fail(at, "a source that was not scanned declares nothing");
            }
          }

          if (!Array.isArray(source.exports)) {
            fail(at, "must carry an exports array");
          } else {
            for (const entry of source.exports) {
              if (!isPlainObject(entry)) {
                fail(at, "export clauses must be plain objects");
                continue;
              }
              if (!SYMBOL_EXPORT_FORMS.includes(entry.form)) {
                fail(at, `export forms must be one of: ${SYMBOL_EXPORT_FORMS.join(", ")}`);
                continue;
              }
              if (entry.name !== null && projectSymbolName(entry.name) === null) {
                fail(at, "an exported name must be null or bounded identifier text");
              }
              if (entry.localName !== null && projectSymbolName(entry.localName) === null) {
                fail(at, "a local export name must be null or bounded identifier text");
              }
              if (entry.specifier !== null && projectModuleSpecifier(entry.specifier) === null) {
                fail(at, "an export specifier must be null or bounded, printable text");
              }
            }
            if (source.status !== "parsed" && source.exports.length > 0) {
              fail(at, "a source that was not scanned exports nothing");
            }
          }

          if (!Array.isArray(source.starExports)) {
            fail(at, "must carry a starExports array");
          } else {
            for (const specifier of source.starExports) {
              if (projectModuleSpecifier(specifier) === null) {
                fail(at, "a star export must carry bounded, printable specifier text");
              }
            }
          }

          if (!Array.isArray(source.references)) {
            fail(at, "must carry a references array");
          } else {
            for (const reference of source.references) {
              if (!isPlainObject(reference)) {
                fail(at, "references must be plain objects");
                continue;
              }
              if (projectSymbolName(reference.name) === null) {
                fail(at, "a referenced name must be bounded identifier text");
              }
              if (!SYMBOL_OCCURRENCE_FORMS.includes(reference.form)) {
                fail(at, `occurrence forms must be one of: ${SYMBOL_OCCURRENCE_FORMS.join(", ")}`);
              }
              if (!isNonNegativeInteger(reference.count) || reference.count < 1) {
                fail(at, "a reference count must be a positive integer");
              }
            }
            if (source.status !== "parsed" && source.references.length > 0) {
              fail(at, "a source that was not scanned references nothing");
            }
          }

          if (!isPlainObject(source.counts)) {
            fail(at, "must carry its acquisition counts");
          } else {
            for (const field of [
              "declarations",
              "exports",
              "names",
              "references",
              "calls",
              "constructs",
              "tokens",
            ]) {
              if (!isNonNegativeInteger(source.counts[field])) {
                fail(at, `counts.${field} must be a non-negative integer`);
              }
            }
          }

          if (!evidenceIds.has(source.evidenceId)) {
            fail(at, "must cite the observation that recorded it");
          }
        }
        for (let next = 1; next < entries.length; next += 1) {
          if (entries[next - 1]?.path >= entries[next]?.path) {
            fail(`symbols.entries[${next}]`, "must be sorted by path and unique");
            break;
          }
        }
      }
      if (symbolsArea.count !== (Array.isArray(entries) ? entries.length : 0)) {
        fail("symbols.count", "must count the semantic sources the area carries");
      }

      const graph = symbolsArea.graph;
      if (!isPlainObject(graph)) {
        fail("symbols.graph", "must be a plain object");
      } else {
        const nodeIds = new Set();
        const evidenceIdSet = evidenceIds;
        const sourcePathSet = new Set(sourceByPath.keys());

        if (typeof graph.version !== "string" || graph.version === "") {
          fail("symbols.graph.version", "must be a non-empty string");
        }
        if (!SYMBOL_GRAPH_STATE_VALUES.includes(graph.state)) {
          fail("symbols.graph.state", `must be one of: ${SYMBOL_GRAPH_STATE_VALUES.join(", ")}`);
        }
        if (typeof graph.established !== "boolean") {
          fail("symbols.graph.established", "must be a boolean");
        } else if (graph.established !== isEstablishedSymbolState(graph.state)) {
          fail("symbols.graph.established", "must agree with the state it reports");
        }

        if (!Array.isArray(graph.nodes)) {
          fail("symbols.graph.nodes", "must be an array");
        } else if (graph.nodes.length > SYMBOL_GRAPH_LIMITS.MAX_SYMBOLS) {
          fail("symbols.graph.nodes", "must stay within the graph node bound");
        } else {
          graph.nodes.forEach((node, index) => {
            const at = `symbols.graph.nodes[${index}]`;
            if (!isPlainObject(node)) {
              fail(at, "must be a plain object");
              return;
            }
            if (typeof node.id !== "string" || node.id === "") {
              fail(`${at}.id`, "must be a non-empty string");
              return;
            }
            if (node.id !== symbolIdOf(node.path, node.name)) {
              fail(`${at}.id`, "must be the identity of the binding it describes");
            }
            if (!filePaths.has(node.path)) {
              fail(`${at}.path`, "must be a file the model observed");
            }
            if (node.fileId !== `file:${node.path}`) {
              fail(`${at}.fileId`, "must name the file the symbol is declared in");
            }
            if (projectSymbolName(node.name) === null) {
              fail(`${at}.name`, "must be bounded identifier text");
            }
            if (!Array.isArray(node.kinds) || node.kinds.length === 0) {
              fail(`${at}.kinds`, "must state at least one kind");
            } else {
              for (const kind of node.kinds) {
                if (!SYMBOL_KINDS.includes(kind)) {
                  fail(`${at}.kinds`, `must contain only: ${SYMBOL_KINDS.join(", ")}`);
                  break;
                }
              }
            }
            for (const field of ["exported", "shadowed", "reassigned"]) {
              if (typeof node[field] !== "boolean") fail(`${at}.${field}`, "must be a boolean");
            }
            for (const field of ["callable", "constructable"]) {
              const value = node[field];
              if (value !== true && value !== false && value !== null) {
                fail(`${at}.${field}`, "must be true, false or null");
              }
            }
            for (const field of ["referenceCount", "callCount", "constructCount"]) {
              if (!isNonNegativeInteger(node[field])) {
                fail(`${at}.${field}`, "must be a non-negative integer");
              }
            }
            if (!Array.isArray(node.exportNames)) {
              fail(`${at}.exportNames`, "must be an array");
            } else if (node.exported !== true && node.exportNames.length > 0) {
              fail(`${at}.exported`, "must be true when the symbol states exported names");
            }
            if (node.binding !== null && node.binding !== undefined) {
              if (!isPlainObject(node.binding)) {
                fail(`${at}.binding`, "must be a plain object or null");
              } else if (!SYMBOL_BINDING_KINDS.includes(node.binding.bindingKind)) {
                fail(`${at}.binding.bindingKind`, "must be a documented binding kind");
              }
            }
            if (nodeIds.has(node.id)) fail(`${at}.id`, "must be unique within the graph");
            nodeIds.add(node.id);
          });
          for (let next = 1; next < graph.nodes.length; next += 1) {
            if (String(graph.nodes[next - 1]?.id) >= String(graph.nodes[next]?.id)) {
              fail("symbols.graph.nodes", "nodes must be sorted by id and unique");
              break;
            }
          }
        }

        if (!Array.isArray(graph.edges)) {
          fail("symbols.graph.edges", "must be an array");
        } else if (graph.edges.length > SYMBOL_GRAPH_LIMITS.MAX_EDGES) {
          fail("symbols.graph.edges", "must stay within the graph edge bound");
        } else {
          graph.edges.forEach((edge, index) => {
            const at = `symbols.graph.edges[${index}]`;
            if (!isPlainObject(edge)) {
              fail(at, "must be a plain object");
              return;
            }
            if (!SYMBOL_GRAPH_EDGE_TYPE_VALUES.includes(edge.type)) {
              fail(`${at}.type`, `must be one of: ${SYMBOL_GRAPH_EDGE_TYPE_VALUES.join(", ")}`);
            }
            if (!Number.isInteger(edge.count) || edge.count < 1) {
              fail(`${at}.count`, "must be a positive integer");
            }
            if (!Array.isArray(edge.sourcePaths) || edge.sourcePaths.length === 0) {
              fail(`${at}.sourcePaths`, "must name the file whose observation stated the edge");
            } else if (edge.sourcePaths.some((path) => !filePaths.has(path))) {
              fail(`${at}.sourcePaths`, "must name files the model observed");
            }
            if (!Array.isArray(edge.evidenceIds) || edge.evidenceIds.length === 0) {
              fail(`${at}.evidenceIds`, "must cite the observation behind the edge");
            } else if (edge.evidenceIds.some((id) => !evidenceIdSet.has(id))) {
              fail(`${at}.evidenceIds`, "must cite observations the model holds");
            }

            const fromIsFile = fileIds.has(edge.from);
            const fromIsSymbol = nodeIds.has(edge.from);
            const toIsFile = fileIds.has(edge.to);
            const toIsSymbol = nodeIds.has(edge.to);
            if (!fromIsFile && !fromIsSymbol) {
              fail(`${at}.from`, "must name a file the model observed or a symbol in this graph");
            }
            if (!toIsFile && !toIsSymbol) {
              fail(`${at}.to`, "must name a file the model observed or a symbol in this graph");
            }
            if (
              edge.type === SYMBOL_GRAPH_EDGE_TYPES.DECLARES ||
              edge.type === SYMBOL_GRAPH_EDGE_TYPES.REFERENCES ||
              edge.type === SYMBOL_GRAPH_EDGE_TYPES.CALLS ||
              edge.type === SYMBOL_GRAPH_EDGE_TYPES.EXPORTS
            ) {
              if (!fromIsFile || !toIsSymbol) {
                fail(`${at}`, `a \`${edge.type}\` edge must join a file to a symbol`);
              }
            }
            if (edge.type === SYMBOL_GRAPH_EDGE_TYPES.IMPORTS_BINDING) {
              if (!fromIsSymbol || !toIsSymbol) {
                fail(`${at}`, "an `imports-binding` edge must join two symbols");
              }
            }
            // A *use* of a symbol (a declaration, a reference, a call) may only name a
            // symbol declared in the file whose observation stated the edge, so an
            // occurrence can never be attributed to a different file than the one that
            // stated it.
            //
            // `exports` and `imports-binding` are exempt because pointing at another
            // module is what those edges *mean*: a re-export publishes a symbol this file
            // did not declare, and an import binding resolves to the symbol the target
            // module exports. In both cases `sourcePaths` still names the file whose own
            // observation stated the relationship, which is the attribution that matters.
            const attributedToStatingFile =
              edge.type === SYMBOL_GRAPH_EDGE_TYPES.DECLARES ||
              edge.type === SYMBOL_GRAPH_EDGE_TYPES.REFERENCES ||
              edge.type === SYMBOL_GRAPH_EDGE_TYPES.CALLS;
            if (toIsSymbol && attributedToStatingFile && typeof edge.to === "string") {
              const separator = edge.to.indexOf("#");
              const symbolPath = edge.to.slice("symbol:".length, separator);
              if (!(edge.sourcePaths ?? []).includes(symbolPath)) {
                fail(
                  `${at}.to`,
                  "must name a symbol declared in a file whose observation stated the edge",
                );
              }
            }
          });
          for (let next = 1; next < graph.edges.length; next += 1) {
            const previous = graph.edges[next - 1];
            const current = graph.edges[next];
            if (!isPlainObject(previous) || !isPlainObject(current)) continue;
            // One relationship, stated once. `A --references--> B` twice would make
            // `referencesTo` double-count a symbol's uses and a finding per edge would
            // describe the same relationship twice, so the graph refuses to carry it.
            if (
              previous.from === current.from &&
              previous.to === current.to &&
              previous.type === current.type
            ) {
              fail("symbols.graph.edges", "must state each relationship once");
              break;
            }
            const ordered =
              previous.from < current.from ||
              (previous.from === current.from &&
                (previous.to < current.to ||
                  (previous.to === current.to && previous.type < current.type)));
            if (!ordered) {
              fail("symbols.graph.edges", "edges must be sorted by (from, to, type)");
              break;
            }
          }
        }

        if (!Array.isArray(graph.unresolved)) {
          fail("symbols.graph.unresolved", "must be an array");
        } else if (graph.unresolved.length > SYMBOL_GRAPH_LIMITS.MAX_UNRESOLVED) {
          fail("symbols.graph.unresolved", "must stay within the unresolved bound");
        } else {
          graph.unresolved.forEach((record, index) => {
            const at = `symbols.graph.unresolved[${index}]`;
            if (!isPlainObject(record)) {
              fail(at, "must be a plain object");
              return;
            }
            if (!filePaths.has(record.path)) {
              fail(`${at}.path`, "must name a file the model observed");
            }
            if (projectSymbolName(record.name) === null) {
              fail(`${at}.name`, "must be bounded identifier text");
            }
            if (!SYMBOL_UNRESOLVED_KINDS.includes(record.kind)) {
              fail(`${at}.kind`, `must be one of: ${SYMBOL_UNRESOLVED_KINDS.join(", ")}`);
            }
            if (!SYMBOL_UNRESOLVED_REASON_VALUES.includes(record.reason)) {
              fail(`${at}.reason`, "must be a documented unresolved reason");
            }
            if (record.evidenceId !== null && !evidenceIdSet.has(record.evidenceId)) {
              fail(`${at}.evidenceId`, "must cite an observation the model holds");
            }
          });
          for (let next = 1; next < graph.unresolved.length; next += 1) {
            const previous = graph.unresolved[next - 1];
            const current = graph.unresolved[next];
            const ordered =
              isPlainObject(previous) &&
              isPlainObject(current) &&
              (previous.path < current.path ||
                (previous.path === current.path &&
                  (previous.name < current.name ||
                    (previous.name === current.name && previous.kind <= current.kind))));
            if (!ordered) {
              fail("symbols.graph.unresolved", "must be sorted deterministically");
              break;
            }
          }
        }

        if (!isPlainObject(graph.coverage)) {
          fail("symbols.graph.coverage", "must be a plain object");
        } else {
          const graphCoverage = graph.coverage;
          if (graphCoverage.state !== graph.state) {
            fail("symbols.graph.coverage.state", "must agree with the graph state");
          }
          if (graphCoverage.established !== graph.established) {
            fail("symbols.graph.coverage.established", "must agree with the graph state");
          }
          if (graphCoverage.symbols !== (Array.isArray(graph.nodes) ? graph.nodes.length : 0)) {
            fail("symbols.graph.coverage.symbols", "must count the symbols the graph contains");
          }
          if (graphCoverage.edges !== (Array.isArray(graph.edges) ? graph.edges.length : 0)) {
            fail("symbols.graph.coverage.edges", "must count the edges the graph contains");
          }
          if (graphCoverage.truncated !== (graph.state === SYMBOL_GRAPH_STATES.TRUNCATED)) {
            fail("symbols.graph.coverage.truncated", "must agree with the graph state");
          }
          if (graphCoverage.complete !== (graph.state === SYMBOL_GRAPH_STATES.COMPLETE)) {
            fail("symbols.graph.coverage.complete", "must agree with the graph state");
          }
          if (graphCoverage.unresolved !== graph.unresolved.length) {
            fail("symbols.graph.coverage.unresolved", "must count every unresolved record");
          }
          if (graphCoverage.unresolvedReported !== graph.unresolved.length) {
            fail("symbols.graph.coverage.unresolvedReported", "must count every unresolved record");
          }
          if (!isNonNegativeInteger(graphCoverage.unestablished)) {
            fail("symbols.graph.coverage.unestablished", "must be a non-negative integer");
          }
          if (!Array.isArray(graphCoverage.unestablishedSources)) {
            fail("symbols.graph.coverage.unestablishedSources", "must be an array");
          } else if (
            graphCoverage.unestablishedSources.length > SYMBOL_GRAPH_LIMITS.MAX_UNESTABLISHED_SOURCES
          ) {
            fail("symbols.graph.coverage.unestablishedSources", "must stay within the graph bound");
          }
          if (graph.state === SYMBOL_GRAPH_STATES.COMPLETE) {
            // The projection only reaches `complete` when the scan behind it finished and
            // every semantic claim in it was established. Restating that here is what makes
            // the state trustworthy rather than merely produced: a tampered graph that
            // claims completeness over an unfinished scan has to be rejected.
            if (
              model.scan.complete !== true ||
              model.scan.truncated === true ||
              graphCoverage.complete !== true ||
              graphCoverage.truncated === true
            ) {
              fail("symbols.graph.state", "cannot be complete unless the scan covered the repository");
            }
            if (graphCoverage.unestablishedSources.length > 0) {
              fail("symbols.graph.state", "cannot be complete while a semantic source is unestablished");
            }
            for (const source of sourceByPath.values()) {
              // The projection reaches `complete` only when *every* source established all
              // three of its claims and carried no problem. Restating the full condition
              // here is the point: a tampered graph that claims completeness over a file
              // that could not be read has to be rejected, not trusted.
              if (
                source.status !== "parsed" ||
                (source.problems ?? []).length > 0 ||
                source.established.declarationsEstablished !== true ||
                source.established.resolutionEstablished !== true ||
                source.established.exportsEstablished !== true
              ) {
                fail("symbols.graph.state", "cannot be complete while a source is unestablished");
                break;
              }
            }
          }
          if (graph.state === SYMBOL_GRAPH_STATES.UNSUPPORTED && sourcePathSet.size === 0) {
            if (!(isNonNegativeInteger(graphCoverage.uninterpretedSources) && graphCoverage.uninterpretedSources > 0)) {
              fail(
                "symbols.graph.state",
                "cannot be unsupported without an unparsed format or an unread language",
              );
            }
          }
        }
      }

      if (isPlainObject(symbolsArea.coverage) && isPlainObject(symbolsArea.graph?.coverage)) {
        if (symbolsArea.coverage.unresolved !== symbolsArea.graph.coverage.unresolved) {
          fail("symbols.coverage.unresolved", "must agree with the graph it summarises");
        }
      }
    }
  }

  // ── API graph (Phase 18) ──────────────────────────────────────────────────
  //
  // Validated with the same care as the symbol graph, and for the same reason: a route
  // makes a claim (*this repository exposes this endpoint, handled by this symbol*), so a
  // malformed graph can mislead a rule into reporting an API surface the repository never
  // declared.
  //
  // The invariants that carry the weight:
  //
  //   - a route node's id **is** the identity of the endpoint (`route:METHOD:path`), so a
  //     fabricated route cannot be smuggled in by inventing an id;
  //   - `handled-by` / `middleware` may only name a symbol the Phase 17 graph carries, and
  //     a route may only be `declared` by a file the model observed — no invented endpoint;
  //   - a state of `complete` requires the scan behind it to have finished and every
  //     source to have established its route set.
  {
    const apiArea = model.api;
    if (!isPlainObject(apiArea)) {
      fail("api", "must be a plain object");
    } else {
      const filePaths = new Set(model.files.entries.map((file) => file.path));
      const fileIds = new Set(model.files.entries.map((file) => file.id));
      const symbolNodeIds = new Set(
        (Array.isArray(model.symbols?.graph?.nodes) ? model.symbols.graph.nodes : []).map(
          (node) => node.id,
        ),
      );
      const evidenceIds = new Set(
        (Array.isArray(model.evidence) ? model.evidence : []).map((record) => record?.id),
      );
      const entries = apiArea.entries;

      if (typeof apiArea.detected !== "boolean") fail("api.detected", "must be a boolean");
      if (!Array.isArray(entries)) {
        fail("api.entries", "must be an array");
      } else {
        const seen = new Set();
        for (const source of entries) {
          const at = `api.entries[${source?.path}]`;
          if (!isPlainObject(source)) {
            fail("api.entries", "every API source must be a plain object");
            continue;
          }
          if (!filePaths.has(source.path)) {
            fail(at, "must name a file the model observed");
            continue;
          }
          if (seen.has(source.path)) fail(at, "must describe each API source once");
          seen.add(source.path);

          if (!SEMANTIC_MODULE_EXTENSIONS.includes(source.extension)) {
            fail(`${at}.extension`, "must be a module source extension");
          }
          if (!API_SOURCE_STATUSES.includes(source.status)) {
            fail(`${at}.status`, "must be a documented API source status");
          }
          if (typeof source.established !== "boolean") {
            fail(`${at}.established`, "must be a boolean");
          }
          if (!Array.isArray(source.frameworks)) {
            fail(`${at}.frameworks`, "must be an array");
          } else {
            for (const framework of source.frameworks) {
              if (!API_FRAMEWORKS.includes(framework)) {
                fail(`${at}.frameworks`, "must name a supported framework");
              }
            }
          }
          if (!Array.isArray(source.routes)) {
            fail(`${at}.routes`, "must be an array");
          } else {
            for (const route of source.routes) {
              if (!API_ROUTE_METHODS.includes(route?.method)) {
                fail(`${at}.routes[].method`, "must be a recorded method");
              }
              if (typeof route?.path !== "string" || !route.path.startsWith("/")) {
                fail(`${at}.routes[].path`, "must be a route path");
              }
              if (!API_FRAMEWORKS.includes(route?.framework)) {
                fail(`${at}.routes[].framework`, "must name a supported framework");
              }
              if (!API_RECEIVER_KINDS.includes(route?.receiverKind)) {
                fail(`${at}.routes[].receiverKind`, "must be app or router");
              }
              const callables = [
                ...(route?.handler == null ? [] : [route.handler]),
                ...(Array.isArray(route?.middleware) ? route.middleware : []),
              ];
              for (const callable of callables) {
                if (!API_CALLABLE_FORMS.includes(callable?.form)) {
                  fail(`${at}.routes[].callables`, "must be a documented callable form");
                }
              }
            }
          }
          if (!Array.isArray(source.shapes)) {
            fail(`${at}.shapes`, "must be an array");
          } else {
            for (const shape of source.shapes) {
              if (!API_SHAPE_REASONS.includes(shape?.reason)) {
                fail(`${at}.shapes[].reason`, "must be a documented reason");
              }
            }
          }
          if (!Array.isArray(source.problems)) {
            fail(`${at}.problems`, "must be an array");
          } else {
            for (const problem of source.problems) {
              if (!API_PROBLEM_REASONS.includes(problem)) {
                fail(`${at}.problems[]`, "must be a documented problem");
              }
            }
          }
          if (!evidenceIds.has(source.evidenceId)) {
            fail(`${at}.evidenceId`, "must name an observation the model carries");
          }
        }
      }
      if (apiArea.count !== (Array.isArray(entries) ? entries.length : 0)) {
        fail("api.count", "must count the API sources the area carries");
      }

      const graph = apiArea.graph;
      if (!isPlainObject(graph)) {
        fail("api.graph", "must be a plain object");
      } else {
        const routeIds = new Set();
        if (!isNonEmptyString(graph.version)) fail("api.graph.version", "must be a non-empty string");
        if (!API_GRAPH_STATE_VALUES.includes(graph.state)) {
          fail("api.graph.state", `must be one of: ${API_GRAPH_STATE_VALUES.join(", ")}`);
        }
        if (typeof graph.established !== "boolean") {
          fail("api.graph.established", "must be a boolean");
        } else if (graph.established !== isEstablishedApiState(graph.state)) {
          fail("api.graph.established", "must agree with the state it reports");
        }

        if (!Array.isArray(graph.nodes)) {
          fail("api.graph.nodes", "must be an array");
        } else {
          if (graph.nodes.length > API_GRAPH_LIMITS.MAX_ROUTES) {
            fail("api.graph.nodes", "must stay within the graph node bound");
          }
          let previous = null;
          graph.nodes.forEach((node, index) => {
            const at = `api.graph.nodes[${index}]`;
            if (!isPlainObject(node)) {
              fail(at, "must be a plain object");
              return;
            }
            if (!API_ROUTE_METHODS.includes(node.method)) {
              fail(`${at}.method`, "must be a recorded method");
            }
            if (typeof node.path !== "string" || !node.path.startsWith("/")) {
              fail(`${at}.path`, "must be a route path");
            }
            if (node.id !== apiRouteIdOf(node.method, node.path)) {
              fail(`${at}.id`, "must be the identity of the endpoint it describes");
            }
            if (!Array.isArray(node.frameworks)) {
              fail(`${at}.frameworks`, "must be an array");
            } else {
              for (const framework of node.frameworks) {
                if (!API_FRAMEWORKS.includes(framework)) {
                  fail(`${at}.frameworks`, "must name a supported framework");
                }
              }
            }
            if (!Array.isArray(node.sourcePaths)) {
              fail(`${at}.sourcePaths`, "must be an array");
            } else {
              for (const sourcePath of node.sourcePaths) {
                if (!filePaths.has(sourcePath)) {
                  fail(`${at}.sourcePaths`, "must name files the model observed");
                }
              }
            }
            if (!Array.isArray(node.evidenceIds)) {
              fail(`${at}.evidenceIds`, "must be an array");
            } else {
              for (const evidenceId of node.evidenceIds) {
                if (!evidenceIds.has(evidenceId)) {
                  fail(`${at}.evidenceIds`, "must name observations the model carries");
                }
              }
            }
            if (previous !== null && previous >= node.id) {
              fail("api.graph.nodes", "nodes must be sorted by id and unique");
            }
            previous = node.id;
            routeIds.add(node.id);
          });
        }

        if (!Array.isArray(graph.edges)) {
          fail("api.graph.edges", "must be an array");
        } else {
          if (graph.edges.length > API_GRAPH_LIMITS.MAX_EDGES) {
            fail("api.graph.edges", "must stay within the graph edge bound");
          }
          let previousEdge = null;
          graph.edges.forEach((edge, index) => {
            const at = `api.graph.edges[${index}]`;
            if (!isPlainObject(edge)) {
              fail(at, "must be a plain object");
              return;
            }
            if (!API_GRAPH_EDGE_TYPE_VALUES.includes(edge.type)) {
              fail(`${at}.type`, "must be a documented edge type");
            }
            const endpointExists = (id) =>
              routeIds.has(id) || fileIds.has(id) || symbolNodeIds.has(id);
            if (!endpointExists(edge.from)) fail(`${at}.from`, "must name an entity the model carries");
            if (!endpointExists(edge.to)) fail(`${at}.to`, "must name an entity the model carries");
            if (edge.type === API_GRAPH_EDGE_TYPES.DECLARES) {
              if (!fileIds.has(edge.from) || !routeIds.has(edge.to)) {
                fail(`${at}`, "a `declares` edge must join a file to a route");
              }
            } else if (!routeIds.has(edge.from) || !symbolNodeIds.has(edge.to)) {
              fail(`${at}`, "a route relationship must join a route to a symbol");
            }
            if (!Array.isArray(edge.evidenceIds)) {
              fail(`${at}.evidenceIds`, "must be an array");
            } else {
              for (const evidenceId of edge.evidenceIds) {
                if (!evidenceIds.has(evidenceId)) {
                  fail(`${at}.evidenceIds`, "must name observations the model carries");
                }
              }
            }
            const key = `${edge.from}\u0000${edge.to}\u0000${edge.type}`;
            if (previousEdge !== null && key <= previousEdge) {
              fail("api.graph.edges", "must state each relationship once, sorted by (from, to, type)");
            }
            previousEdge = key;
          });
        }

        if (!Array.isArray(graph.unresolved)) {
          fail("api.graph.unresolved", "must be an array");
        } else {
          if (graph.unresolved.length > API_GRAPH_LIMITS.MAX_UNRESOLVED) {
            fail("api.graph.unresolved", "must stay within the unresolved bound");
          }
          let previousUnresolved = null;
          graph.unresolved.forEach((record, index) => {
            const at = `api.graph.unresolved[${index}]`;
            if (!isPlainObject(record)) {
              fail(at, "must be a plain object");
              return;
            }
            if (!filePaths.has(record.path)) {
              fail(`${at}.path`, "must name a file the model observed");
            }
            if (!API_UNRESOLVED_KINDS.includes(record.kind)) {
              fail(`${at}.kind`, "must be route, handler or middleware");
            }
            if (!API_UNRESOLVED_REASON_VALUES.includes(record.reason)) {
              fail(`${at}.reason`, "must be a documented reason");
            }
            const key = `${record.path}\u0000${record.reason}\u0000${record.route ?? ""}\u0000${record.kind}\u0000${record.name ?? ""}`;
            if (previousUnresolved !== null && key < previousUnresolved) {
              fail("api.graph.unresolved", "must be sorted deterministically");
            }
            previousUnresolved = key;
          });
        }

        const coverage = graph.coverage;
        if (!isPlainObject(coverage)) {
          fail("api.graph.coverage", "must be a plain object");
        } else {
          if (coverage.state !== graph.state) {
            fail("api.graph.coverage.state", "must agree with the graph state");
          }
          if (coverage.established !== graph.established) {
            fail("api.graph.coverage.established", "must agree with the graph state");
          }
          if (coverage.routes !== (Array.isArray(graph.nodes) ? graph.nodes.length : -1)) {
            fail("api.graph.coverage.routes", "must count the routes the graph contains");
          }
          if (coverage.edges !== (Array.isArray(graph.edges) ? graph.edges.length : -1)) {
            fail("api.graph.coverage.edges", "must count the edges the graph contains");
          }
          if (coverage.unresolved !== (Array.isArray(graph.unresolved) ? graph.unresolved.length : -1)) {
            fail("api.graph.coverage.unresolved", "must count every unresolved record");
          }
          if (coverage.truncated !== (graph.state === API_GRAPH_STATES.TRUNCATED)) {
            fail("api.graph.coverage.truncated", "must agree with the graph state");
          }
          if (coverage.complete !== (graph.state === API_GRAPH_STATES.COMPLETE)) {
            fail("api.graph.coverage.complete", "must agree with the graph state");
          }
          if (graph.state === API_GRAPH_STATES.COMPLETE) {
            if (model.scan.complete !== true) {
              fail("api.graph.state", "cannot be complete unless the scan covered the repository");
            }
            const sources = Array.isArray(entries) ? entries : [];
            if (sources.length > 0 && !sources.every((source) => source.established === true)) {
              fail("api.graph.state", "cannot be complete while an API source is unestablished");
            }
          }
        }
      }

      if (isPlainObject(apiArea.coverage) && isPlainObject(apiArea.graph?.coverage)) {
        if (apiArea.coverage.unresolved !== apiArea.graph.coverage.unresolved) {
          fail("api.coverage.unresolved", "must agree with the graph it summarises");
        }
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
