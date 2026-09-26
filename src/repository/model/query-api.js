/**
 * Code Guardian — Repository Query API (Phase 11)
 *
 * `createRepositoryQuery(model)` is the read-only **semantic interface** over a
 * RepositoryModel. It exists so Rules and future Analyzers can ask repository
 * questions — "which files are TypeScript?", "what is connected to this
 * manifest?", "can I trust this answer?" — without each of them re-implementing
 * entity filtering, relationship traversal, coverage handling and evidence
 * lookup.
 *
 * ### It is a view, not a new source of truth
 *
 * Every method delegates to the Phase 8D accessors in `query.js` and the model's
 * own indexes. The query layer **derives nothing that is not already observed**:
 * it filters, sorts, traverses existing edges, resolves existing evidence and
 * reports the model's existing coverage. It never reads the filesystem, spawns a
 * process, touches the network, consults a clock, or rescans.
 *
 * ### Coverage is never flattened
 *
 * A collection query returns an envelope (`{ entities, coverage, truncated }`),
 * never a bare array. When the scan is incomplete the guarantee is `partial`, so a
 * caller cannot read an empty list as "this does not exist". Path questions go
 * through `coverageOfPath`, which keeps the model's five-way distinction
 * (observed / ignored / unreadable / unknown / absent) intact. `unknown` and
 * `unreadable` are never collapsed into `absent`.
 *
 * ### Ordinary misses do not throw
 *
 * An unknown entity is `null`; a missing relationship or evidence set is `[]`.
 * Only *programmer errors* throw a `RepositoryQueryError`: an unknown entity kind,
 * an invalid traversal limit, an unknown relationship type, a malformed query
 * object. A typo must never silently read as "nothing exists".
 *
 * ### Everything is bounded and deterministic
 *
 * Traversal is depth- and result-bounded and cycle-safe. Every list is sorted by a
 * documented key, never by Map/Set/object iteration order.
 *
 * Import boundary (enforced by a test in `tests/repository-query.test.js`): this
 * module reaches only Core and its sibling modules — no `node:fs`, `node:path`,
 * `child_process`, network, worker, transport or CLI.
 */

import {
  COVERAGE_GUARANTEES,
  coverageClass,
  getDependencyByName as modelGetDependencyByName,
  getEntity as modelGetEntity,
  getEvidence as modelGetEvidence,
  inspectCompleteness,
  isKnownAbsent as modelIsKnownAbsent,
  listDependencies as modelListDependencies,
  listDependenciesByEcosystem,
  listEntitiesByKind,
  listFilesByLanguage,
  listManifestsByEcosystem,
  listRelationships as modelListRelationships,
} from "./query.js";
import { ENTITY_KINDS } from "./identity.js";
import { GRAPH_RELATIONSHIP_TYPES } from "./graph.js";
import {
  ARCHITECTURE_EDGE_TYPES,
  ARCHITECTURE_EDGE_TYPE_VALUES,
  ARCHITECTURE_GRAPH_STATES,
  REPOSITORY_NODE_KIND,
} from "./architecture-graph.js";
import {
  DEPENDENCY_GRAPH_EDGE_TYPE_VALUES,
  DEPENDENCY_GRAPH_STATES,
  isSourceEstablished,
  unestablishedSourceRecord,
} from "./dependency-graph.js";
import {
  IMPORT_GRAPH_EDGE_TYPE_VALUES,
  IMPORT_GRAPH_STATES,
  UNRESOLVED_REFERENCE_REASON_VALUES,
} from "./import-graph.js";
import {
  SYMBOL_GRAPH_EDGE_TYPES,
  SYMBOL_GRAPH_EDGE_TYPE_VALUES,
  SYMBOL_GRAPH_STATES,
  SYMBOL_UNRESOLVED_KINDS,
  SYMBOL_UNRESOLVED_REASON_VALUES,
} from "./symbol-graph.js";
import {
  API_GRAPH_EDGE_TYPES,
  API_GRAPH_EDGE_TYPE_VALUES,
  API_GRAPH_STATES,
  API_UNRESOLVED_KINDS,
  API_UNRESOLVED_REASON_VALUES,
} from "./api-graph.js";
import { API_ROUTE_METHODS, SYMBOL_KINDS } from "./entities.js";
import { isRepositoryRelativePath } from "./paths.js";
import {
  QUERY_DIRECTIONS,
  QUERY_DIRECTION_VALUES,
  QUERY_LIMITS,
  createArchitectureBuildQueryResult,
  createArchitectureEdgeQueryResult,
  createArchitectureGraphResult,
  createArchitectureNodeQueryResult,
  createArchitecturePathResult,
  createApiGraphResult,
  createApiHandlerRouteResult,
  createApiRouteHandlerResult,
  createApiRouteLookupResult,
  createApiRouteMiddlewareResult,
  createApiRouteQueryResult,
  createApiServiceResult,
  createApiUnresolvedRouteResult,
  createDependencyEdgeQueryResult,
  createDependencyGraphResult,
  createDependencyPathResult,
  createDependencyTraversalResult,
  createEntityQueryResult,
  createEvidenceQueryResult,
  createFrameworkUsageQueryResult,
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
  validateArchitectureBuildQueryResult,
  validateArchitectureEdgeQueryResult,
  validateArchitectureGraphResult,
  validateArchitectureNodeQueryResult,
  validateArchitecturePathResult,
  validateApiGraphResult,
  validateApiHandlerRouteResult,
  validateApiRouteHandlerResult,
  validateApiRouteLookupResult,
  validateApiRouteMiddlewareResult,
  validateApiRouteQueryResult,
  validateApiServiceResult,
  validateApiUnresolvedRouteResult,
  validateDependencyEdgeQueryResult,
  validateDependencyGraphResult,
  validateDependencyPathResult,
  validateDependencyTraversalResult,
  validateEntityQueryResult,
  validateEvidenceQueryResult,
  validateFrameworkUsageQueryResult,
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
} from "./query-contracts.js";
import { QUERY_ERROR_KINDS, RepositoryQueryError, safeQueryToken } from "./query-errors.js";

const ENTITY_KIND_VALUES = Object.values(ENTITY_KINDS);
const CRITERIA_KEYS = Object.freeze(["kind", "path", "language", "ecosystem", "framework"]);

/**
 * Criteria `findDependencies` accepts.
 *
 * Deliberately narrow: every criterion is a fact the model recorded (which
 * ecosystem, which name, which manifest stated it, which scope that manifest
 * established, and whether it was declared or resolved), so a query can never ask a
 * question the dependency substrate cannot answer.
 */
const DEPENDENCY_CRITERIA_KEYS = Object.freeze([
  "ecosystem",
  "name",
  "manifest",
  "scope",
  "direct",
  "resolved",
  "declared",
]);

/**
 * Relationship types that connect dependency entities.
 *
 * Used by `dependencyRelationships` so a consumer asking about a dependency's
 * graph gets the dependency graph rather than every edge at that node.
 */
const DEPENDENCY_RELATIONSHIP_TYPES = Object.freeze([
  "declares-dependency",
  "depends-on",
  "resolved-by",
]);
const RESOLUTION_FILTER_KEYS = Object.freeze(["from", "to", "type"]);
const TRAVERSAL_OPTION_KEYS = Object.freeze([
  "direction",
  "type",
  "relationshipTypes",
  "maxDepth",
  "maxResults",
]);

/**
 * Options a dependency-graph traversal accepts.
 *
 * No `direction`: the direction *is* the method (`dependenciesOf` follows edges
 * out, `dependentsOf` follows them in), so a caller cannot ask `dependenciesOf`
 * for dependents and quietly get the opposite answer.
 */
const GRAPH_TRAVERSAL_OPTION_KEYS = Object.freeze(["maxDepth", "maxResults"]);

/** Criteria a dependency edge list accepts. */
const DEPENDENCY_EDGE_FILTER_KEYS = Object.freeze(["from", "to", "type", "maxResults"]);

/** Criteria an architecture edge list accepts. */
const ARCHITECTURE_EDGE_FILTER_KEYS = Object.freeze(["from", "to", "type", "maxResults"]);

/** Criteria a container-declaration list accepts. */
const BUILD_DECLARATION_FILTER_KEYS = Object.freeze([
  "source",
  "dockerfile",
  "service",
  "maxResults",
]);

/** Criteria an import edge list accepts. */
const IMPORT_EDGE_FILTER_KEYS = Object.freeze(["from", "to", "type", "maxResults"]);

/** Criteria an unresolved-reference list accepts. */
const IMPORT_UNRESOLVED_FILTER_KEYS = Object.freeze(["path", "reason", "maxResults"]);

/** Options a topology candidate list accepts (the bound, and nothing else). */
const IMPORT_CANDIDATE_OPTION_KEYS = Object.freeze(["maxResults"]);

/**
 * Criteria a symbol node list accepts.
 *
 * Every criterion is a fact the projection recorded about the node itself — a path,
 * a declaring file, a name, a declaration kind, whether the file publishes it — so a
 * query can never ask a question the symbol graph did not answer. `kind` is matched
 * against the node's `kinds` list, because a name can legitimately be established as
 * more than one kind (`declare function` + `declare const`, a merged namespace).
 */
const SYMBOL_NODE_FILTER_KEYS = Object.freeze([
  "path",
  "fileId",
  "name",
  "kind",
  "exported",
  "maxResults",
]);

/** Criteria a symbol edge list accepts. */
const SYMBOL_EDGE_FILTER_KEYS = Object.freeze(["from", "to", "type", "maxResults"]);

/** Criteria an unresolved semantic-occurrence list accepts. */
const SYMBOL_UNRESOLVED_FILTER_KEYS = Object.freeze([
  "path",
  "name",
  "kind",
  "reason",
  "maxResults",
]);

/** Options a symbol candidate list accepts (the bound, and nothing else). */
const SYMBOL_CANDIDATE_OPTION_KEYS = Object.freeze(["maxResults"]);

/**
 * Criteria a route list accepts.
 *
 * Every criterion is a fact the projection recorded about the route itself — its
 * method, its path, the framework that declared it, the file that declared it, the
 * receiver binding — so a query can never ask a question the API graph did not answer.
 */
const API_ROUTE_FILTER_KEYS = Object.freeze([
  "method",
  "path",
  "framework",
  "sourcePath",
  "maxResults",
]);

/** Criteria an unresolved-route list accepts. */
const API_UNRESOLVED_FILTER_KEYS = Object.freeze(["path", "reason", "maxResults"]);

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function compareById(a, b) {
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

/** Whether a criterion value is a usable (non-empty) query token. */
function isNonEmptyQueryString(value) {
  return typeof value === "string" && value.trim() !== "";
}

/** Deterministic comparator over records sharing a string field. */
function compareByField(field) {
  return (a, b) => {
    const left = typeof a?.[field] === "string" ? a[field] : "";
    const right = typeof b?.[field] === "string" ? b[field] : "";
    return left < right ? -1 : left > right ? 1 : 0;
  };
}

function compareRelationships(a, b) {
  if (a.from !== b.from) return a.from < b.from ? -1 : 1;
  if (a.type !== b.type) return a.type < b.type ? -1 : 1;
  if (a.to === b.to) return 0;
  return a.to < b.to ? -1 : 1;
}

function edgeKey(relationship) {
  return `${relationship.from}\u0000${relationship.type}\u0000${relationship.to}`;
}

function uniqueSortedRelationships(relationships) {
  const seen = new Map();
  for (const relationship of relationships) {
    const key = edgeKey(relationship);
    if (!seen.has(key)) seen.set(key, relationship);
  }
  return [...seen.values()].sort(compareRelationships);
}

/** A query is only meaningful over the shape of a built model. */
function isModelShaped(model) {
  return (
    isPlainObject(model) &&
    isPlainObject(model.identity) &&
    isPlainObject(model.indexes) &&
    isPlainObject(model.scan) &&
    Array.isArray(model.relationships) &&
    Array.isArray(model.evidence)
  );
}

/** The coverage state a collection query reports. */
function coverageState(model) {
  const complete = model.scan.complete === true && model.scan.truncated !== true;
  return {
    coverage: complete ? COVERAGE_GUARANTEES.COMPLETE : COVERAGE_GUARANTEES.PARTIAL,
    truncated: model.scan.truncated === true,
  };
}

function requireEntityKind(kind) {
  if (typeof kind !== "string" || !ENTITY_KIND_VALUES.includes(kind)) {
    throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_ENTITY_KIND, {
      received: safeQueryToken(kind),
    });
  }
}

function requireDirection(direction) {
  if (!QUERY_DIRECTION_VALUES.includes(direction)) {
    throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_DIRECTION, {
      received: safeQueryToken(direction),
    });
  }
}

function requireRelationshipType(type) {
  if (typeof type !== "string" || !GRAPH_RELATIONSHIP_TYPES.includes(type)) {
    throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_RELATIONSHIP_TYPE, {
      received: safeQueryToken(type),
    });
  }
}

function requireLimit(value, { field, min, max }) {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_LIMIT, {
      field,
      received: typeof value === "number" && Number.isFinite(value) ? value : null,
    });
  }
  return value;
}

function requireKeys(value, allowed, field) {
  if (!isPlainObject(value)) {
    throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, { field });
  }
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) {
    throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, {
      field,
      unknown: unknown.map(safeQueryToken).filter((token) => token !== null),
    });
  }
}

/** Resolve the entity-kind association predicates for a language/ecosystem/framework. */
function matchesLanguage(entity, language) {
  const languageEntityId = `${ENTITY_KINDS.LANGUAGE}:${language}`;
  if (entity.kind === ENTITY_KINDS.FILE && entity.languageId === languageEntityId) return true;
  if (entity.id === languageEntityId) return true;
  if (
    entity.kind === ENTITY_KINDS.MANIFEST &&
    Array.isArray(entity.languages) &&
    entity.languages.includes(languageEntityId)
  ) {
    return true;
  }
  return false;
}

function matchesEcosystem(entity, ecosystem) {
  const ecosystemEntityId = `${ENTITY_KINDS.ECOSYSTEM}:${ecosystem}`;
  if (entity.kind === ENTITY_KINDS.MANIFEST && entity.ecosystemId === ecosystemEntityId) return true;
  if (entity.kind === ENTITY_KINDS.DEPENDENCY && entity.ecosystemId === ecosystemEntityId) {
    return true;
  }
  return entity.id === ecosystemEntityId;
}

/** The manifest paths a dependency's facts were stated in, sorted and unique. */
function dependencyManifestIds(dependency) {
  const ids = new Set();
  for (const declaration of dependency.declarations ?? []) ids.add(declaration.manifestId);
  for (const resolution of dependency.resolutions ?? []) ids.add(resolution.manifestId);
  return [...ids].sort();
}

function matchesFramework(entity, framework) {
  const frameworkEntityId = `${ENTITY_KINDS.FRAMEWORK}:${framework}`;
  if (entity.kind === ENTITY_KINDS.FRAMEWORK && entity.name === framework) return true;
  if (entity.kind === ENTITY_KINDS.TEST && entity.frameworkId === frameworkEntityId) return true;
  return false;
}

/**
 * Create the read-only query API for a RepositoryModel.
 *
 * @param {object} model A built (frozen) RepositoryModel.
 * @returns {object} A frozen query handle.
 * @throws {RepositoryQueryError} kind `invalid-model` when the value is not
 *   model-shaped.
 */
export function createRepositoryQuery(model) {
  if (!isModelShaped(model)) {
    throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_MODEL);
  }

  const allEntities = () =>
    Object.keys(model.indexes.entitiesById)
      .sort()
      .map((id) => modelGetEntity(model, id))
      .filter((entity) => entity !== null);

  // ── Result construction ───────────────────────────────────────────────────
  const entityResult = (entities) => {
    const result = createEntityQueryResult({
      entities: [...entities].sort(compareById),
      ...coverageState(model),
    });
    validateEntityQueryResult(result);
    Object.freeze(result.entities);
    return Object.freeze(result);
  };

  const relationshipResult = (relationships) => {
    const result = createRelationshipQueryResult({
      relationships: uniqueSortedRelationships(relationships),
      ...coverageState(model),
    });
    validateRelationshipQueryResult(result);
    Object.freeze(result.relationships);
    return Object.freeze(result);
  };

  const evidenceResult = (evidence) => {
    const result = createEvidenceQueryResult({
      evidence: [...evidence].sort(compareById),
      ...coverageState(model),
    });
    validateEvidenceQueryResult(result);
    Object.freeze(result.evidence);
    return Object.freeze(result);
  };

  /** Edges touching an entity in one direction, de-duplicated and sorted. */
  const edgesAt = (id, direction, relationshipTypes) => {
    const edges = [];
    if (direction !== QUERY_DIRECTIONS.IN) {
      edges.push(...modelListRelationships(model, { from: id }));
    }
    if (direction !== QUERY_DIRECTIONS.OUT) {
      edges.push(...modelListRelationships(model, { to: id }));
    }
    const filtered =
      relationshipTypes.length === 0
        ? edges
        : edges.filter((relationship) => relationshipTypes.includes(relationship.type));
    return uniqueSortedRelationships(filtered);
  };

  // ── Dependency graph (Phase 14) ───────────────────────────────────────────
  //
  // Read from `model.dependencies.graph` — a projection the builder already built
  // and validated — and never recomputed here, so a query answer cannot disagree
  // with the model. Adjacency is indexed once per handle (the model is frozen, so
  // the index cannot go stale) and both indexes keep the graph's own edge order,
  // which is the deterministic `(from, to, type)` order.
  const dependencyGraph =
    model.dependencies?.graph ??
    Object.freeze({
      nodes: Object.freeze([]),
      edges: Object.freeze([]),
      state: DEPENDENCY_GRAPH_STATES.UNKNOWN,
      established: false,
      coverage: Object.freeze({
        state: DEPENDENCY_GRAPH_STATES.UNKNOWN,
        established: false,
        inspected: false,
        complete: false,
        truncated: false,
        nodes: 0,
        edges: 0,
        declarations: 0,
        resolved: 0,
        unestablishedSources: Object.freeze([]),
        versionInstances: Object.freeze({
          ambiguous: false,
          count: 0,
          packages: Object.freeze([]),
        }),
        limits: Object.freeze({}),
      }),
    });

  const graphNodeById = new Map(dependencyGraph.nodes.map((node) => [node.id, node]));
  const outgoingEdgesByNode = new Map();
  const incomingEdgesByNode = new Map();
  for (const edge of dependencyGraph.edges) {
    const out = outgoingEdgesByNode.get(edge.from);
    if (out === undefined) outgoingEdgesByNode.set(edge.from, [edge]);
    else out.push(edge);

    const incoming = incomingEdgesByNode.get(edge.to);
    if (incoming === undefined) incomingEdgesByNode.set(edge.to, [edge]);
    else incoming.push(edge);
  }

  /** Freeze a fresh list of entries, so nothing a query returns can be mutated. */
  const frozenEntries = (entries) => {
    for (const entry of entries) Object.freeze(entry);
    return Object.freeze(entries);
  };

  /**
   * The scan's guarantee plus the graph's own truncation.
   *
   * Kept apart from the graph's `state`: `coverage`/`truncated` say how much of the
   * *repository* was inventoried, `state` says whether a dependency graph was
   * established at all and how completely.
   */
  const graphCoverageState = () => ({
    coverage:
      model.scan.complete === true && model.scan.truncated !== true
        ? COVERAGE_GUARANTEES.COMPLETE
        : COVERAGE_GUARANTEES.PARTIAL,
    truncated: model.scan.truncated === true || dependencyGraph.coverage.truncated === true,
  });

  const compareGraphNodes = (a, b) => {
    if (a.depth !== b.depth) return a.depth - b.depth;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  };

  const compareGraphEdges = (a, b) => {
    if (a.from !== b.from) return a.from < b.from ? -1 : 1;
    if (a.to !== b.to) return a.to < b.to ? -1 : 1;
    return a.type < b.type ? -1 : a.type > b.type ? 1 : 0;
  };

  /** Build and validate a bounded graph traversal result. */
  const graphTraversalResult = (nodes, edges, limited) => {
    const result = createDependencyTraversalResult({
      nodes: frozenEntries(nodes),
      edges: frozenEntries(edges),
      ...graphCoverageState(),
      state: dependencyGraph.state,
      established: dependencyGraph.established,
      limited,
    });
    validateDependencyTraversalResult(result);
    return Object.freeze(result);
  };

  /** Parse the shared traversal limits. */
  const parseGraphTraversalOptions = (options, defaultDepth) => {
    requireKeys(options, GRAPH_TRAVERSAL_OPTION_KEYS, "traversalOptions");
    return {
      maxDepth: requireLimit(options.maxDepth ?? defaultDepth, {
        field: "maxDepth",
        min: 0,
        max: QUERY_LIMITS.MAX_DEPTH,
      }),
      maxResults: requireLimit(options.maxResults ?? QUERY_LIMITS.DEFAULT_RESULTS, {
        field: "maxResults",
        min: 1,
        max: QUERY_LIMITS.MAX_RESULTS,
      }),
    };
  };

  /**
   * Bounded, cycle-safe traversal over `depends-on` edges only.
   *
   * The declaration (`declares-dependency`) and resolution (`resolved-by`) edges are
   * deliberately *not* traversed: they mean "a manifest stated this" and "a lockfile
   * pinned this", not "this package needs that one", and mixing them into a walk
   * would make a dependency path that the repository never stated.
   */
  const traverseGraph = (id, direction, maxDepth, maxResults) => {
    const start = typeof id === "string" && graphNodeById.has(id) ? id : null;
    const visited = new Set(start === null ? [] : [start]);
    const reached = [];
    const collected = new Map();
    let limited = false;
    let frontier = start === null ? [] : [{ id: start, depth: 0 }];

    while (frontier.length > 0) {
      const next = [];
      for (const node of frontier) {
        if (node.depth >= maxDepth) continue;
        const edges =
          direction === QUERY_DIRECTIONS.IN
            ? (incomingEdgesByNode.get(node.id) ?? [])
            : (outgoingEdgesByNode.get(node.id) ?? []);
        for (const edge of edges) {
          const targetId = direction === QUERY_DIRECTIONS.IN ? edge.from : edge.to;
          const summary = graphNodeById.get(targetId);
          if (summary === undefined) continue;

          if (!visited.has(targetId)) {
            visited.add(targetId);
            if (reached.length >= maxResults) {
              limited = true;
            } else {
              reached.push({ ...summary, depth: node.depth + 1 });
              next.push({ id: targetId, depth: node.depth + 1 });
            }
          }

          const key = edgeKey(edge);
          if (collected.has(key)) continue;
          if (collected.size >= maxResults) {
            limited = true;
            continue;
          }
          collected.set(key, edge);
        }
      }
      frontier = next;
    }

    return graphTraversalResult(
      [...reached].sort(compareGraphNodes),
      [...collected.values()].sort(compareGraphEdges),
      limited,
    );
  };

  // ── Architecture graph (Phase 15) ─────────────────────────────────────────
  //
  // Read from `model.architecture.graph` — a projection the builder already built
  // and validated — and never recomputed here, so a query answer cannot disagree
  // with the model. Adjacency is indexed once per handle (the model is frozen, so the
  // index cannot go stale) and every index keeps the graph's own edge order, which is
  // the deterministic `(from, to, type)` order.
  const architectureGraph =
    model.architecture?.graph ??
    Object.freeze({
      nodes: Object.freeze([]),
      edges: Object.freeze([]),
      buildContexts: Object.freeze([]),
      state: ARCHITECTURE_GRAPH_STATES.UNKNOWN,
      established: false,
      coverage: Object.freeze({
        state: ARCHITECTURE_GRAPH_STATES.UNKNOWN,
        established: false,
        complete: false,
        truncated: false,
        nodes: 0,
        edges: 0,
        buildContexts: 0,
        unestablishedSources: Object.freeze([]),
        limits: Object.freeze({}),
      }),
    });

  const architectureNodeById = new Map(architectureGraph.nodes.map((node) => [node.id, node]));
  const architectureOutgoing = new Map();
  const architectureIncoming = new Map();
  const containmentParentByChild = new Map();
  const containmentChildrenByParent = new Map();

  for (const edge of architectureGraph.edges) {
    const out = architectureOutgoing.get(edge.from);
    if (out === undefined) architectureOutgoing.set(edge.from, [edge]);
    else out.push(edge);

    const incoming = architectureIncoming.get(edge.to);
    if (incoming === undefined) architectureIncoming.set(edge.to, [edge]);
    else incoming.push(edge);

    if (edge.type !== ARCHITECTURE_EDGE_TYPES.CONTAINS) continue;
    if (!containmentParentByChild.has(edge.to)) containmentParentByChild.set(edge.to, edge.from);
    const children = containmentChildrenByParent.get(edge.from);
    if (children === undefined) containmentChildrenByParent.set(edge.from, [edge]);
    else children.push(edge);
  }

  /** Containers that directly hold an observed manifest — the graph's components. */
  const containersHoldingManifests = new Set();
  for (const edge of architectureGraph.edges) {
    if (edge.type === ARCHITECTURE_EDGE_TYPES.CONTAINS && architectureNodeById.get(edge.to)?.kind === "manifest") {
      containersHoldingManifests.add(edge.from);
    }
  }

  const repositoryNode =
    architectureGraph.nodes.find((node) => node.kind === REPOSITORY_NODE_KIND) ?? null;
  const repositoryNodeIdOf = () => repositoryNode?.id ?? null;
  const containmentParentOf = (id) => containmentParentByChild.get(id) ?? null;

  /** The scan's guarantee plus this graph's own truncation. */
  const architectureCoverageState = () => ({
    coverage:
      model.scan.complete === true && model.scan.truncated !== true
        ? COVERAGE_GUARANTEES.COMPLETE
        : COVERAGE_GUARANTEES.PARTIAL,
    truncated: model.scan.truncated === true || architectureGraph.coverage.truncated === true,
  });

  const compareArchitectureNodes = (a, b) => {
    if (a.depth !== b.depth) return a.depth - b.depth;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  };

  const compareArchitectureEdges = (a, b) => {
    if (a.from !== b.from) return a.from < b.from ? -1 : 1;
    if (a.to !== b.to) return a.to < b.to ? -1 : 1;
    return a.type < b.type ? -1 : a.type > b.type ? 1 : 0;
  };

  /** Neighbours of a node in either direction, in the graph's own edge order. */
  const architectureStepsAt = (id) => {
    const steps = [];
    for (const edge of architectureOutgoing.get(id) ?? []) steps.push({ to: edge.to, edge });
    for (const edge of architectureIncoming.get(id) ?? []) steps.push({ to: edge.from, edge });
    return steps;
  };

  /**
   * Bounded, cycle-safe descent through `contains` edges.
   *
   * The start node is excluded from `nodes`, a node is entered at most once, and both
   * the frontier and the collected edges are bounded by `maxResults` — so a subtree
   * walk terminates on any input, including a hand-built graph with a containment cycle.
   */
  const descendArchitecture = (id, maxDepth, maxResults) => {
    const start = typeof id === "string" && architectureNodeById.has(id) ? id : null;
    const visited = new Set(start === null ? [] : [start]);
    const nodes = [];
    const edges = [];
    const seenEdges = new Set();
    let limited = false;
    let frontier = start === null ? [] : [{ id: start, depth: 0 }];

    while (frontier.length > 0) {
      const next = [];
      for (const current of frontier) {
        if (current.depth >= maxDepth) continue;
        for (const edge of containmentChildrenByParent.get(current.id) ?? []) {
          const summary = architectureNodeById.get(edge.to);
          if (summary === undefined) continue;

          if (!visited.has(edge.to)) {
            visited.add(edge.to);
            if (nodes.length >= maxResults) {
              limited = true;
            } else {
              nodes.push({ ...summary, depth: current.depth + 1 });
              next.push({ id: edge.to, depth: current.depth + 1 });
            }
          }

          const key = `${edge.from}\u0000${edge.to}\u0000${edge.type}`;
          if (seenEdges.has(key)) continue;
          if (edges.length >= maxResults) {
            limited = true;
            continue;
          }
          seenEdges.add(key);
          edges.push(edge);
        }
      }
      frontier = next;
    }

    return {
      nodes: [...nodes].sort(compareArchitectureNodes),
      edges: [...edges].sort(compareArchitectureEdges),
      limited,
    };
  };

  // ── Import graph (Phase 16) ───────────────────────────────────────────────
  //
  // Read from `model.imports.graph` — a projection the builder already built and
  // validated — and never recomputed here, so an answer cannot disagree with the
  // model. Adjacency is indexed once per handle (the model is frozen, so the index
  // cannot go stale) and both indexes keep the graph's own `(from, to, type)` order.
  const importGraph =
    model.imports?.graph ??
    Object.freeze({
      nodes: Object.freeze([]),
      edges: Object.freeze([]),
      unresolved: Object.freeze([]),
      state: IMPORT_GRAPH_STATES.UNKNOWN,
      established: false,
      coverage: Object.freeze({
        state: IMPORT_GRAPH_STATES.UNKNOWN,
        established: false,
        complete: false,
        truncated: false,
        inspected: false,
        nodes: 0,
        edges: 0,
        sources: 0,
        moduleFiles: 0,
        parsed: 0,
        unsupported: 0,
        failed: 0,
        notInspected: 0,
        references: 0,
        resolved: 0,
        unresolved: 0,
        unresolvedReported: 0,
        unresolvedByReason: Object.freeze({}),
        nonStatic: 0,
        unestablishedSources: Object.freeze([]),
        edgesTruncated: false,
        unresolvedTruncated: false,
        specifiersTruncated: false,
        limits: Object.freeze({}),
      }),
    });

  const importNodeById = new Map(importGraph.nodes.map((node) => [node.id, node]));
  const importOutgoing = new Map();
  const importIncoming = new Map();
  for (const edge of importGraph.edges) {
    const out = importOutgoing.get(edge.from);
    if (out === undefined) importOutgoing.set(edge.from, [edge]);
    else out.push(edge);

    const incoming = importIncoming.get(edge.to);
    if (incoming === undefined) importIncoming.set(edge.to, [edge]);
    else incoming.push(edge);
  }

  /** The scan's guarantee plus the import graph's own truncation. */
  const importCoverageState = () => ({
    coverage:
      model.scan.complete === true && model.scan.truncated !== true
        ? COVERAGE_GUARANTEES.COMPLETE
        : COVERAGE_GUARANTEES.PARTIAL,
    truncated: model.scan.truncated === true || importGraph.coverage.truncated === true,
  });

  const compareImportNodes = (a, b) => {
    if (a.depth !== b.depth) return a.depth - b.depth;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  };

  /**
   * Bounded, cycle-safe traversal over `imports` edges in one direction.
   *
   * Only `imports` edges are traversed — the graph states no other relation, and a
   * walk that invented one would answer a question the repository never asked. A
   * node is entered at most once, both the frontier and the collected edges are
   * bounded by `maxResults`, and the start node is excluded from `nodes` unless a
   * cycle reaches it, so a cyclic import graph terminates on any input.
   */
  const traverseImports = (id, direction, maxDepth, maxResults) => {
    const start = typeof id === "string" && importNodeById.has(id) ? id : null;
    const visited = new Set(start === null ? [] : [start]);
    const reached = [];
    const collected = new Map();
    let limited = false;
    let frontier = start === null ? [] : [{ id: start, depth: 0 }];

    while (frontier.length > 0) {
      const next = [];
      for (const node of frontier) {
        if (node.depth >= maxDepth) continue;
        const edges =
          direction === QUERY_DIRECTIONS.IN
            ? (importIncoming.get(node.id) ?? [])
            : (importOutgoing.get(node.id) ?? []);
        for (const edge of edges) {
          const targetId = direction === QUERY_DIRECTIONS.IN ? edge.from : edge.to;
          const summary = importNodeById.get(targetId);
          if (summary === undefined) continue;

          if (!visited.has(targetId)) {
            visited.add(targetId);
            if (reached.length >= maxResults) {
              limited = true;
            } else {
              reached.push({ ...summary, depth: node.depth + 1 });
              next.push({ id: targetId, depth: node.depth + 1 });
            }
          }

          const key = edgeKey(edge);
          if (collected.has(key)) continue;
          if (collected.size >= maxResults) {
            limited = true;
            continue;
          }
          collected.set(key, edge);
        }
      }
      frontier = next;
    }

    return {
      nodes: [...reached].sort(compareImportNodes),
      edges: [...collected.values()].sort(compareGraphEdges),
      limited,
    };
  };

  // ── Symbol graph (Phase 17) ────────────────────────────────────────────────
  //
  // Read from `model.symbols.graph` — a projection the builder already built and
  // validated — and never recomputed here, so an answer cannot disagree with the
  // model. The graph is deeply frozen, so the adjacency indexes built once per handle
  // cannot go stale, and each keeps the graph's own `(from, to, type)` order.
  const symbolGraph =
    model.symbols?.graph ??
    Object.freeze({
      nodes: Object.freeze([]),
      edges: Object.freeze([]),
      unresolved: Object.freeze([]),
      state: SYMBOL_GRAPH_STATES.UNKNOWN,
      established: false,
      coverage: Object.freeze({
        state: SYMBOL_GRAPH_STATES.UNKNOWN,
        established: false,
        complete: false,
        truncated: false,
        inspected: false,
        symbols: 0,
        edges: 0,
        sources: 0,
        moduleFiles: 0,
        declaredSymbols: 0,
        exportedSymbols: 0,
        referenceEdges: 0,
        callEdges: 0,
        bindingEdges: 0,
        parsed: 0,
        unsupported: 0,
        failed: 0,
        notInspected: 0,
        uninterpretedSources: 0,
        uninterpretedExtensions: Object.freeze([]),
        uninterpretedExtensionsTruncated: false,
        references: 0,
        unresolved: 0,
        unresolvedReported: 0,
        unresolvedByReason: Object.freeze({}),
        shadowedSymbols: 0,
        unestablished: 0,
        unestablishedSources: Object.freeze([]),
        nodesTruncated: false,
        edgesTruncated: false,
        unresolvedTruncated: false,
        limits: Object.freeze({}),
      }),
    });

  const symbolNodeById = new Map(symbolGraph.nodes.map((node) => [node.id, node]));
  const symbolOutgoing = new Map();
  const symbolIncoming = new Map();
  for (const edge of symbolGraph.edges) {
    const out = symbolOutgoing.get(edge.from);
    if (out === undefined) symbolOutgoing.set(edge.from, [edge]);
    else out.push(edge);

    const incoming = symbolIncoming.get(edge.to);
    if (incoming === undefined) symbolIncoming.set(edge.to, [edge]);
    else incoming.push(edge);
  }

  /**
   * The guarantee behind a symbol answer.
   *
   * `complete` is claimed only when the *semantic* graph is complete as well as the scan:
   * a scan that covered every file still leaves a symbol graph partial when a module
   * source was unsupported or an establishment claim could not be made, and a caller
   * reading `coverage: "complete"` next to `state: "partial"` would be told two
   * contradictory things. The stricter of the two facts wins.
   */
  const symbolCoverageState = () => ({
    coverage:
      model.scan.complete === true &&
      model.scan.truncated !== true &&
      symbolGraph.state === SYMBOL_GRAPH_STATES.COMPLETE
        ? COVERAGE_GUARANTEES.COMPLETE
        : COVERAGE_GUARANTEES.PARTIAL,
    truncated: model.scan.truncated === true || symbolGraph.coverage.truncated === true,
  });

  /**
   * The file entity id an argument names.
   *
   * A symbol edge's `from` is always a file entity id, and symbol ids start with
   * `symbol:`, so a bare repository-relative path (`src/a.js`) is read as the file
   * entity id it names (`file:src/a.js`) and an id is passed through unchanged. Both
   * spellings are accepted because both are already projected upstream; nothing is
   * resolved here.
   */
  const fileEntityIdOf = (id) =>
    typeof id === "string" && !id.startsWith("file:") ? `file:${id}` : id;

  /** The repository-relative path a file entity id names. */
  const filePathOfEntityId = (id) => (typeof id === "string" && id.startsWith("file:") ? id.slice(5) : null);

  /** The symbols a file declares, sorted by id. */
  const symbolsOfFile = (fileId) =>
    symbolGraph.nodes.filter((node) => node.fileId === fileId).sort(compareById);

  /** Edges of one type stated by an id, sorted, plus whether a bound cut them. */
  const edgesOfType = (id, type, maxResults) => {
    const matching = (symbolOutgoing.get(id) ?? []).filter((edge) => edge.type === type);
    return {
      edges: matching.slice(0, maxResults),
      limited: matching.length > maxResults,
    };
  };

  // ── API & Service graph (Phase 18) ────────────────────────────────────────
  //
  // Read from `model.api.graph` — a projection the builder already built and validated
  // — and never recomputed here. Handler and middleware edges point at Phase 17 symbol
  // nodes, which are looked up in the symbol graph above rather than duplicated, so a
  // route's handler and the symbol's own view of itself can never disagree.
  const apiGraph =
    model.api?.graph ??
    Object.freeze({
      nodes: Object.freeze([]),
      edges: Object.freeze([]),
      unresolved: Object.freeze([]),
      state: API_GRAPH_STATES.UNKNOWN,
      established: false,
      coverage: Object.freeze({
        state: API_GRAPH_STATES.UNKNOWN,
        established: false,
        complete: false,
        truncated: false,
        inspected: false,
        routes: 0,
        edges: 0,
        sources: 0,
        declaringModules: 0,
        handlerEdges: 0,
        middlewareEdges: 0,
        declareEdges: 0,
        handlerModules: 0,
        parsed: 0,
        unsupported: 0,
        failed: 0,
        notInspected: 0,
        uninterpretedSources: 0,
        uninterpretedExtensions: Object.freeze([]),
        uninterpretedExtensionsTruncated: false,
        unresolved: 0,
        unresolvedReported: 0,
        unresolvedByReason: Object.freeze({}),
        unestablished: 0,
        unestablishedSources: Object.freeze([]),
        nodesTruncated: false,
        edgesTruncated: false,
        unresolvedTruncated: false,
        limits: Object.freeze({}),
      }),
    });

  const apiNodeById = new Map(apiGraph.nodes.map((node) => [node.id, node]));
  const apiOutgoing = new Map();
  const apiIncoming = new Map();
  for (const edge of apiGraph.edges) {
    const out = apiOutgoing.get(edge.from);
    if (out === undefined) apiOutgoing.set(edge.from, [edge]);
    else out.push(edge);

    const incoming = apiIncoming.get(edge.to);
    if (incoming === undefined) apiIncoming.set(edge.to, [edge]);
    else incoming.push(edge);
  }

  /**
   * The guarantee behind an API answer.
   *
   * `complete` is claimed only when the API graph is complete as well as the scan — the
   * stricter of the two facts wins, so a caller is never told `complete` next to a
   * `partial` state.
   */
  const apiCoverageState = () => ({
    coverage:
      model.scan.complete === true &&
      model.scan.truncated !== true &&
      apiGraph.state === API_GRAPH_STATES.COMPLETE
        ? COVERAGE_GUARANTEES.COMPLETE
        : COVERAGE_GUARANTEES.PARTIAL,
    truncated: model.scan.truncated === true || apiGraph.coverage.truncated === true,
  });

  /** The identity of an endpoint, reused from the projection so the two can never disagree. */
  const apiRouteIdOf = (method, path) => `route:${method}:${path}`;

  /** The symbol node behind a `handled-by` / `middleware` endpoint, or `null`. */
  const symbolDetailOf = (edge) =>
    edge === null ? null : { edge: { ...edge }, symbol: symbolNodeById.get(edge.to) ?? null };

  const query = {
    /**
     * Every entity of a kind, sorted by id.
     * @throws {RepositoryQueryError} kind `invalid-entity-kind`.
     */
    listEntities(kind) {
      requireEntityKind(kind);
      return entityResult(listEntitiesByKind(model, kind));
    },

    /** An entity by id, or `null`. Unknown ids are ordinary misses, not errors. */
    getEntity(id) {
      return modelGetEntity(model, id);
    },

    /**
     * Entities matching every supplied criterion (AND).
     *
     * Criteria:
     *   kind       entity kind
     *   path       exact repository-relative path
     *   language   language id — files carrying it, the language entity, and
     *              manifests that declare it
     *   ecosystem  ecosystem id — manifests in it, and the ecosystem entity
     *   framework  framework name — the framework entity, and tests using it
     *
     * @throws {RepositoryQueryError} kind `invalid-query` / `invalid-entity-kind`.
     */
    findEntities(criteria = {}) {
      requireKeys(criteria, CRITERIA_KEYS, "criteria");
      if ("kind" in criteria) requireEntityKind(criteria.kind);
      if ("path" in criteria) {
        if (typeof criteria.path !== "string" || !isRepositoryRelativePath(criteria.path)) {
          throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, { field: "criteria.path" });
        }
      }
      for (const key of ["language", "ecosystem", "framework"]) {
        if (key in criteria && (typeof criteria[key] !== "string" || criteria[key].trim() === "")) {
          throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, {
            field: `criteria.${key}`,
          });
        }
      }

      const matches = (entity) => {
        if ("kind" in criteria && entity.kind !== criteria.kind) return false;
        if ("path" in criteria && entity.path !== criteria.path) return false;
        if ("language" in criteria && !matchesLanguage(entity, criteria.language)) return false;
        if ("ecosystem" in criteria && !matchesEcosystem(entity, criteria.ecosystem)) return false;
        if ("framework" in criteria && !matchesFramework(entity, criteria.framework)) return false;
        return true;
      };

      return entityResult(allEntities().filter(matches));
    },

    /**
     * Relationships matching a `{ from, to, type }` filter, sorted.
     * @throws {RepositoryQueryError} kind `invalid-query` / `invalid-relationship-type`.
     */
    listRelationships(filter = {}) {
      requireKeys(filter, RESOLUTION_FILTER_KEYS, "relationshipFilter");
      if ("type" in filter) requireRelationshipType(filter.type);
      for (const endpoint of ["from", "to"]) {
        if (endpoint in filter && typeof filter[endpoint] !== "string") {
          throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, {
            field: `relationshipFilter.${endpoint}`,
          });
        }
      }
      return relationshipResult(modelListRelationships(model, filter));
    },

    /**
     * Relationships touching an entity, optionally in one direction and of one
     * type. An unknown entity or non-string id has no relationships (not an error).
     *
     * @param {string} id
     * @param {object} [options] `{ direction?, type? }`
     */
    getRelationshipsForEntity(id, options = {}) {
      requireKeys(options, ["direction", "type"], "relationshipOptions");
      const direction = options.direction ?? QUERY_DIRECTIONS.BOTH;
      requireDirection(direction);
      if ("type" in options) requireRelationshipType(options.type);

      if (typeof id !== "string") return relationshipResult([]);
      const edges = edgesAt(id, direction, "type" in options ? [options.type] : []);
      return relationshipResult(edges);
    },

    /**
     * Bounded, cycle-safe traversal from an entity.
     *
     * @param {string} id Starting entity id.
     * @param {string|object} [typeOrOptions] A relationship type, or
     *   `{ direction?, type?, relationshipTypes?, maxDepth?, maxResults? }`.
     * @returns {object} `{ entities, relationships, coverage, truncated, limited }`
     *   — `entities` are the entities reached within `maxDepth` hops (the start is
     *   excluded unless a cycle reaches it), `limited` is `true` when a limit cut
     *   the result short.
     * @throws {RepositoryQueryError} for an invalid direction, type or limit.
     */
    findRelatedEntities(id, typeOrOptions = {}) {
      const options =
        typeof typeOrOptions === "string" ? { type: typeOrOptions } : typeOrOptions;
      requireKeys(options, TRAVERSAL_OPTION_KEYS, "traversalOptions");

      const direction = options.direction ?? QUERY_DIRECTIONS.OUT;
      requireDirection(direction);

      const relationshipTypes = [];
      if ("type" in options) {
        requireRelationshipType(options.type);
        relationshipTypes.push(options.type);
      }
      if ("relationshipTypes" in options) {
        if (!Array.isArray(options.relationshipTypes)) {
          throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, {
            field: "traversalOptions.relationshipTypes",
          });
        }
        for (const type of options.relationshipTypes) {
          requireRelationshipType(type);
          if (!relationshipTypes.includes(type)) relationshipTypes.push(type);
        }
      }

      const maxDepth = requireLimit(options.maxDepth ?? QUERY_LIMITS.DEFAULT_DEPTH, {
        field: "maxDepth",
        min: 0,
        max: QUERY_LIMITS.MAX_DEPTH,
      });
      const maxResults = requireLimit(options.maxResults ?? QUERY_LIMITS.DEFAULT_RESULTS, {
        field: "maxResults",
        min: 1,
        max: QUERY_LIMITS.MAX_RESULTS,
      });

      const reached = new Map();
      const collected = new Map();
      let limited = false;

      const start = typeof id === "string" ? id : null;
      const visited = new Set(start === null ? [] : [start]);
      let frontier = start === null ? [] : [{ id: start, depth: 0 }];

      while (frontier.length > 0) {
        const next = [];
        for (const node of frontier) {
          if (node.depth >= maxDepth) continue;
          for (const relationship of edgesAt(node.id, direction, relationshipTypes)) {
            const targetId =
              direction === QUERY_DIRECTIONS.OUT
                ? relationship.to
                : direction === QUERY_DIRECTIONS.IN
                  ? relationship.from
                  : relationship.from === node.id
                    ? relationship.to
                    : relationship.from;

            // Only entities are returned: the repository node is an endpoint too,
            // and a relationship must never resolve to something the model does not
            // contain.
            if (modelGetEntity(model, targetId) === null) continue;

            if (!visited.has(targetId)) {
              visited.add(targetId);
              if (reached.size >= maxResults) {
                limited = true;
                continue;
              }
              reached.set(targetId, modelGetEntity(model, targetId));
              next.push({ id: targetId, depth: node.depth + 1 });
            }

            const key = edgeKey(relationship);
            if (collected.has(key)) continue;
            if (collected.size >= maxResults) {
              limited = true;
              continue;
            }
            collected.set(key, relationship);
          }
        }
        frontier = next;
      }

      const result = createTraversalResult({
        entities: [...reached.values()].sort(compareById),
        relationships: [...collected.values()].sort(compareRelationships),
        ...coverageState(model),
        limited,
      });
      validateTraversalResult(result);
      Object.freeze(result.entities);
      Object.freeze(result.relationships);
      return Object.freeze(result);
    },

    /**
     * Evidence supporting an entity, sorted by id.
     *
     * Returns the model's own Evidence records — never fabricated, renamed or
     * re-provenanced. A record whose id does not resolve inside the model, or whose
     * location is not repository-relative, is dropped rather than surfaced.
     */
    getEvidenceForEntity(id) {
      const entity = modelGetEntity(model, id);
      if (entity === null) return evidenceResult([]);
      const records = [];
      for (const evidenceId of entity.evidenceIds ?? []) {
        const record = modelGetEvidence(model, evidenceId);
        if (record === null) continue;
        if (!isRepositoryRelativePath(record.location?.path)) continue;
        records.push(record);
      }
      return evidenceResult(records);
    },

    // ── Dependency questions (Phase 13) ─────────────────────────────────────
    /**
     * Every dependency entity, sorted by id.
     *
     * A dependency is identified by `(ecosystem, name)`, so a package declared by
     * three manifests is one entity carrying three declarations — the query surface
     * never merges or picks between them.
     */
    listDependencies() {
      return entityResult(modelListDependencies(model));
    },

    /** A dependency entity by id, or `null`. Unknown ids are ordinary misses. */
    getDependency(id) {
      return modelGetEntity(model, id);
    },

    /**
     * The dependency entity for a package name in an ecosystem, or `null`.
     * The name must be the normalized form (lower-case npm/PEP 503 identity).
     */
    getDependencyByName(ecosystem, name) {
      return modelGetDependencyByName(model, ecosystem, name);
    },

    /** Dependencies in an ecosystem, sorted by id. */
    dependenciesByEcosystem(ecosystemId) {
      return entityResult(listDependenciesByEcosystem(model, ecosystemId));
    },

    /**
     * Dependency entities matching every supplied criterion (AND).
     *
     *   ecosystem  the ecosystem id (`node`, `python`, `go`)
     *   name       the normalized package name
     *   manifest   a manifest **id** — dependencies that manifest declared or resolved
     *   scope      a scope the dependency was declared with
     *   direct     whether a manifest declared it directly
     *   declared   whether any manifest declared it at all
     *   resolved   whether any lockfile resolved it
     *
     * @throws {RepositoryQueryError} kind `invalid-query`.
     */
    findDependencies(criteria = {}) {
      requireKeys(criteria, DEPENDENCY_CRITERIA_KEYS, "dependencyCriteria");
      if ("ecosystem" in criteria && !isNonEmptyQueryString(criteria.ecosystem)) {
        throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, {
          field: "dependencyCriteria.ecosystem",
        });
      }
      if ("name" in criteria && !isNonEmptyQueryString(criteria.name)) {
        throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, {
          field: "dependencyCriteria.name",
        });
      }
      if ("manifest" in criteria && !isNonEmptyQueryString(criteria.manifest)) {
        throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, {
          field: "dependencyCriteria.manifest",
        });
      }
      if ("scope" in criteria && !isNonEmptyQueryString(criteria.scope)) {
        throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, {
          field: "dependencyCriteria.scope",
        });
      }
      for (const flag of ["direct", "declared", "resolved"]) {
        if (flag in criteria && typeof criteria[flag] !== "boolean") {
          throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, {
            field: `dependencyCriteria.${flag}`,
          });
        }
      }

      const matches = (dependency) => {
        if (dependency.kind !== ENTITY_KINDS.DEPENDENCY) return false;
        if ("ecosystem" in criteria && dependency.ecosystem !== criteria.ecosystem) return false;
        if ("name" in criteria && dependency.name !== criteria.name) return false;
        if ("manifest" in criteria && !dependencyManifestIds(dependency).includes(criteria.manifest)) {
          return false;
        }
        if ("scope" in criteria && !(dependency.scopes ?? []).includes(criteria.scope)) {
          return false;
        }
        for (const flag of ["direct", "declared", "resolved"]) {
          if (flag in criteria && dependency[flag] !== criteria[flag]) return false;
        }
        return true;
      };

      return entityResult(modelListDependencies(model).filter(matches));
    },

    /** The dependency facts one manifest stated, in id order. */
    dependenciesForManifest(manifestId) {
      if (typeof manifestId !== "string") return entityResult([]);
      return entityResult(
        modelListDependencies(model).filter((dependency) =>
          dependencyManifestIds(dependency).includes(manifestId),
        ),
      );
    },

    /** The manifests that declared or resolved a dependency, in id order. */
    manifestsForDependency(dependencyId) {
      const dependency = modelGetEntity(model, dependencyId);
      if (dependency === null || dependency.kind !== ENTITY_KINDS.DEPENDENCY) {
        return entityResult([]);
      }
      const manifests = dependencyManifestIds(dependency)
        .map((id) => modelGetEntity(model, id))
        .filter((entity) => entity !== null);
      return entityResult(manifests);
    },

    /**
     * The declaration records a dependency carries, one per manifest that declared
     * it, each with its own scope, spec and evidence ids.
     *
     * Returned as `{ declarations, coverage, truncated }` so a consumer cannot read
     * the list without also seeing whether the scan behind it was complete.
     */
    dependencyDeclarations(dependencyId) {
      const dependency = modelGetEntity(model, dependencyId);
      if (dependency === null || dependency.kind !== ENTITY_KINDS.DEPENDENCY) {
        return Object.freeze({
          declarations: Object.freeze([]),
          ...coverageState(model),
        });
      }
      const declarations = [...(dependency.declarations ?? [])].sort(
        compareByField("manifestPath"),
      );
      Object.freeze(declarations);
      return Object.freeze({ declarations, ...coverageState(model) });
    },

    /**
     * The dependency relationships at a dependency: what declared it, what it
     * depends on, and which lockfiles resolved it.
     */
    dependencyRelationships(dependencyId) {
      if (typeof dependencyId !== "string") return relationshipResult([]);
      const dependency = modelGetEntity(model, dependencyId);
      if (dependency === null || dependency.kind !== ENTITY_KINDS.DEPENDENCY) {
        return relationshipResult([]);
      }
      return relationshipResult(
        edgesAt(dependencyId, QUERY_DIRECTIONS.BOTH, DEPENDENCY_RELATIONSHIP_TYPES),
      );
    },

    /** Dependencies a manifest declared directly, sorted by id. */
    directDependencies() {
      return entityResult(
        modelListDependencies(model).filter((dependency) => dependency.direct === true),
      );
    },

    /**
     * Dependencies a lockfile resolved, sorted by id.
     *
     * Resolution is a lockfile's fact, not a claim of directness: a resolved
     * dependency may be one the repository declares or one it only reaches through
     * the graph.
     */
    resolvedDependencies() {
      return entityResult(
        modelListDependencies(model).filter((dependency) => dependency.resolved === true),
      );
    },

    /**
     * Dependencies the model can only see through a lockfile.
     *
     * `resolved && !direct` is the honest form of "transitive": the repository's
     * lockfile pins it, no manifest declares it. A dependency that a format itself
     * marks indirect (Go's `// indirect`) is included, because the format states it
     * is not a direct requirement.
     */
    transitiveDependencies() {
      return entityResult(
        modelListDependencies(model).filter(
          (dependency) => dependency.resolved === true && dependency.direct !== true,
        ),
      );
    },

    /**
     * What dependency acquisition established, and what it could not.
     *
     * `unestablishedSources` names every manifest whose dependency declarations were
     * not fully interpreted (an unsupported format, an unreadable file, a rejected
     * declaration), so a caller that wants to claim "this dependency does not
     * exist" can see exactly which files would have to be read to support it.
     */
    dependencyCoverage() {
      const coverage = model.dependencies.coverage ?? {};
      const unestablished = (model.dependencies.sources ?? [])
        .filter((source) => !isSourceEstablished(source))
        .map(unestablishedSourceRecord)
        .sort(compareByField("path"));

      return Object.freeze({
        detected: model.dependencies.detected === true,
        count: (model.dependencies.entries ?? []).length,
        inspected: coverage.inspected === true,
        complete: coverage.complete === true,
        truncated: coverage.truncated === true,
        declarations: Number.isInteger(coverage.declarations) ? coverage.declarations : 0,
        resolved: Number.isInteger(coverage.resolved) ? coverage.resolved : 0,
        edges: Number.isInteger(coverage.edges) ? coverage.edges : 0,
        unestablishedSources: Object.freeze(unestablished),
      });
    },

    // ── Dependency graph questions (Phase 14) ────────────────────────────────
    /**
     * The whole dependency graph the repository establishes.
     *
     * `nodes` are dependency entity ids (`dependency:<ecosystem>:<name>`) with the
     * declared/direct/resolved facts each carries — never derived from topology, so a
     * path of length one does not make a package "direct"; `edges` are the
     * `depends-on` relationships a supported lockfile stated, each with the
     * observations and lockfile paths that established it.
     *
     * `state`/`established` are the graph's own coverage answer, and they are the
     * reason this is not `edges: []`: an empty graph the repository establishes and a
     * graph that was never established are different facts. `coverage`/`truncated`
     * stay the scan's guarantee, exactly as on every other query result.
     *
     * Version instances are NOT distinguished — see
     * `dependencyGraphCoverage().versionInstances`, which names every package whose
     * resolution records disagree about the version.
     */
    dependencyGraph() {
      const result = createDependencyGraphResult({
        nodes: frozenEntries([...dependencyGraph.nodes]),
        edges: frozenEntries([...dependencyGraph.edges]),
        ...graphCoverageState(),
        state: dependencyGraph.state,
        established: dependencyGraph.established,
      });
      validateDependencyGraphResult(result);
      return Object.freeze(result);
    },

    /**
     * What the dependency graph does and does not establish.
     *
     * The graph's five-way state, the sources that stopped it being complete, and the
     * documented identity limitation, in one frozen statement.
     */
    dependencyGraphCoverage() {
      return Object.freeze({ ...dependencyGraph.coverage });
    },

    /**
     * Graph edges matching a `{ from, to, type }` filter, sorted and bounded.
     *
     * `type` accepts only the graph's edge vocabulary (today just `depends-on`), so a
     * caller cannot ask the graph for a declaration or resolution edge and receive a
     * dependency edge instead. `limited` is true when `maxResults` cut the list short.
     *
     * @throws {RepositoryQueryError} kind `invalid-query` / `invalid-relationship-type`.
     */
    dependencyEdges(criteria = {}) {
      requireKeys(criteria, DEPENDENCY_EDGE_FILTER_KEYS, "dependencyEdgeCriteria");
      if ("type" in criteria && !DEPENDENCY_GRAPH_EDGE_TYPE_VALUES.includes(criteria.type)) {
        throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_RELATIONSHIP_TYPE, {
          received: safeQueryToken(criteria.type),
        });
      }
      for (const endpoint of ["from", "to"]) {
        if (endpoint in criteria && typeof criteria[endpoint] !== "string") {
          throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, {
            field: `dependencyEdgeCriteria.${endpoint}`,
          });
        }
      }
      const maxResults = requireLimit(criteria.maxResults ?? QUERY_LIMITS.DEFAULT_RESULTS, {
        field: "maxResults",
        min: 1,
        max: QUERY_LIMITS.MAX_RESULTS,
      });

      const matching = dependencyGraph.edges.filter((edge) => {
        if ("from" in criteria && edge.from !== criteria.from) return false;
        if ("to" in criteria && edge.to !== criteria.to) return false;
        if ("type" in criteria && edge.type !== criteria.type) return false;
        return true;
      });

      const result = createDependencyEdgeQueryResult({
        edges: frozenEntries(matching.slice(0, maxResults)),
        ...graphCoverageState(),
        state: dependencyGraph.state,
        limited: matching.length > maxResults,
      });
      validateDependencyEdgeQueryResult(result);
      return Object.freeze(result);
    },

    /**
     * Dependencies the graph says an entity depends on — one hop by default.
     *
     * An unknown id is an ordinary miss (an empty result, not an error). Passing
     * `maxDepth` widens the walk; `dependencyDescendants` is the closure form.
     */
    dependenciesOf(id, options = {}) {
      const { maxDepth, maxResults } = parseGraphTraversalOptions(
        options,
        QUERY_LIMITS.DEFAULT_DEPTH,
      );
      return traverseGraph(id, QUERY_DIRECTIONS.OUT, maxDepth, maxResults);
    },

    /** Dependencies the graph says depend on an entity — one hop by default. */
    dependentsOf(id, options = {}) {
      const { maxDepth, maxResults } = parseGraphTraversalOptions(
        options,
        QUERY_LIMITS.DEFAULT_DEPTH,
      );
      return traverseGraph(id, QUERY_DIRECTIONS.IN, maxDepth, maxResults);
    },

    /**
     * Everything reachable from an entity by following `depends-on` edges.
     *
     * The default depth is the traversal ceiling (`QUERY_LIMITS.MAX_DEPTH`), so the
     * closure is complete within the bound; cycles terminate because a node is
     * entered at most once.
     */
    dependencyDescendants(id, options = {}) {
      const { maxDepth, maxResults } = parseGraphTraversalOptions(options, QUERY_LIMITS.MAX_DEPTH);
      return traverseGraph(id, QUERY_DIRECTIONS.OUT, maxDepth, maxResults);
    },

    /** Everything that reaches an entity by following `depends-on` edges backwards. */
    dependencyAncestors(id, options = {}) {
      const { maxDepth, maxResults } = parseGraphTraversalOptions(options, QUERY_LIMITS.MAX_DEPTH);
      return traverseGraph(id, QUERY_DIRECTIONS.IN, maxDepth, maxResults);
    },

    /**
     * A bounded path between two dependencies, following `depends-on` edges.
     *
     * Breadth-first, so the path returned is a shortest one, and `found: false` with
     * `limited: true` means the search stopped at a bound rather than proving the two
     * are disconnected. `nodes` are in path order (each carrying its `depth`) and
     * `edges` are the traversed graph edges, also in path order — deliberately not
     * sorted, because a path's order is its meaning.
     */
    dependencyPath(fromId, toId, options = {}) {
      const { maxDepth, maxResults } = parseGraphTraversalOptions(options, QUERY_LIMITS.MAX_DEPTH);

      const pathResult = (nodes, edges, found, limited) => {
        const result = createDependencyPathResult({
          nodes: frozenEntries(nodes),
          edges: frozenEntries(edges),
          found,
          ...graphCoverageState(),
          state: dependencyGraph.state,
          limited,
        });
        validateDependencyPathResult(result);
        return Object.freeze(result);
      };

      const startNode = typeof fromId === "string" ? graphNodeById.get(fromId) : undefined;
      const targetNode = typeof toId === "string" ? graphNodeById.get(toId) : undefined;
      if (startNode === undefined || targetNode === undefined) {
        return pathResult([], [], false, false);
      }
      if (fromId === toId) {
        // A node is trivially reachable from itself; reporting that as a path with
        // edges would invent a relationship the repository never stated.
        return pathResult([{ ...startNode, depth: 0 }], [], true, false);
      }

      const predecessor = new Map([[fromId, null]]);
      let frontier = [fromId];
      let found = false;
      let limited = false;
      let depth = 0;

      while (frontier.length > 0 && !found && depth < maxDepth) {
        const next = [];
        for (const id of frontier) {
          for (const edge of outgoingEdgesByNode.get(id) ?? []) {
            if (predecessor.has(edge.to)) continue;
            if (predecessor.size >= maxResults) {
              limited = true;
              continue;
            }
            predecessor.set(edge.to, { via: id, edge });
            if (edge.to === toId) {
              found = true;
              break;
            }
            next.push(edge.to);
          }
          if (found) break;
        }
        frontier = found ? [] : next;
        depth += 1;
      }

      if (!found) return pathResult([], [], false, limited);

      const nodeChain = [];
      const edgeChain = [];
      let cursor = toId;
      while (typeof cursor === "string") {
        nodeChain.push(cursor);
        const step = predecessor.get(cursor);
        if (step === undefined || step === null) break;
        edgeChain.push(step.edge);
        cursor = step.via;
      }
      nodeChain.reverse();
      edgeChain.reverse();

      return pathResult(
        nodeChain.map((id, index) => ({ ...graphNodeById.get(id), depth: index })),
        edgeChain,
        true,
        limited,
      );
    },

    // ── Architecture questions (Phase 15) ───────────────────────────────────
    /**
     * The whole architecture graph the repository establishes.
     *
     * `nodes` are existing entity ids (plus the repository node) with their kind and
     * path; `edges` are the architectural relationships the model already states,
     * each with the observations that established it and the repository-relative
     * paths whose observations stated it. Nothing is derived from topology here: an
     * edge means exactly what its type says and nothing more.
     *
     * **What is deliberately not in this graph.** There is no import edge, no call
     * edge and no "file A is tested by file B" edge — establishing those needs an
     * AST, a symbol table or a runner's own report, and this architecture has none of
     * them. The same applies to CI workflows: the model records that a workflow
     * exists and for which provider, never what it references, so a workflow cannot be
     * connected to a file without inventing the connection.
     *
     * `state`/`established` are the graph's own coverage answer, which is why this is
     * not `edges: []`: an architecture the repository establishes — including one with
     * no container wiring — and an architecture that was never established are
     * different facts.
     */
    architectureGraph() {
      const result = createArchitectureGraphResult({
        nodes: frozenEntries([...architectureGraph.nodes]),
        edges: frozenEntries([...architectureGraph.edges]),
        ...architectureCoverageState(),
        state: architectureGraph.state,
        established: architectureGraph.established,
      });
      validateArchitectureGraphResult(result);
      return Object.freeze(result);
    },

    /**
     * What the architecture graph does and does not establish.
     *
     * The graph's four-way state, the Compose files whose build declarations could
     * not be established, and the container build wiring the model observed in one
     * frozen statement.
     */
    architectureCoverage() {
      return Object.freeze({ ...architectureGraph.coverage });
    },

    /**
     * Architecture edges matching a `{ from, to, type }` filter, sorted and bounded.
     *
     * `type` accepts only the graph's own edge vocabulary, so a caller cannot ask the
     * architecture graph for an import or call edge and receive a containment edge
     * instead. `limited` is true when `maxResults` cut the list short.
     *
     * @throws {RepositoryQueryError} kind `invalid-query` / `invalid-relationship-type`.
     */
    architectureEdges(criteria = {}) {
      requireKeys(criteria, ARCHITECTURE_EDGE_FILTER_KEYS, "architectureEdgeCriteria");
      if ("type" in criteria && !ARCHITECTURE_EDGE_TYPE_VALUES.includes(criteria.type)) {
        throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_RELATIONSHIP_TYPE, {
          received: safeQueryToken(criteria.type),
        });
      }
      for (const endpoint of ["from", "to"]) {
        if (endpoint in criteria && typeof criteria[endpoint] !== "string") {
          throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, {
            field: `architectureEdgeCriteria.${endpoint}`,
          });
        }
      }
      const maxResults = requireLimit(criteria.maxResults ?? QUERY_LIMITS.DEFAULT_RESULTS, {
        field: "maxResults",
        min: 1,
        max: QUERY_LIMITS.MAX_RESULTS,
      });

      const matching = architectureGraph.edges.filter((edge) => {
        if ("from" in criteria && edge.from !== criteria.from) return false;
        if ("to" in criteria && edge.to !== criteria.to) return false;
        if ("type" in criteria && edge.type !== criteria.type) return false;
        return true;
      });

      const result = createArchitectureEdgeQueryResult({
        edges: frozenEntries(matching.slice(0, maxResults)),
        ...architectureCoverageState(),
        state: architectureGraph.state,
        limited: matching.length > maxResults,
      });
      validateArchitectureEdgeQueryResult(result);
      return Object.freeze(result);
    },

    /**
     * The architecture nodes a container directly or transitively contains.
     *
     * Containment is the graph's `contains` tree: the repository node at the root,
     * directories and the entities they hold beneath it. `maxDepth` is in hops (depth
     * `1` is a direct child) and defaults to a single hop, so a caller who wants the
     * *whole* subtree has to ask for a depth rather than accidentally receive one. The
     * start node is not returned unless a cycle reaches it, and a node is entered at
     * most once, so the walk terminates on any input.
     *
     * An unknown id is an ordinary miss (an empty result, not an error).
     */
    containedEntities(id, options = {}) {
      const { maxDepth, maxResults } = parseGraphTraversalOptions(
        options,
        QUERY_LIMITS.DEFAULT_DEPTH,
      );
      const walk = descendArchitecture(id, maxDepth, maxResults);
      const result = createArchitectureNodeQueryResult({
        nodes: frozenEntries(walk.nodes),
        ...architectureCoverageState(),
        state: architectureGraph.state,
        limited: walk.limited,
      });
      validateArchitectureNodeQueryResult(result);
      return Object.freeze(result);
    },

    /**
     * The architecture node that directly contains an entity, or `null`.
     *
     * For a root-level entity that is the repository node, which is why this returns a
     * node record rather than a directory: the repository has no directory entity, and
     * pretending otherwise would lose the difference between "at the root" and
     * "unknown". A non-string id, a node the graph does not contain, or the
     * repository node itself is `null`.
     */
    containerOf(id) {
      if (typeof id !== "string") return null;
      const parentId = containmentParentOf(id);
      if (parentId === null) return null;
      return architectureNodeById.get(parentId) ?? null;
    },

    /**
     * A bounded path between two architecture nodes, following the graph's edges in
     * either direction.
     *
     * Undirected on purpose: "how are these two related" is the architectural
     * question, and a Compose file and the Dockerfile it builds are joined upward
     * through `declares-build` as much as downward through `contains`. Breadth-first,
     * so the path returned is a shortest one, and `found: false` with `limited: true`
     * means the search stopped at a bound rather than proving the two are unconnected.
     * `nodes` are in path order (each carrying its `depth`) and `edges` are the
     * traversed edges in path order — deliberately not sorted, because a path's order
     * is its meaning.
     */
    architecturePath(fromId, toId, options = {}) {
      const { maxDepth, maxResults } = parseGraphTraversalOptions(options, QUERY_LIMITS.MAX_DEPTH);

      const pathResult = (nodes, edges, found, limited) => {
        const result = createArchitecturePathResult({
          nodes: frozenEntries(nodes),
          edges: frozenEntries(edges),
          found,
          ...graphCoverageState(),
          state: architectureGraph.state,
          limited,
        });
        validateArchitecturePathResult(result);
        return Object.freeze(result);
      };

      const startNode = typeof fromId === "string" ? architectureNodeById.get(fromId) : undefined;
      const targetNode = typeof toId === "string" ? architectureNodeById.get(toId) : undefined;
      if (startNode === undefined || targetNode === undefined) {
        return pathResult([], [], false, false);
      }
      if (fromId === toId) {
        // A node is trivially reachable from itself; reporting that as a path with
        // edges would invent a relationship the repository never stated.
        return pathResult([{ ...startNode, depth: 0 }], [], true, false);
      }

      const predecessor = new Map([[fromId, null]]);
      let frontier = [fromId];
      let found = false;
      let limited = false;
      let depth = 0;

      while (frontier.length > 0 && !found && depth < maxDepth) {
        const next = [];
        for (const id of frontier) {
          for (const step of architectureStepsAt(id)) {
            if (predecessor.has(step.to)) continue;
            if (predecessor.size >= maxResults) {
              limited = true;
              continue;
            }
            predecessor.set(step.to, { via: id, edge: step.edge, reversed: step.reversed });
            if (step.to === toId) {
              found = true;
              break;
            }
            next.push(step.to);
          }
          if (found) break;
        }
        frontier = found ? [] : next;
        depth += 1;
      }

      if (!found) return pathResult([], [], false, limited);

      const nodeChain = [];
      const edgeChain = [];
      let cursor = toId;
      while (typeof cursor === "string") {
        nodeChain.push(cursor);
        const step = predecessor.get(cursor);
        if (step === undefined || step === null) break;
        edgeChain.push(step.edge);
        cursor = step.via;
      }
      nodeChain.reverse();
      edgeChain.reverse();

      return pathResult(
        nodeChain.map((id, index) => ({ ...architectureNodeById.get(id), depth: index })),
        edgeChain,
        true,
        limited,
      );
    },

    /**
     * The container build wiring the model observed: which Compose service builds
     * which Dockerfile from which context root.
     *
     * Read from the graph's `buildContexts`, which is the declaration **in full** (a
     * Compose file, a service, a Dockerfile and a context are four facts, not two
     * binary edges) and the same fact the graph's `declares-build`/`build-context`
     * edges project. `context` is `null` for the repository root, and `contextId` /
     * `dockerfileId` are the graph nodes when they exist — `null` when the declaration
     * names an artifact the graph has no node for, which is exactly the difference
     * between "built from the root" and "context not established".
     *
     * A declaration is not an inference: the scanner read it from the Compose file and
     * the model preserved it, and each record cites the observation that recorded it.
     */
    containerBuildDeclarations(criteria = {}) {
      requireKeys(criteria, BUILD_DECLARATION_FILTER_KEYS, "buildDeclarationCriteria");
      for (const field of ["source", "dockerfile", "service"]) {
        if (field in criteria && !isNonEmptyQueryString(criteria[field])) {
          throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, {
            field: `buildDeclarationCriteria.${field}`,
          });
        }
      }
      const maxResults = requireLimit(criteria.maxResults ?? QUERY_LIMITS.DEFAULT_RESULTS, {
        field: "maxResults",
        min: 1,
        max: QUERY_LIMITS.MAX_RESULTS,
      });

      const matching = architectureGraph.buildContexts.filter((record) => {
        if ("source" in criteria && record.source !== criteria.source) return false;
        if ("dockerfile" in criteria && record.dockerfile !== criteria.dockerfile) return false;
        if ("service" in criteria && record.service !== criteria.service) return false;
        return true;
      });

      const declarations = matching.slice(0, maxResults).map((record) =>
        Object.freeze({
          source: record.source,
          service: record.service,
          dockerfile: record.dockerfile,
          context: record.context,
          dockerfileId: architectureNodeById.has(`file:${record.dockerfile}`)
            ? `file:${record.dockerfile}`
            : null,
          contextId:
            record.context === null
              ? repositoryNodeIdOf()
              : architectureNodeById.has(`directory:${record.context}`)
                ? `directory:${record.context}`
                : null,
          evidenceIds: Object.freeze([record.evidenceId]),
        }),
      );

      const result = createArchitectureBuildQueryResult({
        declarations: frozenEntries(declarations),
        ...architectureCoverageState(),
        state: architectureGraph.state,
        limited: matching.length > maxResults,
      });
      validateArchitectureBuildQueryResult(result);
      return Object.freeze(result);
    },

    /**
     * The test artifacts within a container, by containment.
     *
     * Deliberately **not** named `testsForEntity`: this answers "which test artifacts
     * sit inside this container", which the observed paths establish, and not "which
     * files these tests cover", which nothing in the model establishes. A caller that
     * needs coverage has to acquire it in a phase that can read the code.
     *
     * `maxDepth` defaults to the traversal ceiling, unlike `containedEntities`: the
     * question is *which tests are in here*, so the bounded whole subtree is the
     * useful answer, and `limited` says when the bound cut it short.
     */
    testsWithin(id, options = {}) {
      const { maxDepth, maxResults } = parseGraphTraversalOptions(options, QUERY_LIMITS.MAX_DEPTH);
      const walk = descendArchitecture(id, maxDepth, maxResults);
      const tests = walk.nodes.filter((node) => node.kind === "test");
      const result = createArchitectureNodeQueryResult({
        nodes: frozenEntries(tests),
        ...architectureCoverageState(),
        state: architectureGraph.state,
        // A truncated walk may have stopped before a test was reached, so the bound
        // travels with the answer.
        limited: walk.limited || tests.length > maxResults,
      });
      validateArchitectureNodeQueryResult(result);
      return Object.freeze(result);
    },

    /**
     * Every framework the model observed, with the test artifacts that reported it.
     *
     * Each entry is a `framework` entity id and the ids of the `test` entities whose
     * `framework` edge points at it, so "this framework is used" is traceable to the
     * artifacts that said so rather than to a package name that happens to look like a
     * framework.
     */
    frameworkUsage() {
      const frameworks = [];
      for (const node of architectureGraph.nodes) {
        if (node.kind !== "framework") continue;
        const tests = architectureGraph.edges
          .filter((edge) => edge.type === ARCHITECTURE_EDGE_TYPES.FRAMEWORK && edge.to === node.id)
          .map((edge) => edge.from)
          .sort();
        frameworks.push({ id: node.id, name: node.name, tests: Object.freeze(tests) });
      }
      frameworks.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

      const result = createFrameworkUsageQueryResult({
        frameworks: frozenEntries(frameworks),
        ...architectureCoverageState(),
        state: architectureGraph.state,
        limited: false,
      });
      validateFrameworkUsageQueryResult(result);
      return Object.freeze(result);
    },

    /**
     * The innermost observed component an entity belongs to, or `null`.
     *
     * A **component** is defined narrowly and observably: the innermost container at or
     * above the entity that directly holds an observed manifest. Nothing about
     * cohesion, ownership, layering or domain is implied — a directory holding a
     * `package.json` is a component because a manifest was observed there, and a
     * repository with no manifest at all has exactly one component: the repository.
     *
     * A dependency or framework node has no path, so it has no component and this is
     * `null` (not the repository, which would claim it belongs somewhere).
     */
    componentOf(id) {
      if (typeof id !== "string") return null;
      const node = architectureNodeById.get(id);
      if (node === undefined) return null;
      if (node.kind === "dependency" || node.kind === "framework") return null;

      const visited = new Set();
      let current = node.id;
      while (typeof current === "string" && !visited.has(current)) {
        visited.add(current);
        if (containersHoldingManifests.has(current)) {
          return architectureNodeById.get(current) ?? null;
        }
        current = containmentParentOf(current);
      }
      return architectureNodeById.get(repositoryNodeIdOf()) ?? null;
    },

    // ── Import graph (Phase 16) ─────────────────────────────────────────────
    /**
     * The whole import graph: the module nodes and the established `imports` edges.
     *
     * `state` distinguishes an established-but-empty graph from one that was never
     * established, so `edges: []` is never mistaken for an all-clear on its own.
     */
    importGraph() {
      const result = createImportGraphResult({
        nodes: frozenEntries([...importGraph.nodes]),
        edges: frozenEntries([...importGraph.edges]),
        ...importCoverageState(),
        state: importGraph.state,
        established: importGraph.established,
      });
      validateImportGraphResult(result);
      return Object.freeze(result);
    },

    /**
     * What the import graph does and does not establish.
     *
     * The five-way state, the per-reason count of unresolved references, the module
     * sources whose references could not be fully established, and every bound that
     * bit — one frozen statement a caller can branch on without reading the graph.
     */
    importCoverage() {
      return Object.freeze({ ...importGraph.coverage });
    },

    /**
     * Import edges matching a `{ from, to, type }` filter, sorted and bounded.
     *
     * `type` accepts only the graph's own edge vocabulary, so a caller cannot ask the
     * import graph for a call or dependency edge and receive an import edge instead.
     * `limited` is true when `maxResults` cut the list short.
     *
     * @throws {RepositoryQueryError} kind `invalid-query` / `invalid-relationship-type`.
     */
    importEdges(criteria = {}) {
      requireKeys(criteria, IMPORT_EDGE_FILTER_KEYS, "importEdgeCriteria");
      if ("type" in criteria && !IMPORT_GRAPH_EDGE_TYPE_VALUES.includes(criteria.type)) {
        throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_RELATIONSHIP_TYPE, {
          received: safeQueryToken(criteria.type),
        });
      }
      for (const endpoint of ["from", "to"]) {
        if (endpoint in criteria && typeof criteria[endpoint] !== "string") {
          throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, {
            field: `importEdgeCriteria.${endpoint}`,
          });
        }
      }
      const maxResults = requireLimit(criteria.maxResults ?? QUERY_LIMITS.DEFAULT_RESULTS, {
        field: "maxResults",
        min: 1,
        max: QUERY_LIMITS.MAX_RESULTS,
      });

      const matching = importGraph.edges.filter((edge) => {
        if ("from" in criteria && edge.from !== criteria.from) return false;
        if ("to" in criteria && edge.to !== criteria.to) return false;
        if ("type" in criteria && edge.type !== criteria.type) return false;
        return true;
      });

      const result = createImportEdgeQueryResult({
        edges: frozenEntries(matching.slice(0, maxResults)),
        ...importCoverageState(),
        state: importGraph.state,
        limited: matching.length > maxResults,
      });
      validateImportEdgeQueryResult(result);
      return Object.freeze(result);
    },

    /**
     * What a file imports: bounded descent through `imports` edges it states.
     *
     * `maxDepth` is in hops (depth `1` is a direct import) and defaults to a single
     * hop, so a caller who wants the whole transitive closure has to ask for a depth
     * rather than accidentally receive one. An unknown id is an ordinary miss (an
     * empty result, not an error), and a cyclic graph terminates because a node is
     * entered at most once.
     */
    importsOf(id, options = {}) {
      const { maxDepth, maxResults } = parseGraphTraversalOptions(
        options,
        QUERY_LIMITS.DEFAULT_DEPTH,
      );
      const walk = traverseImports(id, QUERY_DIRECTIONS.OUT, maxDepth, maxResults);
      const result = createImportTraversalResult({
        nodes: frozenEntries(walk.nodes),
        edges: frozenEntries(walk.edges),
        ...importCoverageState(),
        state: importGraph.state,
        established: importGraph.established,
        limited: walk.limited,
      });
      validateImportTraversalResult(result);
      return Object.freeze(result);
    },

    /**
     * What imports a file: bounded descent through `imports` edges that point at it.
     *
     * The reverse direction on purpose and never a second edge: an import edge is
     * stated once, and `importedBy` reads it backward, so the two answers cannot
     * disagree.
     */
    importedBy(id, options = {}) {
      const { maxDepth, maxResults } = parseGraphTraversalOptions(
        options,
        QUERY_LIMITS.DEFAULT_DEPTH,
      );
      const walk = traverseImports(id, QUERY_DIRECTIONS.IN, maxDepth, maxResults);
      const result = createImportTraversalResult({
        nodes: frozenEntries(walk.nodes),
        edges: frozenEntries(walk.edges),
        ...importCoverageState(),
        state: importGraph.state,
        established: importGraph.established,
        limited: walk.limited,
      });
      validateImportTraversalResult(result);
      return Object.freeze(result);
    },

    /**
     * References that are not edges: the specifiers a file states whose target the
     * repository does not establish.
     *
     * Kept in their own result rather than mixed into `importEdges`, because
     * "this file said `./missing`" and "this file imports that one" are different
     * facts and a caller that received them together would read a non-fact as a
     * fact. Each record carries a closed `reason`, so *a bare package specifier* is
     * distinguishable from *a path leaving the repository* from *a path the scan did
     * not observe*.
     */
    unresolvedImports(criteria = {}) {
      requireKeys(criteria, IMPORT_UNRESOLVED_FILTER_KEYS, "unresolvedImportCriteria");
      if ("path" in criteria && !isNonEmptyQueryString(criteria.path)) {
        throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, {
          field: "unresolvedImportCriteria.path",
        });
      }
      if ("reason" in criteria && !UNRESOLVED_REFERENCE_REASON_VALUES.includes(criteria.reason)) {
        throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, {
          field: "unresolvedImportCriteria.reason",
        });
      }
      const maxResults = requireLimit(criteria.maxResults ?? QUERY_LIMITS.DEFAULT_RESULTS, {
        field: "maxResults",
        min: 1,
        max: QUERY_LIMITS.MAX_RESULTS,
      });

      const matching = importGraph.unresolved.filter((record) => {
        if ("path" in criteria && record.path !== criteria.path) return false;
        if ("reason" in criteria && record.reason !== criteria.reason) return false;
        return true;
      });

      const result = createImportUnresolvedQueryResult({
        unresolved: frozenEntries(matching.slice(0, maxResults)),
        ...importCoverageState(),
        state: importGraph.state,
        limited: matching.length > maxResults,
      });
      validateImportUnresolvedQueryResult(result);
      return Object.freeze(result);
    },

    /**
     * A bounded path from one file to another, following `imports` edges forward.
     *
     * Directed on purpose: an import is a one-way static reference, and a path that
     * walked edges backward would answer "these two files are in the same connected
     * component", which is not the question. Breadth-first, so the path returned is
     * a shortest one, and `found: false` with `limited: true` means the search
     * stopped at a bound rather than proving the target unreachable. `nodes` are in
     * path order (each carrying its `depth`) and `edges` are the traversed edges in
     * path order — deliberately not sorted, because a path's order is its meaning.
     */
    importPath(fromId, toId, options = {}) {
      const { maxDepth, maxResults } = parseGraphTraversalOptions(options, QUERY_LIMITS.MAX_DEPTH);

      const pathResult = (nodes, edges, found, limited) => {
        const result = createImportPathResult({
          nodes: frozenEntries(nodes),
          edges: frozenEntries(edges),
          found,
          ...importCoverageState(),
          state: importGraph.state,
          limited,
        });
        validateImportPathResult(result);
        return Object.freeze(result);
      };

      const startNode = typeof fromId === "string" ? importNodeById.get(fromId) : undefined;
      const targetNode = typeof toId === "string" ? importNodeById.get(toId) : undefined;
      if (startNode === undefined || targetNode === undefined) {
        return pathResult([], [], false, false);
      }
      if (fromId === toId) {
        // A file is trivially reachable from itself; reporting that as a path with
        // edges would invent a relationship the repository never stated (unless it
        // literally imports itself, which is a one-edge path the search finds).
        return pathResult([{ ...startNode, depth: 0 }], [], true, false);
      }

      const predecessor = new Map([[fromId, null]]);
      let frontier = [fromId];
      let found = false;
      let limited = false;
      let depth = 0;

      while (frontier.length > 0 && !found && depth < maxDepth) {
        const next = [];
        for (const id of frontier) {
          for (const edge of importOutgoing.get(id) ?? []) {
            if (predecessor.has(edge.to)) continue;
            if (predecessor.size >= maxResults) {
              limited = true;
              continue;
            }
            predecessor.set(edge.to, { via: id, edge });
            if (edge.to === toId) {
              found = true;
              break;
            }
            next.push(edge.to);
          }
          if (found) break;
        }
        frontier = found ? [] : next;
        depth += 1;
      }

      if (!found) return pathResult([], [], false, limited);

      const nodeChain = [];
      const edgeChain = [];
      let cursor = toId;
      while (typeof cursor === "string") {
        nodeChain.push(cursor);
        const step = predecessor.get(cursor);
        if (step === undefined || step === null) break;
        edgeChain.push(step.edge);
        cursor = step.via;
      }
      nodeChain.reverse();
      edgeChain.reverse();

      return pathResult(
        nodeChain.map((id, index) => ({ ...importNodeById.get(id), depth: index })),
        edgeChain,
        true,
        limited,
      );
    },

    /**
     * Module files no established edge points at — *candidates*, not verdicts.
     *
     * An entry point in the ordinary sense (`src/index.js`, a CLI entry, a server
     * bootstrap) is exactly a file nothing imports, so this is the same evidence; but
     * the same evidence is produced by a file whose only importer was not analysed,
     * and by one reached only through a dynamic or aliased reference. That is why the
     * result carries the graph's `state`: over a `partial` or `truncated` graph this
     * is a candidate list, and only over a `complete` one is it a statement about the
     * repository. Nothing about reachability, liveness or dead code follows, and no
     * traversal is performed — a node with no incoming edge would be a candidate even
     * if it were imported dynamically.
     */
    entryPointCandidates(options = {}) {
      requireKeys(options, IMPORT_CANDIDATE_OPTION_KEYS, "importCandidateOptions");
      const maxResults = requireLimit(options.maxResults ?? QUERY_LIMITS.DEFAULT_RESULTS, {
        field: "maxResults",
        min: 1,
        max: QUERY_LIMITS.MAX_RESULTS,
      });

      const candidates = importGraph.nodes.filter(
        (node) => node.module === true && !importIncoming.has(node.id),
      );
      const result = createImportNodeQueryResult({
        nodes: frozenEntries(
          candidates.slice(0, maxResults).map((node) => ({ ...node, depth: 0 })),
        ),
        ...importCoverageState(),
        state: importGraph.state,
        limited: candidates.length > maxResults,
      });
      validateImportNodeQueryResult(result);
      return Object.freeze(result);
    },

    /**
     * Module files that neither import nor are imported — again **candidates**.
     *
     * The strictest topological statement this graph can make: no established edge
     * touches the file in either direction. It is not a dead-code claim. A file can
     * be an executable script, a dynamically loaded plugin, a build entry, or simply
     * a file whose importer could not be parsed — and on a graph whose `state` is not
     * `complete`, the last of those is the likeliest reading. Non-module nodes (a
     * JSON file a `require` reached, for instance) are never reported here.
     */
    orphanModules(options = {}) {
      requireKeys(options, IMPORT_CANDIDATE_OPTION_KEYS, "importCandidateOptions");
      const maxResults = requireLimit(options.maxResults ?? QUERY_LIMITS.DEFAULT_RESULTS, {
        field: "maxResults",
        min: 1,
        max: QUERY_LIMITS.MAX_RESULTS,
      });

      const candidates = importGraph.nodes.filter(
        (node) =>
          node.module === true &&
          !importIncoming.has(node.id) &&
          !importOutgoing.has(node.id),
      );
      const result = createImportNodeQueryResult({
        nodes: frozenEntries(
          candidates.slice(0, maxResults).map((node) => ({ ...node, depth: 0 })),
        ),
        ...importCoverageState(),
        state: importGraph.state,
        limited: candidates.length > maxResults,
      });
      validateImportNodeQueryResult(result);
      return Object.freeze(result);
    },

    // ── Symbol graph (Phase 17) ─────────────────────────────────────────────
    /**
     * The whole symbol graph: the symbol nodes and the established edges.
     *
     * `state` distinguishes an established-but-empty graph (a repository whose
     * sources declare nothing) from one that was never established, so an empty
     * `nodes` list is never mistaken for "this repository defines no symbols". The
     * unresolved occurrences are *not* folded in here — they are not edges, and a
     * caller that received them together would read a non-fact as a fact. Ask for
     * them with `unresolvedSymbolReferences`.
     */
    symbolGraph() {
      const result = createSymbolGraphResult({
        nodes: frozenEntries([...symbolGraph.nodes]),
        edges: frozenEntries([...symbolGraph.edges]),
        ...symbolCoverageState(),
        state: symbolGraph.state,
        established: symbolGraph.established,
      });
      validateSymbolGraphResult(result);
      return Object.freeze(result);
    },

    /**
     * The five-way symbol-graph state, its per-reason unresolved counts, the sources
     * whose semantic claims could not be established, and every bound that bit.
     */
    symbolCoverage() {
      return Object.freeze({ ...symbolGraph.coverage });
    },

    /**
     * Symbol nodes matching a `{ path, fileId, name, kind, exported }` filter.
     *
     * `kind` is checked against the graph's own declaration vocabulary, so a caller
     * cannot ask for a kind this build never establishes and receive a plausible
     * answer. Results are sorted by id and bounded by `maxResults`.
     *
     * @throws {RepositoryQueryError} kind `invalid-query`.
     */
    symbolNodes(criteria = {}) {
      requireKeys(criteria, SYMBOL_NODE_FILTER_KEYS, "symbolNodeCriteria");
      for (const field of ["path", "fileId", "name"]) {
        if (field in criteria && !isNonEmptyQueryString(criteria[field])) {
          throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, {
            field: `symbolNodeCriteria.${field}`,
          });
        }
      }
      if ("kind" in criteria && !SYMBOL_KINDS.includes(criteria.kind)) {
        throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, {
          field: "symbolNodeCriteria.kind",
        });
      }
      if ("exported" in criteria && typeof criteria.exported !== "boolean") {
        throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, {
          field: "symbolNodeCriteria.exported",
        });
      }
      const maxResults = requireLimit(criteria.maxResults ?? QUERY_LIMITS.DEFAULT_RESULTS, {
        field: "maxResults",
        min: 1,
        max: QUERY_LIMITS.MAX_RESULTS,
      });

      const matching = symbolGraph.nodes
        .filter((node) => {
          if ("path" in criteria && node.path !== criteria.path) return false;
          if ("fileId" in criteria) {
            const fileId = fileEntityIdOf(criteria.fileId);
            if (node.fileId !== fileId) return false;
          }
          if ("name" in criteria && node.name !== criteria.name) return false;
          if ("kind" in criteria && !node.kinds.includes(criteria.kind)) return false;
          if ("exported" in criteria && node.exported !== criteria.exported) return false;
          return true;
        })
        .slice()
        .sort(compareById);

      const result = createSymbolNodeQueryResult({
        nodes: frozenEntries(matching.slice(0, maxResults)),
        ...symbolCoverageState(),
        state: symbolGraph.state,
        limited: matching.length > maxResults,
      });
      validateSymbolNodeQueryResult(result);
      return Object.freeze(result);
    },

    /**
     * The symbols a file declares, sorted by id.
     *
     * Accepts a file entity id (`file:src/a.js`) or the repository-relative path it
     * names. An unknown file is an ordinary miss: an empty result carrying the graph's
     * coverage, never a claim that the file declares nothing.
     */
    symbolsInFile(fileId, options = {}) {
      requireKeys(options, SYMBOL_CANDIDATE_OPTION_KEYS, "symbolCandidateOptions");
      if (!isNonEmptyQueryString(fileId)) {
        throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, { field: "fileId" });
      }
      const maxResults = requireLimit(options.maxResults ?? QUERY_LIMITS.DEFAULT_RESULTS, {
        field: "maxResults",
        min: 1,
        max: QUERY_LIMITS.MAX_RESULTS,
      });

      const matching = symbolsOfFile(fileEntityIdOf(fileId));
      const result = createSymbolNodeQueryResult({
        nodes: frozenEntries(matching.slice(0, maxResults)),
        ...symbolCoverageState(),
        state: symbolGraph.state,
        limited: matching.length > maxResults,
      });
      validateSymbolNodeQueryResult(result);
      return Object.freeze(result);
    },

    /**
     * Symbol edges matching a `{ from, to, type }` filter, sorted and bounded.
     *
     * `type` accepts only the graph's own five-value vocabulary, so a caller cannot
     * ask the symbol graph for an import or dependency edge and receive a semantic one
     * instead.
     *
     * @throws {RepositoryQueryError} kind `invalid-query` / `invalid-relationship-type`.
     */
    symbolEdges(criteria = {}) {
      requireKeys(criteria, SYMBOL_EDGE_FILTER_KEYS, "symbolEdgeCriteria");
      if ("type" in criteria && !SYMBOL_GRAPH_EDGE_TYPE_VALUES.includes(criteria.type)) {
        throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_RELATIONSHIP_TYPE, {
          received: safeQueryToken(criteria.type),
        });
      }
      for (const endpoint of ["from", "to"]) {
        if (endpoint in criteria && typeof criteria[endpoint] !== "string") {
          throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, {
            field: `symbolEdgeCriteria.${endpoint}`,
          });
        }
      }
      const maxResults = requireLimit(criteria.maxResults ?? QUERY_LIMITS.DEFAULT_RESULTS, {
        field: "maxResults",
        min: 1,
        max: QUERY_LIMITS.MAX_RESULTS,
      });

      const matching = symbolGraph.edges.filter((edge) => {
        if ("from" in criteria && edge.from !== criteria.from) return false;
        if ("to" in criteria && edge.to !== criteria.to) return false;
        if ("type" in criteria && edge.type !== criteria.type) return false;
        return true;
      });

      const result = createSymbolEdgeQueryResult({
        edges: frozenEntries(matching.slice(0, maxResults)),
        ...symbolCoverageState(),
        state: symbolGraph.state,
        limited: matching.length > maxResults,
      });
      validateSymbolEdgeQueryResult(result);
      return Object.freeze(result);
    },

    /**
     * What the graph states points at one symbol, split by edge type.
     *
     * `references` and `calls` are separate lists because the graph states them as
     * separate edges: an occurrence that is established as a call is recorded as a
     * `calls` edge and not also as a reference, so the two lists never double-count
     * one occurrence. Each edge records the *file* that stated the occurrence, never a
     * declaring symbol — this build does not attribute a call site to an enclosing
     * function, and pretending otherwise would be exactly the syntactic approximation
     * this graph refuses to make.
     *
     * An unknown symbol id is an ordinary miss (`symbol: null`, empty lists).
     */
    referencesTo(symbolId, options = {}) {
      requireKeys(options, SYMBOL_CANDIDATE_OPTION_KEYS, "symbolCandidateOptions");
      const maxResults = requireLimit(options.maxResults ?? QUERY_LIMITS.DEFAULT_RESULTS, {
        field: "maxResults",
        min: 1,
        max: QUERY_LIMITS.MAX_RESULTS,
      });

      const symbol = typeof symbolId === "string" ? (symbolNodeById.get(symbolId) ?? null) : null;
      const incoming = symbol === null ? [] : (symbolIncoming.get(symbol.id) ?? []);
      const references = incoming
        .filter((edge) => edge.type === SYMBOL_GRAPH_EDGE_TYPES.REFERENCES)
        .sort(compareGraphEdges);
      const calls = incoming
        .filter((edge) => edge.type === SYMBOL_GRAPH_EDGE_TYPES.CALLS)
        .sort(compareGraphEdges);

      const result = createSymbolReferenceResult({
        symbol,
        references: frozenEntries(references.slice(0, maxResults)),
        calls: frozenEntries(calls.slice(0, maxResults)),
        ...symbolCoverageState(),
        state: symbolGraph.state,
        limited: references.length > maxResults || calls.length > maxResults,
      });
      validateSymbolReferenceResult(result);
      return Object.freeze(result);
    },

    /**
     * The `calls` edges that point at a symbol: the files that call it.
     *
     * The reverse of the edge the graph states, never a second edge, so `calledBy` and
     * the edge list cannot disagree about who calls what.
     */
    calledBy(symbolId, options = {}) {
      requireKeys(options, SYMBOL_CANDIDATE_OPTION_KEYS, "symbolCandidateOptions");
      const maxResults = requireLimit(options.maxResults ?? QUERY_LIMITS.DEFAULT_RESULTS, {
        field: "maxResults",
        min: 1,
        max: QUERY_LIMITS.MAX_RESULTS,
      });

      const symbol = typeof symbolId === "string" ? symbolNodeById.get(symbolId) : undefined;
      const matching =
        symbol === undefined
          ? []
          : (symbolIncoming.get(symbol.id) ?? [])
              .filter((edge) => edge.type === SYMBOL_GRAPH_EDGE_TYPES.CALLS)
              .sort(compareGraphEdges);

      const result = createSymbolEdgeQueryResult({
        edges: frozenEntries(matching.slice(0, maxResults)),
        ...symbolCoverageState(),
        state: symbolGraph.state,
        limited: matching.length > maxResults,
      });
      validateSymbolEdgeQueryResult(result);
      return Object.freeze(result);
    },

    /**
     * The `calls` edges a **file** states: `file --calls--> symbol`.
     *
     * Strictly a file question. A symbol id is rejected rather than answered with its
     * file's calls, because the acquisition layer attributes a call site to the file
     * that states it and to nothing finer — answering a symbol-id lookup with the
     * enclosing file's call edges would attribute calls to a function the graph never
     * established them for. Per-symbol callers are available the other way round, as
     * `calledBy`, which the graph *does* establish.
     *
     * @throws {RepositoryQueryError} kind `invalid-query`.
     */
    callsFrom(fileId, options = {}) {
      requireKeys(options, SYMBOL_CANDIDATE_OPTION_KEYS, "symbolCandidateOptions");
      // A *file* question, and only a file question: `symbol:` is not a file id, so it is
      // refused as the malformed argument it is. There is deliberately no symbol-scoped
      // variant of this query, because no per-symbol call ownership is established — a
      // symbol-scoped answer would attribute the enclosing file's calls to a function the
      // graph never established them for.
      if (!isNonEmptyQueryString(fileId) || fileId.startsWith("symbol:")) {
        throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, { field: "fileId" });
      }
      const maxResults = requireLimit(options.maxResults ?? QUERY_LIMITS.DEFAULT_RESULTS, {
        field: "maxResults",
        min: 1,
        max: QUERY_LIMITS.MAX_RESULTS,
      });

      const { edges, limited } = edgesOfType(
        fileEntityIdOf(fileId),
        SYMBOL_GRAPH_EDGE_TYPES.CALLS,
        maxResults,
      );
      const result = createSymbolEdgeQueryResult({
        edges: frozenEntries(edges),
        ...symbolCoverageState(),
        state: symbolGraph.state,
        limited,
      });
      validateSymbolEdgeQueryResult(result);
      return Object.freeze(result);
    },

    /**
     * The symbols a file publishes, sorted by id.
     *
     * Read from the file's own `exports` edges, so a re-export resolves to the symbol
     * the repository established rather than to a name this layer guessed. Each node
     * carries its own `exportNames`, because one symbol can be published under more
     * than one name (`export { a as b }`).
     */
    exportsOf(fileId, options = {}) {
      requireKeys(options, SYMBOL_CANDIDATE_OPTION_KEYS, "symbolCandidateOptions");
      if (!isNonEmptyQueryString(fileId)) {
        throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, { field: "fileId" });
      }
      const maxResults = requireLimit(options.maxResults ?? QUERY_LIMITS.DEFAULT_RESULTS, {
        field: "maxResults",
        min: 1,
        max: QUERY_LIMITS.MAX_RESULTS,
      });

      const fileEntityId = fileEntityIdOf(fileId);
      const targets = new Set(
        (symbolOutgoing.get(fileEntityId) ?? [])
          .filter((edge) => edge.type === SYMBOL_GRAPH_EDGE_TYPES.EXPORTS)
          .map((edge) => edge.to),
      );
      const matching = [...targets]
        .map((id) => symbolNodeById.get(id))
        .filter((node) => node !== undefined)
        .sort(compareById);

      const result = createSymbolNodeQueryResult({
        nodes: frozenEntries(matching.slice(0, maxResults)),
        ...symbolCoverageState(),
        state: symbolGraph.state,
        limited: matching.length > maxResults,
      });
      validateSymbolNodeQueryResult(result);
      return Object.freeze(result);
    },

    /**
     * A file's imported bindings, each joined to the symbol it resolves to when the
     * repository establishes the target, and to the graph's unresolved record when it
     * does not.
     *
     * The two lists are kept apart on purpose: `resolved: false` in `bindings` means the
     * binding exists but its target was not established, and `unresolved` carries the
     * closed `reason` for it (`module-not-interpreted`, `namespace-binding`, …). Split,
     * because "this file binds `x` from `./m`" and "we could not establish what `x`
     * points at" are different facts.
     */
    importsToSymbols(fileId, options = {}) {
      requireKeys(options, SYMBOL_CANDIDATE_OPTION_KEYS, "symbolCandidateOptions");
      if (!isNonEmptyQueryString(fileId)) {
        throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, { field: "fileId" });
      }
      const maxResults = requireLimit(options.maxResults ?? QUERY_LIMITS.DEFAULT_RESULTS, {
        field: "maxResults",
        min: 1,
        max: QUERY_LIMITS.MAX_RESULTS,
      });

      const fileEntityId = fileEntityIdOf(fileId);
      const path = filePathOfEntityId(fileEntityId);
      const bindings = [];
      for (const node of symbolsOfFile(fileEntityId)) {
        if (node.binding === null) continue;
        const edge =
          (symbolOutgoing.get(node.id) ?? []).find(
            (candidate) => candidate.type === SYMBOL_GRAPH_EDGE_TYPES.IMPORTS_BINDING,
          ) ?? null;
        const target = edge === null ? undefined : symbolNodeById.get(edge.to);
        bindings.push(
          Object.freeze({
            symbolId: node.id,
            fileId: node.fileId,
            path: node.path,
            name: node.name,
            bindingKind: node.binding.bindingKind,
            importedName: node.binding.importedName,
            specifier: node.binding.specifier,
            typeOnly: node.binding.typeOnly === true,
            resolved: edge !== null,
            targetSymbolId: edge === null ? null : edge.to,
            targetPath: target === undefined ? null : target.path,
            evidenceIds: edge === null ? Object.freeze([]) : edge.evidenceIds,
          }),
        );
      }
      bindings.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

      // The graph already sorts its unresolved records by `(path, name, kind)`, and
      // filtering preserves that order, so this needs no second sort.
      const unresolved = symbolGraph.unresolved.filter(
        (record) => record.kind === "import-binding" && record.path === path,
      );

      const result = createSymbolBindingQueryResult({
        bindings: frozenEntries(bindings.slice(0, maxResults)),
        unresolved: frozenEntries(unresolved.slice(0, maxResults)),
        ...symbolCoverageState(),
        state: symbolGraph.state,
        limited: bindings.length > maxResults || unresolved.length > maxResults,
      });
      validateSymbolBindingQueryResult(result);
      return Object.freeze(result);
    },

    /**
     * Occurrences that are not edges: a name the file refers to, calls or exports whose
     * target the repository does not establish.
     *
     * Each record carries a closed `kind` (which occurrence) and `reason` (why it was
     * not established), so *a name this file never declares* is distinguishable from *a
     * name it also binds elsewhere* from *a callee whose value shape is not
     * established* from *a module the scan did not observe*.
     *
     * @throws {RepositoryQueryError} kind `invalid-query`.
     */
    unresolvedSymbolReferences(criteria = {}) {
      requireKeys(criteria, SYMBOL_UNRESOLVED_FILTER_KEYS, "unresolvedSymbolCriteria");
      for (const field of ["path", "name"]) {
        if (field in criteria && !isNonEmptyQueryString(criteria[field])) {
          throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, {
            field: `unresolvedSymbolCriteria.${field}`,
          });
        }
      }
      if ("kind" in criteria && !SYMBOL_UNRESOLVED_KINDS.includes(criteria.kind)) {
        throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, {
          field: "unresolvedSymbolCriteria.kind",
        });
      }
      if ("reason" in criteria && !SYMBOL_UNRESOLVED_REASON_VALUES.includes(criteria.reason)) {
        throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, {
          field: "unresolvedSymbolCriteria.reason",
        });
      }
      const maxResults = requireLimit(criteria.maxResults ?? QUERY_LIMITS.DEFAULT_RESULTS, {
        field: "maxResults",
        min: 1,
        max: QUERY_LIMITS.MAX_RESULTS,
      });

      const matching = symbolGraph.unresolved.filter((record) => {
        if ("path" in criteria && record.path !== criteria.path) return false;
        if ("name" in criteria && record.name !== criteria.name) return false;
        if ("kind" in criteria && record.kind !== criteria.kind) return false;
        if ("reason" in criteria && record.reason !== criteria.reason) return false;
        return true;
      });

      const result = createSymbolUnresolvedQueryResult({
        unresolved: frozenEntries(matching.slice(0, maxResults)),
        ...symbolCoverageState(),
        state: symbolGraph.state,
        limited: matching.length > maxResults,
      });
      validateSymbolUnresolvedQueryResult(result);
      return Object.freeze(result);
    },

    /**
     * A bounded, cycle-safe path between two **symbols** along established edges.
     *
     * Follows edges in their stated direction (`symbol --imports-binding--> symbol`),
     * so the path is a chain of relationships the repository established: following an
     * imported binding to the symbol it resolves to, through re-exports if the graph
     * resolved them. A file id is not accepted as an endpoint — a path between two file
     * *containers* is a different question, and `importPath` already answers it — and two
     * symbols of the same file are simply not connected by any edge this graph states,
     * which is a non-answer rather than a negative fact. An unknown endpoint is an
     * ordinary miss (`found: false`).
     */
    symbolPath(fromId, toId, options = {}) {
      const { maxDepth, maxResults } = parseGraphTraversalOptions(
        options,
        QUERY_LIMITS.DEFAULT_DEPTH,
      );
      const pathResult = (nodes, edges, found, limited) => {
        const result = createSymbolPathResult({
          nodes: frozenEntries(nodes),
          edges: frozenEntries(edges),
          found,
          ...symbolCoverageState(),
          state: symbolGraph.state,
          limited,
        });
        validateSymbolPathResult(result);
        return Object.freeze(result);
      };

      const startNode = typeof fromId === "string" ? symbolNodeById.get(fromId) : undefined;
      const targetNode = typeof toId === "string" ? symbolNodeById.get(toId) : undefined;
      if (startNode === undefined || targetNode === undefined) {
        return pathResult([], [], false, false);
      }
      if (fromId === toId) {
        return pathResult([{ ...startNode, depth: 0 }], [], true, false);
      }

      const predecessor = new Map([[fromId, null]]);
      const edgeInto = new Map();
      let frontier = [fromId];
      let found = false;
      let limited = false;
      let depth = 0;

      while (frontier.length > 0 && !found && depth < maxDepth) {
        const next = [];
        for (const id of frontier) {
          for (const edge of symbolOutgoing.get(id) ?? []) {
            if (predecessor.has(edge.to)) continue;
            if (predecessor.size >= maxResults) {
              limited = true;
              continue;
            }
            predecessor.set(edge.to, id);
            edgeInto.set(edge.to, edge);
            if (edge.to === toId) {
              found = true;
              break;
            }
            next.push(edge.to);
          }
          if (found) break;
        }
        frontier = next;
        depth += 1;
      }

      if (!found) return pathResult([], [], false, limited);

      const chainIds = [toId];
      const chainEdges = [];
      let cursor = toId;
      while (cursor !== fromId) {
        chainEdges.push(edgeInto.get(cursor));
        cursor = predecessor.get(cursor);
        chainIds.push(cursor);
      }
      chainIds.reverse();
      chainEdges.reverse();

      return pathResult(
        chainIds.map((id, hops) => ({ ...(symbolNodeById.get(id) ?? {}), depth: hops })),
        chainEdges,
        true,
        limited,
      );
    },

    // ── API & Service graph (Phase 18) ──────────────────────────────────────
    /**
     * The whole API graph: the route nodes and the established edges.
     *
     * `state` distinguishes an established-but-empty graph (a repository that declares
     * no route) from one that was never established, so an empty `nodes` list is never
     * mistaken for "this repository exposes nothing". The unresolved occurrences are
     * *not* folded in here — they are not edges, and a caller that received them
     * together would read a non-fact as a fact. Ask for them with `unresolvedRoutes`.
     */
    apiGraph() {
      const result = createApiGraphResult({
        nodes: frozenEntries([...apiGraph.nodes]),
        edges: frozenEntries([...apiGraph.edges]),
        ...apiCoverageState(),
        state: apiGraph.state,
        established: apiGraph.established,
      });
      validateApiGraphResult(result);
      return Object.freeze(result);
    },

    /**
     * The five-way API-graph state, its per-reason unresolved counts, the sources whose
     * route set could not be established, and every bound that bit.
     */
    apiCoverage() {
      return Object.freeze({ ...apiGraph.coverage });
    },

    /**
     * Route nodes matching a `{ method, path, framework, sourcePath }` filter.
     *
     * `method` is checked against the recorded method vocabulary, so a caller cannot ask
     * for a method this build never records and receive a plausible answer. Results are
     * sorted by id and bounded by `maxResults`.
     *
     * @throws {RepositoryQueryError} kind `invalid-query`.
     */
    routes(criteria = {}) {
      requireKeys(criteria, API_ROUTE_FILTER_KEYS, "routeCriteria");
      if ("method" in criteria && !API_ROUTE_METHODS.includes(criteria.method)) {
        throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, {
          field: "routeCriteria.method",
        });
      }
      for (const field of ["path", "framework", "sourcePath"]) {
        if (field in criteria && !isNonEmptyQueryString(criteria[field])) {
          throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, {
            field: `routeCriteria.${field}`,
          });
        }
      }
      const maxResults = requireLimit(criteria.maxResults ?? QUERY_LIMITS.DEFAULT_RESULTS, {
        field: "maxResults",
        min: 1,
        max: QUERY_LIMITS.MAX_RESULTS,
      });

      const matching = apiGraph.nodes
        .filter((node) => {
          if ("method" in criteria && node.method !== criteria.method) return false;
          if ("path" in criteria && node.path !== criteria.path) return false;
          if ("framework" in criteria && !node.frameworks.includes(criteria.framework)) return false;
          if ("sourcePath" in criteria && !node.sourcePaths.includes(criteria.sourcePath)) {
            return false;
          }
          return true;
        })
        .slice()
        .sort(compareById);

      const result = createApiRouteQueryResult({
        routes: frozenEntries(matching.slice(0, maxResults)),
        ...apiCoverageState(),
        state: apiGraph.state,
        limited: matching.length > maxResults,
      });
      validateApiRouteQueryResult(result);
      return Object.freeze(result);
    },

    /**
     * One route by its method and declared path.
     *
     * An unknown route is an ordinary miss (`route: null`), never a claim that the
     * repository does not expose it: an absent node alongside a `partial` state is
     * exactly the case a caller must not read as an absence.
     *
     * @throws {RepositoryQueryError} kind `invalid-query`.
     */
    routeByPath(method, path) {
      if (!API_ROUTE_METHODS.includes(method)) {
        throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, { field: "method" });
      }
      if (!isNonEmptyQueryString(path)) {
        throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, { field: "path" });
      }
      const route = apiNodeById.get(apiRouteIdOf(method, path)) ?? null;
      const result = createApiRouteLookupResult({
        route,
        ...apiCoverageState(),
        state: apiGraph.state,
      });
      validateApiRouteLookupResult(result);
      return Object.freeze(result);
    },

    /**
     * The symbols a route is `handled-by`, each with the edge that states it.
     *
     * `handlers` are the graph's `handled-by` edges, so a handler reference the graph
     * could not resolve is *not* here — it is reported by `unresolvedRoutes`-adjacent
     * coverage, never presented as a handler.
     */
    handlersForRoute(routeId, options = {}) {
      requireKeys(options, SYMBOL_CANDIDATE_OPTION_KEYS, "routeHandlerOptions");
      const maxResults = requireLimit(options.maxResults ?? QUERY_LIMITS.DEFAULT_RESULTS, {
        field: "maxResults",
        min: 1,
        max: QUERY_LIMITS.MAX_RESULTS,
      });
      const route = typeof routeId === "string" ? (apiNodeById.get(routeId) ?? null) : null;
      const edges =
        route === null
          ? []
          : (apiOutgoing.get(route.id) ?? [])
              .filter((edge) => edge.type === API_GRAPH_EDGE_TYPES.HANDLED_BY)
              .slice()
              .sort(compareGraphEdges);
      const handlers = edges.slice(0, maxResults).map(symbolDetailOf).filter((entry) => entry !== null);
      const result = createApiRouteHandlerResult({
        route,
        handlers: frozenEntries(handlers),
        ...apiCoverageState(),
        state: apiGraph.state,
        limited: edges.length > maxResults,
      });
      validateApiRouteHandlerResult(result);
      return Object.freeze(result);
    },

    /**
     * The symbols a route lists as `middleware`.
     *
     * A middleware reference is a positional reading of the call, and the graph states
     * it as such: this is not a claim about runtime ordering.
     */
    middlewareForRoute(routeId, options = {}) {
      requireKeys(options, SYMBOL_CANDIDATE_OPTION_KEYS, "routeMiddlewareOptions");
      const maxResults = requireLimit(options.maxResults ?? QUERY_LIMITS.DEFAULT_RESULTS, {
        field: "maxResults",
        min: 1,
        max: QUERY_LIMITS.MAX_RESULTS,
      });
      const route = typeof routeId === "string" ? (apiNodeById.get(routeId) ?? null) : null;
      const edges =
        route === null
          ? []
          : (apiOutgoing.get(route.id) ?? [])
              .filter((edge) => edge.type === API_GRAPH_EDGE_TYPES.MIDDLEWARE)
              .slice()
              .sort(compareGraphEdges);
      const middleware = edges.slice(0, maxResults).map(symbolDetailOf).filter((entry) => entry !== null);
      const result = createApiRouteMiddlewareResult({
        route,
        middleware: frozenEntries(middleware),
        ...apiCoverageState(),
        state: apiGraph.state,
        limited: edges.length > maxResults,
      });
      validateApiRouteMiddlewareResult(result);
      return Object.freeze(result);
    },

    /**
     * The routes a symbol is a resolved handler of.
     *
     * The reverse of the `handled-by` edge the graph states, never a second edge, so a
     * symbol's routes and a route's handlers cannot disagree.
     */
    routesForHandler(symbolId, options = {}) {
      requireKeys(options, SYMBOL_CANDIDATE_OPTION_KEYS, "handlerRouteOptions");
      const maxResults = requireLimit(options.maxResults ?? QUERY_LIMITS.DEFAULT_RESULTS, {
        field: "maxResults",
        min: 1,
        max: QUERY_LIMITS.MAX_RESULTS,
      });
      const symbol =
        typeof symbolId === "string" ? (symbolNodeById.get(symbolId) ?? null) : null;
      const incoming =
        symbol === null
          ? []
          : (apiIncoming.get(symbol.id) ?? []).filter(
              (edge) => edge.type === API_GRAPH_EDGE_TYPES.HANDLED_BY,
            );
      const routeIds = [...new Set(incoming.map((edge) => edge.from))].sort();
      const routes = routeIds
        .map((id) => apiNodeById.get(id))
        .filter((node) => node !== undefined)
        .slice(0, maxResults);
      const result = createApiHandlerRouteResult({
        symbol,
        routes: frozenEntries(routes),
        ...apiCoverageState(),
        state: apiGraph.state,
        limited: routeIds.length > maxResults,
      });
      validateApiHandlerRouteResult(result);
      return Object.freeze(result);
    },

    /**
     * The modules that declare at least one resolved route handler.
     *
     * Deliberately *not* a call or dependency relationship: this build establishes no
     * controller→service edge, so "which module provides a handler" is the most this
     * graph can honestly say. Each module carries the handler names and route ids that
     * make it a member, so nothing is left implicit.
     */
    services(options = {}) {
      requireKeys(options, SYMBOL_CANDIDATE_OPTION_KEYS, "serviceOptions");
      const maxResults = requireLimit(options.maxResults ?? QUERY_LIMITS.DEFAULT_RESULTS, {
        field: "maxResults",
        min: 1,
        max: QUERY_LIMITS.MAX_RESULTS,
      });
      const byFile = new Map();
      for (const edge of apiGraph.edges) {
        if (edge.type !== API_GRAPH_EDGE_TYPES.HANDLED_BY) continue;
        const symbol = symbolNodeById.get(edge.to);
        if (symbol === undefined) continue;
        let entry = byFile.get(symbol.fileId);
        if (entry === undefined) {
          entry = {
            fileId: symbol.fileId,
            path: symbol.path,
            handlerNames: new Set(),
            routeIds: new Set(),
          };
          byFile.set(symbol.fileId, entry);
        }
        entry.handlerNames.add(symbol.name);
        entry.routeIds.add(edge.from);
      }
      const modules = [...byFile.values()]
        .map((entry) => ({
          fileId: entry.fileId,
          path: entry.path,
          handlerCount: entry.handlerNames.size,
          routeCount: entry.routeIds.size,
          handlerNames: [...entry.handlerNames].sort(),
          routeIds: [...entry.routeIds].sort(),
        }))
        .sort((a, b) => (a.fileId < b.fileId ? -1 : a.fileId > b.fileId ? 1 : 0));
      const result = createApiServiceResult({
        modules: frozenEntries(modules.slice(0, maxResults)),
        ...apiCoverageState(),
        state: apiGraph.state,
        limited: modules.length > maxResults,
      });
      validateApiServiceResult(result);
      return Object.freeze(result);
    },

    /**
     * The route-shaped occurrences the repository does **not** establish as routes.
     *
     * Kept separate from `routes` on purpose: an occurrence whose receiver is not a
     * framework registrar — or whose path is computed, or whose framework this build
     * does not support — is a different fact from a declared endpoint, and a caller that
     * received them together would read a non-fact as a fact.
     */
    unresolvedRoutes(criteria = {}) {
      requireKeys(criteria, API_UNRESOLVED_FILTER_KEYS, "unresolvedRouteCriteria");
      for (const field of ["path", "reason"]) {
        if (field in criteria && !isNonEmptyQueryString(criteria[field])) {
          throw new RepositoryQueryError(QUERY_ERROR_KINDS.INVALID_QUERY, {
            field: `unresolvedRouteCriteria.${field}`,
          });
        }
      }
      const maxResults = requireLimit(criteria.maxResults ?? QUERY_LIMITS.DEFAULT_RESULTS, {
        field: "maxResults",
        min: 1,
        max: QUERY_LIMITS.MAX_RESULTS,
      });
      const matching = apiGraph.unresolved
        .filter((record) => {
          if (record.kind !== "route") return false;
          if ("path" in criteria && record.path !== criteria.path) return false;
          if ("reason" in criteria && record.reason !== criteria.reason) return false;
          return true;
        })
        .slice()
        .sort((a, b) => {
          if (a.path !== b.path) return a.path < b.path ? -1 : 1;
          if (a.reason !== b.reason) return a.reason < b.reason ? -1 : 1;
          const left = a.route ?? "";
          const right = b.route ?? "";
          return left < right ? -1 : left > right ? 1 : 0;
        });
      const result = createApiUnresolvedRouteResult({
        unresolved: frozenEntries(matching.slice(0, maxResults)),
        ...apiCoverageState(),
        state: apiGraph.state,
        limited: matching.length > maxResults,
      });
      validateApiUnresolvedRouteResult(result);
      return Object.freeze(result);
    },

    // ── Coverage questions ──────────────────────────────────────────────────
    /** A compact statement of what the scan covered. */
    coverage() {
      return Object.freeze({ ...inspectCompleteness(model) });
    },

    /**
     * Classify a path against the scan's coverage:
     * `observed` / `ignored` / `unreadable` / `unknown` / `absent`.
     * A non-relative path is `unknown` — the model says nothing about it.
     */
    coverageOfPath(path) {
      return coverageClass(model, path);
    },

    /** Whether the model positively supports "this path does not exist". */
    isKnownAbsent(path) {
      return modelIsKnownAbsent(model, path);
    },

    // ── Thin semantic views (documented shortcuts over findEntities) ─────────
    /** Files carrying a language id. */
    filesByLanguage(languageId) {
      return entityResult(listFilesByLanguage(model, languageId));
    },

    /** Manifests in an ecosystem. */
    manifestsByEcosystem(ecosystemId) {
      return entityResult(listManifestsByEcosystem(model, ecosystemId));
    },

    /** Framework entities the model observed. */
    frameworksObserved() {
      return entityResult(listEntitiesByKind(model, ENTITY_KINDS.FRAMEWORK));
    },

    /** Test entities that report using a framework name. */
    testsForFramework(frameworkId) {
      const frameworkEntityId = `${ENTITY_KINDS.FRAMEWORK}:${frameworkId}`;
      const tests = listEntitiesByKind(model, ENTITY_KINDS.TEST).filter(
        (entity) => entity.frameworkId === frameworkEntityId,
      );
      return entityResult(tests);
    },
  };

  return Object.freeze(query);
}
