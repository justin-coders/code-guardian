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
  DEPENDENCY_GRAPH_EDGE_TYPE_VALUES,
  DEPENDENCY_GRAPH_STATES,
  isSourceEstablished,
  unestablishedSourceRecord,
} from "./dependency-graph.js";
import { isRepositoryRelativePath } from "./paths.js";
import {
  QUERY_DIRECTIONS,
  QUERY_DIRECTION_VALUES,
  QUERY_LIMITS,
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
