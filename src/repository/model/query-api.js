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
  getEntity as modelGetEntity,
  getEvidence as modelGetEvidence,
  inspectCompleteness,
  isKnownAbsent as modelIsKnownAbsent,
  listEntitiesByKind,
  listFilesByLanguage,
  listManifestsByEcosystem,
  listRelationships as modelListRelationships,
} from "./query.js";
import { ENTITY_KINDS } from "./identity.js";
import { GRAPH_RELATIONSHIP_TYPES } from "./graph.js";
import { isRepositoryRelativePath } from "./paths.js";
import {
  QUERY_DIRECTIONS,
  QUERY_DIRECTION_VALUES,
  QUERY_LIMITS,
  createEntityQueryResult,
  createEvidenceQueryResult,
  createRelationshipQueryResult,
  createTraversalResult,
  validateEntityQueryResult,
  validateEvidenceQueryResult,
  validateRelationshipQueryResult,
  validateTraversalResult,
} from "./query-contracts.js";
import { QUERY_ERROR_KINDS, RepositoryQueryError, safeQueryToken } from "./query-errors.js";

const ENTITY_KIND_VALUES = Object.values(ENTITY_KINDS);
const CRITERIA_KEYS = Object.freeze(["kind", "path", "language", "ecosystem", "framework"]);
const RESOLUTION_FILTER_KEYS = Object.freeze(["from", "to", "type"]);
const TRAVERSAL_OPTION_KEYS = Object.freeze([
  "direction",
  "type",
  "relationshipTypes",
  "maxDepth",
  "maxResults",
]);

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function compareById(a, b) {
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
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
  return entity.id === ecosystemEntityId;
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
