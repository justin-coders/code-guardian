/**
 * Code Guardian — Repository Query Contracts (Phase 11)
 *
 * Vocabulary and result shapes for the query layer. Nothing here redefines a
 * concept the model already owns: directions are new (the model has no notion of
 * traversal direction), but *coverage* is re-exported from `query.js` rather than
 * reinventing the `complete`/`partial` guarantee, and entity kinds and
 * relationship types stay in the modules that already define them.
 *
 * ### Result envelopes are coverage-aware
 *
 * Every collection query returns an envelope, not a bare array, because a list is
 * only as trustworthy as the scan behind it:
 *
 *   {
 *     entities: [...],        // sorted by id, frozen elements from the model
 *     coverage: "complete",   // the model's guarantee (`complete` | `partial`)
 *     truncated: false,       // the scan hit a limit (`scan.truncated`)
 *   }
 *
 * `coverage: "partial"` is the honest answer for an incomplete inventory: the list
 * is "everything observed so far", not "everything that exists". A caller that
 * treats an empty list as proof of absence must first check the guarantee, which is
 * why the envelope makes it impossible to read the list without seeing it.
 *
 * Shape/draft factories are validated by a matching validator — the same Core
 * convention used across the model, filesystem, analysis and rules layers.
 */

import { ValidationError } from "../../core/index.js";

import { DEPENDENCY_GRAPH_STATE_VALUES } from "./dependency-graph.js";
import { COVERAGE_GUARANTEES } from "./query.js";

/** Re-exported so callers read the coverage vocabulary from one place. */
export { COVERAGE_GUARANTEES };

/** Direction of a relationship query, relative to the entity asked about. */
export const QUERY_DIRECTIONS = Object.freeze({
  /** Edges whose `from` is the entity. */
  OUT: "out",
  /** Edges whose `to` is the entity. */
  IN: "in",
  /** Both, de-duplicated. */
  BOTH: "both",
});

/** The direction vocabulary as a list, for validation. */
export const QUERY_DIRECTION_VALUES = Object.freeze(Object.values(QUERY_DIRECTIONS));

/**
 * Traversal limits.
 *
 * A traversal is always bounded. `MAX_DEPTH`/`MAX_RESULTS` are hard ceilings, not
 * defaults, so no caller can ask for "the whole graph, recursively, forever" and
 * no result can grow without bound. `depth` counts *hops*: depth `0` is just the
 * starting entity (no neighbours), depth `1` is its direct neighbours.
 */
export const QUERY_LIMITS = Object.freeze({
  DEFAULT_DEPTH: 1,
  MAX_DEPTH: 8,
  DEFAULT_RESULTS: 200,
  MAX_RESULTS: 1000,
});

/** Fields every entity-collection result declares. */
export const ENTITY_QUERY_RESULT_FIELDS = Object.freeze(["entities", "coverage", "truncated"]);

/** Fields every relationship-collection result declares. */
export const RELATIONSHIP_QUERY_RESULT_FIELDS = Object.freeze([
  "relationships",
  "coverage",
  "truncated",
]);

/** Fields every evidence-collection result declares. */
export const EVIDENCE_QUERY_RESULT_FIELDS = Object.freeze(["evidence", "coverage", "truncated"]);

/** Fields a bounded traversal result declares. */
export const TRAVERSAL_RESULT_FIELDS = Object.freeze([
  "entities",
  "relationships",
  "coverage",
  "truncated",
  "limited",
]);

/**
 * Fields a whole-graph result declares.
 *
 * Graph results carry **two** coverage statements on purpose, because they answer
 * different questions: `coverage` (inherited from every other query result) is the
 * scan's guarantee — "how much of the repository was inventoried" — while `state`
 * is the graph's own five-way state — "was a graph established at all, and how
 * completely". An empty graph and a graph that was never established are different
 * answers, and `established` makes that unmissable.
 */
export const DEPENDENCY_GRAPH_RESULT_FIELDS = Object.freeze([
  "nodes",
  "edges",
  "coverage",
  "state",
  "established",
  "truncated",
]);

/** Fields a bounded dependency-graph traversal result declares. */
export const DEPENDENCY_TRAVERSAL_RESULT_FIELDS = Object.freeze([
  ...DEPENDENCY_GRAPH_RESULT_FIELDS,
  "limited",
]);

/** Fields a bounded dependency edge-list result declares. */
export const DEPENDENCY_EDGE_RESULT_FIELDS = Object.freeze([
  "edges",
  "coverage",
  "state",
  "truncated",
  "limited",
]);

/** Fields a bounded dependency-path result declares. */
export const DEPENDENCY_PATH_RESULT_FIELDS = Object.freeze([
  "nodes",
  "edges",
  "found",
  "coverage",
  "state",
  "truncated",
  "limited",
]);

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

const GUARANTEE_VALUES = Object.freeze(Object.values(COVERAGE_GUARANTEES));

function createEnvelope(fields, input) {
  const envelope = {};
  for (const field of fields) envelope[field] = input[field];
  return envelope;
}

/**
 * Build an entity-collection result draft.
 * @param {object} [input] `{ entities, coverage, truncated }`
 */
export function createEntityQueryResult(input = {}) {
  return createEnvelope(ENTITY_QUERY_RESULT_FIELDS, {
    entities: input.entities ?? [],
    coverage: input.coverage,
    truncated: input.truncated === true,
  });
}

/** Build a relationship-collection result draft. */
export function createRelationshipQueryResult(input = {}) {
  return createEnvelope(RELATIONSHIP_QUERY_RESULT_FIELDS, {
    relationships: input.relationships ?? [],
    coverage: input.coverage,
    truncated: input.truncated === true,
  });
}

/** Build an evidence-collection result draft. */
export function createEvidenceQueryResult(input = {}) {
  return createEnvelope(EVIDENCE_QUERY_RESULT_FIELDS, {
    evidence: input.evidence ?? [],
    coverage: input.coverage,
    truncated: input.truncated === true,
  });
}

/** Build a bounded-traversal result draft. */
export function createTraversalResult(input = {}) {
  return createEnvelope(TRAVERSAL_RESULT_FIELDS, {
    entities: input.entities ?? [],
    relationships: input.relationships ?? [],
    coverage: input.coverage,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Build a whole-dependency-graph result draft. */
export function createDependencyGraphResult(input = {}) {
  return createEnvelope(DEPENDENCY_GRAPH_RESULT_FIELDS, {
    nodes: input.nodes ?? [],
    edges: input.edges ?? [],
    coverage: input.coverage,
    state: input.state,
    established: input.established === true,
    truncated: input.truncated === true,
  });
}

/** Build a bounded dependency-graph traversal result draft. */
export function createDependencyTraversalResult(input = {}) {
  return createEnvelope(DEPENDENCY_TRAVERSAL_RESULT_FIELDS, {
    nodes: input.nodes ?? [],
    edges: input.edges ?? [],
    coverage: input.coverage,
    state: input.state,
    established: input.established === true,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Build a bounded dependency edge-list result draft. */
export function createDependencyEdgeQueryResult(input = {}) {
  return createEnvelope(DEPENDENCY_EDGE_RESULT_FIELDS, {
    edges: input.edges ?? [],
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Build a bounded dependency-path result draft. */
export function createDependencyPathResult(input = {}) {
  return createEnvelope(DEPENDENCY_PATH_RESULT_FIELDS, {
    nodes: input.nodes ?? [],
    edges: input.edges ?? [],
    found: input.found === true,
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

function validateEnvelope(value, fields, arrayFields, contract) {
  const issues = [];
  const fail = (path, message) => issues.push(`${path}: ${message}`);

  if (!isPlainObject(value)) {
    throw new ValidationError(`Invalid ${contract}`, {
      details: { contract, issues: ["result: must be a plain object"] },
    });
  }

  for (const field of fields) {
    if (!(field in value)) fail(`${contract}.${field}`, "is required");
  }

  for (const field of arrayFields) {
    if (!Array.isArray(value[field])) {
      fail(`${contract}.${field}`, "must be an array");
    } else {
      value[field].forEach((entry, index) => {
        if (!isPlainObject(entry)) {
          fail(`${contract}.${field}[${index}]`, "must be a plain object");
        }
      });
    }
  }

  if (!GUARANTEE_VALUES.includes(value.coverage)) {
    fail(`${contract}.coverage`, `must be one of: ${GUARANTEE_VALUES.join(", ")}`);
  }
  if (typeof value.truncated !== "boolean") {
    fail(`${contract}.truncated`, "must be a boolean");
  }
  if ("limited" in value && typeof value.limited !== "boolean") {
    fail(`${contract}.limited`, "must be a boolean");
  }

  if (issues.length > 0) {
    throw new ValidationError(`Invalid ${contract}`, { details: { contract, issues } });
  }
  return value;
}

/** Validate an entity-collection result. */
export function validateEntityQueryResult(value) {
  return validateEnvelope(value, ENTITY_QUERY_RESULT_FIELDS, ["entities"], "EntityQueryResult");
}

/** Validate a relationship-collection result. */
export function validateRelationshipQueryResult(value) {
  return validateEnvelope(
    value,
    RELATIONSHIP_QUERY_RESULT_FIELDS,
    ["relationships"],
    "RelationshipQueryResult",
  );
}

/** Validate an evidence-collection result. */
export function validateEvidenceQueryResult(value) {
  return validateEnvelope(value, EVIDENCE_QUERY_RESULT_FIELDS, ["evidence"], "EvidenceQueryResult");
}

/** Validate a bounded-traversal result. */
export function validateTraversalResult(value) {
  const validated = validateEnvelope(
    value,
    TRAVERSAL_RESULT_FIELDS,
    ["entities", "relationships"],
    "TraversalResult",
  );
  return validated;
}

/**
 * The extra checks every graph result shares.
 *
 * `state` must be one of the closed graph states and `established` must be a
 * boolean, so a consumer can branch on them without defensively guessing. The
 * graph-specific booleans are checked per contract below.
 */
function validateGraphEnvelope(value, fields, arrayFields, contract, booleanFields) {
  validateEnvelope(value, fields, arrayFields, contract);

  const issues = [];
  if (!DEPENDENCY_GRAPH_STATE_VALUES.includes(value.state)) {
    issues.push(
      `${contract}.state: must be one of: ${DEPENDENCY_GRAPH_STATE_VALUES.join(", ")}`,
    );
  }
  for (const field of booleanFields) {
    if (typeof value[field] !== "boolean") {
      issues.push(`${contract}.${field}: must be a boolean`);
    }
  }

  if (issues.length > 0) {
    throw new ValidationError(`Invalid ${contract}`, { details: { contract, issues } });
  }
  return value;
}

/** Validate a whole-dependency-graph result. */
export function validateDependencyGraphResult(value) {
  return validateGraphEnvelope(
    value,
    DEPENDENCY_GRAPH_RESULT_FIELDS,
    ["nodes", "edges"],
    "DependencyGraphResult",
    ["established", "truncated"],
  );
}

/** Validate a bounded dependency-graph traversal result. */
export function validateDependencyTraversalResult(value) {
  return validateGraphEnvelope(
    value,
    DEPENDENCY_TRAVERSAL_RESULT_FIELDS,
    ["nodes", "edges"],
    "DependencyTraversalResult",
    ["established", "truncated", "limited"],
  );
}

/** Validate a bounded dependency edge-list result. */
export function validateDependencyEdgeQueryResult(value) {
  return validateGraphEnvelope(
    value,
    DEPENDENCY_EDGE_RESULT_FIELDS,
    ["edges"],
    "DependencyEdgeQueryResult",
    ["truncated", "limited"],
  );
}

/** Validate a bounded dependency-path result. */
export function validateDependencyPathResult(value) {
  return validateGraphEnvelope(
    value,
    DEPENDENCY_PATH_RESULT_FIELDS,
    ["nodes", "edges"],
    "DependencyPathResult",
    ["found", "truncated", "limited"],
  );
}
