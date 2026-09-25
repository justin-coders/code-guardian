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

import { ARCHITECTURE_GRAPH_STATE_VALUES } from "./architecture-graph.js";
import { DEPENDENCY_GRAPH_STATE_VALUES } from "./dependency-graph.js";
import { IMPORT_GRAPH_STATE_VALUES } from "./import-graph.js";
import {
  SYMBOL_GRAPH_STATE_VALUES,
  SYMBOL_UNRESOLVED_KINDS,
  SYMBOL_UNRESOLVED_REASON_VALUES,
} from "./symbol-graph.js";
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

/**
 * Fields a whole-architecture-graph result declares.
 *
 * Same two-coverage split as the dependency graph: `coverage`/`truncated` are the
 * scan's guarantee (how much of the repository was inventoried), while
 * `state`/`established` are the graph's own answer (was an architecture established
 * at all, and how completely).
 */
export const ARCHITECTURE_GRAPH_RESULT_FIELDS = Object.freeze([
  "nodes",
  "edges",
  "coverage",
  "state",
  "established",
  "truncated",
]);

/** Fields a bounded architecture-node result declares. */
export const ARCHITECTURE_NODE_RESULT_FIELDS = Object.freeze([
  "nodes",
  "coverage",
  "state",
  "truncated",
  "limited",
]);

/** Fields a bounded architecture edge-list result declares. */
export const ARCHITECTURE_EDGE_RESULT_FIELDS = Object.freeze([
  "edges",
  "coverage",
  "state",
  "truncated",
  "limited",
]);

/** Fields a bounded architecture-path result declares. */
export const ARCHITECTURE_PATH_RESULT_FIELDS = Object.freeze([
  "nodes",
  "edges",
  "found",
  "coverage",
  "state",
  "truncated",
  "limited",
]);

/** Fields a bounded container-declaration result declares. */
export const ARCHITECTURE_BUILD_RESULT_FIELDS = Object.freeze([
  "declarations",
  "coverage",
  "state",
  "truncated",
  "limited",
]);

/** Fields a bounded framework-usage result declares. */
export const FRAMEWORK_USAGE_RESULT_FIELDS = Object.freeze([
  "frameworks",
  "coverage",
  "state",
  "truncated",
  "limited",
]);

/**
 * Fields the import graph's results declare.
 *
 * Same two-coverage split as the other graph results, and the same reason for it:
 * `coverage`/`truncated` are the scan's guarantee (how much of the repository was
 * inventoried), while `state`/`established` are the import graph's own answer (was a
 * graph established at all, and how completely). `state` carries the import graph's
 * five values, so a caller can tell *the graph is complete*, *a bound was reached*
 * and *nothing was established* apart without inferring them from counts.
 */
export const IMPORT_GRAPH_RESULT_FIELDS = Object.freeze([
  "nodes",
  "edges",
  "coverage",
  "state",
  "established",
  "truncated",
]);

/** Fields a bounded import traversal result declares. */
export const IMPORT_TRAVERSAL_RESULT_FIELDS = Object.freeze([
  ...IMPORT_GRAPH_RESULT_FIELDS,
  "limited",
]);

export const IMPORT_NODE_RESULT_FIELDS = Object.freeze([
  "nodes",
  "coverage",
  "state",
  "truncated",
  "limited",
]);

export const IMPORT_EDGE_RESULT_FIELDS = Object.freeze([
  "edges",
  "coverage",
  "state",
  "truncated",
  "limited",
]);

/**
 * Fields a bounded unresolved-reference result declares.
 *
 * `unresolved` is deliberately not named `edges`: these records are references the
 * repository does *not* establish a target for, and a caller that received them as
 * edges would be reading a non-fact as a fact.
 */
export const IMPORT_UNRESOLVED_RESULT_FIELDS = Object.freeze([
  "unresolved",
  "coverage",
  "state",
  "truncated",
  "limited",
]);

/** Fields a whole-symbol-graph result declares. */
export const SYMBOL_GRAPH_RESULT_FIELDS = Object.freeze([
  "nodes",
  "edges",
  "coverage",
  "state",
  "established",
  "truncated",
]);

/** Fields a bounded symbol traversal declares. */
export const SYMBOL_TRAVERSAL_RESULT_FIELDS = Object.freeze([
  ...SYMBOL_GRAPH_RESULT_FIELDS,
  "limited",
]);

/** Fields a bounded symbol-node list declares. */
export const SYMBOL_NODE_RESULT_FIELDS = Object.freeze([
  "nodes",
  "coverage",
  "state",
  "truncated",
  "limited",
]);

/** Fields a bounded symbol-edge list declares. */
export const SYMBOL_EDGE_RESULT_FIELDS = Object.freeze([
  "edges",
  "coverage",
  "state",
  "truncated",
  "limited",
]);

/** Fields a bounded symbol-reference result declares. */
export const SYMBOL_REFERENCE_RESULT_FIELDS = Object.freeze([
  "symbol",
  "references",
  "calls",
  "coverage",
  "state",
  "truncated",
  "limited",
]);

/** Fields a bounded unresolved-occurrence list declares. */
export const SYMBOL_UNRESOLVED_RESULT_FIELDS = Object.freeze([
  "unresolved",
  "coverage",
  "state",
  "truncated",
  "limited",
]);

/** Fields a bounded import-binding list declares. */
export const SYMBOL_BINDING_RESULT_FIELDS = Object.freeze([
  "bindings",
  "unresolved",
  "coverage",
  "state",
  "truncated",
  "limited",
]);

/** Fields a bounded symbol-path result declares. */
export const SYMBOL_PATH_RESULT_FIELDS = Object.freeze([
  "nodes",
  "edges",
  "found",
  "coverage",
  "state",
  "truncated",
  "limited",
]);

/**
 * The vocabularies a symbol query validates its criteria against.
 *
 * Re-exported here so a consumer (or a test) can ask the query layer what it accepts
 * without importing the projection module.
 */
export const SYMBOL_UNRESOLVED_KIND_VALUES = SYMBOL_UNRESOLVED_KINDS;
export const SYMBOL_UNRESOLVED_REASONS = SYMBOL_UNRESOLVED_REASON_VALUES;

/** Fields a bounded import-path result declares. */
export const IMPORT_PATH_RESULT_FIELDS = Object.freeze([
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

/** Build a whole-architecture-graph result draft. */
export function createArchitectureGraphResult(input = {}) {
  return createEnvelope(ARCHITECTURE_GRAPH_RESULT_FIELDS, {
    nodes: input.nodes ?? [],
    edges: input.edges ?? [],
    coverage: input.coverage,
    state: input.state,
    established: input.established === true,
    truncated: input.truncated === true,
  });
}

/** Build a bounded architecture-node result draft. */
export function createArchitectureNodeQueryResult(input = {}) {
  return createEnvelope(ARCHITECTURE_NODE_RESULT_FIELDS, {
    nodes: input.nodes ?? [],
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Build a bounded architecture edge-list result draft. */
export function createArchitectureEdgeQueryResult(input = {}) {
  return createEnvelope(ARCHITECTURE_EDGE_RESULT_FIELDS, {
    edges: input.edges ?? [],
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Build a bounded architecture-path result draft. */
export function createArchitecturePathResult(input = {}) {
  return createEnvelope(ARCHITECTURE_PATH_RESULT_FIELDS, {
    nodes: input.nodes ?? [],
    edges: input.edges ?? [],
    found: input.found === true,
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Build a bounded container-declaration result draft. */
export function createArchitectureBuildQueryResult(input = {}) {
  return createEnvelope(ARCHITECTURE_BUILD_RESULT_FIELDS, {
    declarations: input.declarations ?? [],
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Build a bounded framework-usage result draft. */
export function createFrameworkUsageQueryResult(input = {}) {
  return createEnvelope(FRAMEWORK_USAGE_RESULT_FIELDS, {
    frameworks: input.frameworks ?? [],
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Build a whole-import-graph result draft. */
export function createImportGraphResult(input = {}) {
  return createEnvelope(IMPORT_GRAPH_RESULT_FIELDS, {
    nodes: input.nodes ?? [],
    edges: input.edges ?? [],
    coverage: input.coverage,
    state: input.state,
    established: input.established === true,
    truncated: input.truncated === true,
  });
}

/** Build a bounded import-traversal result draft. */
export function createImportTraversalResult(input = {}) {
  return createEnvelope(IMPORT_TRAVERSAL_RESULT_FIELDS, {
    nodes: input.nodes ?? [],
    edges: input.edges ?? [],
    coverage: input.coverage,
    state: input.state,
    established: input.established === true,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Build a bounded import-node result draft. */
export function createImportNodeQueryResult(input = {}) {
  return createEnvelope(IMPORT_NODE_RESULT_FIELDS, {
    nodes: input.nodes ?? [],
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Build a bounded import edge-list result draft. */
export function createImportEdgeQueryResult(input = {}) {
  return createEnvelope(IMPORT_EDGE_RESULT_FIELDS, {
    edges: input.edges ?? [],
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Build a bounded unresolved-reference result draft. */
export function createImportUnresolvedQueryResult(input = {}) {
  return createEnvelope(IMPORT_UNRESOLVED_RESULT_FIELDS, {
    unresolved: input.unresolved ?? [],
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Build a bounded import-path result draft. */
export function createImportPathResult(input = {}) {
  return createEnvelope(IMPORT_PATH_RESULT_FIELDS, {
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
function validateGraphEnvelope(
  value,
  fields,
  arrayFields,
  contract,
  booleanFields,
  stateValues = DEPENDENCY_GRAPH_STATE_VALUES,
) {
  validateEnvelope(value, fields, arrayFields, contract);

  const issues = [];
  if (!stateValues.includes(value.state)) {
    issues.push(`${contract}.state: must be one of: ${stateValues.join(", ")}`);
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

/** Validate a whole-architecture-graph result. */
export function validateArchitectureGraphResult(value) {
  return validateGraphEnvelope(
    value,
    ARCHITECTURE_GRAPH_RESULT_FIELDS,
    ["nodes", "edges"],
    "ArchitectureGraphResult",
    ["established", "truncated"],
    ARCHITECTURE_GRAPH_STATE_VALUES,
  );
}

/** Validate a bounded architecture-node result. */
export function validateArchitectureNodeQueryResult(value) {
  return validateGraphEnvelope(
    value,
    ARCHITECTURE_NODE_RESULT_FIELDS,
    ["nodes"],
    "ArchitectureNodeQueryResult",
    ["truncated", "limited"],
    ARCHITECTURE_GRAPH_STATE_VALUES,
  );
}

/** Validate a bounded architecture edge-list result. */
export function validateArchitectureEdgeQueryResult(value) {
  return validateGraphEnvelope(
    value,
    ARCHITECTURE_EDGE_RESULT_FIELDS,
    ["edges"],
    "ArchitectureEdgeQueryResult",
    ["truncated", "limited"],
    ARCHITECTURE_GRAPH_STATE_VALUES,
  );
}

/** Validate a bounded architecture-path result. */
export function validateArchitecturePathResult(value) {
  return validateGraphEnvelope(
    value,
    ARCHITECTURE_PATH_RESULT_FIELDS,
    ["nodes", "edges"],
    "ArchitecturePathResult",
    ["found", "truncated", "limited"],
    ARCHITECTURE_GRAPH_STATE_VALUES,
  );
}

/** Validate a bounded container-declaration result. */
export function validateArchitectureBuildQueryResult(value) {
  return validateGraphEnvelope(
    value,
    ARCHITECTURE_BUILD_RESULT_FIELDS,
    ["declarations"],
    "ArchitectureBuildQueryResult",
    ["truncated", "limited"],
    ARCHITECTURE_GRAPH_STATE_VALUES,
  );
}

/** Validate a bounded framework-usage result. */
export function validateFrameworkUsageQueryResult(value) {
  return validateGraphEnvelope(
    value,
    FRAMEWORK_USAGE_RESULT_FIELDS,
    ["frameworks"],
    "FrameworkUsageQueryResult",
    ["truncated", "limited"],
    ARCHITECTURE_GRAPH_STATE_VALUES,
  );
}

/** Build a whole-symbol-graph result draft. */
export function createSymbolGraphResult(input = {}) {
  return createEnvelope(SYMBOL_GRAPH_RESULT_FIELDS, {
    nodes: input.nodes ?? [],
    edges: input.edges ?? [],
    coverage: input.coverage,
    state: input.state,
    established: input.established === true,
    truncated: input.truncated === true,
  });
}

/** Build a bounded symbol-traversal result draft. */
export function createSymbolTraversalResult(input = {}) {
  return createEnvelope(SYMBOL_TRAVERSAL_RESULT_FIELDS, {
    nodes: input.nodes ?? [],
    edges: input.edges ?? [],
    coverage: input.coverage,
    state: input.state,
    established: input.established === true,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Build a bounded symbol-node result draft. */
export function createSymbolNodeQueryResult(input = {}) {
  return createEnvelope(SYMBOL_NODE_RESULT_FIELDS, {
    nodes: input.nodes ?? [],
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Build a bounded symbol-edge result draft. */
export function createSymbolEdgeQueryResult(input = {}) {
  return createEnvelope(SYMBOL_EDGE_RESULT_FIELDS, {
    edges: input.edges ?? [],
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Build a bounded symbol-reference result draft. */
export function createSymbolReferenceResult(input = {}) {
  return createEnvelope(SYMBOL_REFERENCE_RESULT_FIELDS, {
    symbol: input.symbol ?? null,
    references: input.references ?? [],
    calls: input.calls ?? [],
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Build a bounded unresolved-occurrence result draft. */
export function createSymbolUnresolvedQueryResult(input = {}) {
  return createEnvelope(SYMBOL_UNRESOLVED_RESULT_FIELDS, {
    unresolved: input.unresolved ?? [],
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Build a bounded import-binding result draft. */
export function createSymbolBindingQueryResult(input = {}) {
  return createEnvelope(SYMBOL_BINDING_RESULT_FIELDS, {
    bindings: input.bindings ?? [],
    unresolved: input.unresolved ?? [],
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Build a bounded symbol-path result draft. */
export function createSymbolPathResult(input = {}) {
  return createEnvelope(SYMBOL_PATH_RESULT_FIELDS, {
    nodes: input.nodes ?? [],
    edges: input.edges ?? [],
    found: input.found === true,
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Validate a whole-import-graph result. */
export function validateImportGraphResult(value) {
  return validateGraphEnvelope(
    value,
    IMPORT_GRAPH_RESULT_FIELDS,
    ["nodes", "edges"],
    "ImportGraphResult",
    ["established", "truncated"],
    IMPORT_GRAPH_STATE_VALUES,
  );
}

/** Validate a bounded import-traversal result. */
export function validateImportTraversalResult(value) {
  return validateGraphEnvelope(
    value,
    IMPORT_TRAVERSAL_RESULT_FIELDS,
    ["nodes", "edges"],
    "ImportTraversalResult",
    ["established", "truncated", "limited"],
    IMPORT_GRAPH_STATE_VALUES,
  );
}

/** Validate a bounded import-node result. */
export function validateImportNodeQueryResult(value) {
  return validateGraphEnvelope(
    value,
    IMPORT_NODE_RESULT_FIELDS,
    ["nodes"],
    "ImportNodeQueryResult",
    ["truncated", "limited"],
    IMPORT_GRAPH_STATE_VALUES,
  );
}

/** Validate a whole-symbol-graph result. */
export function validateSymbolGraphResult(value) {
  return validateGraphEnvelope(
    value,
    SYMBOL_GRAPH_RESULT_FIELDS,
    ["nodes", "edges"],
    "SymbolGraphResult",
    ["established", "truncated"],
    SYMBOL_GRAPH_STATE_VALUES,
  );
}

/** Validate a bounded symbol-traversal result. */
export function validateSymbolTraversalResult(value) {
  return validateGraphEnvelope(
    value,
    SYMBOL_TRAVERSAL_RESULT_FIELDS,
    ["nodes", "edges"],
    "SymbolTraversalResult",
    ["established", "truncated", "limited"],
    SYMBOL_GRAPH_STATE_VALUES,
  );
}

/** Validate a bounded symbol-node result. */
export function validateSymbolNodeQueryResult(value) {
  return validateGraphEnvelope(
    value,
    SYMBOL_NODE_RESULT_FIELDS,
    ["nodes"],
    "SymbolNodeQueryResult",
    ["truncated", "limited"],
    SYMBOL_GRAPH_STATE_VALUES,
  );
}

/** Validate a bounded symbol-edge result. */
export function validateSymbolEdgeQueryResult(value) {
  return validateGraphEnvelope(
    value,
    SYMBOL_EDGE_RESULT_FIELDS,
    ["edges"],
    "SymbolEdgeQueryResult",
    ["truncated", "limited"],
    SYMBOL_GRAPH_STATE_VALUES,
  );
}

/** Validate a bounded symbol-reference result. */
export function validateSymbolReferenceResult(value) {
  return validateGraphEnvelope(
    value,
    SYMBOL_REFERENCE_RESULT_FIELDS,
    ["references", "calls"],
    "SymbolReferenceResult",
    ["truncated", "limited"],
    SYMBOL_GRAPH_STATE_VALUES,
  );
}

/** Validate a bounded unresolved-occurrence result. */
export function validateSymbolUnresolvedQueryResult(value) {
  return validateGraphEnvelope(
    value,
    SYMBOL_UNRESOLVED_RESULT_FIELDS,
    ["unresolved"],
    "SymbolUnresolvedQueryResult",
    ["truncated", "limited"],
    SYMBOL_GRAPH_STATE_VALUES,
  );
}

/** Validate a bounded import-binding result. */
export function validateSymbolBindingQueryResult(value) {
  return validateGraphEnvelope(
    value,
    SYMBOL_BINDING_RESULT_FIELDS,
    ["bindings", "unresolved"],
    "SymbolBindingQueryResult",
    ["truncated", "limited"],
    SYMBOL_GRAPH_STATE_VALUES,
  );
}

/** Validate a bounded symbol-path result. */
export function validateSymbolPathResult(value) {
  return validateGraphEnvelope(
    value,
    SYMBOL_PATH_RESULT_FIELDS,
    ["nodes", "edges"],
    "SymbolPathResult",
    ["found", "truncated", "limited"],
    SYMBOL_GRAPH_STATE_VALUES,
  );
}

/** Validate a bounded import edge-list result. */
export function validateImportEdgeQueryResult(value) {
  return validateGraphEnvelope(
    value,
    IMPORT_EDGE_RESULT_FIELDS,
    ["edges"],
    "ImportEdgeQueryResult",
    ["truncated", "limited"],
    IMPORT_GRAPH_STATE_VALUES,
  );
}

/** Validate a bounded unresolved-reference result. */
export function validateImportUnresolvedQueryResult(value) {
  return validateGraphEnvelope(
    value,
    IMPORT_UNRESOLVED_RESULT_FIELDS,
    ["unresolved"],
    "ImportUnresolvedQueryResult",
    ["truncated", "limited"],
    IMPORT_GRAPH_STATE_VALUES,
  );
}

/** Validate a bounded import-path result. */
export function validateImportPathResult(value) {
  return validateGraphEnvelope(
    value,
    IMPORT_PATH_RESULT_FIELDS,
    ["nodes", "edges"],
    "ImportPathResult",
    ["found", "truncated", "limited"],
    IMPORT_GRAPH_STATE_VALUES,
  );
}
