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

import {
  COMPLIANCE_CHECK_IDS as COMPLIANCE_CHECK_IDS_SOURCE,
  COMPLIANCE_LIMITS as COMPLIANCE_LIMITS_SOURCE,
  COMPLIANCE_OBSERVED_VALUES as COMPLIANCE_OBSERVED_VALUES_SOURCE,
  COMPLIANCE_SECTIONS as COMPLIANCE_SECTIONS_SOURCE,
  COMPLIANCE_SECTION_STATE_VALUES as COMPLIANCE_SECTION_STATE_VALUES_SOURCE,
  COMPLIANCE_STATE_VALUES as COMPLIANCE_STATE_VALUES_SOURCE,
  COMPLIANCE_STATUSES as COMPLIANCE_STATUSES_SOURCE,
  COMPLIANCE_STATUS_VALUES as COMPLIANCE_STATUS_VALUES_SOURCE,
  COMPLIANCE_VERSION,
  renderComplianceRationale,
} from "./compliance-report.js";
import {
  POLICY_DOCUMENT_KEYS as POLICY_DOCUMENT_KEYS_SOURCE,
  POLICY_DOCUMENT_PATH as POLICY_DOCUMENT_PATH_SOURCE,
  POLICY_DOCUMENT_VERSION as POLICY_DOCUMENT_VERSION_SOURCE,
  POLICY_STATE_VALUES as POLICY_STATE_VALUES_SOURCE,
  POLICY_UNKNOWN_REASON_VALUES as POLICY_UNKNOWN_REASON_VALUES_SOURCE,
} from "./policy.js";
// Phase 24 — the pack vocabulary the policy answers are checked against. A pack reference is a
// closed grammar, so a provenance or pack answer naming something outside it is refused here rather
// than handed to a caller as a token that merely looks like a pack.
import {
  POLICY_PACK_ORIGIN_VALUES,
  isPackReference,
  isPresetName,
  packReference,
} from "../../policy/index.js";
import { ARCHITECTURE_GRAPH_STATE_VALUES } from "./architecture-graph.js";
import { DEPENDENCY_GRAPH_STATE_VALUES } from "./dependency-graph.js";
import { IMPORT_GRAPH_STATE_VALUES } from "./import-graph.js";
import {
  SYMBOL_GRAPH_STATE_VALUES,
  SYMBOL_UNRESOLVED_KINDS,
  SYMBOL_UNRESOLVED_REASON_VALUES,
} from "./symbol-graph.js";
import {
  API_GRAPH_STATE_VALUES,
  API_UNRESOLVED_KINDS,
  API_UNRESOLVED_REASON_VALUES,
} from "./api-graph.js";
import {
  MIDDLEWARE_CLASSIFICATION_VALUES as MIDDLEWARE_CLASSIFICATION_VALUES_SOURCE,
  MIDDLEWARE_GRAPH_STATE_VALUES as MIDDLEWARE_GRAPH_STATE_VALUES_SOURCE,
  MIDDLEWARE_PROTECTION_VALUES as MIDDLEWARE_PROTECTION_VALUES_SOURCE,
  MIDDLEWARE_REGISTRATIONS as MIDDLEWARE_GRAPH_REGISTRATIONS_SOURCE,
  MIDDLEWARE_SCOPES as MIDDLEWARE_GRAPH_SCOPES_SOURCE,
  MIDDLEWARE_UNRESOLVED_KINDS as MIDDLEWARE_UNRESOLVED_KINDS_SOURCE,
  MIDDLEWARE_UNRESOLVED_REASON_VALUES as MIDDLEWARE_UNRESOLVED_REASON_VALUES_SOURCE,
} from "./middleware-graph.js";
import {
  PRODUCTION_OBSERVATION_KINDS as PRODUCTION_OBSERVATION_KINDS_SOURCE,
  PRODUCTION_REPORT_STATE_VALUES as PRODUCTION_REPORT_STATE_VALUES_SOURCE,
  PRODUCTION_REPORT_VERSION,
  PRODUCTION_SECTIONS as PRODUCTION_SECTIONS_SOURCE,
  PRODUCTION_UNKNOWN_REASONS as PRODUCTION_UNKNOWN_REASONS_SOURCE,
} from "./production-report.js";
import {
  PRODUCTION_RISK_CLASSIFICATION_VALUES as PRODUCTION_RISK_CLASSIFICATION_VALUES_SOURCE,
  PRODUCTION_RISK_FINDING_KINDS as PRODUCTION_RISK_FINDING_KINDS_SOURCE,
  PRODUCTION_RISK_REPORT_VERSION,
  PRODUCTION_RISK_SECTIONS as PRODUCTION_RISK_SECTIONS_SOURCE,
  PRODUCTION_RISK_SEVERITY_VALUES as PRODUCTION_RISK_SEVERITY_VALUES_SOURCE,
  PRODUCTION_RISK_STATE_VALUES as PRODUCTION_RISK_STATE_VALUES_SOURCE,
  PRODUCTION_RISK_UNKNOWN_REASONS as PRODUCTION_RISK_UNKNOWN_REASONS_SOURCE,
} from "./production-risk-report.js";
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

/** Fields a whole-API-graph result declares. */
export const API_GRAPH_RESULT_FIELDS = Object.freeze([
  "nodes",
  "edges",
  "coverage",
  "state",
  "established",
  "truncated",
]);

/** Fields a bounded route list declares. */
export const API_ROUTE_RESULT_FIELDS = Object.freeze([
  "routes",
  "coverage",
  "state",
  "truncated",
  "limited",
]);

/** Fields a single-route lookup declares. */
export const API_ROUTE_LOOKUP_RESULT_FIELDS = Object.freeze([
  "route",
  "coverage",
  "state",
  "truncated",
]);

/** Fields a route's handler list declares. */
export const API_ROUTE_HANDLER_RESULT_FIELDS = Object.freeze([
  "route",
  "handlers",
  "coverage",
  "state",
  "truncated",
  "limited",
]);

/**
 * Fields a route's middleware answer declares.
 *
 * Phase 19 extended this envelope rather than adding a second method with the same name:
 * `middleware` is the route-scope middleware the API graph resolved from the route's own
 * declaration, `applied` is the receiver-scope middleware the middleware graph established
 * for the route, and `unresolved` and `protection` are the middleware graph's answer for
 * the occurrences it could not establish. One method, one route, one coherent answer.
 */
export const API_ROUTE_MIDDLEWARE_RESULT_FIELDS = Object.freeze([
  "route",
  "middleware",
  "applied",
  "unresolved",
  "protection",
  "coverage",
  "state",
  "truncated",
  "limited",
]);

/** Fields a symbol's route list declares. */
export const API_HANDLER_ROUTE_RESULT_FIELDS = Object.freeze([
  "symbol",
  "routes",
  "coverage",
  "state",
  "truncated",
  "limited",
]);

/** Fields a bounded handler-module list declares. */
export const API_SERVICE_RESULT_FIELDS = Object.freeze([
  "modules",
  "coverage",
  "state",
  "truncated",
  "limited",
]);

/** Fields a bounded unresolved-route list declares. */
export const API_UNRESOLVED_ROUTE_RESULT_FIELDS = Object.freeze([
  "unresolved",
  "coverage",
  "state",
  "truncated",
  "limited",
]);

/**
 * The vocabularies an API query validates its criteria against.
 *
 * Re-exported so a consumer can ask the query layer what it accepts without importing
 * the projection module.
 */
export const API_UNRESOLVED_KIND_VALUES = API_UNRESOLVED_KINDS;
export const API_UNRESOLVED_REASONS = API_UNRESOLVED_REASON_VALUES;
export const API_ROUTE_STATE_VALUES = API_GRAPH_STATE_VALUES;

/** Fields a whole-middleware-graph result declares. */
export const MIDDLEWARE_GRAPH_RESULT_FIELDS = Object.freeze([
  "nodes",
  "edges",
  "routes",
  "coverage",
  "state",
  "established",
  "truncated",
]);

/** Fields a bounded middleware-node list declares. */
export const MIDDLEWARE_RESULT_FIELDS = Object.freeze([
  "middleware",
  "coverage",
  "state",
  "truncated",
  "limited",
]);

/** Fields a middleware node's route list declares. */
export const MIDDLEWARE_PROTECTED_ROUTE_RESULT_FIELDS = Object.freeze([
  "symbol",
  "routes",
  "coverage",
  "state",
  "truncated",
  "limited",
]);

/** Fields a bounded middleware-chain list declares. */
export const MIDDLEWARE_CHAIN_RESULT_FIELDS = Object.freeze([
  "chains",
  "coverage",
  "state",
  "truncated",
  "limited",
]);

/** Fields a bounded unresolved-middleware list declares. */
export const MIDDLEWARE_UNRESOLVED_RESULT_FIELDS = Object.freeze([
  "unresolved",
  "coverage",
  "state",
  "truncated",
  "limited",
]);

/**
 * The vocabularies a middleware query validates its criteria against.
 *
 * Re-exported so a consumer can ask the query layer what it accepts without importing the
 * projection module.
 */
export const MIDDLEWARE_CLASSIFICATION_VALUES = MIDDLEWARE_CLASSIFICATION_VALUES_SOURCE;
export const MIDDLEWARE_PROTECTION_VALUES = MIDDLEWARE_PROTECTION_VALUES_SOURCE;
export const MIDDLEWARE_SCOPE_VALUES = MIDDLEWARE_GRAPH_SCOPES_SOURCE;
export const MIDDLEWARE_REGISTRATION_VALUES = MIDDLEWARE_GRAPH_REGISTRATIONS_SOURCE;
export const MIDDLEWARE_UNRESOLVED_KIND_VALUES = MIDDLEWARE_UNRESOLVED_KINDS_SOURCE;
export const MIDDLEWARE_UNRESOLVED_REASON_VALUES = MIDDLEWARE_UNRESOLVED_REASON_VALUES_SOURCE;
export const MIDDLEWARE_STATE_VALUES = MIDDLEWARE_GRAPH_STATE_VALUES_SOURCE;

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

// ── API & Service graph results (Phase 18) ───────────────────────────────────

/** Build a whole-API-graph result draft. */
export function createApiGraphResult(input = {}) {
  return createEnvelope(API_GRAPH_RESULT_FIELDS, {
    nodes: input.nodes ?? [],
    edges: input.edges ?? [],
    coverage: input.coverage,
    state: input.state,
    established: input.established === true,
    truncated: input.truncated === true,
  });
}

/** Build a bounded route-list result draft. */
export function createApiRouteQueryResult(input = {}) {
  return createEnvelope(API_ROUTE_RESULT_FIELDS, {
    routes: input.routes ?? [],
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Build a single-route lookup result draft. */
export function createApiRouteLookupResult(input = {}) {
  return createEnvelope(API_ROUTE_LOOKUP_RESULT_FIELDS, {
    route: input.route ?? null,
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
  });
}

/** Build a route's handler-list result draft. */
export function createApiRouteHandlerResult(input = {}) {
  return createEnvelope(API_ROUTE_HANDLER_RESULT_FIELDS, {
    route: input.route ?? null,
    handlers: input.handlers ?? [],
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Build a route's middleware result draft. */
export function createApiRouteMiddlewareResult(input = {}) {
  return createEnvelope(API_ROUTE_MIDDLEWARE_RESULT_FIELDS, {
    route: input.route ?? null,
    middleware: input.middleware ?? [],
    applied: input.applied ?? [],
    unresolved: input.unresolved ?? [],
    protection: input.protection === undefined ? null : input.protection,
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Build a symbol's route-list result draft. */
export function createApiHandlerRouteResult(input = {}) {
  return createEnvelope(API_HANDLER_ROUTE_RESULT_FIELDS, {
    symbol: input.symbol ?? null,
    routes: input.routes ?? [],
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Build a bounded handler-module list result draft. */
export function createApiServiceResult(input = {}) {
  return createEnvelope(API_SERVICE_RESULT_FIELDS, {
    modules: input.modules ?? [],
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Build a bounded unresolved-route result draft. */
export function createApiUnresolvedRouteResult(input = {}) {
  return createEnvelope(API_UNRESOLVED_ROUTE_RESULT_FIELDS, {
    unresolved: input.unresolved ?? [],
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Validate a whole-API-graph result. */
export function validateApiGraphResult(value) {
  return validateGraphEnvelope(
    value,
    API_GRAPH_RESULT_FIELDS,
    ["nodes", "edges"],
    "ApiGraphResult",
    ["established", "truncated"],
    API_GRAPH_STATE_VALUES,
  );
}

/** Validate a bounded route-list result. */
export function validateApiRouteQueryResult(value) {
  return validateGraphEnvelope(
    value,
    API_ROUTE_RESULT_FIELDS,
    ["routes"],
    "ApiRouteQueryResult",
    ["truncated", "limited"],
    API_GRAPH_STATE_VALUES,
  );
}

/** Validate a single-route lookup result. */
export function validateApiRouteLookupResult(value) {
  return validateGraphEnvelope(
    value,
    API_ROUTE_LOOKUP_RESULT_FIELDS,
    [],
    "ApiRouteLookupResult",
    ["truncated"],
    API_GRAPH_STATE_VALUES,
  );
}

/** Validate a route's handler-list result. */
export function validateApiRouteHandlerResult(value) {
  return validateGraphEnvelope(
    value,
    API_ROUTE_HANDLER_RESULT_FIELDS,
    ["handlers"],
    "ApiRouteHandlerResult",
    ["truncated", "limited"],
    API_GRAPH_STATE_VALUES,
  );
}

/** Validate a route's middleware result. */
export function validateApiRouteMiddlewareResult(value) {
  return validateGraphEnvelope(
    value,
    API_ROUTE_MIDDLEWARE_RESULT_FIELDS,
    ["middleware", "applied", "unresolved"],
    "ApiRouteMiddlewareResult",
    ["truncated", "limited"],
    API_GRAPH_STATE_VALUES,
  );
}

/** Validate a symbol's route-list result. */
export function validateApiHandlerRouteResult(value) {
  return validateGraphEnvelope(
    value,
    API_HANDLER_ROUTE_RESULT_FIELDS,
    ["routes"],
    "ApiHandlerRouteResult",
    ["truncated", "limited"],
    API_GRAPH_STATE_VALUES,
  );
}

/** Validate a bounded handler-module list result. */
export function validateApiServiceResult(value) {
  return validateGraphEnvelope(
    value,
    API_SERVICE_RESULT_FIELDS,
    ["modules"],
    "ApiServiceResult",
    ["truncated", "limited"],
    API_GRAPH_STATE_VALUES,
  );
}

/** Validate a bounded unresolved-route result. */
export function validateApiUnresolvedRouteResult(value) {
  return validateGraphEnvelope(
    value,
    API_UNRESOLVED_ROUTE_RESULT_FIELDS,
    ["unresolved"],
    "ApiUnresolvedRouteResult",
    ["truncated", "limited"],
    API_GRAPH_STATE_VALUES,
  );
}

// ── Middleware & authorization graph results (Phase 19) ──────────────────────

/** Build a whole-middleware-graph result draft. */
export function createMiddlewareGraphResult(input = {}) {
  return createEnvelope(MIDDLEWARE_GRAPH_RESULT_FIELDS, {
    nodes: input.nodes ?? [],
    edges: input.edges ?? [],
    routes: input.routes ?? [],
    coverage: input.coverage,
    state: input.state,
    established: input.established === true,
    truncated: input.truncated === true,
  });
}

/** Build a bounded middleware-node list draft. */
export function createMiddlewareQueryResult(input = {}) {
  return createEnvelope(MIDDLEWARE_RESULT_FIELDS, {
    middleware: input.middleware ?? [],
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Build a middleware node's route-list draft. */
export function createMiddlewareProtectedRouteResult(input = {}) {
  return createEnvelope(MIDDLEWARE_PROTECTED_ROUTE_RESULT_FIELDS, {
    symbol: input.symbol ?? null,
    routes: input.routes ?? [],
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Build a bounded middleware-chain list draft. */
export function createMiddlewareChainResult(input = {}) {
  return createEnvelope(MIDDLEWARE_CHAIN_RESULT_FIELDS, {
    chains: input.chains ?? [],
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Build a bounded unresolved-middleware list draft. */
export function createMiddlewareUnresolvedResult(input = {}) {
  return createEnvelope(MIDDLEWARE_UNRESOLVED_RESULT_FIELDS, {
    unresolved: input.unresolved ?? [],
    coverage: input.coverage,
    state: input.state,
    truncated: input.truncated === true,
    limited: input.limited === true,
  });
}

/** Validate a whole-middleware-graph result. */
export function validateMiddlewareGraphResult(value) {
  return validateGraphEnvelope(
    value,
    MIDDLEWARE_GRAPH_RESULT_FIELDS,
    ["nodes", "edges", "routes"],
    "MiddlewareGraphResult",
    ["established", "truncated"],
    MIDDLEWARE_GRAPH_STATE_VALUES_SOURCE,
  );
}

/** Validate a bounded middleware-node list. */
export function validateMiddlewareQueryResult(value) {
  return validateGraphEnvelope(
    value,
    MIDDLEWARE_RESULT_FIELDS,
    ["middleware"],
    "MiddlewareQueryResult",
    ["truncated", "limited"],
    MIDDLEWARE_GRAPH_STATE_VALUES_SOURCE,
  );
}

/** Validate a middleware node's route list. */
export function validateMiddlewareProtectedRouteResult(value) {
  return validateGraphEnvelope(
    value,
    MIDDLEWARE_PROTECTED_ROUTE_RESULT_FIELDS,
    ["routes"],
    "MiddlewareProtectedRouteResult",
    ["truncated", "limited"],
    MIDDLEWARE_GRAPH_STATE_VALUES_SOURCE,
  );
}

/** Validate a bounded middleware-chain list. */
export function validateMiddlewareChainResult(value) {
  return validateGraphEnvelope(
    value,
    MIDDLEWARE_CHAIN_RESULT_FIELDS,
    ["chains"],
    "MiddlewareChainResult",
    ["truncated", "limited"],
    MIDDLEWARE_GRAPH_STATE_VALUES_SOURCE,
  );
}

// ── Production report (Phase 20) ─────────────────────────────────────────────
//
// The production report is returned in full rather than wrapped: it *is* the projection,
// and its `coverage` is the report's own structured statement — six domains cannot be
// described by one guarantee string. Every method that hands a report or a section out
// validates it first, so a consumer never receives a malformed document from this layer.

/** Fields the production report declares. */
export const PRODUCTION_REPORT_RESULT_FIELDS = Object.freeze([
  "version",
  "state",
  "established",
  "sections",
  "coverage",
]);

/** Fields one production section declares. */
export const PRODUCTION_SECTION_RESULT_FIELDS = Object.freeze([
  "name",
  "title",
  "state",
  "established",
  "counts",
  "observations",
  "evidenceIds",
  "unknown",
  "coverage",
]);

/** Fields the report's structured coverage statement declares. */
export const PRODUCTION_COVERAGE_RESULT_FIELDS = Object.freeze([
  "state",
  "established",
  "complete",
  "truncated",
  "inspected",
  "sections",
  "observations",
  "evidence",
  "unknownReasons",
  "limits",
]);

/** The six audit domains, re-exported so a caller reads them from one place. */
export const PRODUCTION_SECTIONS = PRODUCTION_SECTIONS_SOURCE;

/** The report's coverage vocabulary, re-exported for the same reason. */
export const PRODUCTION_REPORT_STATE_VALUES = PRODUCTION_REPORT_STATE_VALUES_SOURCE;

/** Build a structured production-coverage draft. */
export function createProductionCoverageResult(input = {}) {
  return createEnvelope(PRODUCTION_COVERAGE_RESULT_FIELDS, {
    state: input.state,
    established: input.established === true,
    complete: input.complete === true,
    truncated: input.truncated === true,
    inspected: input.inspected === true,
    sections: input.sections ?? 0,
    observations: input.observations ?? 0,
    evidence: input.evidence ?? 0,
    unknownReasons: input.unknownReasons ?? {},
    limits: input.limits ?? {},
  });
}

/**
 * Validate a structured production-coverage statement.
 *
 * The counts are checked as non-negative integers rather than merely present, because a
 * coverage statement whose totals are wrong is exactly the kind of document that lets a
 * reader believe a bounded list is a complete one.
 */
export function validateProductionCoverageResult(value) {
  const contract = "ProductionCoverageResult";
  requireProductionFields(value, contract, PRODUCTION_COVERAGE_RESULT_FIELDS);
  const issues = [];
  const fail = (path, message) => issues.push(`${path}: ${message}`);

  if (!PRODUCTION_REPORT_STATE_VALUES_SOURCE.includes(value.state)) {
    fail(`${contract}.state`, "must be a documented report state");
  }
  for (const field of ["established", "complete", "truncated", "inspected"]) {
    if (typeof value[field] !== "boolean") fail(`${contract}.${field}`, "must be a boolean");
  }
  for (const field of ["sections", "observations", "evidence"]) {
    if (!Number.isInteger(value[field]) || value[field] < 0) {
      fail(`${contract}.${field}`, "must be a non-negative integer");
    }
  }
  if (!isPlainObject(value.unknownReasons)) {
    fail(`${contract}.unknownReasons`, "must be a plain object");
  } else {
    for (const key of Object.keys(value.unknownReasons)) {
      const count = value.unknownReasons[key];
      if (!Number.isInteger(count) || count < 0) {
        fail(`${contract}.unknownReasons.${key}`, "must be a non-negative integer");
      }
    }
  }
  if (!isPlainObject(value.limits)) fail(`${contract}.limits`, "must be a plain object");

  throwProductionIssues(contract, issues);
  return value;
}

/** Build a production-report draft. */
export function createProductionReportResult(input = {}) {
  return createEnvelope(PRODUCTION_REPORT_RESULT_FIELDS, {
    version: input.version ?? PRODUCTION_REPORT_VERSION,
    state: input.state,
    established: input.established === true,
    sections: input.sections ?? [],
    coverage: input.coverage,
  });
}

/**
 * Validate a production report.
 *
 * Structural only: whether the report's *facts* are true is the model's question and is
 * answered by `validateRepositoryModelGraph`. What this contract enforces is that the
 * document a query hands out is addressable — every declared field present, the six
 * domains present and named, each observation carrying a kind its own domain declares and
 * at least one evidence id, and a coverage statement for every section.
 */
export function validateProductionReportResult(value) {
  const contract = "ProductionReportResult";
  requireProductionFields(value, contract, PRODUCTION_REPORT_RESULT_FIELDS);
  const issues = [];
  const fail = (path, message) => issues.push(`${path}: ${message}`);

  if (value.version !== PRODUCTION_REPORT_VERSION) {
    fail(`${contract}.version`, "must be the report version this build produces");
  }
  if (!PRODUCTION_REPORT_STATE_VALUES_SOURCE.includes(value.state)) {
    fail(`${contract}.state`, "must be a documented report state");
  }
  if (typeof value.established !== "boolean") {
    fail(`${contract}.established`, "must be a boolean");
  }

  if (!Array.isArray(value.sections)) {
    fail(`${contract}.sections`, "must be an array");
  } else {
    if (value.sections.length !== PRODUCTION_SECTIONS_SOURCE.length) {
      fail(`${contract}.sections`, "must carry every audit domain exactly once");
    }
    value.sections.forEach((section, index) => {
      try {
        validateProductionSectionResult(section);
      } catch (error) {
        const reported = error?.details?.issues;
        if (Array.isArray(reported)) {
          issues.push(...reported.map((issue) => `${contract}.sections[${index}]: ${issue}`));
        } else {
          fail(`${contract}.sections[${index}]`, "must be a well-formed production section");
        }
      }
    });
  }

  try {
    validateProductionCoverageResult(value.coverage);
  } catch (error) {
    const reported = error?.details?.issues;
    if (Array.isArray(reported)) issues.push(...reported);
    else fail(`${contract}.coverage`, "must be a well-formed coverage statement");
  }

  throwProductionIssues(contract, issues);
  return value;
}

/** Build a production-section draft. */
export function createProductionSectionResult(input = {}) {
  return createEnvelope(PRODUCTION_SECTION_RESULT_FIELDS, {
    name: input.name,
    title: input.title,
    state: input.state,
    established: input.established === true,
    counts: input.counts ?? {},
    observations: input.observations ?? [],
    evidenceIds: input.evidenceIds ?? [],
    unknown: input.unknown ?? [],
    coverage: input.coverage,
  });
}

/**
 * Validate one production section.
 *
 * An observation with no evidence id is rejected rather than tolerated: the report's whole
 * promise is that every statement resolves to an observation the repository made.
 */
export function validateProductionSectionResult(value) {
  const contract = "ProductionSectionResult";
  requireProductionFields(value, contract, PRODUCTION_SECTION_RESULT_FIELDS);
  const issues = [];
  const fail = (path, message) => issues.push(`${path}: ${message}`);

  if (!PRODUCTION_SECTIONS_SOURCE.includes(value.name)) {
    fail(`${contract}.name`, "must be a declared audit domain");
  }
  if (typeof value.title !== "string" || value.title.trim() === "") {
    fail(`${contract}.title`, "must be a non-empty title");
  }
  if (!PRODUCTION_REPORT_STATE_VALUES_SOURCE.includes(value.state)) {
    fail(`${contract}.state`, "must be a documented report state");
  }
  if (typeof value.established !== "boolean") {
    fail(`${contract}.established`, "must be a boolean");
  }
  if (!isPlainObject(value.counts)) fail(`${contract}.counts`, "must be a plain object");

  const kinds = PRODUCTION_OBSERVATION_KINDS_SOURCE[value.name];
  if (!Array.isArray(value.observations)) {
    fail(`${contract}.observations`, "must be an array");
  } else {
    value.observations.forEach((observation, index) => {
      const at = `${contract}.observations[${index}]`;
      if (!isPlainObject(observation)) {
        fail(at, "must be a plain object");
        return;
      }
      if (Array.isArray(kinds) && !kinds.includes(observation.kind)) {
        fail(`${at}.kind`, "must be an observation kind this domain declares");
      }
      if (typeof observation.key !== "string" || observation.key === "") {
        fail(`${at}.key`, "must be a non-empty deterministic key");
      }
      if (!Array.isArray(observation.evidenceIds) || observation.evidenceIds.length === 0) {
        fail(`${at}.evidenceIds`, "must cite at least one observation");
      }
    });
  }

  if (!Array.isArray(value.evidenceIds)) {
    fail(`${contract}.evidenceIds`, "must be an array");
  }

  const reasons = PRODUCTION_UNKNOWN_REASONS_SOURCE[value.name];
  if (!Array.isArray(value.unknown)) {
    fail(`${contract}.unknown`, "must be an array");
  } else {
    value.unknown.forEach((record, index) => {
      const at = `${contract}.unknown[${index}]`;
      if (!isPlainObject(record)) {
        fail(at, "must be a plain object");
        return;
      }
      if (Array.isArray(reasons) && !reasons.includes(record.reason)) {
        fail(`${at}.reason`, "must be a reason this domain declares");
      }
      if (!Number.isInteger(record.count) || record.count < 1) {
        fail(`${at}.count`, "must be a positive integer");
      }
    });
  }

  if (!isPlainObject(value.coverage)) {
    fail(`${contract}.coverage`, "must be a plain object");
  } else {
    if (value.coverage.state !== value.state) {
      fail(`${contract}.coverage.state`, "must agree with the section state");
    }
    if (typeof value.coverage.truncated !== "boolean") {
      fail(`${contract}.coverage.truncated`, "must be a boolean");
    }
    for (const field of ["observations", "evidence", "unknownReasons"]) {
      if (!Number.isInteger(value.coverage[field]) || value.coverage[field] < 0) {
        fail(`${contract}.coverage.${field}`, "must be a non-negative integer");
      }
    }
  }

  throwProductionIssues(contract, issues);
  return value;
}

/** Collect a required-field violation, throwing immediately on a non-object. */
function requireProductionFields(value, contract, fields) {
  if (!isPlainObject(value)) {
    throw new ValidationError(`Invalid ${contract}`, {
      details: { contract, issues: ["result: must be a plain object"] },
    });
  }
  const missing = fields.filter((field) => !(field in value));
  if (missing.length > 0) {
    throw new ValidationError(`Invalid ${contract}`, {
      details: { contract, issues: missing.map((field) => `${contract}.${field}: is required`) },
    });
  }
}

/** Throw the collected issues, if any. */
function throwProductionIssues(contract, issues) {
  if (issues.length > 0) {
    throw new ValidationError(`Invalid ${contract}`, { details: { contract, issues } });
  }
}

// ── Repository policy and compliance report (Phase 22) ───────────────────────
//
// The policy area and the compliance report are handed out in full: the policy *is* the
// document plus what the reading established about it, and the report *is* the sections and
// items. The query layer adds no interpretation — it re-validates the shape it is about to hand
// a caller, so a consumer cannot receive a report the model itself would refuse.

/**
 * Fields every policy result declares.
 *
 * Phase 23 adds three: the repository-authored `declared` document, the built-in `preset` that was
 * applied, and the per-key `provenance` of the effective policy. `document` remains the *effective*
 * document, so a consumer that only ever read the policy area in Phase 22 reads exactly what it read
 * then — and the three new fields are the only way the preset answer is visible at all.
 *
 * Phase 24 adds a fourth, `pack`: the pack and pinned version the applied preset came from. The
 * preset name alone does not identify a policy definition, so the identity a consumer needs in order
 * to say *which* `web-production` was applied travels beside it.
 */
export const POLICY_RESULT_FIELDS = Object.freeze([
  "detected",
  "established",
  "state",
  "document",
  "declared",
  "preset",
  "pack",
  "provenance",
  "coverage",
]);

/** Fields a `policyPreset()` answer declares. */
export const POLICY_PRESET_RESULT_FIELDS = Object.freeze([
  "name",
  "version",
  "origin",
  "active",
]);

/** Fields an `effectivePolicy()` answer declares. */
export const EFFECTIVE_POLICY_RESULT_FIELDS = Object.freeze([
  "version",
  "preset",
  "document",
  "domains",
  "settings",
]);

/** Fields a `policyProvenance()` answer declares. */
export const POLICY_PROVENANCE_RESULT_FIELDS = Object.freeze([
  "version",
  "preset",
  "pack",
  "sources",
  "inherited",
  "overridden",
]);

/**
 * Fields a `policyPack()` answer declares.
 *
 * Seven, and each answers something the preset answer cannot: which pack, which pinned version,
 * which origin, the canonical reference, whether the *repository* named the pack or this build
 * pinned it, which preset it supplied, and whether any pack governed the policy at all. The answer
 * deliberately carries no preset documents, no pack title or purpose and no registry internals — it
 * is an answer about *this* repository, not a catalogue.
 */
export const POLICY_PACK_RESULT_FIELDS = Object.freeze([
  "active",
  "name",
  "version",
  "origin",
  "reference",
  "explicit",
  "preset",
]);

/** Fields every compliance item declares. */
export const COMPLIANCE_ITEM_RESULT_FIELDS = Object.freeze([
  "id",
  "domain",
  "key",
  "policyKey",
  "expected",
  "observed",
  "status",
  "subject",
  "basis",
  "rationale",
  "policyEvidenceIds",
  "evidenceIds",
]);

/** Fields every compliance section declares. */
export const COMPLIANCE_SECTION_RESULT_FIELDS = Object.freeze([
  "name",
  "title",
  "state",
  "established",
  "policyDeclared",
  "policyKeys",
  "items",
  "counts",
  "evidenceIds",
  "policyEvidenceIds",
  "unknown",
  "coverage",
]);

/** Fields every compliance report declares. */
export const COMPLIANCE_REPORT_RESULT_FIELDS = Object.freeze([
  "version",
  "state",
  "established",
  "sections",
  "violations",
  "passed",
  "unknown",
  "coverage",
]);

/** Fields every compliance coverage statement declares. */
export const COMPLIANCE_COVERAGE_RESULT_FIELDS = Object.freeze([
  "state",
  "established",
  "complete",
  "truncated",
  "sections",
  "sectionsEstablished",
  "items",
  "violations",
  "passed",
  "unknown",
  "policyState",
  "policyEstablished",
  "policyDomains",
  "policySettings",
  "evidence",
  "limits",
  "unknownReasons",
]);

/** The policy states, re-exported for consumers of this contract. */
export const POLICY_STATE_VALUES = POLICY_STATE_VALUES_SOURCE;

/** The compliance states, statuses and section states, re-exported for the same reason. */
export const COMPLIANCE_STATE_VALUES = COMPLIANCE_STATE_VALUES_SOURCE;
export const COMPLIANCE_STATUS_VALUES = COMPLIANCE_STATUS_VALUES_SOURCE;
export const COMPLIANCE_SECTION_STATE_VALUES = COMPLIANCE_SECTION_STATE_VALUES_SOURCE;

/** The six policy domains, re-exported for the same reason. */
export const COMPLIANCE_DOMAINS = COMPLIANCE_SECTIONS_SOURCE;

/** Build a policy result draft. */
export function createPolicyResult(input = {}) {
  return createEnvelope(POLICY_RESULT_FIELDS, {
    detected: input.detected === true,
    established: input.established === true,
    state: input.state,
    document: input.document ?? null,
    declared: input.declared ?? null,
    preset: input.preset ?? null,
    pack: input.pack ?? null,
    provenance: input.provenance ?? null,
    coverage: input.coverage,
  });
}

/**
 * Validate a policy result.
 *
 * The four fields that matter are pinned to each other: a document may be carried only by an
 * `established` reading, `established` may be true only for the two states that answer "what
 * does this repository declare?", and a reading that did not answer must say why. The document
 * itself is checked against the closed schema, so a caller can never receive a setting this
 * build's policy contract does not declare.
 */
export function validatePolicyResult(value) {
  const contract = "PolicyResult";
  requireProductionFields(value, contract, POLICY_RESULT_FIELDS);
  const issues = [];
  const fail = (path, message) => issues.push(`${path}: ${message}`);

  if (typeof value.detected !== "boolean") fail(`${contract}.detected`, "must be a boolean");
  if (typeof value.established !== "boolean") {
    fail(`${contract}.established`, "must be a boolean");
  }
  if (!POLICY_STATE_VALUES_SOURCE.includes(value.state)) {
    fail(`${contract}.state`, "must be a documented policy state");
  }
  if (value.document !== null && !isPlainObject(value.document)) {
    fail(`${contract}.document`, "must be a plain object or null");
  }
  if ((value.document !== null) !== (value.state === "established")) {
    fail(`${contract}.document`, "must be carried exactly when the state is established");
  }
  // Phase 23 — the declared document, the applied preset and the provenance are carried exactly
  // when an effective document is, and the provenance must name the same preset the area does.
  if ((value.declared !== null) !== (value.document !== null)) {
    fail(`${contract}.declared`, "must be carried exactly when an effective policy is");
  }
  if ((value.provenance !== null) !== (value.document !== null)) {
    fail(`${contract}.provenance`, "must be carried exactly when an effective policy is");
  }
  if (value.preset !== null && !isPlainObject(value.preset)) {
    fail(`${contract}.preset`, "must be a plain object or null");
  }
  if (value.preset !== null && value.document === null) {
    fail(`${contract}.preset`, "must be null when no effective policy was resolved");
  }
  if (isPlainObject(value.provenance) && isPlainObject(value.preset)) {
    if (value.provenance.preset !== value.preset.name) {
      fail(`${contract}.provenance.preset`, "must name the preset the area carries");
    }
  }
  // Phase 24 — the pack the preset came from. It is carried exactly when a preset was applied to a
  // resolved policy, its reference must be the one its own name and version spell, and it must name
  // the same preset the rest of the answer does.
  if (value.pack !== null && !isPlainObject(value.pack)) {
    fail(`${contract}.pack`, "must be a plain object or null");
  }
  if ((value.pack !== null) !== (isPlainObject(value.preset) && value.document !== null)) {
    fail(`${contract}.pack`, "must be carried exactly when a preset was applied");
  }
  if (isPlainObject(value.pack)) {
    if (!isPackReference(value.pack.reference)) {
      fail(`${contract}.pack.reference`, "must be a well-formed pack reference");
    } else if (value.pack.reference !== packReference(value.pack.name, value.pack.version)) {
      fail(`${contract}.pack.reference`, "must be the pack's own name and version");
    }
    if (typeof value.pack.explicit !== "boolean") {
      fail(`${contract}.pack.explicit`, "must say whether the repository named the pack");
    }
    if (isPlainObject(value.preset) && value.pack.preset !== value.preset.name) {
      fail(`${contract}.pack.preset`, "must name the preset the pack supplied");
    }
    if (isPlainObject(value.provenance) && value.provenance.pack !== value.pack.reference) {
      fail(`${contract}.provenance.pack`, "must name the pack the answer carries");
    }
  } else if (isPlainObject(value.provenance) && value.provenance.pack !== null) {
    fail(`${contract}.provenance.pack`, "must be null when no pack supplied anything");
  }

  if (isPlainObject(value.document)) {
    for (const domain of Object.keys(value.document)) {
      if (!COMPLIANCE_SECTIONS_SOURCE.includes(domain)) {
        fail(`${contract}.document.${domain}`, "must be a declared policy domain");
        continue;
      }
      if (!isPlainObject(value.document[domain])) {
        fail(`${contract}.document.${domain}`, "must be a plain object of settings");
        continue;
      }
      for (const key of Object.keys(value.document[domain])) {
        if (!POLICY_DOCUMENT_KEYS_SOURCE[domain].includes(key)) {
          fail(`${contract}.document.${domain}.${key}`, "is not a declared setting");
        }
      }
    }
  }

  if (!isPlainObject(value.coverage)) {
    fail(`${contract}.coverage`, "must be a plain object");
  } else {
    if (value.coverage.state !== value.state) {
      fail(`${contract}.coverage.state`, "must agree with the result state");
    }
    if (value.coverage.established !== value.established) {
      fail(`${contract}.coverage.established`, "must agree with the result state");
    }
    if (value.coverage.path !== POLICY_DOCUMENT_PATH_SOURCE) {
      fail(`${contract}.coverage.path`, "must be the contracted policy document path");
    }
    if (
      !isEstablishedPolicyResultState(value.state) &&
      !POLICY_UNKNOWN_REASON_VALUES_SOURCE.includes(value.coverage.reason)
    ) {
      fail(`${contract}.coverage.reason`, "must document why the reading did not answer");
    }
    if (!Array.isArray(value.coverage.domains)) {
      fail(`${contract}.coverage.domains`, "must be an array");
    }
    if (!Array.isArray(value.coverage.evidenceIds)) {
      fail(`${contract}.coverage.evidenceIds`, "must be an array");
    }
    if (!isPlainObject(value.coverage.limits)) {
      fail(`${contract}.coverage.limits`, "must be a plain object");
    }
  }

  throwProductionIssues(contract, issues);
  return value;
}

/** Whether a policy state answers what the repository declares. */
function isEstablishedPolicyResultState(state) {
  return state === "established" || state === "absent";
}

// ── Policy presets, effective policy and provenance (Phase 23) ───────────────
//
// Three answers, and a deliberate split between them: `policyPreset` names the preset that was
// applied, `effectivePolicy` is the policy the repository is actually measured against, and
// `policyProvenance` says where every one of its values came from. They are separate because they
// answer different questions — which preset, what it requires, and who stated it — and because
// collapsing them into one object would make it easy to read a preset name and assume the document
// beside it came from that preset.

/** Build a `policyPreset()` answer. */
export function createPolicyPresetResult(input = {}) {
  return createEnvelope(POLICY_PRESET_RESULT_FIELDS, {
    name: input.name ?? null,
    version: input.version ?? null,
    origin: input.origin ?? null,
    active: input.active === true,
  });
}

/**
 * Validate a `policyPreset()` answer.
 *
 * `active` is pinned to `name`: a preset is either named or it is not, and an answer that claimed a
 * preset was applied without naming it — or named one while reporting itself inactive — would be
 * the one thing this contract exists to prevent.
 */
export function validatePolicyPresetResult(value) {
  const contract = "PolicyPresetResult";
  requireProductionFields(value, contract, POLICY_PRESET_RESULT_FIELDS);
  const issues = [];
  const fail = (path, message) => issues.push(`${path}: ${message}`);

  for (const field of ["name", "version", "origin"]) {
    const token = value[field];
    if (token !== null && (typeof token !== "string" || token === "")) {
      fail(`${contract}.${field}`, "must be a non-empty string or null");
    }
  }
  if (typeof value.active !== "boolean") fail(`${contract}.active`, "must be a boolean");
  if (value.active !== (value.name !== null)) {
    fail(`${contract}.active`, "must agree with whether a preset is named");
  }
  if (value.version !== null && value.version !== POLICY_DOCUMENT_VERSION_SOURCE) {
    fail(`${contract}.version`, "must be the pinned policy version");
  }
  if ((value.name === null) !== (value.origin === null)) {
    fail(`${contract}.origin`, "must name an origin exactly when a preset is named");
  }

  throwProductionIssues(contract, issues);
  return value;
}

/** Build an `effectivePolicy()` answer. */
export function createEffectivePolicyResult(input = {}) {
  return createEnvelope(EFFECTIVE_POLICY_RESULT_FIELDS, {
    version: input.version ?? null,
    preset: input.preset ?? null,
    document: input.document ?? {},
    domains: input.domains ?? [],
    settings: input.settings ?? 0,
  });
}

/**
 * Validate an `effectivePolicy()` answer.
 *
 * The document's domains and its setting count are recomputed from the document itself, so an
 * answer that claimed more (or fewer) settings than it carried cannot be handed to a caller. The
 * document is checked against the closed schema for the same reason every other policy document is.
 */
export function validateEffectivePolicyResult(value) {
  const contract = "EffectivePolicyResult";
  requireProductionFields(value, contract, EFFECTIVE_POLICY_RESULT_FIELDS);
  const issues = [];
  const fail = (path, message) => issues.push(`${path}: ${message}`);

  if (value.version !== POLICY_DOCUMENT_VERSION_SOURCE) {
    fail(`${contract}.version`, "must be the pinned policy version");
  }
  if (value.preset !== null && (typeof value.preset !== "string" || value.preset === "")) {
    fail(`${contract}.preset`, "must name the applied preset or be null");
  }
  if (!isPlainObject(value.document)) {
    fail(`${contract}.document`, "must be a plain object");
  } else {
    const domains = [];
    let settings = 0;
    for (const domain of Object.keys(value.document)) {
      if (!COMPLIANCE_SECTIONS_SOURCE.includes(domain)) {
        fail(`${contract}.document.${domain}`, "must be a declared policy domain");
        continue;
      }
      const stated = value.document[domain];
      if (!isPlainObject(stated)) {
        fail(`${contract}.document.${domain}`, "must be a plain object of settings");
        continue;
      }
      domains.push(domain);
      settings += Object.keys(stated).length;
      for (const key of Object.keys(stated)) {
        if (!POLICY_DOCUMENT_KEYS_SOURCE[domain].includes(key)) {
          fail(`${contract}.document.${domain}.${key}`, "is not a declared setting");
        }
      }
    }
    if (!Array.isArray(value.domains) || value.domains.join("\u0000") !== domains.join("\u0000")) {
      fail(`${contract}.domains`, "must be the domains the document states, in declared order");
    }
    if (value.settings !== settings) {
      fail(`${contract}.settings`, "must count the settings the document states");
    }
  }

  throwProductionIssues(contract, issues);
  return value;
}

/** Build a `policyProvenance()` answer. */
export function createPolicyProvenanceResult(input = {}) {
  return createEnvelope(POLICY_PROVENANCE_RESULT_FIELDS, {
    version: input.version ?? null,
    preset: input.preset ?? null,
    pack: input.pack ?? null,
    sources: input.sources ?? {},
    inherited: input.inherited ?? [],
    overridden: input.overridden ?? [],
  });
}

/**
 * Validate a `policyProvenance()` answer.
 *
 * The three lists must agree with each other and with `sources`: every `domain.key` a preset
 * supplied appears in `inherited`, every one the repository replaced appears in `overridden`, and
 * each carries the source token `sources` records for it. That makes "never lose provenance" a
 * checkable property of the answer rather than a claim about the resolver.
 *
 * Phase 24 adds the pack the inherited values came from. One document names one preset, hence one
 * pack, so the pack is a property of the provenance *record*: every inherited token is read against
 * it and none repeats an identity that cannot differ per key. The pin is two-way — a pack with no
 * preset, or a preset with no pack, is the same contradiction either way.
 */
export function validatePolicyProvenanceResult(value) {
  const contract = "PolicyProvenanceResult";
  requireProductionFields(value, contract, POLICY_PROVENANCE_RESULT_FIELDS);
  const issues = [];
  const fail = (path, message) => issues.push(`${path}: ${message}`);

  if (value.version !== POLICY_DOCUMENT_VERSION_SOURCE) {
    fail(`${contract}.version`, "must be the pinned policy version");
  }
  if (value.preset !== null && (typeof value.preset !== "string" || value.preset === "")) {
    fail(`${contract}.preset`, "must name the applied preset or be null");
  }
  if (value.pack !== null && !isPackReference(value.pack)) {
    fail(`${contract}.pack`, "must be a well-formed pack reference or null");
  }
  if ((value.pack === null) !== (value.preset === null)) {
    fail(`${contract}.pack`, "must be carried exactly when a preset supplied values");
  }
  for (const field of ["inherited", "overridden"]) {
    const list = value[field];
    if (!Array.isArray(list)) {
      fail(`${contract}.${field}`, "must be an array");
      continue;
    }
    if (JSON.stringify([...new Set(list)].sort()) !== JSON.stringify(list)) {
      fail(`${contract}.${field}`, "must be sorted and unique");
    }
  }
  if (!isPlainObject(value.sources)) {
    fail(`${contract}.sources`, "must be a plain object");
  } else {
    const sources = Object.keys(value.sources);
    if (JSON.stringify([...sources].sort()) !== JSON.stringify(sources)) {
      fail(`${contract}.sources`, "must be keyed in sorted order");
    }
    for (const id of sources) {
      const [domain, key] = id.split(".");
      if (!COMPLIANCE_SECTIONS_SOURCE.includes(domain) || !(POLICY_DOCUMENT_KEYS_SOURCE[domain] ?? []).includes(key)) {
        fail(`${contract}.sources`, `must name a declared policy setting (${id})`);
        continue;
      }
      const token = value.sources[id];
      if (typeof token !== "string" || token === "") {
        fail(`${contract}.sources.${id}`, "must name where the value came from");
        continue;
      }
      if (Array.isArray(value.inherited) && value.inherited.includes(id)) {
        if (token === "user") fail(`${contract}.sources.${id}`, "an inherited value cannot be user-stated");
      }
      if (Array.isArray(value.overridden) && value.overridden.includes(id)) {
        if (token !== "user") fail(`${contract}.sources.${id}`, "an overridden value must be user-stated");
      }
    }
    if (Array.isArray(value.inherited)) {
      for (const id of value.inherited) {
        if (!Object.hasOwn(value.sources, id)) {
          fail(`${contract}.inherited`, `must be a value the provenance records (${id})`);
        }
      }
    }
    if (Array.isArray(value.overridden)) {
      for (const id of value.overridden) {
        if (!Object.hasOwn(value.sources, id)) {
          fail(`${contract}.overridden`, `must be a value the provenance records (${id})`);
        }
      }
    }
    if (value.preset === null) {
      if (value.inherited.length > 0 || value.overridden.length > 0) {
        fail(`${contract}.preset`, "must be named when anything was inherited or overridden");
      }
      for (const id of sources) {
        if (value.sources[id] !== "user") {
          fail(`${contract}.sources.${id}`, "must be user-stated when no preset was applied");
        }
      }
    }
  }

  throwProductionIssues(contract, issues);
  return value;
}

/** Build a `policyPack()` answer. */
export function createPolicyPackResult(input = {}) {
  return createEnvelope(POLICY_PACK_RESULT_FIELDS, {
    active: input.active === true,
    name: input.name ?? null,
    version: input.version ?? null,
    origin: input.origin ?? null,
    reference: input.reference ?? null,
    explicit: input.explicit === true,
    preset: input.preset ?? null,
  });
}

/**
 * Validate a `policyPack()` answer.
 *
 * `active` is pinned to `name`: a pack either governed the policy or it did not. When one did, every
 * identity field must be present and mutually consistent — the reference must be the one the pack's
 * own name and version spell, the origin must be one a pack may claim, and the preset it supplied
 * must be a well-formed preset name. When none did, every one of them must be absent, so an answer
 * cannot describe a pack that governed nothing.
 */
export function validatePolicyPackResult(value) {
  const contract = "PolicyPackResult";
  requireProductionFields(value, contract, POLICY_PACK_RESULT_FIELDS);
  const issues = [];
  const fail = (path, message) => issues.push(`${path}: ${message}`);

  if (typeof value.active !== "boolean") fail(`${contract}.active`, "must be a boolean");
  if (typeof value.explicit !== "boolean") fail(`${contract}.explicit`, "must be a boolean");
  for (const field of ["name", "version", "origin", "reference", "preset"]) {
    const token = value[field];
    if (token !== null && (typeof token !== "string" || token === "")) {
      fail(`${contract}.${field}`, "must be a non-empty string or null");
    }
  }
  if (value.active !== (value.name !== null)) {
    fail(`${contract}.active`, "must agree with whether a pack is named");
  }
  if (!value.active) {
    if (value.preset !== null) fail(`${contract}.preset`, "must be null when no pack is active");
    if (value.explicit !== false) {
      fail(`${contract}.explicit`, "must be false when no pack is active");
    }
    throwProductionIssues(contract, issues);
    return value;
  }

  if (!isPackReference(value.reference)) {
    fail(`${contract}.reference`, "must be a well-formed pack reference");
  } else if (value.reference !== packReference(value.name, value.version)) {
    fail(`${contract}.reference`, "must be the pack's own name and version");
  }
  if (!POLICY_PACK_ORIGIN_VALUES.includes(value.origin)) {
    fail(`${contract}.origin`, "must name a declared pack origin");
  }
  if (!isPresetName(value.preset)) {
    fail(`${contract}.preset`, "must name the preset the pack supplied");
  }

  throwProductionIssues(contract, issues);
  return value;
}

/** Build a compliance item draft. */
export function createComplianceItemResult(input = {}) {
  return createEnvelope(COMPLIANCE_ITEM_RESULT_FIELDS, {
    id: input.id,
    domain: input.domain,
    key: input.key,
    policyKey: input.policyKey,
    expected: input.expected,
    observed: input.observed,
    status: input.status,
    subject: input.subject ?? null,
    basis: input.basis ?? null,
    rationale: input.rationale,
    policyEvidenceIds: input.policyEvidenceIds ?? [],
    evidenceIds: input.evidenceIds ?? [],
  });
}

/**
 * Validate one compliance item.
 *
 * Three checks carry the phase here, and they are the three a consumer would otherwise have to
 * remember: the requirement the item measures must be one the policy *declares*, the observation
 * must come from the vocabulary its own key declares, and a `violation` must cite both the
 * repository observation and the policy document. The rationale is re-rendered from the item's
 * own fields, so the sentence a caller reads can never disagree with the tuple behind it.
 */
export function validateComplianceItem(value) {
  const contract = "ComplianceItemResult";
  requireProductionFields(value, contract, COMPLIANCE_ITEM_RESULT_FIELDS);
  const issues = [];
  const fail = (path, message) => issues.push(`${path}: ${message}`);

  if (!COMPLIANCE_SECTIONS_SOURCE.includes(value.domain)) {
    fail(`${contract}.domain`, "must be a declared policy domain");
  }
  if (!(POLICY_DOCUMENT_KEYS_SOURCE[value.domain] ?? []).includes(value.key)) {
    fail(`${contract}.key`, "must be a policy key this domain declares");
  }
  if (value.policyKey !== `${value.domain}.${value.key}`) {
    fail(`${contract}.policyKey`, "must name the policy key it measures");
  }
  if (typeof value.id !== "string" || value.id === "") {
    fail(`${contract}.id`, "must be a non-empty identifier");
  }
  if (!COMPLIANCE_CHECK_IDS_SOURCE.includes(value.policyKey)) {
    fail(`${contract}.policyKey`, "must be a policy key this build measures");
  }

  const vocabulary = COMPLIANCE_OBSERVED_VALUES_SOURCE[value.policyKey] ?? [];
  const countedObservation = Number.isInteger(value.observed) && value.observed >= 0;
  if (!vocabulary.includes(value.observed) && !countedObservation) {
    fail(`${contract}.observed`, "must be one of the observations this key declares");
  }
  if (value.policyKey !== "ci.maxReleaseWorkflows" && countedObservation) {
    fail(`${contract}.observed`, "must be a token for a key that observes no count");
  }
  if (!COMPLIANCE_STATUS_VALUES_SOURCE.includes(value.status)) {
    fail(`${contract}.status`, "must be one of: pass, violation, unknown");
  }
  if (value.subject !== null && (typeof value.subject !== "string" || value.subject === "")) {
    fail(`${contract}.subject`, "must name its subject or be null");
  }
  if (value.basis !== null && (typeof value.basis !== "string" || value.basis === "")) {
    fail(`${contract}.basis`, "must name the basis it rests on, or be null");
  }
  if (value.rationale !== renderComplianceRationale(value)) {
    fail(`${contract}.rationale`, "must be the sentence its own fields render");
  }
  if (!Array.isArray(value.evidenceIds) || !Array.isArray(value.policyEvidenceIds)) {
    fail(`${contract}.evidenceIds`, "must be arrays");
    throwProductionIssues(contract, issues);
    return value;
  }
  if (value.status === COMPLIANCE_STATUSES_SOURCE.VIOLATION) {
    if (value.evidenceIds.length === 0) {
      fail(`${contract}.evidenceIds`, "must cite the observation a violation rests on");
    }
    if (value.policyEvidenceIds.length === 0) {
      fail(`${contract}.policyEvidenceIds`, "must cite the policy a violation contradicts");
    }
  }
  if (value.evidenceIds.length > COMPLIANCE_LIMITS_SOURCE.maxEvidencePerItem) {
    fail(`${contract}.evidenceIds`, "must stay within the citation bound");
  }

  throwProductionIssues(contract, issues);
  return value;
}

/** Build a compliance section draft. */
export function createComplianceSectionResult(input = {}) {
  return createEnvelope(COMPLIANCE_SECTION_RESULT_FIELDS, {
    name: input.name,
    title: input.title,
    state: input.state,
    established: input.established === true,
    policyDeclared: input.policyDeclared === true,
    policyKeys: input.policyKeys ?? [],
    items: input.items ?? [],
    counts: input.counts ?? {},
    evidenceIds: input.evidenceIds ?? [],
    policyEvidenceIds: input.policyEvidenceIds ?? [],
    unknown: input.unknown ?? [],
    coverage: input.coverage,
  });
}

/** Validate one compliance section. */
export function validateComplianceSectionResult(value) {
  const contract = "ComplianceSectionResult";
  requireProductionFields(value, contract, COMPLIANCE_SECTION_RESULT_FIELDS);
  const issues = [];
  const fail = (path, message) => issues.push(`${path}: ${message}`);

  if (!COMPLIANCE_SECTIONS_SOURCE.includes(value.name)) {
    fail(`${contract}.name`, "must be a declared policy domain");
  }
  if (!COMPLIANCE_SECTION_STATE_VALUES_SOURCE.includes(value.state)) {
    fail(`${contract}.state`, "must be a documented section state");
  }
  for (const field of ["established", "policyDeclared"]) {
    if (typeof value[field] !== "boolean") fail(`${contract}.${field}`, "must be a boolean");
  }
  if (!Array.isArray(value.policyKeys)) {
    fail(`${contract}.policyKeys`, "must be an array");
  } else {
    for (const key of value.policyKeys) {
      if (!(POLICY_DOCUMENT_KEYS_SOURCE[value.name] ?? []).includes(key)) {
        fail(`${contract}.policyKeys`, "must be keys this domain declares");
      }
    }
  }
  if (!Array.isArray(value.items)) {
    fail(`${contract}.items`, "must be an array");
  } else {
    value.items.forEach((item, index) => {
      try {
        validateComplianceItem(item);
      } catch (error) {
        const reported = error?.details?.issues;
        if (Array.isArray(reported)) {
          issues.push(...reported.map((issue) => `${contract}.items[${index}]: ${issue}`));
        } else {
          fail(`${contract}.items[${index}]`, "must be a well-formed compliance item");
        }
      }
    });
  }
  if (!isPlainObject(value.counts)) fail(`${contract}.counts`, "must be a plain object");
  if (!Array.isArray(value.evidenceIds)) fail(`${contract}.evidenceIds`, "must be an array");
  if (!Array.isArray(value.policyEvidenceIds)) {
    fail(`${contract}.policyEvidenceIds`, "must be an array");
  }
  if (!Array.isArray(value.unknown)) {
    fail(`${contract}.unknown`, "must be an array");
  } else {
    value.unknown.forEach((record, index) => {
      if (!isPlainObject(record)) {
        fail(`${contract}.unknown[${index}]`, "must be a plain object");
        return;
      }
      if (typeof record.reason !== "string" || record.reason === "") {
        fail(`${contract}.unknown[${index}].reason`, "must name the reason");
      }
      if (!Number.isInteger(record.count) || record.count < 1) {
        fail(`${contract}.unknown[${index}].count`, "must be a positive integer");
      }
    });
  }
  if (!isPlainObject(value.coverage)) fail(`${contract}.coverage`, "must be a plain object");

  throwProductionIssues(contract, issues);
  return value;
}

/** Build a compliance report draft. */
export function createComplianceReportResult(input = {}) {
  return createEnvelope(COMPLIANCE_REPORT_RESULT_FIELDS, {
    version: input.version ?? COMPLIANCE_VERSION,
    state: input.state,
    established: input.established === true,
    sections: input.sections ?? [],
    violations: input.violations ?? [],
    passed: input.passed ?? [],
    unknown: input.unknown ?? [],
    coverage: input.coverage,
  });
}

/**
 * Validate a compliance report.
 *
 * The three item lists are checked against the sections that carry them, so `report.violations`
 * and the sections cannot disagree about what was violated — the one inconsistency that would
 * let a caller read a partial answer as the whole story.
 */
export function validateComplianceReportResult(value) {
  const contract = "ComplianceReportResult";
  requireProductionFields(value, contract, COMPLIANCE_REPORT_RESULT_FIELDS);
  const issues = [];
  const fail = (path, message) => issues.push(`${path}: ${message}`);

  if (value.version !== COMPLIANCE_VERSION) {
    fail(`${contract}.version`, "must be the report version this build produces");
  }
  if (!COMPLIANCE_STATE_VALUES_SOURCE.includes(value.state)) {
    fail(`${contract}.state`, "must be a documented compliance state");
  }
  if (typeof value.established !== "boolean") {
    fail(`${contract}.established`, "must be a boolean");
  }

  if (!Array.isArray(value.sections)) {
    fail(`${contract}.sections`, "must be an array");
  } else {
    if (value.sections.length !== COMPLIANCE_SECTIONS_SOURCE.length) {
      fail(`${contract}.sections`, "must carry every policy domain exactly once");
    }
    value.sections.forEach((section, index) => {
      try {
        validateComplianceSectionResult(section);
      } catch (error) {
        const reported = error?.details?.issues;
        if (Array.isArray(reported)) {
          issues.push(...reported.map((issue) => `${contract}.sections[${index}]: ${issue}`));
        } else {
          fail(`${contract}.sections[${index}]`, "must be a well-formed compliance section");
        }
      }
    });
  }

  const sections = Array.isArray(value.sections) ? value.sections : [];
  for (const [field, status] of [
    ["violations", COMPLIANCE_STATUSES_SOURCE.VIOLATION],
    ["passed", COMPLIANCE_STATUSES_SOURCE.PASS],
    ["unknown", COMPLIANCE_STATUSES_SOURCE.UNKNOWN],
  ]) {
    const expected = sections.flatMap((section) =>
      (Array.isArray(section?.items) ? section.items : []).filter(
        (item) => item?.status === status,
      ),
    );
    if (!Array.isArray(value[field])) {
      fail(`${contract}.${field}`, "must be an array");
    } else if (
      JSON.stringify(value[field].map((item) => item?.id)) !==
      JSON.stringify(expected.map((item) => item?.id))
    ) {
      fail(`${contract}.${field}`, `must be every ${status} item the sections carry, in order`);
    }
  }

  try {
    validateComplianceCoverageResult(value.coverage);
  } catch (error) {
    const reported = error?.details?.issues;
    if (Array.isArray(reported)) issues.push(...reported);
    else fail(`${contract}.coverage`, "must be a well-formed coverage statement");
  }

  throwProductionIssues(contract, issues);
  return value;
}

/** Build a compliance coverage draft. */
export function createComplianceCoverageResult(input = {}) {
  return createEnvelope(COMPLIANCE_COVERAGE_RESULT_FIELDS, {
    state: input.state,
    established: input.established === true,
    complete: input.complete === true,
    truncated: input.truncated === true,
    sections: input.sections ?? 0,
    sectionsEstablished: input.sectionsEstablished ?? 0,
    items: input.items ?? 0,
    violations: input.violations ?? 0,
    passed: input.passed ?? 0,
    unknown: input.unknown ?? 0,
    policyState: input.policyState ?? null,
    policyEstablished: input.policyEstablished === true,
    policyDomains: input.policyDomains ?? [],
    policySettings: input.policySettings ?? 0,
    evidence: input.evidence ?? [],
    limits: input.limits ?? {},
    unknownReasons: input.unknownReasons ?? {},
  });
}

/**
 * Validate a compliance coverage statement.
 *
 * The counts are checked as non-negative integers rather than merely present, because a coverage
 * statement whose totals are wrong is exactly the document that lets a reader believe a bounded
 * item list is a complete one. `unknownReasons` is a census, not a score, and it is validated as
 * one: every key a count of the reason it names.
 */
export function validateComplianceCoverageResult(value) {
  const contract = "ComplianceCoverageResult";
  requireProductionFields(value, contract, COMPLIANCE_COVERAGE_RESULT_FIELDS);
  const issues = [];
  const fail = (path, message) => issues.push(`${path}: ${message}`);

  if (!COMPLIANCE_STATE_VALUES_SOURCE.includes(value.state)) {
    fail(`${contract}.state`, "must be a documented compliance state");
  }
  for (const field of ["established", "complete", "truncated", "policyEstablished"]) {
    if (typeof value[field] !== "boolean") fail(`${contract}.${field}`, "must be a boolean");
  }
  for (const field of [
    "sections",
    "sectionsEstablished",
    "items",
    "violations",
    "passed",
    "unknown",
    "policySettings",
  ]) {
    if (!Number.isInteger(value[field]) || value[field] < 0) {
      fail(`${contract}.${field}`, "must be a non-negative integer");
    }
  }
  if (!isPlainObject(value.unknownReasons)) {
    fail(`${contract}.unknownReasons`, "must be a plain object");
  } else {
    for (const key of Object.keys(value.unknownReasons)) {
      if (!Number.isInteger(value.unknownReasons[key]) || value.unknownReasons[key] < 0) {
        fail(`${contract}.unknownReasons.${key}`, "must be a non-negative integer");
      }
    }
  }
  if (!isPlainObject(value.limits)) fail(`${contract}.limits`, "must be a plain object");
  if (!Array.isArray(value.policyDomains)) {
    fail(`${contract}.policyDomains`, "must be an array");
  } else {
    for (const domain of value.policyDomains) {
      if (!COMPLIANCE_SECTIONS_SOURCE.includes(domain)) {
        fail(`${contract}.policyDomains`, "must be declared policy domains");
      }
    }
  }
  if (!Array.isArray(value.evidence)) fail(`${contract}.evidence`, "must be an array");

  throwProductionIssues(contract, issues);
  return value;
}

// ── Production risk report (Phase 21) ────────────────────────────────────────
//
// The risk report is handed out in full for the same reason the inventory report is: it *is*
// the projection, and its `coverage` is its own structured statement. These validators are
// structural — whether a finding's *facts* are true is the model's question, answered by
// `validateRepositoryModelGraph` — and they enforce that the document is addressable: every
// field present, every section a declared domain, every finding a kind its own domain
// declares with a severity from the closed table and at least one evidence id, and a coverage
// statement for every section.

/** Fields the production risk report declares. */
export const PRODUCTION_RISK_REPORT_RESULT_FIELDS = Object.freeze([
  "version",
  "state",
  "established",
  "sections",
  "findings",
  "evidenceIds",
  "unknowns",
  "coverage",
]);

/** Fields one production risk section declares. */
export const PRODUCTION_RISK_SECTION_RESULT_FIELDS = Object.freeze([
  "name",
  "title",
  "state",
  "established",
  "counts",
  "findings",
  "evidenceIds",
  "unknown",
  "coverage",
]);

/** Fields one risk finding declares. Prose and vocabulary fields are required too. */
export const PRODUCTION_RISK_FINDING_RESULT_FIELDS = Object.freeze([
  "id",
  "section",
  "kind",
  "severity",
  "classification",
  "confidence",
  "basis",
  "key",
  "statement",
  "evidenceIds",
]);

/** Fields the risk report's structured coverage statement declares. */
export const PRODUCTION_RISK_COVERAGE_RESULT_FIELDS = Object.freeze([
  "state",
  "established",
  "complete",
  "truncated",
  "sections",
  "findings",
  "evidence",
  "sectionsWithFindings",
  "severities",
  "unknownReasons",
  "limits",
]);

/** The report's coverage vocabulary, re-exported so a caller reads it from one place. */
export const PRODUCTION_RISK_STATE_VALUES = PRODUCTION_RISK_STATE_VALUES_SOURCE;

/** The severity vocabulary, re-exported for the same reason. */
export const PRODUCTION_RISK_SEVERITY_VALUES = PRODUCTION_RISK_SEVERITY_VALUES_SOURCE;

/** The classification vocabulary — whether a finding may claim a defect at all. */
export const PRODUCTION_RISK_CLASSIFICATION_VALUES = PRODUCTION_RISK_CLASSIFICATION_VALUES_SOURCE;

/** The six audit domains, re-exported for the same reason. */
export const RISK_SECTIONS = PRODUCTION_RISK_SECTIONS_SOURCE;

/** Build a risk-coverage draft. */
export function createProductionRiskCoverageResult(input = {}) {
  return createEnvelope(PRODUCTION_RISK_COVERAGE_RESULT_FIELDS, {
    state: input.state,
    established: input.established === true,
    complete: input.complete === true,
    truncated: input.truncated === true,
    sections: input.sections ?? 0,
    findings: input.findings ?? 0,
    evidence: input.evidence ?? 0,
    sectionsWithFindings: input.sectionsWithFindings ?? 0,
    severities: input.severities ?? {},
    unknownReasons: input.unknownReasons ?? {},
    limits: input.limits ?? {},
  });
}

/**
 * Validate a risk-coverage statement.
 *
 * The counts are checked as non-negative integers rather than merely present, because a
 * coverage statement whose totals are wrong is exactly the document that lets a reader believe
 * a bounded finding list is a complete one. `severities` is a census of findings, not a score,
 * and it is validated as a census: three keys, each a count of the severity it names.
 */
export function validateProductionRiskCoverageResult(value) {
  const contract = "ProductionRiskCoverageResult";
  requireProductionFields(value, contract, PRODUCTION_RISK_COVERAGE_RESULT_FIELDS);
  const issues = [];
  const fail = (path, message) => issues.push(`${path}: ${message}`);

  if (!PRODUCTION_RISK_STATE_VALUES_SOURCE.includes(value.state)) {
    fail(`${contract}.state`, "must be a documented report state");
  }
  for (const field of ["established", "complete", "truncated"]) {
    if (typeof value[field] !== "boolean") fail(`${contract}.${field}`, "must be a boolean");
  }
  for (const field of ["sections", "findings", "evidence", "sectionsWithFindings"]) {
    if (!Number.isInteger(value[field]) || value[field] < 0) {
      fail(`${contract}.${field}`, "must be a non-negative integer");
    }
  }
  if (!isPlainObject(value.severities)) {
    fail(`${contract}.severities`, "must be a plain object");
  } else {
    for (const severity of PRODUCTION_RISK_SEVERITY_VALUES_SOURCE) {
      const total = value.severities[severity];
      if (!Number.isInteger(total) || total < 0) {
        fail(`${contract}.severities.${severity}`, "must be a non-negative integer");
      }
    }
  }
  if (!isPlainObject(value.unknownReasons)) {
    fail(`${contract}.unknownReasons`, "must be a plain object");
  } else {
    for (const key of Object.keys(value.unknownReasons)) {
      const total = value.unknownReasons[key];
      if (!Number.isInteger(total) || total < 0) {
        fail(`${contract}.unknownReasons.${key}`, "must be a non-negative integer");
      }
    }
  }
  if (!isPlainObject(value.limits)) fail(`${contract}.limits`, "must be a plain object");

  throwProductionIssues(contract, issues);
  return value;
}

/** Build a risk-report draft. */
export function createProductionRiskReportResult(input = {}) {
  return createEnvelope(PRODUCTION_RISK_REPORT_RESULT_FIELDS, {
    version: input.version ?? PRODUCTION_RISK_REPORT_VERSION,
    state: input.state,
    established: input.established === true,
    sections: input.sections ?? [],
    findings: input.findings ?? [],
    evidenceIds: input.evidenceIds ?? [],
    unknowns: input.unknowns ?? [],
    coverage: input.coverage,
  });
}

/** Validate a production risk report. */
export function validateProductionRiskReportResult(value) {
  const contract = "ProductionRiskReportResult";
  requireProductionFields(value, contract, PRODUCTION_RISK_REPORT_RESULT_FIELDS);
  const issues = [];
  const fail = (path, message) => issues.push(`${path}: ${message}`);

  if (value.version !== PRODUCTION_RISK_REPORT_VERSION) {
    fail(`${contract}.version`, "must be the report version this build produces");
  }
  if (!PRODUCTION_RISK_STATE_VALUES_SOURCE.includes(value.state)) {
    fail(`${contract}.state`, "must be a documented report state");
  }
  if (typeof value.established !== "boolean") {
    fail(`${contract}.established`, "must be a boolean");
  }

  if (!Array.isArray(value.sections)) {
    fail(`${contract}.sections`, "must be an array");
  } else {
    if (value.sections.length !== PRODUCTION_RISK_SECTIONS_SOURCE.length) {
      fail(`${contract}.sections`, "must carry every audit domain exactly once");
    }
    value.sections.forEach((section, index) => {
      try {
        validateProductionRiskSectionResult(section);
      } catch (error) {
        const reported = error?.details?.issues;
        if (Array.isArray(reported)) {
          issues.push(...reported.map((issue) => `${contract}.sections[${index}]: ${issue}`));
        } else {
          fail(`${contract}.sections[${index}]`, "must be a well-formed risk section");
        }
      }
    });
  }

  if (!Array.isArray(value.findings)) {
    fail(`${contract}.findings`, "must be an array");
  } else {
    value.findings.forEach((finding, index) => {
      try {
        validateRiskFinding(finding);
      } catch (error) {
        const reported = error?.details?.issues;
        if (Array.isArray(reported)) {
          issues.push(...reported.map((issue) => `${contract}.findings[${index}]: ${issue}`));
        } else {
          fail(`${contract}.findings[${index}]`, "must be a well-formed risk finding");
        }
      }
    });
  }

  if (!Array.isArray(value.evidenceIds)) fail(`${contract}.evidenceIds`, "must be an array");
  if (!Array.isArray(value.unknowns)) fail(`${contract}.unknowns`, "must be an array");

  try {
    validateProductionRiskCoverageResult(value.coverage);
  } catch (error) {
    const reported = error?.details?.issues;
    if (Array.isArray(reported)) issues.push(...reported);
    else fail(`${contract}.coverage`, "must be a well-formed coverage statement");
  }

  throwProductionIssues(contract, issues);
  return value;
}

/** Build a risk-section draft. */
export function createProductionRiskSectionResult(input = {}) {
  return createEnvelope(PRODUCTION_RISK_SECTION_RESULT_FIELDS, {
    name: input.name,
    title: input.title,
    state: input.state,
    established: input.established === true,
    counts: input.counts ?? {},
    findings: input.findings ?? [],
    evidenceIds: input.evidenceIds ?? [],
    unknown: input.unknown ?? [],
    coverage: input.coverage,
  });
}

/**
 * Validate one risk section.
 *
 * A finding with no evidence id is rejected rather than tolerated: the whole promise of this
 * report is that every statement resolves to an observation the repository made. The
 * abstention vocabulary is the inventory domain's own plus the reasons this report may add, so
 * a section can neither invent a reason nor lose the knowledge gaps it inherited.
 */
export function validateProductionRiskSectionResult(value) {
  const contract = "ProductionRiskSectionResult";
  requireProductionFields(value, contract, PRODUCTION_RISK_SECTION_RESULT_FIELDS);
  const issues = [];
  const fail = (path, message) => issues.push(`${path}: ${message}`);

  if (!PRODUCTION_RISK_SECTIONS_SOURCE.includes(value.name)) {
    fail(`${contract}.name`, "must be a declared audit domain");
  }
  if (typeof value.title !== "string" || value.title.trim() === "") {
    fail(`${contract}.title`, "must be a non-empty title");
  }
  if (!PRODUCTION_RISK_STATE_VALUES_SOURCE.includes(value.state)) {
    fail(`${contract}.state`, "must be a documented report state");
  }
  if (typeof value.established !== "boolean") {
    fail(`${contract}.established`, "must be a boolean");
  }
  if (!isPlainObject(value.counts)) fail(`${contract}.counts`, "must be a plain object");

  const kinds = PRODUCTION_RISK_FINDING_KINDS_SOURCE[value.name];
  if (!Array.isArray(value.findings)) {
    fail(`${contract}.findings`, "must be an array");
  } else {
    value.findings.forEach((finding, index) => {
      const at = `${contract}.findings[${index}]`;
      if (Array.isArray(kinds) && !kinds.includes(finding?.kind)) {
        fail(`${at}.kind`, "must be a finding kind this domain declares");
      }
    });
  }

  if (!Array.isArray(value.evidenceIds)) {
    fail(`${contract}.evidenceIds`, "must be an array");
  }

  const reasons = [
    ...(PRODUCTION_UNKNOWN_REASONS_SOURCE[value.name] ?? []),
    ...(PRODUCTION_RISK_UNKNOWN_REASONS_SOURCE[value.name] ?? []),
  ];
  if (!Array.isArray(value.unknown)) {
    fail(`${contract}.unknown`, "must be an array");
  } else {
    value.unknown.forEach((record, index) => {
      const at = `${contract}.unknown[${index}]`;
      if (!isPlainObject(record)) {
        fail(at, "must be a plain object");
        return;
      }
      if (!reasons.includes(record.reason)) {
        fail(`${at}.reason`, "must be a reason this domain declares");
      }
      if (!Number.isInteger(record.count) || record.count < 1) {
        fail(`${at}.count`, "must be a positive integer");
      }
    });
  }

  if (!isPlainObject(value.coverage)) {
    fail(`${contract}.coverage`, "must be a plain object");
  } else {
    if (value.coverage.state !== value.state) {
      fail(`${contract}.coverage.state`, "must agree with the section state");
    }
    if (typeof value.coverage.truncated !== "boolean") {
      fail(`${contract}.coverage.truncated`, "must be a boolean");
    }
    for (const field of ["findings", "evidence", "unknownReasons"]) {
      if (!Number.isInteger(value.coverage[field]) || value.coverage[field] < 0) {
        fail(`${contract}.coverage.${field}`, "must be a non-negative integer");
      }
    }
  }

  throwProductionIssues(contract, issues);
  return value;
}

/**
 * Validate one risk finding's addressable shape.
 *
 * The classification must be present and one of its two closed words, so a consumer can always
 * tell a claimed defect from a structural observation before it reads the severity; the severity
 * must be one of the three closed words and the basis non-empty, so a consumer can switch on
 * both without defensively guessing; the statement must be a non-empty sentence and the
 * remediation `null` or a bounded sentence, so "a finding may carry advice it did not imply" is
 * not expressible here either.
 */
export function validateRiskFinding(value) {
  const contract = "ProductionRiskFindingResult";
  requireProductionFields(value, contract, PRODUCTION_RISK_FINDING_RESULT_FIELDS);
  const issues = [];
  const fail = (path, message) => issues.push(`${path}: ${message}`);

  if (!PRODUCTION_RISK_SECTIONS_SOURCE.includes(value.section)) {
    fail(`${contract}.section`, "must be a declared audit domain");
  }
  if (!PRODUCTION_RISK_CLASSIFICATION_VALUES_SOURCE.includes(value.classification)) {
    fail(`${contract}.classification`, "must be one of the report's closed classifications");
  }
  if (!PRODUCTION_RISK_SEVERITY_VALUES_SOURCE.includes(value.severity)) {
    fail(`${contract}.severity`, "must be one of the report's closed severities");
  }
  if (typeof value.basis !== "string" || value.basis.trim() === "") {
    fail(`${contract}.basis`, "must name what was read");
  }
  if (typeof value.statement !== "string" || value.statement.trim() === "") {
    fail(`${contract}.statement`, "must state the finding");
  }
  if (!Array.isArray(value.evidenceIds) || value.evidenceIds.length === 0) {
    fail(`${contract}.evidenceIds`, "must cite at least one observation");
  }
  if ("remediation" in value && value.remediation !== null) {
    if (typeof value.remediation !== "string" || value.remediation.trim() === "") {
      fail(`${contract}.remediation`, "must be null or a non-empty sentence");
    }
  }

  throwProductionIssues(contract, issues);
  return value;
}

/** Validate a bounded unresolved-middleware list. */
export function validateMiddlewareUnresolvedResult(value) {
  return validateGraphEnvelope(
    value,
    MIDDLEWARE_UNRESOLVED_RESULT_FIELDS,
    ["unresolved"],
    "MiddlewareUnresolvedResult",
    ["truncated", "limited"],
    MIDDLEWARE_GRAPH_STATE_VALUES_SOURCE,
  );
}
