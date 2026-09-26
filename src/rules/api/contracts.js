/**
 * Code Guardian — API Rule Pack Contracts (Phase 18)
 *
 * The API domain's vocabulary. This pack exists to prove one thing: the API & Service
 * graph Phase 18 added is *consumable through the accepted Rule Engine* — a rule can
 * enumerate the HTTP routes the repository declares, cite the observation behind each
 * one, and state `unknown` when the graph was never established, without any rule reading
 * a file, parsing source, resolving a handler or starting a server.
 *
 * ### It ships exactly one informational rule, on purpose
 *
 * `api.graph.inventory` enumerates the endpoints the graph establishes. There is no
 * authentication rule, no REST-quality rule, no missing-middleware rule, no versioning
 * rule and no API-health rule anywhere in this pack: each of those needs a judgment about
 * what the API *should* be — a threat model, a specification, a convention — and a route
 * inventory is not that judgment. `GET /admin` is a fact; whether it *should* require
 * authentication is a claim this phase has no evidence for.
 *
 * ### Rule identity is a long-term contract
 *
 * Rule ids are namespace-shaped (`api.graph.inventory`) and appear in every fingerprint
 * the rule produces, so a rename retires every existing fingerprint. `API_RULE_IDS`
 * declares the shipped ids in one place and the registry fails if a declared rule is
 * missing or an id leaves the `api.` namespace.
 */

/** Version of the pack as a whole (analyzer version, rule set revision). */
export const API_RULE_PACK_VERSION = "1.0.0";

/** Initial version of every rule in the pack. */
export const API_RULE_VERSION = "1.0.0";

/** Analyzer identity. `api` is the domain namespace, not a rule. */
export const API_ANALYZER_ID = "api";
export const API_ANALYZER_NAME = "API";
export const API_ANALYZER_SCOPE = "api";

/** Category recorded on every API finding (Core Finding contract). */
export const API_CATEGORY = "architecture";

/** Every API rule id must live in this namespace. */
export const API_RULE_ID_PREFIX = "api.";

/** The rules this pack ships. */
export const API_RULE_IDS = Object.freeze({
  GRAPH_INVENTORY: "api.graph.inventory",
});

/**
 * Confidence policy.
 *
 * One honest level, and it is not certainty: `OBSERVED_ENDPOINT` means the repository
 * establishes the endpoint — a supported source file was read to the end, its route set
 * was established, and the declaring file bound the receiver to a supported framework
 * factory while stating a literal path. It says nothing about whether the route is
 * *reachable* at runtime, whether a handler executes, whether authentication applies, or
 * whether the endpoint is correct.
 */
export const API_CONFIDENCE = Object.freeze({
  OBSERVED_ENDPOINT: 0.9,
});

/** `metadata.basis` recorded on every API finding. */
export const API_BASIS = "static-api-declaration";

/** Findings one rule run will report before it stops and says so. */
export const MAX_API_FINDINGS = 200;

/**
 * How each API-graph edge type reads in a finding.
 *
 * A closed map over the graph's own edge vocabulary: an edge type the graph can state but
 * this map cannot describe is a contract mismatch, and the pack's own test pins the two
 * vocabularies together.
 */
export const API_EDGE_TYPE_WORDING = Object.freeze({
  declares: "declares",
  "handled-by": "is handled by",
  middleware: "lists as middleware",
});

/**
 * How each unresolved reason reads in the abstention's metadata.
 *
 * Closed map over the graph's own reason vocabulary, so a new reason has to be described
 * deliberately instead of appearing as a raw token.
 */
export const API_UNRESOLVED_REASON_WORDING = Object.freeze({
  "receiver-not-established":
    "the route-shaped call's receiver was not bound to a framework factory in the module",
  "framework-unsupported": "the receiver is bound to a framework this build does not support",
  "path-not-established": "the first argument is not a plain string literal",
  "path-computed": "the path is a template literal",
  "path-concatenated": "the path is a concatenated string",
  "shorthand-not-established": "the object shorthand (`route({ … })`) this build does not interpret",
  "method-not-established": "the chained call states a method this build does not recognise",
  "handler-not-established": "no module-scope binding of that handler name exists in the file",
  "handler-not-unique": "the handler name is bound elsewhere in the file too",
  "member-expression": "the handler is a member access (`controller.list`): runtime dispatch",
  "inline-handler": "the handler is an inline function the repository does not name",
  "resolution-not-established": "the declaring file's declarations were not established",
});
