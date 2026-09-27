/**
 * Code Guardian — Middleware Rule Pack Contracts (Phase 19)
 *
 * The middleware domain's vocabulary. This pack exists to prove one thing: the middleware &
 * authorization graph Phase 19 added is *consumable through the accepted Rule Engine* — a
 * rule can enumerate the middleware the repository registers, cite the observation behind
 * each registration, state which routes that registration structurally reaches, and report a
 * classification derived from the middleware's own name, without any rule reading a file,
 * parsing source, resolving a symbol or running a request.
 *
 * ### It ships exactly one informational rule, on purpose
 *
 * `middleware.graph.inventory` enumerates the middleware the graph establishes. There is no
 * missing-authentication rule, no weak-authentication rule, no ordering rule, no
 * exposed-admin-route rule, no CORS rule and no rate-limit rule anywhere in this pack: each
 * of those needs a judgment about what the application *should* require — a threat model, a
 * policy, a specification — and a registration inventory is not that judgment. `GET /admin`
 * being declared behind `requireAuth` is a fact; whether `requireAuth` is strong enough,
 * correctly ordered, or applied everywhere it should be is a claim this phase has no
 * evidence for.
 *
 * ### Rule identity is a long-term contract
 *
 * Rule ids are namespace-shaped (`middleware.graph.inventory`) and appear in every
 * fingerprint the rule produces, so a rename retires every existing fingerprint.
 * `MIDDLEWARE_RULE_IDS` declares the shipped ids in one place and the registry fails if a
 * declared rule is missing or an id leaves the `middleware.` namespace.
 */

/** Version of the pack as a whole (analyzer version, rule set revision). */
export const MIDDLEWARE_RULE_PACK_VERSION = "1.0.0";

/** Initial version of every rule in the pack. */
export const MIDDLEWARE_RULE_VERSION = "1.0.0";

/** Analyzer identity. `middleware` is the domain namespace, not a rule. */
export const MIDDLEWARE_ANALYZER_ID = "middleware";
export const MIDDLEWARE_ANALYZER_NAME = "Middleware";
export const MIDDLEWARE_ANALYZER_SCOPE = "middleware";

/** Category recorded on every middleware finding (Core Finding contract). */
export const MIDDLEWARE_CATEGORY = "architecture";

/** Every middleware rule id must live in this namespace. */
export const MIDDLEWARE_RULE_ID_PREFIX = "middleware.";

/** The rules this pack ships. */
export const MIDDLEWARE_RULE_IDS = Object.freeze({
  GRAPH_INVENTORY: "middleware.graph.inventory",
});

/**
 * Confidence policy.
 *
 * One honest level, and it is not certainty: `OBSERVED_REGISTRATION` means the repository
 * establishes the middleware — a supported source file was read to the end, its
 * registrations were established, and the name resolved to exactly one module-scope binding
 * the semantic layer established. It says nothing about whether the middleware runs, what it
 * does, whether it is correct, or whether it is sufficient.
 */
export const MIDDLEWARE_CONFIDENCE = Object.freeze({
  OBSERVED_REGISTRATION: 0.9,
});

/** `metadata.basis` recorded on every middleware finding. */
export const MIDDLEWARE_BASIS = "static-middleware-registration";

/** Findings one rule run will report before it stops and says so. */
export const MAX_MIDDLEWARE_FINDINGS = 200;

/**
 * How each middleware-graph edge type reads in a finding.
 *
 * A closed map over the graph's own edge vocabulary: an edge type the graph can state but
 * this map cannot describe is a contract mismatch, and the pack's own test pins the two
 * vocabularies together.
 */
export const MIDDLEWARE_EDGE_TYPE_WORDING = Object.freeze({
  protects: "protects",
  precedes: "is declared before",
  "registered-on": "is registered in",
  "applies-to": "applies to",
});

/**
 * How each classification reads in a finding.
 *
 * The wording describes the *name*, never a behaviour: `authentication` here means "the
 * middleware's own name is authentication-shaped", which is the only thing this build
 * established.
 */
export const MIDDLEWARE_CLASSIFICATION_WORDING = Object.freeze({
  authentication: "authentication-shaped",
  authorization: "authorization-shaped",
  validation: "validation-shaped",
  cors: "CORS",
  "rate-limit": "rate-limiting",
  logging: "logging",
  parsing: "parsing",
  unknown: "unclassified",
});

/** How each protection state reads in a finding's metadata. */
export const MIDDLEWARE_PROTECTION_WORDING = Object.freeze({
  protected: "at least one middleware was established for the route",
  unresolved: "a middleware-shaped occurrence could not be established for the route",
  "none-observed": "the declaring file's registrations were established and state none",
  unknown: "the declaring file's registrations were not established",
});

/**
 * How each unresolved reason reads in the abstention's metadata.
 *
 * Closed map over the graph's own reason vocabulary, so a new reason has to be described
 * deliberately instead of appearing as a raw token.
 */
export const MIDDLEWARE_UNRESOLVED_REASON_WORDING = Object.freeze({
  "middleware-not-established": "no module-scope binding of that name exists in the file",
  "middleware-not-unique": "the name is bound elsewhere in the file too",
  "resolution-not-established": "the file's declarations were not established",
  "member-expression": "the value is a member access (`express.json`): runtime dispatch",
  "inline-middleware": "the value is an inline function the repository does not name",
  "array-not-established": "the argument is a computed middleware array",
  "spread-not-established": "the argument is a spread",
  "registration-not-established": "the argument is a call or another computed value",
  "conditional-not-established": "the registration sits inside a conditional block",
  "hook-name-not-established": "the hook name is not a literal string",
  "framework-unsupported": "the receiver is bound to a framework this build does not support",
});
