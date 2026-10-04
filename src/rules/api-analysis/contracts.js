/**
 * Code Guardian — API Analysis Rule Pack Contracts (Official Roadmap Phase 16)
 *
 * The API domain's vocabulary for the official roadmap's **Phase 16 — API Analyzer**, which
 * asks for an `APIAnalyzer` over thirteen listed API domains:
 *
 *   input validation · schema validation · authentication · authorization · error handling ·
 *   status codes · pagination · rate limiting · CORS · OpenAPI · request limits · logging ·
 *   correlation IDs
 *
 * The roadmap's code block contains thirteen items (the surrounding prose says "twelve"),
 * counted directly; all thirteen are covered here.
 *
 * ### Substrate vs analysis, kept apart on purpose
 *
 * The existing `src/rules/api/` pack (rule `api.graph.inventory`) and `src/rules/middleware/`
 * pack state *facts*: which endpoints the repository declares, which middleware it registers,
 * and how a route is structurally protected. This pack adds *analysis* — the thirteen domains
 * above — and never renames, replaces or deletes those inventory rules. A declaration finding
 * rests on the API graph; an analysis finding rests on a comparison, a measured relationship
 * or an observed artifact, and its `metadata.basis` says which.
 *
 * ### What the repository can and cannot establish, stated once
 *
 * The model this analyzer reads establishes a great deal about *structure* and very little
 * about *runtime behaviour*:
 *
 *   - API routes: a supported framework receiver with a literal `/`-prefixed path, the
 *     declaring files and the observation behind each.
 *   - middleware: a registered module-scope binding, its receiver scope and a `classification`
 *     the middleware graph derives **from the name alone** (`authentication`, `authorization`,
 *     `validation`, `cors`, `rate-limit`, `logging`, `parsing`, `unknown`).
 *   - route protection: `protected` / `unresolved` / `none-observed` / `unknown`.
 *
 * It establishes nothing about request bodies, schemas, response statuses, pagination
 * parameters, error handlers, request size limits or correlation-ID propagation. Therefore the
 * pack splits the thirteen domains into three honest groups:
 *
 *   structural   the domain's evidence is a middleware *classification* the graph established
 *                from a name (input validation, authentication, authorization, rate limiting,
 *                CORS, logging). A finding says what the repository's own registrations show,
 *                never that the middleware works.
 *   artifact     the domain's evidence is an observed file (OpenAPI). A finding says the
 *                artifact exists, never that it is synchronised with the API.
 *   unestablished the model holds no fact for the domain (schema validation, error handling,
 *                status codes, pagination, request limits, correlation IDs). The rule answers
 *                `unknown` when an API subject exists and `not_applicable` when none does,
 *                rather than inventing a failure.
 *
 * ### No score, no remediation, no duplicate security claim
 *
 * There is no API score, grade, readiness percentage or aggregate rating anywhere in the pack,
 * and no rule edits, reorders or fixes anything. The Security Analyzer owns
 * `security.authorization.unprotected-privileged-route` and
 * `security.exposure.diagnostic-endpoint`; this pack does not restate either, and its
 * authentication/authorization rules use a broader, name-derived, all-route contract rather
 * than the security pack's privileged-path contract.
 */

/** Version of the pack as a whole (analyzer version, rule set revision). */
export const API_ANALYSIS_RULE_PACK_VERSION = "1.0.0";

/** Initial version of every rule in the pack. */
export const API_ANALYSIS_RULE_VERSION = "1.0.0";

/**
 * Analyzer identity.
 *
 * Distinct from the internal API *substrate* integration analyzer (`api`) that ships the
 * inventory rule. This pack is the official Phase 16 analyzer.
 */
export const API_ANALYSIS_ANALYZER_ID = "api-analysis";
export const API_ANALYSIS_ANALYZER_NAME = "API Analysis";
export const API_ANALYSIS_ANALYZER_SCOPE = "api-analysis";

/** Category recorded on every api-analysis finding (Core Finding contract). */
export const API_ANALYSIS_CATEGORY = "architecture";

/** Every rule id in this pack must live in this namespace. */
export const API_ANALYSIS_RULE_ID_PREFIX = "api.";

/**
 * The thirteen official domains, in the roadmap's own order, paired with their rule id.
 *
 * Declared centrally so a registry test can pin the pack to the roadmap list, and so a rule id
 * rename — which retires every fingerprint the rule produced — is a deliberate, visible edit.
 */
export const API_ANALYSIS_RULE_IDS = Object.freeze({
  INPUT_VALIDATION: "api.input-validation",
  SCHEMA_VALIDATION: "api.schema-validation",
  AUTHENTICATION: "api.authentication",
  AUTHORIZATION: "api.authorization",
  ERROR_HANDLING: "api.error-handling",
  STATUS_CODES: "api.status-codes",
  PAGINATION: "api.pagination",
  RATE_LIMITING: "api.rate-limiting",
  CORS: "api.cors",
  OPENAPI: "api.openapi",
  REQUEST_LIMITS: "api.request-limits",
  LOGGING: "api.logging",
  CORRELATION_IDS: "api.correlation-ids",
});

/** The official domain list, in roadmap order, with the domain's rule id. */
export const API_ANALYSIS_DOMAINS = Object.freeze([
  Object.freeze({ domain: "input-validation", ruleId: API_ANALYSIS_RULE_IDS.INPUT_VALIDATION }),
  Object.freeze({ domain: "schema-validation", ruleId: API_ANALYSIS_RULE_IDS.SCHEMA_VALIDATION }),
  Object.freeze({ domain: "authentication", ruleId: API_ANALYSIS_RULE_IDS.AUTHENTICATION }),
  Object.freeze({ domain: "authorization", ruleId: API_ANALYSIS_RULE_IDS.AUTHORIZATION }),
  Object.freeze({ domain: "error-handling", ruleId: API_ANALYSIS_RULE_IDS.ERROR_HANDLING }),
  Object.freeze({ domain: "status-codes", ruleId: API_ANALYSIS_RULE_IDS.STATUS_CODES }),
  Object.freeze({ domain: "pagination", ruleId: API_ANALYSIS_RULE_IDS.PAGINATION }),
  Object.freeze({ domain: "rate-limiting", ruleId: API_ANALYSIS_RULE_IDS.RATE_LIMITING }),
  Object.freeze({ domain: "cors", ruleId: API_ANALYSIS_RULE_IDS.CORS }),
  Object.freeze({ domain: "openapi", ruleId: API_ANALYSIS_RULE_IDS.OPENAPI }),
  Object.freeze({ domain: "request-limits", ruleId: API_ANALYSIS_RULE_IDS.REQUEST_LIMITS }),
  Object.freeze({ domain: "logging", ruleId: API_ANALYSIS_RULE_IDS.LOGGING }),
  Object.freeze({ domain: "correlation-ids", ruleId: API_ANALYSIS_RULE_IDS.CORRELATION_IDS }),
]);

/**
 * The `metadata.state` vocabulary every rule records.
 *
 *   established    the domain's evidence is established: the positive fact was observed, or a
 *                  complete-coverage conclusion ("the API establishes none of this") holds
 *   detected       a gap/condition finding was produced
 *   unknown        an API subject exists, but the repository does not establish enough to
 *                  conclude — never read as clean
 *   not_applicable no API subject exists at all (a CLI repository, a repository that declares
 *                  no route and leaves no route-shaped occurrence unread)
 */
export const API_ANALYSIS_STATES = Object.freeze({
  ESTABLISHED: "established",
  DETECTED: "detected",
  UNKNOWN: "unknown",
  NOT_APPLICABLE: "not_applicable",
});

/**
 * The applicability of the *API subject itself* — a separate axis from a rule's state.
 *
 *   applicable      the model established an API graph that declares at least one route
 *   unknown         an API subject exists (routes, route-shaped occurrences, or an
 *                   uninterpretable source) but could not be established — an unsupported
 *                   framework is this, never `not_applicable`
 *   not_applicable  the graph was established and complete, declared no route, and left no
 *                   route-shaped occurrence unread
 */
export const API_ANALYSIS_SUBJECTS = Object.freeze({
  APPLICABLE: "applicable",
  UNKNOWN: "unknown",
  NOT_APPLICABLE: "not_applicable",
});

/** The `metadata.basis` values this pack records. */
export const API_ANALYSIS_BASES = Object.freeze({
  API_GRAPH: "api-graph",
  MIDDLEWARE_GRAPH: "middleware-graph",
  API_SOURCE: "api-source",
  FILE_INVENTORY: "file-inventory",
});

/**
 * Confidence policy, chosen to match the *evidence strength* behind each claim.
 *
 *   OBSERVED_ARTIFACT      the repository observes a file (an OpenAPI document). Strongest:
 *                          the artifact's existence is a fact, though its content and its
 *                          relationship to the API are not.
 *   ESTABLISHED_STRUCTURE  the finding rests on a fully established structural fact (a route
 *                          whose protection the middleware graph establishes).
 *   NAME_DERIVED           the finding's vocabulary is a middleware *name* classification, the
 *                          weakest evidence in the pack, and its wording says so.
 */
export const API_ANALYSIS_CONFIDENCE = Object.freeze({
  OBSERVED_ARTIFACT: 0.9,
  ESTABLISHED_STRUCTURE: 0.7,
  NAME_DERIVED: 0.5,
});

/**
 * The middleware classifications each structural domain reads, as a closed map.
 *
 * The values are the middleware graph's own `MIDDLEWARE_CLASSIFICATIONS` (pinned against it by
 * a test), never re-declared here as new vocabulary.
 */
export const API_ANALYSIS_DOMAIN_CLASSIFICATION = Object.freeze({
  "input-validation": "validation",
  authentication: "authentication",
  authorization: "authorization",
  "rate-limiting": "rate-limit",
  cors: "cors",
  logging: "logging",
});

/**
 * The HTTP methods a request body may travel on, for the input-validation rule's scope.
 *
 * A documented convention, not an inference: the model establishes a route's method but not
 * whether it reads a body, so the rule states the convention it used rather than pretending to
 * know. A body-carrying route is where input validation is conventionally expected.
 */
export const API_ANALYSIS_BODY_METHODS = Object.freeze(["POST", "PUT", "PATCH"]);

/**
 * OpenAPI artifact basenames this build recognises.
 *
 * A closed set: a file whose basename is not here establishes no OpenAPI artifact, so the rule
 * never guesses from a partial name. Matching is by basename only, because that is what the
 * scanner observed; the rule's wording says "observed artifact", never "documented API".
 */
export const API_ANALYSIS_OPENAPI_BASENAMES = Object.freeze([
  "openapi.yaml",
  "openapi.yml",
  "openapi.json",
  "swagger.yaml",
  "swagger.yml",
  "swagger.json",
]);

/**
 * Findings one rule run will report before it stops and records the cap.
 *
 * A cap that does bite is recorded in `metadata.capped` — never silently applied.
 */
export const API_ANALYSIS_LIMITS = Object.freeze({
  MAX_FINDINGS: 200,
});
