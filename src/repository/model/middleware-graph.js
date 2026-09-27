/**
 * Code Guardian — RepositoryModel Middleware & Authorization Graph (Phase 19)
 *
 * The middleware projection: which middleware the repository registers, on which receiver,
 * and which routes that registration structurally reaches — plus the middleware-shaped
 * occurrences that produced no middleware node at all. Like the dependency, architecture,
 * import, symbol and API graphs, it is a **deterministic projection of facts the model
 * already holds**: the registration records Phase 19's acquisition layer produced, the
 * route declarations and route→middleware edges Phase 18's API graph established, and the
 * symbol nodes Phase 17's projection established. It is not a request pipeline, not a
 * runtime tracer, not an authorization analyzer and not a policy engine.
 *
 * ### What "structural protection" means here, exactly
 *
 * This graph models **structure**, never correctness:
 *
 *   protects       `middleware --protects--> route`
 *                  the middleware is declared *in the route's own registration call* —
 *                  `router.get("/x", auth, handler)` — which is exactly the relationship
 *                  Phase 18's API graph already established as a `middleware` edge. This
 *                  projection reads that edge rather than re-deriving a positional reading
 *                  of the same call, so the two graphs cannot disagree about it.
 *   applies-to     `middleware --applies-to--> route`
 *                  the middleware is registered on a receiver (`app.use(auth)`,
 *                  `router.use(auth)`, `fastify.addHook(…)`, `fastify.register(…)`) that
 *                  the route is declared on, or on a receiver that the route's receiver is
 *                  mounted inside (`app.use("/api", router)`). The edge states which
 *                  receiver registration the route is on; it makes no claim about whether
 *                  the middleware runs, in what order relative to the route declaration, or
 *                  what it does.
 *   registered-on  `middleware --registered-on--> file`
 *                  the file in which a receiver-scope registration of this middleware was
 *                  observed. A file entity is the only entity the model has that can stand
 *                  for "where a receiver registration happened", so this is the honest
 *                  target; the receiver names and scopes travel on the edge.
 *   precedes       `middleware --precedes--> middleware`
 *                  the two middleware are consecutive in at least one route's resolved
 *                  chain, in the **declared registration sequence**: receiver-scope
 *                  registrations in declaration order, then the route's own middleware in
 *                  argument order. It is not execution order and not async flow.
 *
 * There is no `authenticates`, `authorizes`, `blocks`, `allows`, `ordered-before-route` or
 * `missing` edge, because nothing in this phase can establish one.
 *
 * ### Middleware identity is Phase 17 identity, never a second symbol table
 *
 * A middleware node exists **only** when its name is a module-scope binding the Phase 17
 * symbol graph established, uniquely, in a file whose declarations were established. A
 * middleware node's `id` *is* the Phase 17 symbol id (`symbol:<path>#<name>`) — the symbol
 * is never duplicated, and this projection creates no symbol node of its own. When a
 * middleware cannot be resolved the route is kept, the observation is kept with a closed
 * reason, and **no node is fabricated**:
 *
 *   `app.use(auth)`      resolves only when `auth` is a unique module-scope binding of the
 *                        declaring file; otherwise `middleware-not-established`,
 *                        `middleware-not-unique` or `resolution-not-established`
 *   `app.use([a, b])`    a computed middleware array: `array-not-established`
 *   `app.use(...list)`   a spread: `spread-not-established`
 *   `app.use(getMw())`   runtime registration: `registration-not-established`
 *   `if (dev) app.use(d)` a conditional registration: `conditional-not-established`
 *   `app.use(express.json())` a member call: `registration-not-established`
 *   `app.use(security.auth)` a member access: `member-expression`
 *   `app.use((req, res, next) => …)` an inline function: `inline-middleware`
 *   `fastify.addHook(name, …)` a non-literal hook name: `hook-name-not-established`
 *   a Koa/Hapi/Nest receiver: `framework-unsupported`
 *
 * ### Authorization classification is a closed, name-only function
 *
 * Each middleware node carries exactly one `classification` from a closed vocabulary
 * (`authentication`, `authorization`, `validation`, `cors`, `rate-limit`, `logging`,
 * `parsing`, `unknown`), computed from the **established name alone** by a documented,
 * deterministic keyword table with a fixed precedence order. No function body is read, no
 * implementation is inspected, no behaviour is inferred, and a name that matches nothing is
 * `unknown` rather than guessed at. `express-jwt` is `authentication` because the name says
 * so; whether it authenticates anything is not this graph's business.
 *
 * ### A route with unresolved middleware is never "unprotected"
 *
 * Every route's `protection` is four-valued, and the unresolved case is its own value:
 *
 *   protected      at least one middleware was established for it
 *   unresolved     no middleware was established, but a middleware-shaped observation on
 *                  it (or on a receiver it is declared on) could not be — so "no middleware
 *                  here" is a claim this graph refuses to make
 *   none-observed  the declaring file's registrations were established, were not truncated,
 *                  and state no middleware for this route
 *   unknown        the declaring file has no established middleware record (so nothing
 *                  about it is known)
 *
 * ### Coverage
 *
 * Same five-way vocabulary as every other graph, for the same reason: an empty middleware
 * list must never be readable as "this repository protects nothing" when the truth is that
 * the sources could not be read.
 *
 * ### Determinism
 *
 * Nodes are sorted by id, edges by `(from, to, type)`, routes by id, unresolved records by
 * `(path, reason, route, kind, name)`. Nothing here reads the clock, the environment, the
 * filesystem, a process or a random source, and no input is iterated in insertion order.
 */

import { apiRouteIdOf } from "./api-graph.js";

/** Version of the projection's shape (not of the model). */
export const MIDDLEWARE_GRAPH_VERSION = "1";

/**
 * The relationships this graph states. A closed, four-value vocabulary.
 *
 * `registered-on` is what makes the graph a graph rooted in the repository; `protects`,
 * `applies-to` and `precedes` describe the declared registration structure around a route.
 * No other relation exists here — there is no `authenticates`, no `allows`, no `blocks`, no
 * `ordered-before`, because nothing in this phase can establish one.
 */
export const MIDDLEWARE_EDGE_TYPES = Object.freeze({
  PROTECTS: "protects",
  PRECEDES: "precedes",
  REGISTERED_ON: "registered-on",
  APPLIES_TO: "applies-to",
});

/** The edge-type vocabulary as a list, for validation. */
export const MIDDLEWARE_EDGE_TYPE_VALUES = Object.freeze(Object.values(MIDDLEWARE_EDGE_TYPES));

/**
 * The authorization vocabulary. Closed, and derived from observable *names* only.
 *
 * `unknown` is a first-class value rather than an absence: a middleware whose name says
 * nothing about its role is classified `unknown`, never guessed into `authentication`
 * because it is registered before a route.
 */
export const MIDDLEWARE_CLASSIFICATIONS = Object.freeze({
  AUTHENTICATION: "authentication",
  AUTHORIZATION: "authorization",
  VALIDATION: "validation",
  CORS: "cors",
  RATE_LIMIT: "rate-limit",
  LOGGING: "logging",
  PARSING: "parsing",
  UNKNOWN: "unknown",
});

/** The classification vocabulary as a list, for validation. */
export const MIDDLEWARE_CLASSIFICATION_VALUES = Object.freeze(
  Object.values(MIDDLEWARE_CLASSIFICATIONS),
);

/**
 * The classification table. Ordered: the first classification whose pattern matches wins,
 * so the order *is* part of the contract and is pinned by a test.
 *
 * A pattern of four or more characters matches anywhere inside the name's compact form (so
 * `requireAuth`, `checkAuthToken` and `jwtAuth` are all `authentication`); a shorter pattern
 * must match a whole word (so `can` does not match `candidate`). Names are split on case
 * boundaries and non-alphanumerics first, so `rateLimit`, `rate-limiter` and `rate_limit`
 * all reduce to the same words.
 */
export const MIDDLEWARE_CLASSIFICATION_RULES = Object.freeze([
  {
    classification: MIDDLEWARE_CLASSIFICATIONS.CORS,
    patterns: Object.freeze(["cors", "crossorigin", "cross-origin"]),
  },
  {
    classification: MIDDLEWARE_CLASSIFICATIONS.RATE_LIMIT,
    patterns: Object.freeze([
      "ratelimit",
      "rate-limiter",
      "throttle",
      "bruteforce",
      "brute-force",
      "slowdown",
      "limiter",
    ]),
  },
  {
    classification: MIDDLEWARE_CLASSIFICATIONS.AUTHORIZATION,
    patterns: Object.freeze([
      "authorize",
      "authorization",
      "authorise",
      "isauthorized",
      "requireadmin",
      "requirerole",
      "requirepermission",
      "permission",
      "rbac",
      "role",
      "policy",
      "acl",
      "grant",
      "scope",
      "can",
    ]),
  },
  {
    classification: MIDDLEWARE_CLASSIFICATIONS.AUTHENTICATION,
    patterns: Object.freeze([
      "auth",
      "authenticate",
      "authentication",
      "isauthenticated",
      "requireauth",
      "requirelogin",
      "login",
      "signin",
      "jwt",
      "passport",
      "bearer",
      "token",
      "session",
      "basic",
      "credential",
    ]),
  },
  {
    classification: MIDDLEWARE_CLASSIFICATIONS.VALIDATION,
    patterns: Object.freeze([
      "validate",
      "validator",
      "validation",
      "sanitize",
      "sanitizer",
      "schema",
      "joi",
      "zod",
      "celebrate",
      "check",
      "verify",
      "constraint",
    ]),
  },
  {
    classification: MIDDLEWARE_CLASSIFICATIONS.PARSING,
    patterns: Object.freeze([
      "parse",
      "parser",
      "bodyparser",
      "json",
      "urlencoded",
      "multipart",
      "cookieparser",
      "cookie",
      "upload",
      "multer",
      "formidable",
      "raw",
      "text",
    ]),
  },
  {
    classification: MIDDLEWARE_CLASSIFICATIONS.LOGGING,
    patterns: Object.freeze([
      "log",
      "logger",
      "logging",
      "morgan",
      "winston",
      "pino",
      "trace",
      "telemetry",
      "audit",
      "metrics",
      "monitor",
    ]),
  },
]);

/** Why a middleware-shaped occurrence produced no middleware node. A closed vocabulary. */
export const MIDDLEWARE_UNRESOLVED_REASONS = Object.freeze({
  MIDDLEWARE_NOT_ESTABLISHED: "middleware-not-established",
  MIDDLEWARE_NOT_UNIQUE: "middleware-not-unique",
  RESOLUTION_NOT_ESTABLISHED: "resolution-not-established",
  MEMBER_EXPRESSION: "member-expression",
  INLINE_MIDDLEWARE: "inline-middleware",
  ARRAY_NOT_ESTABLISHED: "array-not-established",
  SPREAD_NOT_ESTABLISHED: "spread-not-established",
  REGISTRATION_NOT_ESTABLISHED: "registration-not-established",
  CONDITIONAL_NOT_ESTABLISHED: "conditional-not-established",
  HOOK_NAME_NOT_ESTABLISHED: "hook-name-not-established",
  FRAMEWORK_UNSUPPORTED: "framework-unsupported",
});

/** The unresolved-reason vocabulary as a list, for validation. */
export const MIDDLEWARE_UNRESOLVED_REASON_VALUES = Object.freeze(
  Object.values(MIDDLEWARE_UNRESOLVED_REASONS),
);

/**
 * The scopes a middleware node can carry. A closed, four-value vocabulary.
 *
 * The first three are the acquisition layer's own (`app` / `router` / `hook`); `route` is
 * added by this projection for the middleware a route's *own* declaration states —
 * `router.get("/x", auth, handler)` — because that registration is established by Phase 18's
 * API acquisition rather than by this phase's receiver scan. The two vocabularies are
 * related by a documented superset rule, pinned by a test: every scope the scanner can
 * record is a scope the graph can carry, and `route` is the one the graph adds.
 */
export const MIDDLEWARE_SCOPES = Object.freeze(["app", "router", "hook", "route"]);

/** The registration kinds a middleware node can carry. Same superset rule as the scopes. */
export const MIDDLEWARE_REGISTRATIONS = Object.freeze(["use", "hook", "register", "route"]);

/** The scope and registration kind a route's own declaration establishes. */
export const MIDDLEWARE_ROUTE_SCOPE = "route";
export const MIDDLEWARE_ROUTE_REGISTRATION = "route";

/**
 * What kind of occurrence an unresolved record describes.
 *
 *   registration      a receiver-scope `use` / `addHook` / `register`
 *   route-middleware  one entry of a route's own middleware list, carried over from the API
 *                     graph's own unresolved middleware records
 */
export const MIDDLEWARE_UNRESOLVED_KINDS = Object.freeze(["registration", "route-middleware"]);

/**
 * How one of the API graph's own unresolved reasons reads in this graph's vocabulary.
 *
 * The API graph answers a route-scope middleware reference with its handler vocabulary
 * (`handler-not-established`, `inline-handler`, …), because from its point of view a
 * middleware reference is a callable in the same position a handler would be. This graph has
 * its own vocabulary for exactly the same occurrences, so the mapping is explicit rather
 * than implicit: an occurrence that is a middleware in one graph is a middleware in the
 * other, and the mapping is pinned by a test.
 */
export const MIDDLEWARE_ROUTE_REASON_MAP = Object.freeze({
  "handler-not-established": MIDDLEWARE_UNRESOLVED_REASONS.MIDDLEWARE_NOT_ESTABLISHED,
  "handler-not-unique": MIDDLEWARE_UNRESOLVED_REASONS.MIDDLEWARE_NOT_UNIQUE,
  "inline-handler": MIDDLEWARE_UNRESOLVED_REASONS.INLINE_MIDDLEWARE,
  "member-expression": MIDDLEWARE_UNRESOLVED_REASONS.MEMBER_EXPRESSION,
  "resolution-not-established": MIDDLEWARE_UNRESOLVED_REASONS.RESOLUTION_NOT_ESTABLISHED,
});

/** What a route's structural protection is. Closed, four-value vocabulary. */
export const MIDDLEWARE_PROTECTION_STATES = Object.freeze({
  PROTECTED: "protected",
  UNRESOLVED: "unresolved",
  NONE_OBSERVED: "none-observed",
  UNKNOWN: "unknown",
});

/** The protection vocabulary as a list, for validation. */
export const MIDDLEWARE_PROTECTION_VALUES = Object.freeze(
  Object.values(MIDDLEWARE_PROTECTION_STATES),
);

/** Middleware graph coverage states. The same five-way vocabulary every graph uses. */
export const MIDDLEWARE_GRAPH_STATES = Object.freeze({
  COMPLETE: "complete",
  PARTIAL: "partial",
  TRUNCATED: "truncated",
  UNSUPPORTED: "unsupported",
  UNKNOWN: "unknown",
});

/** The state vocabulary as a list, for validation. */
export const MIDDLEWARE_GRAPH_STATE_VALUES = Object.freeze(
  Object.values(MIDDLEWARE_GRAPH_STATES),
);

/**
 * Graph bounds.
 *
 * `MAX_MIDDLEWARE` sits above what acquisition can produce (at most `maxFiles` module
 * sources, each establishing at most `maxRegistrationsPerFile` registrations). A cap that
 * does bite is recorded — never silently applied.
 */
export const MIDDLEWARE_GRAPH_LIMITS = Object.freeze({
  MAX_MIDDLEWARE: 20000,
  MAX_EDGES: 200000,
  MAX_ROUTES: 20000,
  MAX_UNRESOLVED: 20000,
  MAX_CHAIN_LENGTH: 64,
  MAX_RECEIVERS_PER_NODE: 32,
  MAX_SOURCE_PATHS_PER_NODE: 32,
  MAX_UNESTABLISHED_SOURCES: 1024,
  MAX_UNINTERPRETED_EXTENSIONS: 32,
  /** How far a mount chain is followed before it is treated as unestablished. */
  MAX_MOUNT_DEPTH: 8,
});

/** Acquisition statuses, re-declared so this module does not import the scanner. */
const PARSED_STATUS = "parsed";
const UNSUPPORTED_STATUS = "unsupported";
const NOT_INSPECTED_STATUS = "not-inspected";

/** Freeze a value and everything reachable from it. */
function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const key of Object.keys(value)) deepFreeze(value[key]);
  return value;
}

/**
 * Sort by a list of keys, so no two records compare equal.
 *
 * Strings compare lexicographically and **numbers numerically**. The numeric branch is not
 * decoration: `sequence` — a registration's declared ordinal — is a number, and a
 * comparator that answered `-1` in both directions for a numeric key would not be a
 * comparator at all, so `sort` would be free to return any order and the declared
 * registration sequence the graph claims to state would depend on the engine's internals.
 */
function compareByKeys(keys) {
  return (a, b) => {
    for (const key of keys) {
      const left = a?.[key];
      const right = b?.[key];
      if (left === right) continue;
      if (typeof left === "string" && typeof right === "string") return left < right ? -1 : 1;
      if (typeof left === "number" && typeof right === "number") return left < right ? -1 : 1;
      return left === undefined || left === null ? 1 : -1;
    }
    return 0;
  };
}

function sortedUnique(values) {
  return [...new Set(values)].sort();
}

/**
 * The deterministic order of the unresolved list.
 *
 * Deliberately the model contract's own key — `(path, reason, route, kind, name)` with an
 * absent field rendered as the empty string — with the remaining recorded fields appended as
 * tie-breakers so no two records ever compare equal. Rendering `null` as the empty string is
 * the point: a comparator that pushed nulls last would order a receiver-scope observation
 * *before* a route-scope observation with the same reason, while the contract — which orders
 * by its key — requires the opposite, so a file that states both would make the whole model
 * unbuildable. The projection and the contract must agree about this list, and the only way
 * to guarantee that is for both to use the same key.
 */
function unresolvedOrderKey(record) {
  return [
    record.path,
    record.reason,
    record.route ?? "",
    record.kind,
    record.name ?? "",
    record.receiver ?? "",
    record.member ?? "",
  ].join("\u0000");
}

/** The file entity id for a repository-relative path. */
function fileIdOf(path) {
  return `file:${path}`;
}

/**
 * The identity of one HTTP endpoint, reused from the API graph verbatim.
 *
 * Re-exported rather than re-implemented: a second route-identity scheme would let this
 * graph and the API graph disagree about which route an edge names.
 */
export const middlewareRouteIdOf = apiRouteIdOf;

/** Whether a state means a middleware graph was established. */
export function isEstablishedMiddlewareState(state) {
  return (
    state === MIDDLEWARE_GRAPH_STATES.COMPLETE ||
    state === MIDDLEWARE_GRAPH_STATES.PARTIAL ||
    state === MIDDLEWARE_GRAPH_STATES.TRUNCATED
  );
}

/** Whether a source's *registration set* was established. */
export function isMiddlewareSourceEstablished(source) {
  return source.status === PARSED_STATUS && source.established === true;
}

/**
 * Split an identifier into lower-cased words.
 *
 * Case boundaries, digits and any non-alphanumeric separator all split, so `rateLimit`,
 * `rate-limit`, `RATE_LIMIT` and `rateLimiter` reduce to the same words.
 *
 * @param {string} name
 * @returns {string[]}
 */
export function middlewareNameWords(name) {
  return String(name)
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .filter((word) => word.length > 0)
    .map((word) => word.toLowerCase());
}

/**
 * Classify a middleware from its established name alone.
 *
 * Deterministic and closed: the name is split into words, its compact form is the words
 * joined, and the classification table is scanned in its declared order — a pattern of four
 * or more characters matches anywhere in the compact form, a shorter pattern must equal a
 * whole word. The first match wins; no match is `unknown`.
 *
 * @param {string} name
 * @returns {string} One of `MIDDLEWARE_CLASSIFICATIONS`.
 */
export function classifyMiddlewareName(name) {
  const words = middlewareNameWords(name);
  if (words.length === 0) return MIDDLEWARE_CLASSIFICATIONS.UNKNOWN;
  const compact = words.join("");
  for (const rule of MIDDLEWARE_CLASSIFICATION_RULES) {
    for (const pattern of rule.patterns) {
      const normalized = pattern.replace(/[^a-z0-9]/g, "");
      if (normalized.length === 0) continue;
      if (normalized.length >= 4 ? compact.includes(normalized) : words.includes(normalized)) {
        return rule.classification;
      }
    }
  }
  return MIDDLEWARE_CLASSIFICATIONS.UNKNOWN;
}

/**
 * The graph's coverage state.
 *
 * Read only from facts the model already validated. Nothing is inferred from node or edge
 * counts — an empty middleware list is a *result*, not evidence of missing information.
 */
export function middlewareGraphState({
  sources,
  scanComplete,
  scanTruncated,
  hasScanState,
  projectionTruncated,
  uninterpretedSources = 0,
}) {
  if (!hasScanState) return MIDDLEWARE_GRAPH_STATES.UNKNOWN;

  if (sources.length === 0) {
    if (scanComplete !== true || scanTruncated === true) return MIDDLEWARE_GRAPH_STATES.UNKNOWN;
    return uninterpretedSources > 0
      ? MIDDLEWARE_GRAPH_STATES.UNSUPPORTED
      : MIDDLEWARE_GRAPH_STATES.COMPLETE;
  }

  if (scanTruncated === true || projectionTruncated === true) {
    return MIDDLEWARE_GRAPH_STATES.TRUNCATED;
  }
  if (
    sources.some(
      (source) =>
        source.truncated === true ||
        source.status === NOT_INSPECTED_STATUS ||
        source.reason === "budget-exhausted",
    )
  ) {
    return MIDDLEWARE_GRAPH_STATES.TRUNCATED;
  }

  const parsed = sources.filter((source) => source.status === PARSED_STATUS);
  if (parsed.length === 0) {
    return sources.every((source) => source.status === UNSUPPORTED_STATUS)
      ? MIDDLEWARE_GRAPH_STATES.UNSUPPORTED
      : MIDDLEWARE_GRAPH_STATES.UNKNOWN;
  }

  const everyClaimEstablished = parsed.every(
    (source) => (source.problems ?? []).length === 0 && source.established === true,
  );
  if (everyClaimEstablished && parsed.length === sources.length && scanComplete === true) {
    return MIDDLEWARE_GRAPH_STATES.COMPLETE;
  }
  return MIDDLEWARE_GRAPH_STATES.PARTIAL;
}

/**
 * Build the middleware graph from the model's middleware records, the API graph and the
 * symbol graph.
 *
 * @param {object} input
 * @param {object[]} input.sources Middleware source records from `entities.js`.
 * @param {object[]} input.apiSources API source records from `entities.js`.
 * @param {object} input.apiGraph The Phase 18 API graph.
 * @param {object[]} input.semanticsSources Semantic source records, for establishment.
 * @param {object} input.symbolGraph The Phase 17 symbol graph (for middleware identity).
 * @param {object} input.coverage `{ scanComplete, scanTruncated }`.
 * @param {object} [input.uninterpreted] Source files this graph does not read.
 * @returns {object} Deeply frozen
 *   `{ version, state, established, nodes, edges, routes, unresolved, coverage }`.
 */
export function buildMiddlewareGraph({
  sources,
  apiSources = [],
  apiGraph,
  semanticsSources = [],
  symbolGraph,
  coverage,
  uninterpreted,
}) {
  const limits = MIDDLEWARE_GRAPH_LIMITS;
  const uninterpretedSources =
    Number.isInteger(uninterpreted?.sources) && uninterpreted.sources > 0
      ? uninterpreted.sources
      : 0;
  const uninterpretedExtensions = sortedUnique(
    (Array.isArray(uninterpreted?.extensions) ? uninterpreted.extensions : []).filter(
      (extension) => typeof extension === "string" && extension !== "",
    ),
  );

  // Which files the semantic layer established, so a middleware that cannot be resolved can
  // say *why*: the file was not semantically scanned, or the name is not a module-scope
  // binding there.
  const semanticsEstablishedByPath = new Map();
  for (const source of semanticsSources) {
    semanticsEstablishedByPath.set(
      source.path,
      source.status === PARSED_STATUS && source.established?.declarationsEstablished === true,
    );
  }

  const symbolById = new Map((symbolGraph?.nodes ?? []).map((node) => [node.id, node]));
  const symbolByKey = new Map(
    (symbolGraph?.nodes ?? []).map((node) => [`${node.path}\u0000${node.name}`, node]),
  );

  const apiNodeIds = new Set((apiGraph?.nodes ?? []).map((node) => node.id));

  const unresolvedAll = [];
  const unresolvedIndex = new Map();
  // Receiver-scope observations indexed by `(path, receiver)`, so associating them with a
  // route is a lookup rather than a scan of every observation for every route.
  const registrationUnresolvedByPath = new Map();
  const noteUnresolved = (record) => {
    const key = `${record.path}\u0000${record.kind}\u0000${record.reason}\u0000${record.route ?? ""}\u0000${record.name ?? ""}\u0000${record.member ?? ""}\u0000${record.receiver ?? ""}`;
    const existing = unresolvedIndex.get(key);
    if (existing !== undefined) {
      existing.count += 1;
      return existing;
    }
    const entry = { ...record, count: 1, evidenceId: record.evidenceId ?? null };
    unresolvedIndex.set(key, entry);
    unresolvedAll.push(entry);
    if (record.kind === "registration" && typeof record.receiver === "string") {
      let list = registrationUnresolvedByPath.get(record.path);
      if (list === undefined) {
        list = [];
        registrationUnresolvedByPath.set(record.path, list);
      }
      list.push(entry);
    }
    return entry;
  };

  const nodeBySymbolId = new Map();
  const middlewareNodeFor = (symbol) => {
    let node = nodeBySymbolId.get(symbol.id);
    if (node === undefined) {
      node = {
        id: symbol.id,
        symbolId: symbol.id,
        path: symbol.path,
        fileId: symbol.fileId,
        name: symbol.name,
        classification: classifyMiddlewareName(symbol.name),
        scopes: new Set(),
        registrations: new Set(),
        hooks: new Set(),
        receivers: new Set(),
        frameworks: new Set(),
        sourcePaths: new Set(),
        evidenceIds: new Set(),
        registrationCount: 0,
      };
      nodeBySymbolId.set(symbol.id, node);
    }
    return node;
  };

  const edges = [];
  const edgeIndex = new Map();
  const addEdge = (from, to, type) => {
    const key = `${from}\u0000${to}\u0000${type}`;
    let edge = edgeIndex.get(key);
    if (edge === undefined) {
      edge = {
        from,
        to,
        type,
        count: 0,
        names: new Set(),
        receivers: new Set(),
        sourcePaths: new Set(),
        evidenceIds: new Set(),
      };
      edgeIndex.set(key, edge);
      edges.push(edge);
      return edge;
    }
    return edge;
  };

  // ── Receiver-scope registrations ───────────────────────────────────────────
  //
  // Per file, the registrations that apply to a receiver: the registration itself plus the
  // registrations on any receiver whose mount chain contains it. Mounts are read only from
  // the same file, because a mount target this build cannot statically identify is
  // deliberately never followed.
  const registrationsByPath = new Map();
  const mountParentsByPath = new Map();

  for (const source of sources) {
    if (!isMiddlewareSourceEstablished(source)) continue;
    const registered = [];
    const parents = new Map();

    for (const mount of source.mounts) {
      const list = parents.get(mount.child);
      if (list === undefined) parents.set(mount.child, [mount.parent]);
      else if (!list.includes(mount.parent)) list.push(mount.parent);
    }
    mountParentsByPath.set(source.path, parents);

    for (const registration of source.registrations) {
      const resolved = [];
      const unresolvedCandidates = [];
      const semanticsEstablished = semanticsEstablishedByPath.get(source.path) === true;

      const items = [
        ...registration.middleware.map((entry) => ({ entry, conditional: registration.conditional === true })),
        ...registration.unresolved.map((entry) => ({ entry, fromObservation: true })),
      ];

      for (const item of items) {
        const entry = item.entry;
        const reason = item.fromObservation
          ? entry.reason
          : entry.form === "inline"
            ? MIDDLEWARE_UNRESOLVED_REASONS.INLINE_MIDDLEWARE
            : entry.member !== null
              ? MIDDLEWARE_UNRESOLVED_REASONS.MEMBER_EXPRESSION
              : null;

        if (reason !== null) {
          unresolvedCandidates.push({
            reason,
            name: entry.name ?? null,
            member: entry.member ?? null,
          });
          continue;
        }

        if (!semanticsEstablished) {
          unresolvedCandidates.push({
            reason: MIDDLEWARE_UNRESOLVED_REASONS.RESOLUTION_NOT_ESTABLISHED,
            name: entry.name,
            member: null,
          });
          continue;
        }
        const symbol = symbolByKey.get(`${source.path}\u0000${entry.name}`);
        if (symbol === undefined) {
          unresolvedCandidates.push({
            reason: MIDDLEWARE_UNRESOLVED_REASONS.MIDDLEWARE_NOT_ESTABLISHED,
            name: entry.name,
            member: null,
          });
          continue;
        }
        if (symbol.shadowed === true) {
          unresolvedCandidates.push({
            reason: MIDDLEWARE_UNRESOLVED_REASONS.MIDDLEWARE_NOT_UNIQUE,
            name: entry.name,
            member: null,
          });
          continue;
        }

        const node = middlewareNodeFor(symbol);
        node.scopes.add(registration.scope);
        node.registrations.add(registration.registration);
        if (registration.hook !== null) node.hooks.add(registration.hook);
        node.receivers.add(registration.receiver);
        if (registration.framework !== null) node.frameworks.add(registration.framework);
        node.sourcePaths.add(source.path);
        node.evidenceIds.add(source.evidenceId);
        node.registrationCount += 1;

        const edge = addEdge(symbol.id, fileIdOf(source.path), MIDDLEWARE_EDGE_TYPES.REGISTERED_ON);
        edge.count += 1;
        edge.names.add(registration.registration);
        edge.receivers.add(registration.receiver);
        edge.sourcePaths.add(source.path);
        edge.evidenceIds.add(source.evidenceId);

        resolved.push({ symbolId: symbol.id, order: registration.sequence });
      }

      for (const candidate of unresolvedCandidates) {
        noteUnresolved({
          path: source.path,
          kind: "registration",
          reason: candidate.reason,
          receiver: registration.receiver,
          scope: registration.scope,
          registration: registration.registration,
          name: candidate.name,
          member: candidate.member,
          route: null,
          evidenceId: source.evidenceId,
        });
      }

      registered.push({
        receiver: registration.receiver,
        receiverKind: registration.receiverKind,
        registration: registration.registration,
        scope: registration.scope,
        hook: registration.hook,
        path: registration.path,
        sequence: registration.sequence,
        resolved,
      });
    }

    registered.sort(compareByKeys(["sequence", "receiver"]));
    registrationsByPath.set(source.path, registered);
  }

  /** The mount ancestors of a receiver in one file, nearest first. */
  const mountAncestors = (path, receiver) => {
    const parents = mountParentsByPath.get(path);
    if (parents === undefined) return [];
    const out = [];
    const visited = new Set([receiver]);
    let frontier = parents.get(receiver) ?? [];
    let depth = 0;
    while (frontier.length > 0 && depth < limits.MAX_MOUNT_DEPTH) {
      const next = [];
      for (const parent of frontier) {
        if (visited.has(parent)) continue;
        visited.add(parent);
        out.push(parent);
        next.push(...(parents.get(parent) ?? []));
      }
      frontier = next;
      depth += 1;
    }
    return out;
  };

  /** The registrations in one file that structurally apply to a receiver. */
  const applicableRegistrations = (path, receiver) => {
    const registered = registrationsByPath.get(path);
    if (registered === undefined) return [];
    const wanted = new Set([receiver, ...mountAncestors(path, receiver)]);
    return registered.filter((entry) => wanted.has(entry.receiver));
  };

  const unresolvedRegistrations = (path, receiver) => {
    const registered = registrationUnresolvedByPath.get(path);
    if (registered === undefined) return [];
    const wanted = new Set([receiver, ...mountAncestors(path, receiver)]);
    return registered.filter((record) => wanted.has(record.receiver));
  };

  // ── Route records ──────────────────────────────────────────────────────────
  //
  // Which (file, receiver) pairs declare each route, and — for the chain's route-scope part
  // — the route's own middleware entries in declared argument order. Both come from the API
  // source records, never from a re-reading of the call.
  const pairsByRoute = new Map();
  for (const source of apiSources) {
    if (source.status !== PARSED_STATUS || source.established !== true) continue;
    for (const route of source.routes) {
      const routeId = middlewareRouteIdOf(route.method, route.path);
      const list = pairsByRoute.get(routeId);
      const pair = {
        path: source.path,
        receiver: route.receiver,
        middlewareNames: route.middleware
          .filter((entry) => entry.form === "reference" && entry.member === null)
          .map((entry) => entry.name),
      };
      if (list === undefined) pairsByRoute.set(routeId, [pair]);
      else list.push(pair);
    }
  }
  for (const list of pairsByRoute.values()) {
    list.sort(compareByKeys(["path", "receiver"]));
  }

  // The API graph's own resolved route→middleware edges, keyed for a name lookup so the
  // route-scope part of a chain is ordered by the declaration while remaining *resolved* by
  // the API graph rather than re-resolved here.
  const routeMiddlewareSymbols = new Map();
  for (const edge of apiGraph?.edges ?? []) {
    if (edge.type !== "middleware") continue;
    const symbols = routeMiddlewareSymbols.get(edge.from);
    if (symbols === undefined) routeMiddlewareSymbols.set(edge.from, [edge.to]);
    else if (!symbols.includes(edge.to)) symbols.push(edge.to);
  }
  const routeMiddlewareSymbolByName = new Map();
  for (const edge of apiGraph?.edges ?? []) {
    if (edge.type !== "middleware") continue;
    for (const name of edge.names ?? []) {
      routeMiddlewareSymbolByName.set(`${edge.from}\u0000${name}`, edge.to);
    }
  }

  const sourceByPath = new Map(sources.map((source) => [source.path, source]));
  const apiSourceByPath = new Map(apiSources.map((source) => [source.path, source]));

  const routes = [];
  for (const routeNode of apiGraph?.nodes ?? []) {
    const routeId = routeNode.id;
    const pairs = pairsByRoute.get(routeId) ?? [];

    const middlewareIds = new Set();
    const chain = [];
    let chainTruncated = false;
    let establishedFiles = 0;

    for (const pair of pairs) {
      const source = sourceByPath.get(pair.path);        if (source !== undefined && isMiddlewareSourceEstablished(source) && source.truncated !== true) {
        establishedFiles += 1;
      }

      for (const registration of applicableRegistrations(pair.path, pair.receiver)) {
        for (const entry of registration.resolved) {
          const edge = addEdge(entry.symbolId, routeId, MIDDLEWARE_EDGE_TYPES.APPLIES_TO);
          edge.count += 1;
          edge.names.add(registration.registration);
          edge.receivers.add(registration.receiver);
          edge.sourcePaths.add(pair.path);
          if (source?.evidenceId != null) edge.evidenceIds.add(source.evidenceId);
          middlewareIds.add(entry.symbolId);
          if (chain.length >= limits.MAX_CHAIN_LENGTH) chainTruncated = true;
          else if (!chain.includes(entry.symbolId)) chain.push(entry.symbolId);
        }
      }

      for (const name of pair.middlewareNames) {
        const symbolId = routeMiddlewareSymbolByName.get(`${routeId}\u0000${name}`);
        if (symbolId === undefined) continue;
        const symbol = symbolById.get(symbolId);
        if (symbol !== undefined) {
          // The route's own declaration is itself a registration of this middleware, so the
          // node exists even when nothing else registers it. The scope and registration kind
          // say where it came from: the route, not a receiver.
          const node = middlewareNodeFor(symbol);
          node.scopes.add(MIDDLEWARE_ROUTE_SCOPE);
          node.registrations.add(MIDDLEWARE_ROUTE_REGISTRATION);
          node.sourcePaths.add(pair.path);
          const apiSource = apiSourceByPath.get(pair.path);
          if (apiSource?.evidenceId != null) node.evidenceIds.add(apiSource.evidenceId);
          node.registrationCount += 1;
        }
        const edge = addEdge(symbolId, routeId, MIDDLEWARE_EDGE_TYPES.PROTECTS);
        edge.count += 1;
        edge.names.add(name);
        edge.sourcePaths.add(pair.path);
        const evidenceSource = apiSourceByPath.get(pair.path);
        if (evidenceSource?.evidenceId != null) edge.evidenceIds.add(evidenceSource.evidenceId);
        middlewareIds.add(symbolId);
        if (chain.length >= limits.MAX_CHAIN_LENGTH) chainTruncated = true;
        else if (!chain.includes(symbolId)) chain.push(symbolId);
      }
    }

    // The route's own middleware entries the API graph could not resolve, translated into
    // this graph's vocabulary.
    const unresolvedHere = [];
    for (const record of apiGraph?.unresolved ?? []) {
      if (record.kind !== "middleware" || record.route !== routeId) continue;
      const reason = MIDDLEWARE_ROUTE_REASON_MAP[record.reason];
      if (reason === undefined) continue;
      unresolvedHere.push(
        noteUnresolved({
          path: record.path,
          kind: "route-middleware",
          reason,
          receiver: null,
          scope: "route",
          registration: null,
          name: record.name ?? null,
          member: record.member ?? null,
          route: routeId,
          evidenceId: record.evidenceId ?? null,
        }),
      );
    }
    for (const pair of pairs) {
      for (const record of unresolvedRegistrations(pair.path, pair.receiver)) {
        unresolvedHere.push(record);
      }
    }

    for (let index = 0; index + 1 < chain.length; index += 1) {
      const edge = addEdge(chain[index], chain[index + 1], MIDDLEWARE_EDGE_TYPES.PRECEDES);
      edge.count += 1;
      for (const pair of pairs) edge.sourcePaths.add(pair.path);
      for (const entry of sources) {
        if (pairs.some((pair) => pair.path === entry.path) && entry.evidenceId != null) {
          edge.evidenceIds.add(entry.evidenceId);
        }
      }
    }

    const unresolvedCount = new Set(unresolvedHere.filter((entry) => entry !== undefined)).size;
    const protection =
      middlewareIds.size > 0
        ? MIDDLEWARE_PROTECTION_STATES.PROTECTED
        : unresolvedCount > 0
          ? MIDDLEWARE_PROTECTION_STATES.UNRESOLVED
          : establishedFiles === pairs.length && pairs.length > 0 && !chainTruncated
            ? MIDDLEWARE_PROTECTION_STATES.NONE_OBSERVED
            : MIDDLEWARE_PROTECTION_STATES.UNKNOWN;

    routes.push({
      route: routeId,
      method: routeNode.method,
      path: routeNode.path,
      protection,
      middleware: sortedUnique([...middlewareIds]),
      middlewareCount: middlewareIds.size,
      unresolvedCount,
      chainTruncated,
      // Deliberately only counts: the individual observations live in `unresolved`, so a
      // consumer that wants them asks for them, and a consumer that only needs the shape of
      // the route does not receive a list it will misread.
      protectionBasis:
        protection === MIDDLEWARE_PROTECTION_STATES.PROTECTED
          ? "established-registration"
          : protection === MIDDLEWARE_PROTECTION_STATES.UNRESOLVED
            ? "unresolved-registration"
            : protection === MIDDLEWARE_PROTECTION_STATES.NONE_OBSERVED
              ? "established-and-empty"
              : "not-established",
    });
  }

  routes.sort(compareByKeys(["route"]));

  // ── Materialize ────────────────────────────────────────────────────────────
  const allNodes = [...nodeBySymbolId.values()]
    .map((node) => ({
      id: node.id,
      symbolId: node.symbolId,
      path: node.path,
      fileId: node.fileId,
      name: node.name,
      classification: node.classification,
      scopes: sortedUnique([...node.scopes]),
      registrations: sortedUnique([...node.registrations]),
      hooks: sortedUnique([...node.hooks]),
      receivers: sortedUnique([...node.receivers]).slice(0, limits.MAX_RECEIVERS_PER_NODE),
      frameworks: sortedUnique([...node.frameworks]),
      sourcePaths: sortedUnique([...node.sourcePaths]).slice(0, limits.MAX_SOURCE_PATHS_PER_NODE),
      evidenceIds: sortedUnique([...node.evidenceIds]),
      registrationCount: node.registrationCount,
      routeCount: 0,
      protectsCount: 0,
      appliesToCount: 0,
    }))
    .sort(compareByKeys(["id"]));

  const nodesTruncated = allNodes.length > limits.MAX_MIDDLEWARE;
  const nodes = nodesTruncated ? allNodes.slice(0, limits.MAX_MIDDLEWARE) : allNodes;
  const nodeIds = new Set(nodes.map((node) => node.id));

  const routesTruncated = routes.length > limits.MAX_ROUTES;
  const finalRoutes = routesTruncated ? routes.slice(0, limits.MAX_ROUTES) : routes;
  const routeIds = new Set(finalRoutes.map((route) => route.route));

  const knownEndpoint = (id) =>
    (id.startsWith("symbol:") && nodeIds.has(id)) ||
    (id.startsWith("route:") && routeIds.has(id)) ||
    id.startsWith("file:");

  const allEdges = edges
    .filter((edge) => knownEndpoint(edge.from) && knownEndpoint(edge.to))
    .map((edge) => {
      const names = sortedUnique([...edge.names]);
      const receivers = sortedUnique([...edge.receivers]);
      const sourcePaths = sortedUnique([...edge.sourcePaths]);
      return {
        from: edge.from,
        to: edge.to,
        type: edge.type,
        count: edge.count,
        names: names.slice(0, limits.MAX_RECEIVERS_PER_NODE),
        receivers: receivers.slice(0, limits.MAX_RECEIVERS_PER_NODE),
        sourcePaths: sourcePaths.slice(0, limits.MAX_SOURCE_PATHS_PER_NODE),
        evidenceIds: sortedUnique([...edge.evidenceIds]),
      };
    })
    .sort(compareByKeys(["from", "to", "type"]));

  const edgesTruncated = allEdges.length > limits.MAX_EDGES;
  const finalEdges = edgesTruncated ? allEdges.slice(0, limits.MAX_EDGES) : allEdges;

  // Fold the edge counts back into the nodes, so a node states how many routes it reaches
  // rather than leaving a consumer to count edges.
  const nodesById = new Map(nodes.map((node) => [node.id, node]));
  for (const edge of finalEdges) {
    const node = nodesById.get(edge.from);
    if (node === undefined) continue;
    if (edge.type === MIDDLEWARE_EDGE_TYPES.PROTECTS) node.protectsCount += edge.count;
    else if (edge.type === MIDDLEWARE_EDGE_TYPES.APPLIES_TO) node.appliesToCount += edge.count;
  }
  for (const route of finalRoutes) {
    for (const middlewareId of route.middleware) {
      const node = nodesById.get(middlewareId);
      if (node !== undefined) node.routeCount += 1;
    }
  }

  const sortedUnresolved = unresolvedAll
    .slice()
    .sort((a, b) => {
      const left = unresolvedOrderKey(a);
      const right = unresolvedOrderKey(b);
      return left < right ? -1 : left > right ? 1 : 0;
    })
    .map((record) => deepFreeze({ ...record }));
  const unresolvedTruncated = sortedUnresolved.length > limits.MAX_UNRESOLVED;
  const unresolved = unresolvedTruncated
    ? sortedUnresolved.slice(0, limits.MAX_UNRESOLVED)
    : sortedUnresolved;

  const state = middlewareGraphState({
    sources,
    scanComplete: coverage?.scanComplete === true,
    scanTruncated: coverage?.scanTruncated === true,
    hasScanState:
      typeof coverage?.scanComplete === "boolean" && typeof coverage?.scanTruncated === "boolean",
    projectionTruncated: nodesTruncated || edgesTruncated || unresolvedTruncated,
    uninterpretedSources,
  });
  const established = isEstablishedMiddlewareState(state);

  const unestablished = sources
    .filter((source) => !isMiddlewareSourceEstablished(source))
    .map((source) =>
      Object.freeze({
        path: source.path,
        status: source.status,
        reason: source.reason ?? null,
        problems: Object.freeze([...(source.problems ?? [])]),
        established: source.established === true,
        truncated: source.truncated === true,
        evidenceId: source.evidenceId ?? null,
      }),
    )
    .sort(compareByKeys(["path"]))
    .slice(0, limits.MAX_UNESTABLISHED_SOURCES);

  const unresolvedByReason = {};
  for (const reason of MIDDLEWARE_UNRESOLVED_REASON_VALUES) unresolvedByReason[reason] = 0;
  for (const record of unresolvedAll) {
    unresolvedByReason[record.reason] = (unresolvedByReason[record.reason] ?? 0) + 1;
  }
  const unestablishedCount = sources.filter(
    (source) => !isMiddlewareSourceEstablished(source),
  ).length;

  const countByStatus = (status) => sources.filter((source) => source.status === status).length;
  const countEdges = (type) => finalEdges.filter((edge) => edge.type === type).length;
  const classificationCounts = {};
  for (const classification of MIDDLEWARE_CLASSIFICATION_VALUES) classificationCounts[classification] = 0;
  for (const node of nodes) {
    classificationCounts[node.classification] = (classificationCounts[node.classification] ?? 0) + 1;
  }
  const protectionCounts = {};
  for (const value of MIDDLEWARE_PROTECTION_VALUES) protectionCounts[value] = 0;
  for (const route of finalRoutes) {
    protectionCounts[route.protection] = (protectionCounts[route.protection] ?? 0) + 1;
  }
  const registrationCount = sources.reduce(
    (total, source) => total + (source.counts?.registrations ?? 0),
    0,
  );

  return deepFreeze({
    version: MIDDLEWARE_GRAPH_VERSION,
    state,
    established,
    nodes,
    edges: finalEdges,
    routes: finalRoutes,
    // Middleware-shaped occurrences that are not registrations: "the file says this and we
    // cannot establish what it denotes" is a different fact from *this middleware is
    // registered here*.
    unresolved,
    coverage: {
      state,
      established,
      complete: state === MIDDLEWARE_GRAPH_STATES.COMPLETE,
      truncated: state === MIDDLEWARE_GRAPH_STATES.TRUNCATED,
      inspected: sources.some((source) => source.status === PARSED_STATUS),
      middleware: nodes.length,
      edges: finalEdges.length,
      sources: sources.length,
      registrations: registrationCount,
      mounts: sources.reduce((total, source) => total + (source.counts?.mounts ?? 0), 0),
      declaringModules: sortedUnique(nodes.flatMap((node) => node.sourcePaths)).length,
      protectsEdges: countEdges(MIDDLEWARE_EDGE_TYPES.PROTECTS),
      appliesToEdges: countEdges(MIDDLEWARE_EDGE_TYPES.APPLIES_TO),
      precedesEdges: countEdges(MIDDLEWARE_EDGE_TYPES.PRECEDES),
      registeredOnEdges: countEdges(MIDDLEWARE_EDGE_TYPES.REGISTERED_ON),
      routes: finalRoutes.length,
      protectedRoutes: protectionCounts[MIDDLEWARE_PROTECTION_STATES.PROTECTED],
      unresolvedRoutes: protectionCounts[MIDDLEWARE_PROTECTION_STATES.UNRESOLVED],
      unprotectedRoutes: protectionCounts[MIDDLEWARE_PROTECTION_STATES.NONE_OBSERVED],
      unknownProtectionRoutes: protectionCounts[MIDDLEWARE_PROTECTION_STATES.UNKNOWN],
      classifications: Object.freeze(classificationCounts),
      parsed: countByStatus(PARSED_STATUS),
      unsupported: countByStatus(UNSUPPORTED_STATUS),
      failed: sources.filter(
        (source) =>
          source.status !== PARSED_STATUS &&
          source.status !== UNSUPPORTED_STATUS &&
          source.status !== NOT_INSPECTED_STATUS,
      ).length,
      notInspected: countByStatus(NOT_INSPECTED_STATUS),
      uninterpretedSources,
      uninterpretedExtensions: Object.freeze(
        uninterpretedExtensions.slice(0, limits.MAX_UNINTERPRETED_EXTENSIONS),
      ),
      uninterpretedExtensionsTruncated:
        uninterpretedExtensions.length > limits.MAX_UNINTERPRETED_EXTENSIONS,
      unresolved: unresolvedAll.length,
      unresolvedReported: unresolved.length,
      unresolvedByReason: Object.freeze(unresolvedByReason),
      unestablished: unestablishedCount,
      unestablishedSources: Object.freeze(unestablished),
      nodesTruncated,
      edgesTruncated,
      routesTruncated,
      unresolvedTruncated,
      limits,
    },
  });
}
