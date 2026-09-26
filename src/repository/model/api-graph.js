/**
 * Code Guardian — RepositoryModel API & Service Graph (Phase 18)
 *
 * The API projection: the HTTP routes each module declares on a framework registrar it
 * establishes, the handler and middleware symbols those routes are connected to, and the
 * route-shaped occurrences that produced no route. Like the dependency, architecture,
 * import and symbol graphs, it is a **deterministic projection of facts the model
 * already holds** — the route declarations Phase 18's acquisition layer produced and the
 * symbol nodes Phase 17's projection established. It is not a router, not a runtime
 * tracer, not a request-flow model and not an HTTP client.
 *
 * ### What "a route" means here, exactly
 *
 * A route node exists **only** when the acquisition layer established both halves from
 * the module's own text: the receiver was bound to a supported framework factory
 * (`const app = express()`, `const router = express.Router()`, `const app =
 * require("fastify")()`), and the path is a plain string literal beginning with `/`.
 * Everything else that looks route-shaped stays an **unresolved observation**: a
 * receiver that was never bound to a framework, a framework this build does not support
 * (Koa, Hapi, NestJS, …), a template or concatenated path, the object shorthand
 * (`route({ … })`).
 *
 * ### Handler resolution reuses Phase 17 identity, never a second symbol table
 *
 * A handler resolves **only** against the symbol graph's own nodes: `file#name` must
 * exist as a module-scope binding the semantic layer established. There is no
 * name-matching heuristic:
 *
 *   bare identifier       `app.get("/x", handler)` resolves to `symbol:<file>#handler`
 *                         when the symbol graph established that binding, and the edge
 *                         cites the declaring file's observation.
 *   member expression     `app.get("/x", controller.list)` is **never** resolved to the
 *                         controller: the method target is runtime dispatch. It stays an
 *                         observation (`member-expression`), carrying the base name when
 *                         the base itself is an established binding.
 *   inline function       `app.get("/x", (req, res) => …)` has no symbol to point at and
 *                         stays an observation (`inline-handler`): a real handler the
 *                         repository does not name.
 *   shadowed binding      a name that could be bound elsewhere in its file yields no
 *                         edge (`handler-not-unique`), exactly as a symbol reference does.
 *
 * The symbols themselves are **not** duplicated: a handler edge points at the Phase 17
 * symbol node that already exists, and the graph contributes no symbol node of its own.
 *
 * ### Coverage
 *
 * Same five-way vocabulary as every other graph, for the same reason: an empty route list
 * must never be readable as "this repository exposes nothing" when the truth is that the
 * sources could not be read.
 *
 *   complete     every module source was read, its route set established, and the scan
 *                finished — the graph is whatever the repository declares, including
 *                nothing
 *   partial      at least one source establishes its route set only partly, or a
 *                route-shaped occurrence was left unresolved
 *   truncated    a bound bit: the inventory was truncated, a budget stopped acquisition,
 *                or this projection reached its own cap
 *   unsupported  no source was scanned because every module source is a format this build
 *                does not interpret (a JSX/TSX-only repository)
 *   unknown      nothing established a graph at all
 *
 * ### Determinism
 *
 * Route nodes are sorted by id, edges by `(from, to, type)`, unresolved records by
 * `(path, reason, route, kind, name)`. Nothing here reads the clock, the environment, the
 * filesystem, a process or a random source, and no input is iterated in insertion order.
 */

/** Version of the projection's shape (not of the model). */
export const API_GRAPH_VERSION = "1";

/**
 * The relationships the graph states. A closed, three-value vocabulary.
 *
 * `declares` is what makes the graph a graph: a route is reachable from the file entity
 * that declared it. `handled-by` and `middleware` connect a route to the Phase 17 symbol
 * node it is connected to. No other relation exists here — there is no `calls`, no
 * `depends-on`, no `serves`, because nothing in this phase can establish one.
 */
export const API_ROUTE_EDGE_TYPES = Object.freeze({
  DECLARES: "declares",
  HANDLED_BY: "handled-by",
  MIDDLEWARE: "middleware",
});

/**
 * Why a route-shaped occurrence, or a handler/middleware reference, produced no edge.
 * Closed vocabulary.
 *
 * The first seven reasons are the acquisition layer's own route-shape answers, reused
 * verbatim so one vocabulary covers both the route decision and the edge decision:
 *
 *   receiver-not-established   the `RECEIVER.VERB("/path")` receiver was never bound
 *                              to a framework factory in the module
 *   framework-unsupported      the receiver is bound to a framework this build does not
 *                              support (Koa, Hapi, NestJS, …)
 *   path-not-established       the first argument is not a plain string literal
 *   path-computed              the first argument is a template literal
 *   path-concatenated          the first argument is a concatenated string
 *   shorthand-not-established  the object shorthand (`route({ … })`)
 *   method-not-established     a chained call states an unrecognised method
 *
 * and the remaining five are this projection's resolution answers:
 *
 *   handler-not-established    no module-scope binding of that name exists in the file
 *   handler-not-unique         the name is bound elsewhere in the file too
 *   member-expression          a member access (`controller.list`): runtime dispatch, so
 *                              no single symbol is established
 *   inline-handler             an inline function: a real handler the repository does
 *                              not name
 *   resolution-not-established the declaring file's declarations were not established,
 *                              so no handler name in it can be resolved at all
 */
export const API_UNRESOLVED_REASONS = Object.freeze({
  RECEIVER_NOT_ESTABLISHED: "receiver-not-established",
  FRAMEWORK_UNSUPPORTED: "framework-unsupported",
  PATH_NOT_ESTABLISHED: "path-not-established",
  PATH_COMPUTED: "path-computed",
  PATH_CONCATENATED: "path-concatenated",
  SHORTHAND_NOT_ESTABLISHED: "shorthand-not-established",
  METHOD_NOT_ESTABLISHED: "method-not-established",
  HANDLER_NOT_ESTABLISHED: "handler-not-established",
  HANDLER_NOT_UNIQUE: "handler-not-unique",
  MEMBER_EXPRESSION: "member-expression",
  INLINE_HANDLER: "inline-handler",
  RESOLUTION_NOT_ESTABLISHED: "resolution-not-established",
});

/**
 * API graph coverage states. The same five-way vocabulary the other graphs use.
 */
export const API_GRAPH_STATES = Object.freeze({
  COMPLETE: "complete",
  PARTIAL: "partial",
  TRUNCATED: "truncated",
  UNSUPPORTED: "unsupported",
  UNKNOWN: "unknown",
});

/** The state vocabulary as a list, for validation. */
export const API_GRAPH_STATE_VALUES = Object.freeze(Object.values(API_GRAPH_STATES));

/** The edge-type vocabulary, re-exported for the contract test. */
export const API_GRAPH_EDGE_TYPES = API_ROUTE_EDGE_TYPES;

/** The edge-type vocabulary as a list, for validation. */
export const API_GRAPH_EDGE_TYPE_VALUES = Object.freeze(Object.values(API_GRAPH_EDGE_TYPES));

/**
 * The unresolved-reason vocabulary as a list, in a fixed order, for validation.
 *
 * It combines the acquisition layer's route-shape reasons with the resolution reasons
 * this projection adds, so one vocabulary describes every occurrence that produced no
 * route or no edge.
 */
export const API_UNRESOLVED_REASON_VALUES = Object.freeze(Object.values(API_UNRESOLVED_REASONS));

/** The unresolved kinds. Closed, three-value vocabulary. */
export const API_UNRESOLVED_KINDS = Object.freeze(["route", "handler", "middleware"]);

/**
 * Graph bounds.
 *
 * A cap that does bite is recorded — never silently applied.
 */
export const API_GRAPH_LIMITS = Object.freeze({
  MAX_ROUTES: 20000,
  MAX_EDGES: 200000,
  MAX_UNRESOLVED: 20000,
  MAX_UNESTABLISHED_SOURCES: 1024,
  MAX_UNINTERPRETED_EXTENSIONS: 32,
  MAX_NAMES_PER_ROUTE: 16,
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

/** Sort by a list of keys, so no two records compare equal. */
function compareByKeys(keys) {
  return (a, b) => {
    for (const key of keys) {
      const left = a?.[key];
      const right = b?.[key];
      if (left === right) continue;
      if (typeof left === "string" && typeof right === "string") return left < right ? -1 : 1;
      return left === undefined || left === null ? 1 : -1;
    }
    return 0;
  };
}

function sortedUnique(values) {
  return [...new Set(values)].sort();
}

/** The file entity id for a repository-relative path. */
function fileIdOf(path) {
  return `file:${path}`;
}

/** The Phase 17 symbol identity for a binding. Reused verbatim — never a second scheme. */
export function apiHandlerSymbolId(path, name) {
  return `symbol:${path}#${name}`;
}

/**
 * The identity of one HTTP endpoint.
 *
 * Deterministic and content-free: the recorded method and the declared path. Two modules
 * that declare the same method and path therefore describe **one** endpoint, and the node
 * carries every declaring path rather than being duplicated.
 *
 * @param {string} method Uppercase HTTP method.
 * @param {string} path Declared route path.
 * @returns {string}
 */
export function apiRouteIdOf(method, path) {
  return `route:${method}:${path}`;
}

/** Whether a state means an API graph was established. */
export function isEstablishedApiState(state) {
  return (
    state === API_GRAPH_STATES.COMPLETE ||
    state === API_GRAPH_STATES.PARTIAL ||
    state === API_GRAPH_STATES.TRUNCATED
  );
}

/**
 * Whether a source's *route set* was established.
 *
 * The scanner answers this per file; a file whose lexer failed establishes no route at
 * all, and the projection cites that decision rather than second-guessing it.
 */
export function isApiSourceEstablished(source) {
  return source.status === PARSED_STATUS && source.established === true;
}

/**
 * The graph's coverage state.
 *
 * Read only from facts the model already validated. Nothing is inferred from route or
 * edge counts — an empty graph is a *result*, not evidence of missing information.
 */
export function apiGraphState({
  sources,
  scanComplete,
  scanTruncated,
  hasScanState,
  projectionTruncated,
  uninterpretedSources = 0,
}) {
  if (!hasScanState) return API_GRAPH_STATES.UNKNOWN;

  if (sources.length === 0) {
    if (scanComplete !== true || scanTruncated === true) return API_GRAPH_STATES.UNKNOWN;
    return uninterpretedSources > 0 ? API_GRAPH_STATES.UNSUPPORTED : API_GRAPH_STATES.COMPLETE;
  }

  if (scanTruncated === true || projectionTruncated === true) return API_GRAPH_STATES.TRUNCATED;
  if (
    sources.some(
      (source) =>
        source.truncated === true ||
        source.status === NOT_INSPECTED_STATUS ||
        source.reason === "budget-exhausted",
    )
  ) {
    return API_GRAPH_STATES.TRUNCATED;
  }

  const parsed = sources.filter((source) => source.status === PARSED_STATUS);
  if (parsed.length === 0) {
    return sources.every((source) => source.status === UNSUPPORTED_STATUS)
      ? API_GRAPH_STATES.UNSUPPORTED
      : API_GRAPH_STATES.UNKNOWN;
  }

  const everyClaimEstablished = parsed.every(
    (source) => (source.problems ?? []).length === 0 && source.established === true,
  );
  if (everyClaimEstablished && parsed.length === sources.length && scanComplete === true) {
    return API_GRAPH_STATES.COMPLETE;
  }
  return API_GRAPH_STATES.PARTIAL;
}

/**
 * Build the API graph from the model's API source records and symbol nodes.
 *
 * @param {object} input
 * @param {object[]} input.sources API source records from `entities.js`.
 * @param {object[]} input.semanticsSources Semantic source records, for establishment.
 * @param {object} input.symbolGraph The Phase 17 symbol graph (for handler identity).
 * @param {object} input.coverage `{ scanComplete, scanTruncated }`.
 * @param {object} [input.uninterpreted] Source files this graph does not read.
 * @returns {object} Deeply frozen
 *   `{ version, state, established, nodes, edges, unresolved, coverage }`.
 */
export function buildApiGraph({
  sources,
  semanticsSources = [],
  symbolGraph,
  coverage,
  uninterpreted,
}) {
  const limits = API_GRAPH_LIMITS;
  const uninterpretedSources =
    Number.isInteger(uninterpreted?.sources) && uninterpreted.sources > 0
      ? uninterpreted.sources
      : 0;
  const uninterpretedExtensions = sortedUnique(
    (Array.isArray(uninterpreted?.extensions) ? uninterpreted.extensions : []).filter(
      (extension) => typeof extension === "string" && extension !== "",
    ),
  );

  // Which files the semantic layer established, so a handler that cannot be resolved can
  // say *why*: the file was not semantically scanned, or the name simply is not a
  // module-scope binding there.
  const semanticsEstablishedByPath = new Map();
  for (const source of semanticsSources) {
    semanticsEstablishedByPath.set(
      source.path,
      source.status === PARSED_STATUS && source.established?.declarationsEstablished === true,
    );
  }

  // The Phase 17 nodes, keyed by `path#name`. The api graph never creates a symbol node.
  const symbolByKey = new Map();
  for (const node of symbolGraph?.nodes ?? []) {
    symbolByKey.set(`${node.path}\u0000${node.name}`, node);
  }
  const symbolExists = (id) => (symbolGraph?.nodes ?? []).some((node) => node.id === id);

  const routeIndex = new Map();
  const edges = [];
  const edgeIndex = new Map();
  const unresolvedAll = [];
  const unresolvedIndex = new Map();

  const noteUnresolved = (record) => {
    const key = `${record.path}\u0000${record.kind}\u0000${record.reason}\u0000${record.name ?? ""}\u0000${record.member ?? ""}\u0000${record.route ?? ""}`;
    const existing = unresolvedIndex.get(key);
    if (existing !== undefined) {
      existing.count += 1;
      return;
    }
    const entry = { ...record, count: 1 };
    unresolvedIndex.set(key, entry);
    unresolvedAll.push(entry);
  };

  const addEdge = (partial) => {
    const key = `${partial.from}\u0000${partial.to}\u0000${partial.type}`;
    let edge = edgeIndex.get(key);
    if (edge === undefined) {
      edge = { ...partial, count: 0, names: new Set(), sourcePaths: new Set(), evidenceIds: new Set() };
      edgeIndex.set(key, edge);
      edges.push(edge);
      return edge;
    }
    return edge;
  };

  const routeNodeFor = (method, path) => {
    const id = apiRouteIdOf(method, path);
    let node = routeIndex.get(id);
    if (node === undefined) {
      node = {
        id,
        method,
        path,
        frameworks: new Set(),
        receivers: new Set(),
        receiverKinds: new Set(),
        sourcePaths: new Set(),
        evidenceIds: new Set(),
        handlerCount: 0,
        middlewareCount: 0,
      };
      routeIndex.set(id, node);
    }
    return node;
  };

  for (const source of sources) {
    // Route-shaped occurrences the acquisition layer could not turn into a route are
    // observations, never routes: they are recorded with their closed reason.
    for (const shape of source.shapes) {
      noteUnresolved({
        path: source.path,
        kind: "route",
        reason: shape.reason,
        name: shape.receiver,
        member: null,
        method: shape.method,
        route: shape.path === null ? null : apiRouteIdOf(shape.method ?? "ALL", shape.path),
        framework: shape.framework,
        evidenceId: source.evidenceId ?? null,
      });
    }

    if (!isApiSourceEstablished(source)) continue;

    for (const route of source.routes) {
      const node = routeNodeFor(route.method, route.path);
      node.frameworks.add(route.framework);
      node.receivers.add(route.receiver);
      node.receiverKinds.add(route.receiverKind);
      node.sourcePaths.add(source.path);
      node.evidenceIds.add(source.evidenceId);

      const declares = addEdge({
        from: fileIdOf(source.path),
        to: node.id,
        type: API_ROUTE_EDGE_TYPES.DECLARES,
      });
      declares.count += 1;
      declares.sourcePaths.add(source.path);
      declares.evidenceIds.add(source.evidenceId);

      const semanticsEstablished = semanticsEstablishedByPath.get(source.path) === true;

      const resolveCallable = (callable, role) => {
        if (callable === null) return;
        const kind = role;
        if (callable.form === "inline") {
          noteUnresolved({
            path: source.path,
            kind,
            reason: API_UNRESOLVED_REASONS.INLINE_HANDLER,
            name: null,
            member: null,
            method: route.method,
            route: node.id,
            framework: route.framework,
            evidenceId: source.evidenceId ?? null,
          });
          return;
        }
        if (callable.member !== null) {
          noteUnresolved({
            path: source.path,
            kind,
            reason: API_UNRESOLVED_REASONS.MEMBER_EXPRESSION,
            name: callable.name,
            member: callable.member,
            method: route.method,
            route: node.id,
            framework: route.framework,
            evidenceId: source.evidenceId ?? null,
          });
          return;
        }
        if (!semanticsEstablished) {
          noteUnresolved({
            path: source.path,
            kind,
            reason: API_UNRESOLVED_REASONS.RESOLUTION_NOT_ESTABLISHED,
            name: callable.name,
            member: null,
            method: route.method,
            route: node.id,
            framework: route.framework,
            evidenceId: source.evidenceId ?? null,
          });
          return;
        }
        const symbol = symbolByKey.get(`${source.path}\u0000${callable.name}`);
        if (symbol === undefined) {
          noteUnresolved({
            path: source.path,
            kind,
            reason: API_UNRESOLVED_REASONS.HANDLER_NOT_ESTABLISHED,
            name: callable.name,
            member: null,
            method: route.method,
            route: node.id,
            framework: route.framework,
            evidenceId: source.evidenceId ?? null,
          });
          return;
        }
        if (symbol.shadowed === true) {
          noteUnresolved({
            path: source.path,
            kind,
            reason: API_UNRESOLVED_REASONS.HANDLER_NOT_UNIQUE,
            name: callable.name,
            member: null,
            method: route.method,
            route: node.id,
            framework: route.framework,
            evidenceId: source.evidenceId ?? null,
          });
          return;
        }
        const edge = addEdge({
          from: node.id,
          to: symbol.id,
          type:
            role === "handler"
              ? API_ROUTE_EDGE_TYPES.HANDLED_BY
              : API_ROUTE_EDGE_TYPES.MIDDLEWARE,
        });
        edge.count += 1;
        edge.names.add(callable.name);
        edge.sourcePaths.add(source.path);
        edge.evidenceIds.add(source.evidenceId);
      };

      resolveCallable(route.handler, "handler");
      for (const entry of route.middleware) resolveCallable(entry, "middleware");
    }
  }

  // ── Materialize ────────────────────────────────────────────────────────────
  const allNodes = [...routeIndex.values()]
    .map((node) => {
      const handlerEdges = edges.filter(
        (edge) => edge.from === node.id && edge.type === API_ROUTE_EDGE_TYPES.HANDLED_BY,
      );
      const middlewareEdges = edges.filter(
        (edge) => edge.from === node.id && edge.type === API_ROUTE_EDGE_TYPES.MIDDLEWARE,
      );
      return {
        id: node.id,
        method: node.method,
        path: node.path,
        frameworks: sortedUnique([...node.frameworks]),
        receivers: sortedUnique([...node.receivers]),
        receiverKinds: sortedUnique([...node.receiverKinds]),
        sourcePaths: sortedUnique([...node.sourcePaths]),
        evidenceIds: sortedUnique([...node.evidenceIds]),
        handlerCount: handlerEdges.reduce((total, edge) => total + edge.count, 0),
        middlewareCount: middlewareEdges.reduce((total, edge) => total + edge.count, 0),
      };
    })
    .sort(compareByKeys(["id"]));

  const nodesTruncated = allNodes.length > limits.MAX_ROUTES;
  const nodes = nodesTruncated ? allNodes.slice(0, limits.MAX_ROUTES) : allNodes;
  const nodeIds = new Set(nodes.map((node) => node.id));

  // An edge that names a route the projection dropped is dropped with it; an edge that
  // names a symbol the symbol graph does not carry is dropped too, rather than left
  // pointing at a node the model does not describe.
  const knownEndpoint = (id) =>
    nodeIds.has(id) || (id.startsWith("symbol:") && symbolExists(id)) || id.startsWith("file:");
  const allEdges = edges
    .filter((edge) => knownEndpoint(edge.from) && knownEndpoint(edge.to))
    .map((edge) => ({
      from: edge.from,
      to: edge.to,
      type: edge.type,
      count: edge.count,
      names: sortedUnique([...edge.names]).slice(0, limits.MAX_NAMES_PER_ROUTE),
      sourcePaths: sortedUnique([...edge.sourcePaths]),
      evidenceIds: sortedUnique([...edge.evidenceIds]),
    }))
    .sort(compareByKeys(["from", "to", "type"]));

  const edgesTruncated = allEdges.length > limits.MAX_EDGES;
  const finalEdges = edgesTruncated ? allEdges.slice(0, limits.MAX_EDGES) : allEdges;

  const sortedUnresolved = unresolvedAll
    .slice()
    .sort(compareByKeys(["path", "reason", "route", "kind", "name"]))
    .map((record) => deepFreeze({ ...record }));
  const unresolvedTruncated = sortedUnresolved.length > limits.MAX_UNRESOLVED;
  const unresolved = unresolvedTruncated
    ? sortedUnresolved.slice(0, limits.MAX_UNRESOLVED)
    : sortedUnresolved;

  const state = apiGraphState({
    sources,
    scanComplete: coverage?.scanComplete === true,
    scanTruncated: coverage?.scanTruncated === true,
    hasScanState:
      typeof coverage?.scanComplete === "boolean" && typeof coverage?.scanTruncated === "boolean",
    projectionTruncated: nodesTruncated || edgesTruncated || unresolvedTruncated,
    uninterpretedSources,
  });
  const established = isEstablishedApiState(state);

  const unestablished = sources
    .filter((source) => !isApiSourceEstablished(source))
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
  for (const reason of API_UNRESOLVED_REASON_VALUES) unresolvedByReason[reason] = 0;
  for (const record of unresolvedAll) {
    unresolvedByReason[record.reason] = (unresolvedByReason[record.reason] ?? 0) + 1;
  }
  const unestablishedCount = sources.filter((source) => !isApiSourceEstablished(source)).length;

  const countByStatus = (status) => sources.filter((source) => source.status === status).length;
  const countEdges = (type) => finalEdges.filter((edge) => edge.type === type).length;

  // The modules that declare a resolved handler — the "handler modules" a future service
  // layer would start from. Deliberately not called a *service* graph: a controller→service
  // call edge is not established by anything in this phase.
  const handlerModulePaths = sortedUnique(
    finalEdges
      .filter((edge) => edge.type === API_ROUTE_EDGE_TYPES.HANDLED_BY)
      .flatMap((edge) => (edge.to.startsWith("symbol:") ? [edge.to.slice("symbol:".length).split("#")[0]] : [])),
  );

  return deepFreeze({
    version: API_GRAPH_VERSION,
    state,
    established,
    nodes,
    edges: finalEdges,
    // Route-shaped occurrences, and handler/middleware references, that are not edges:
    // "the file says this and we cannot establish what it denotes" is a different fact
    // from *these two entities are connected*.
    unresolved,
    coverage: {
      state,
      established,
      complete: state === API_GRAPH_STATES.COMPLETE,
      truncated: state === API_GRAPH_STATES.TRUNCATED,
      inspected: sources.some((source) => source.status === PARSED_STATUS),
      routes: nodes.length,
      edges: finalEdges.length,
      sources: sources.length,
      declaringModules: sortedUnique(nodes.flatMap((node) => node.sourcePaths)).length,
      handlerEdges: countEdges(API_ROUTE_EDGE_TYPES.HANDLED_BY),
      middlewareEdges: countEdges(API_ROUTE_EDGE_TYPES.MIDDLEWARE),
      declareEdges: countEdges(API_ROUTE_EDGE_TYPES.DECLARES),
      handlerModules: handlerModulePaths.length,
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
      unresolvedTruncated,
      limits,
    },
  });
}
