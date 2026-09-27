/**
 * Code Guardian — Middleware Repository Signals (Phase 19)
 *
 * The one place middleware rules ask the repository questions. Every read goes through the
 * Phase 11 query API over the frozen RepositoryModel: no filesystem, no `node:path`, no
 * source parsing, no symbol resolution, no process, no network, no clock. A rule that cannot
 * answer a question from the model reports `unknown` rather than going to look for itself —
 * which is the whole point of building the middleware graph once, in the model.
 *
 * ### Relationships are flattened here, provenance is not
 *
 * A middleware node already carries its scope, its registration kinds, the receivers it was
 * registered on and the observation behind each registration, and the graph's route views
 * already carry which middleware reaches which route. Flattening adds only what a
 * description needs — the file paths a middleware was registered in, and the routes it
 * reaches — and never re-derives a relationship.
 */

import {
  MIDDLEWARE_GRAPH_STATES,
  createRepositoryQuery,
  stabilityHash,
} from "../../repository/model/index.js";

import {
  MIDDLEWARE_EDGE_TYPE_WORDING,
  MIDDLEWARE_UNRESOLVED_REASON_WORDING,
} from "./contracts.js";

/**
 * Build the read-only query handle for an AnalysisContext.
 *
 * @param {object} context A validated AnalysisContext.
 * @returns {object} A frozen query handle.
 */
export function queryFor(context) {
  return createRepositoryQuery(context.repository);
}

/**
 * Every middleware the graph establishes, with the routes it structurally reaches.
 *
 * Sorted by id, so the order never depends on a model internal. Each row carries a
 * `fingerprintKey` naming the middleware: a finding's canonical fingerprint is derived from
 * its rule, category and evidence set, and every middleware registered in one file cites
 * that file's single middleware observation, so without a disambiguator two middleware from
 * one file would collapse into one finding and the run would fail as a duplicate. The key is
 * a stability hash of the symbol id — never an index, which would shift every fingerprint
 * when an unrelated middleware is added.
 *
 * @param {object} query
 * @returns {Array<object>} Frozen middleware rows.
 */
export function middlewareNodes(query) {
  const graph = query.middlewareGraph();
  const registeredOn = new Map();
  const routeIds = new Map();
  const routeById = new Map(graph.routes.map((route) => [route.route, route]));

  for (const edge of graph.edges) {
    if (edge.type === "registered-on") {
      registeredOn.set(edge.from, [...(edge.sourcePaths ?? [])]);
    }
  }
  for (const route of graph.routes) {
    for (const id of route.middleware) {
      const list = routeIds.get(id);
      if (list === undefined) routeIds.set(id, [route.route]);
      else list.push(route.route);
    }
  }

  return graph.nodes
    .map((node) => ({
      id: node.id,
      name: node.name,
      path: node.path,
      fileId: node.fileId,
      classification: node.classification,
      scopes: [...node.scopes],
      registrations: [...node.registrations],
      hooks: [...node.hooks],
      receivers: [...node.receivers],
      frameworks: [...node.frameworks],
      sourcePaths: [...node.sourcePaths],
      evidenceIds: [...node.evidenceIds],
      registrationCount: node.registrationCount,
      registeredOn: registeredOn.get(node.id) ?? [],
      routeIds: (routeIds.get(node.id) ?? []).slice().sort(),
      routeProtection: (routeIds.get(node.id) ?? [])
        .slice()
        .sort()
        .map((id) => ({
          route: id,
          method: routeById.get(id)?.method ?? null,
          path: routeById.get(id)?.path ?? null,
          protection: routeById.get(id)?.protection ?? null,
        })),
      fingerprintKey: `middleware:${stabilityHash(node.id)}`,
    }))
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

/**
 * Every route the graph describes, with its protection state and the middleware that reaches
 * it.
 *
 * Kept as its own signal because the protection state is the fact a consumer must be able to
 * read *without* inferring it from a middleware list: `unresolved` is a different answer from
 * `none-observed`, and collapsing the two would let a route whose middleware could not be
 * established read as a route with no middleware.
 */
export function middlewareRouteViews(query) {
  return query.middlewareGraph().routes.map((route) => ({
    route: route.route,
    method: route.method,
    path: route.path,
    protection: route.protection,
    middlewareIds: [...route.middleware],
    middlewareCount: route.middlewareCount,
    unresolvedCount: route.unresolvedCount,
  }));
}

/**
 * The middleware-shaped occurrences the repository does **not** establish as middleware.
 *
 * Kept separate from `middlewareNodes` on purpose: an occurrence that is a computed array, a
 * spread, a conditional registration or a name this build cannot resolve is a different fact
 * from a registered middleware, and a rule that mixed them would report a non-fact as a
 * registration.
 */
export function middlewareUnresolved(query) {
  return query.unresolvedMiddleware({ maxResults: 1000 }).unresolved.map((record) => ({
    path: record.path,
    kind: record.kind,
    reason: record.reason,
    receiver: record.receiver ?? null,
    scope: record.scope ?? null,
    registration: record.registration ?? null,
    route: record.route ?? null,
    name: record.name ?? null,
    member: record.member ?? null,
    count: record.count ?? 1,
    evidenceId: record.evidenceId ?? null,
  }));
}

/** The graph's own coverage statement. */
export function middlewareCoverage(query) {
  return query.middlewareCoverage();
}

/**
 * Whether the model supports a claim that the repository registers no middleware at all.
 *
 * Two separate things have to hold, and neither is inferred from an empty middleware list: a
 * graph must actually have been established (`unsupported` and `unknown` are not "no
 * middleware", they are "no answer"), and the scan behind it must have covered the
 * repository. A partial graph can be missing exactly the registration a caller would
 * conclude does not exist.
 *
 * @param {object} query
 * @returns {{established: boolean, reason: string|null, state: string}}
 */
export function middlewareAbsence(query) {
  const graph = middlewareCoverage(query);
  const inventory = query.coverage();
  const reasons = [];

  if (graph.established !== true) {
    const unreadLanguage =
      graph.state === MIDDLEWARE_GRAPH_STATES.UNSUPPORTED &&
      graph.sources === 0 &&
      (graph.uninterpretedSources ?? 0) > 0;
    reasons.push(
      unreadLanguage
        ? "every source file in this repository is in a language this build does not read"
        : graph.state === MIDDLEWARE_GRAPH_STATES.UNSUPPORTED
          ? "no module source in this repository is a format this build interprets"
          : "the model did not establish a middleware graph",
    );
  } else if (graph.state !== MIDDLEWARE_GRAPH_STATES.COMPLETE) {
    const unestablished = graph.unestablishedSources ?? [];
    if (graph.state === MIDDLEWARE_GRAPH_STATES.TRUNCATED) {
      reasons.push(
        "a resource bound stopped middleware acquisition before every source's registrations were established",
      );
    } else if (unestablished.length > 0) {
      reasons.push(
        `registrations could not be fully established for ${unestablished
          .slice(0, 5)
          .map((entry) => `\`${entry.path}\``)
          .join(", ")}${unestablished.length > 5 ? " and others" : ""}`,
      );
    } else {
      reasons.push("the graph judged the repository only partly established");
    }
  }
  if (inventory.complete !== true) {
    reasons.push(
      inventory.truncated === true
        ? "the scan stopped at a limit before the inventory was complete"
        : "the scan did not cover the repository completely",
    );
  }

  return Object.freeze({
    established: reasons.length === 0,
    reason: reasons.length === 0 ? null : reasons.join("; "),
    state: graph.state,
  });
}

/** The edge-type vocabulary this module can describe, for tests. */
export const MIDDLEWARE_DESCRIBED_EDGE_TYPES = Object.freeze(
  Object.keys(MIDDLEWARE_EDGE_TYPE_WORDING),
);

/** The unresolved-reason vocabulary this module can describe, for tests. */
export const MIDDLEWARE_DESCRIBED_UNRESOLVED_REASONS = Object.freeze(
  Object.keys(MIDDLEWARE_UNRESOLVED_REASON_WORDING),
);

export { MIDDLEWARE_GRAPH_STATES };
