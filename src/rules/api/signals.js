/**
 * Code Guardian — API Repository Signals (Phase 18)
 *
 * The one place API rules ask the repository questions. Every read goes through the
 * Phase 11 query API over the frozen RepositoryModel: no filesystem, no `node:path`, no
 * source parsing, no handler resolution, no process, no network, no clock. A rule that
 * cannot answer a question from the model reports `unknown` rather than going to look for
 * itself — which is the whole point of building the API graph once, in the model.
 *
 * ### Relationships are flattened here, provenance is not
 *
 * A route node already carries the declaring files and the observation behind each one,
 * so flattening adds only what a description needs — the handler and middleware symbol
 * names, gathered from the graph's own edges — and never re-derives a relationship.
 */

import { API_GRAPH_STATES, createRepositoryQuery, stabilityHash } from "../../repository/model/index.js";

import { API_EDGE_TYPE_WORDING, API_UNRESOLVED_REASON_WORDING } from "./contracts.js";

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
 * Every endpoint the graph establishes, with its handler and middleware symbol names.
 *
 * Sorted by id, so the order never depends on a model internal. Each row carries a
 * `fingerprintKey` naming the endpoint: a finding's canonical fingerprint is derived from
 * its rule, category and evidence set, and every route from one file cites that file's
 * single API observation, so without a disambiguator two routes from one file would
 * collapse into one finding and the run would fail as a duplicate. The key is a stability
 * hash of the route id — never an index, which would shift every fingerprint when an
 * unrelated route is added.
 *
 * @param {object} query
 * @returns {Array<object>} Frozen route rows.
 */
export function apiRoutes(query) {
  const graph = query.apiGraph();
  const handlerNames = new Map();
  const middlewareNames = new Map();

  for (const edge of graph.edges) {
    if (edge.type === "handled-by") handlerNames.set(edge.from, [...(edge.names ?? [])]);
    else if (edge.type === "middleware") middlewareNames.set(edge.from, [...(edge.names ?? [])]);
  }

  return graph.nodes
    .map((node) => ({
      id: node.id,
      method: node.method,
      path: node.path,
      frameworks: [...node.frameworks],
      receivers: [...node.receivers],
      receiverKinds: [...node.receiverKinds],
      sourcePaths: [...node.sourcePaths],
      evidenceIds: [...node.evidenceIds],
      handlerNames: handlerNames.get(node.id) ?? [],
      middlewareNames: middlewareNames.get(node.id) ?? [],
      fingerprintKey: `api:${stabilityHash(node.id)}`,
    }))
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

/**
 * The route-shaped occurrences the repository does **not** establish as routes.
 *
 * Kept separate from `apiRoutes` on purpose: an occurrence whose receiver is not a
 * framework registrar is a different fact from a declared endpoint, and a rule that mixed
 * them would report a non-fact as an endpoint.
 */
export function apiUnresolved(query) {
  return query.unresolvedRoutes({ maxResults: 1000 }).unresolved.map((record) => ({
    path: record.path,
    reason: record.reason,
    receiver: record.name ?? null,
    method: record.method ?? null,
    route: record.route ?? null,
    framework: record.framework ?? null,
    evidenceId: record.evidenceId ?? null,
  }));
}

/** The graph's own coverage statement. */
export function apiCoverage(query) {
  return query.apiCoverage();
}

/**
 * Whether the model supports a claim that the repository declares no route at all.
 *
 * Two separate things have to hold, and neither is inferred from an empty route list: a
 * graph must actually have been established (`unsupported` and `unknown` are not "no
 * routes", they are "no answer"), and the scan behind it must have covered the
 * repository. A partial graph can be missing exactly the endpoint a caller would conclude
 * does not exist.
 *
 * @param {object} query
 * @returns {{established: boolean, reason: string|null, state: string}}
 */
export function apiAbsence(query) {
  const graph = apiCoverage(query);
  const inventory = query.coverage();
  const reasons = [];

  if (graph.established !== true) {
    const unreadLanguage =
      graph.state === API_GRAPH_STATES.UNSUPPORTED &&
      graph.sources === 0 &&
      (graph.uninterpretedSources ?? 0) > 0;
    reasons.push(
      unreadLanguage
        ? "every source file in this repository is in a language this build does not read"
        : graph.state === API_GRAPH_STATES.UNSUPPORTED
          ? "no module source in this repository is a format this build interprets"
          : "the model did not establish an API graph",
    );
  } else if (graph.state !== API_GRAPH_STATES.COMPLETE) {
    const unestablished = graph.unestablishedSources ?? [];
    if (graph.state === API_GRAPH_STATES.TRUNCATED) {
      reasons.push(
        "a resource bound stopped API acquisition before every source's route set was established",
      );
    } else if (unestablished.length > 0) {
      reasons.push(
        `routes could not be fully established for ${unestablished
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
export const API_DESCRIBED_EDGE_TYPES = Object.freeze(Object.keys(API_EDGE_TYPE_WORDING));

/** The unresolved-reason vocabulary this module can describe, for tests. */
export const API_DESCRIBED_UNRESOLVED_REASONS = Object.freeze(
  Object.keys(API_UNRESOLVED_REASON_WORDING),
);

export { API_GRAPH_STATES };
