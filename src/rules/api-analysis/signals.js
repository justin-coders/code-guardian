/**
 * Code Guardian — API Analysis Repository Signals (Official Roadmap Phase 16)
 *
 * The one place the api-analysis rules ask the repository questions. Every read goes through
 * the Phase 11 query API over the frozen RepositoryModel: no filesystem, no `node:path`, no
 * source parsing, no route resolution, no process, no network, no clock. A rule that cannot
 * answer a question from the model reports `unknown` rather than going to look for itself.
 *
 * ### What this module reuses instead of rebuilding
 *
 * The API and middleware substrate already established the facts every domain needs:
 *
 *   `query.apiGraph()`          route nodes (method, path, frameworks, declaring files, evidence)
 *   `query.apiCoverage()`       the API graph's five-way state and its bounds
 *   `query.middlewareGraph()`   middleware nodes (with their name-derived classification) and
 *                               per-route structural protection
 *   `query.middlewareCoverage()` the middleware graph's five-way state, classification census
 *                               and per-route protection counts
 *   `query.listEntities("file")` observed files (for artifact domains)
 *   `query.coverage()`          the scan's own completeness
 *
 * Nothing here re-parses a module, re-derives a route or a middleware relationship, or
 * re-classifies a name: the distinction the substrate keeps — declared route vs unresolved
 * occurrence, established middleware vs unresolved registration, structured protection vs
 * absence — is preserved all the way into the findings.
 *
 * ### Absence is a claim, and it has a gate
 *
 * The pack's gap rules conclude "this route establishes no <domain> middleware", which is an
 * absence claim and therefore needs the coverage to support it. `routeCoverageGap` and
 * `middlewareCoverageGap` decide whether the model supports that claim, and they are
 * deliberately conservative in the same way the security pack's are: an unestablished graph, a
 * truncated one, an unresolved route-shaped occurrence, a path that could not be read, or an
 * incomplete inventory all leave the answer `unknown`.
 */

import {
  API_GRAPH_STATES,
  ENTITY_KINDS,
  MIDDLEWARE_CLASSIFICATIONS,
  MIDDLEWARE_GRAPH_STATES,
  MIDDLEWARE_PROTECTION_STATES,
  createRepositoryQuery,
  stabilityHash,
} from "../../repository/model/index.js";

import {
  API_ANALYSIS_OPENAPI_BASENAMES,
  API_ANALYSIS_SUBJECTS,
} from "./contracts.js";

/** Build the read-only query handle for an AnalysisContext. */
export function queryFor(context) {
  return createRepositoryQuery(context.repository);
}

/** The API graph's own coverage statement. */
export function apiGraphCoverage(query) {
  return query.apiCoverage();
}

/** The middleware graph's own coverage statement. */
export function middlewareGraphCoverage(query) {
  return query.middlewareCoverage();
}

/**
 * Whether the repository has an API subject at all, and how confident that is.
 *
 * The roadmap's central requirement — "a CLI application should not receive HTTP API findings"
 * — is answered from the model's own facts, never from a route count:
 *
 *   - an API graph that was never established (including one whose sources are a format this
 *     build does not read) is `unknown`: an unsupported framework is not the same fact as no
 *     API;
 *   - an established graph that declares at least one route is `applicable`;
 *   - an established graph that declares no route but leaves a route-shaped occurrence
 *     unread (for example a Koa receiver) is `unknown` — the routes could exist;
 *   - an established, complete graph with no routes and no unresolved occurrence is
 *     `not_applicable`.
 *
 * @param {object} query
 * @returns {{state: string, reason: string|null, routes: number, graph: string}}
 */
export function apiSubject(query) {
  const coverage = apiGraphCoverage(query);
  const routes = Number.isInteger(coverage.routes) ? coverage.routes : 0;

  if (coverage.established !== true) {
    const reason =
      coverage.state === API_GRAPH_STATES.UNSUPPORTED
        ? "every module source in this repository is in a format this build does not interpret, so no API could be established"
        : "the model did not establish an API graph";
    return Object.freeze({ state: API_ANALYSIS_SUBJECTS.UNKNOWN, reason, routes, graph: coverage.state });
  }

  if (routes > 0) {
    return Object.freeze({ state: API_ANALYSIS_SUBJECTS.APPLICABLE, reason: null, routes, graph: coverage.state });
  }

  const unresolved = Number.isInteger(coverage.unresolved) ? coverage.unresolved : 0;
  if (unresolved > 0) {
    return Object.freeze({
      state: API_ANALYSIS_SUBJECTS.UNKNOWN,
      reason: `${unresolved} route-shaped occurrence(s) were not established as routes, so the repository may expose endpoints this build could not read`,
      routes,
      graph: coverage.state,
    });
  }

  return Object.freeze({ state: API_ANALYSIS_SUBJECTS.NOT_APPLICABLE, reason: null, routes, graph: coverage.state });
}

/**
 * Why the repository's route set cannot be read as complete, or `null` when it can.
 *
 * Mirrors the security pack's `routeCoverageGap`: a rule about to conclude an absence over
 * routes has to know that a route-shaped occurrence was left unread, that the graph stopped at
 * a limit, or that the inventory it was read from is itself incomplete.
 */
export function routeCoverageGap(query) {
  const inventory = query.apiCoverage();
  const scan = query.coverage();

  if (inventory.established !== true) {
    return `the API graph is ${inventory.state}, so the repository's routes are not established`;
  }
  if (inventory.truncated === true) {
    return "the API graph stopped at a limit before every route was established";
  }
  if ((inventory.unresolved ?? 0) > 0) {
    return `${inventory.unresolved} route-shaped occurrence(s) were not established as routes`;
  }
  if (inventory.unresolvedTruncated === true) {
    return "more route-shaped occurrences were left unresolved than the graph reports";
  }
  if (scan.complete !== true) {
    return scan.truncated === true
      ? "the scan stopped at a limit before the inventory was complete"
      : "the scan did not cover the repository completely";
  }
  return null;
}

/** Why no route's registrations can be read as complete, or `null` when they can. */
export function middlewareCoverageGap(query) {
  const coverage = middlewareGraphCoverage(query);

  if (coverage.established !== true) {
    return `the middleware graph is ${coverage.state}, so no route's registrations are established`;
  }
  if (coverage.truncated === true) {
    return "the middleware graph stopped at a limit before every registration was established";
  }
  return null;
}

/**
 * Every established route, joined with its structural protection and its resolved middleware
 * chain, each middleware carrying the classification the middleware graph derived from its name.
 *
 *   `id`                 the route's own graph identity (`route:METHOD:/path`)
 *   `protection`         the middleware graph's per-route state, or `null` when it has no record
 *   `middleware`         the resolved chain: `{ id, name, classification }`, sorted by identity
 *   `unresolvedCount`    middleware-shaped occurrences on the route that were not established
 *   `chainTruncated`     whether the chain stopped at a bound
 *   `evidenceIds`        the route's own declarations
 *   `fingerprintKey`     a stability hash of the route id, for fingerprint disambiguation
 *
 * The join is a lookup over the graph's own frozen records; this module re-derives no
 * relationship.
 *
 * @param {object} query
 * @returns {object[]} Frozen route rows, sorted by id.
 */
export function routeControls(query) {
  const api = query.apiGraph();
  const middleware = query.middlewareGraph();
  const viewById = new Map(middleware.routes.map((view) => [view.route, view]));
  const nodeById = new Map(middleware.nodes.map((node) => [node.id, node]));

  return api.nodes
    .map((node) => {
      const view = viewById.get(node.id) ?? null;
      const chain = (view?.middleware ?? [])
        .map((id) => nodeById.get(id))
        .filter((entry) => entry !== undefined)
        .map((entry) =>
          Object.freeze({
            id: entry.id,
            name: entry.name,
            classification: entry.classification,
            evidenceIds: Object.freeze([...(entry.evidenceIds ?? [])]),
          }),
        )
        .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

      return Object.freeze({
        id: node.id,
        method: node.method,
        path: node.path,
        frameworks: Object.freeze([...node.frameworks]),
        sourcePaths: Object.freeze([...node.sourcePaths]),
        evidenceIds: Object.freeze([...node.evidenceIds]),
        protection: view?.protection ?? null,
        protectionBasis: view?.protectionBasis ?? null,
        middlewareChainIsComplete: chain.length === (view?.middleware ?? []).length,
        middleware: Object.freeze(chain),
        unresolvedCount: view?.unresolvedCount ?? 0,
        chainTruncated: view?.chainTruncated === true,
        fingerprintKey: `api:route:${stabilityHash(node.id)}`,
      });
    })
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

/**
 * Why one route's middleware chain cannot support an absence conclusion, or `null` when it can.
 *
 * The four abstention cases are exactly the security pack's, read from the same graph records:
 * no registration record, a truncated chain, an unresolved middleware-shaped occurrence, an
 * unknown protection state, a chain whose entries the projection does not fully describe, or a
 * middleware the graph classified `unknown` (its name says nothing about its role, so it could
 * be the very middleware the rule is asking about).
 */
export function routeAbsenceReason(route) {
  if (route.protection === null) return `no registration record was established for ${route.method} ${route.path}`;
  if (route.chainTruncated) return `the middleware chain established for ${route.method} ${route.path} was truncated`;
  if (route.unresolvedCount > 0) {
    return `${route.unresolvedCount} middleware-shaped occurrence(s) on ${route.method} ${route.path} were not established as middleware`;
  }
  if (route.protection === MIDDLEWARE_PROTECTION_STATES.UNKNOWN) {
    return `the registrations of the file declaring ${route.method} ${route.path} are not established`;
  }
  if (!route.middlewareChainIsComplete) {
    return `not every middleware established for ${route.method} ${route.path} is described`;
  }
  if (route.middleware.some((entry) => entry.classification === MIDDLEWARE_CLASSIFICATIONS.UNKNOWN)) {
    return `a middleware reaching ${route.method} ${route.path} is classified unknown, so its role is not established`;
  }
  if (
    route.protection !== MIDDLEWARE_PROTECTION_STATES.PROTECTED &&
    route.protection !== MIDDLEWARE_PROTECTION_STATES.NONE_OBSERVED
  ) {
    return `the protection of ${route.method} ${route.path} is ${route.protection}`;
  }
  return null;
}

/**
 * The middleware-source evidence id for one module path, or `null`.
 *
 * Reused from the model's evidence, so a gap finding can cite both halves of its claim — the
 * route's declaration and the registration record of the file that declares it. `null` means
 * the file carries no middleware observation at all, which a caller treats as unknown.
 */
export function middlewareSourceEvidenceId(query, path) {
  if (typeof path !== "string" || path === "") return null;
  for (const record of query.getEvidenceForEntity(`file:${path}`).evidence ?? []) {
    if (record?.data?.signal === MIDDLEWARE_SOURCE_SIGNAL) return record.id;
  }
  return null;
}

/** The middleware-source signal name the model records for a module's registration scan. */
export const MIDDLEWARE_SOURCE_SIGNAL = "middleware-source";

/**
 * The observed OpenAPI artifact files, matched by basename against a closed set.
 *
 * Matching is by basename only, because that is what the scanner observed and recorded. The
 * result is a file entity with its own evidence id; the domain's rule reports the artifact's
 * existence and explicitly disclaims any relationship to the API graph, because the model
 * establishes none.
 */
export function openapiArtifacts(query) {
  const names = new Set(API_ANALYSIS_OPENAPI_BASENAMES);
  return query
    .listEntities(ENTITY_KINDS.FILE)
    .entities.filter((file) => names.has(basenameOf(file.path)))
    .map((file) =>
      Object.freeze({
        id: file.id,
        path: file.path,
        basename: basenameOf(file.path),
        evidenceIds: Object.freeze([...(file.evidenceIds ?? [])]),
        fingerprintKey: `api:openapi:${stabilityHash(file.id)}`,
      }),
    )
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

/** The file inventory's completeness, for an artifact-absence claim. */
export function fileInventoryCoverage(query) {
  const inventory = query.listEntities(ENTITY_KINDS.FILE);
  const scan = query.coverage();
  return Object.freeze({
    coverage: inventory.coverage,
    truncated: inventory.truncated === true || scan.truncated === true,
    files: inventory.entities.length,
  });
}

/** The basename of a repository-relative path (POSIX, no `node:path`). */
export function basenameOf(path) {
  const parts = String(path ?? "").split("/");
  return parts.length === 0 ? "" : parts[parts.length - 1];
}
