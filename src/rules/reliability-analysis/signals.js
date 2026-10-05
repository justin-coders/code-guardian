/**
 * Code Guardian — Reliability Analysis Repository Signals (Official Roadmap Phase 17)
 *
 * The one place the reliability-analysis rules ask the repository questions. Every read goes
 * through the Phase 11 query API over the frozen RepositoryModel: no filesystem, no `node:path`,
 * no source parsing, no process, no network, no clock. A rule that cannot answer a question from
 * the model reports `unknown` rather than going to look for itself.
 *
 * ### What this module reuses instead of rebuilding
 *
 *   `query.symbolGraph()`               module-scope bindings, with the module specifier each
 *                                       imported binding names and the occurrences the file states
 *   `query.unresolvedSymbolReferences()`the call/construct occurrences withheld for an imported
 *                                       binding (`callee-not-established`) — the half that turns
 *                                       an *import* into an observed *use*
 *   `query.symbolCoverage()`            the semantic graph's five-way state and its bounds
 *   `query.apiGraph()` / `query.routes()` route nodes (`route:METHOD:/path`)
 *   `query.apiCoverage()`               the API graph's state and bounds
 *   `query.middlewareGraph()`           middleware nodes with their name-derived classification
 *   `query.productionSection("container")` the Phase 20 judgement-free container inventory
 *                                       (definitions + Dockerfile healthcheck structure)
 *   `query.listEntities("test")`        test file identities, so test-only usage is not read as
 *                                       application behaviour
 *   `query.coverage()`                  the scan's own completeness
 *
 * Nothing here re-parses a module, re-derives a route or a symbol relationship, re-classifies a
 * middleware name, or re-reads a Dockerfile.
 */

import {
  API_GRAPH_STATES,
  ENTITY_KINDS,
  MIDDLEWARE_CLASSIFICATIONS,
  SYMBOL_GRAPH_STATES,
  SYMBOL_UNRESOLVED_REASONS,
  createRepositoryQuery,
  stabilityHash,
} from "../../repository/model/index.js";

import {
  RELIABILITY_ANALYSIS_LIMITS,
  RELIABILITY_ANALYSIS_SUBJECTS,
  RELIABILITY_CONTAINER_SECTION,
  RELIABILITY_HEALTH_PATH_SEGMENTS,
  RELIABILITY_LOCAL_VOCABULARY,
  RELIABILITY_OBSERVABILITY_DIMENSIONS,
  RELIABILITY_PACKAGE_VOCABULARY,
  RELIABILITY_SERVICE_RUNTIME_PACKAGES,
} from "./contracts.js";

/** Build the read-only query handle for an AnalysisContext. */
export function queryFor(context) {
  return createRepositoryQuery(context.repository);
}

// ── Reverse indexes over the closed vocabularies ─────────────────────────────

/** package specifier → `{ domain, dimension }`. Built once at module load (input is frozen). */
const PACKAGE_INDEX = (() => {
  const index = new Map();
  for (const [domain, packages] of Object.entries(RELIABILITY_PACKAGE_VOCABULARY)) {
    for (const name of packages) index.set(name, { domain, dimension: null });
  }
  for (const [dimension, packages] of Object.entries(RELIABILITY_OBSERVABILITY_DIMENSIONS)) {
    for (const name of packages) index.set(name, { domain: "observability", dimension });
  }
  return index;
})();

/** compacted local name (lower-cased) → `{ domain, name }`. */
const LOCAL_INDEX = (() => {
  const index = new Map();
  for (const [domain, names] of Object.entries(RELIABILITY_LOCAL_VOCABULARY)) {
    for (const name of names) index.set(name.toLowerCase(), { domain, name });
  }
  return index;
})();

const SERVICE_RUNTIME = new Set(RELIABILITY_SERVICE_RUNTIME_PACKAGES);

// ── Coverage statements ──────────────────────────────────────────────────────

/** The API graph's own coverage statement. */
export function apiGraphCoverage(query) {
  return query.apiCoverage();
}

/** The semantic (symbol) graph's own coverage statement. */
export function symbolGraphCoverage(query) {
  return query.symbolCoverage();
}

/** The scan's own completeness. */
export function scanCoverage(query) {
  return query.coverage();
}

/**
 * Why the repository's route set cannot be read as complete, or `null` when it can.
 *
 * Mirrors the api-analysis pack's `routeCoverageGap`, so an absence claim over routes rests on
 * the same facts every other pack uses.
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

/**
 * Why the semantic (symbol) graph cannot be read as complete, or `null` when it can.
 *
 * Used by every usage-based domain before it reports anything: an incomplete semantic graph may
 * have missed the import/occurrence that would have established the mechanism.
 */
export function symbolCoverageGap(query) {
  const coverage = query.symbolCoverage();
  const scan = query.coverage();

  if (coverage.established !== true) {
    return `the semantic graph is ${coverage.state}, so the repository's module bindings are not established`;
  }
  if (coverage.truncated === true) {
    return "the semantic graph stopped at a limit before every module was established";
  }
  if (coverage.unresolvedTruncated === true) {
    return "more symbol occurrences were left unresolved than the graph reports";
  }
  if ((coverage.unresolvedByReason?.["resolution-not-established"] ?? 0) > 0) {
    return "a module contains a dynamic-scope construct, so its name resolution is not established";
  }
  if (scan.complete !== true) {
    return scan.truncated === true
      ? "the scan stopped at a limit before the inventory was complete"
      : "the scan did not cover the repository completely";
  }
  return null;
}

/** The Phase 20 container section, or `null` when the model carries no production report. */
export function containerSection(query) {
  if (typeof query.productionReport !== "function" || query.productionReport() === null) {
    return null;
  }
  try {
    return query.productionSection(RELIABILITY_CONTAINER_SECTION);
  } catch {
    return null;
  }
}

/**
 * The container inventory, reduced to the facts the health-checks domain needs.
 *
 *   definitions        container definitions observed (`Dockerfile`, `*.dockerfile`, …)
 *   healthchecks       Dockerfiles whose own instructions declare a `HEALTHCHECK`
 *   healthcheckDisabled Dockerfiles declaring `HEALTHCHECK NONE`
 *   uncertain          Dockerfiles whose structure could not be established
 *   established        the section was established
 *   coverageState      the section's own state
 *
 * Read from the accepted report, never re-derived: the section already distinguishes "declares
 * no healthcheck" from "was not read".
 */
export function containerFacts(query) {
  const section = containerSection(query);
  if (section === null || section.established !== true) {
    return Object.freeze({
      definitions: 0,
      healthchecks: 0,
      healthcheckDisabled: 0,
      uncertain: 0,
      established: false,
      coverageState: section?.state ?? "unknown",
      evidenceIds: Object.freeze([]),
    });
  }

  const observations = section.observations ?? [];
  const evidenceIds = [...new Set((section.evidenceIds ?? []).concat(observations.flatMap((o) => o.evidenceIds ?? [])))]
    .filter((id) => typeof id === "string")
    .sort();

  return Object.freeze({
    definitions: (section.counts?.definitions ?? 0) | 0,
    healthchecks: (section.counts?.healthchecks ?? 0) | 0,
    healthcheckDisabled: (section.counts?.healthcheckDisabled ?? 0) | 0,
    uncertain: (section.unknown ?? []).length,
    established: true,
    coverageState: section.state,
    evidenceIds: Object.freeze(evidenceIds),
  });
}

// ── Test-file exclusion ──────────────────────────────────────────────────────

/**
 * The Dockerfiles whose own instructions declare a `HEALTHCHECK`, with their evidence ids.
 *
 * Read from the accepted container section's own observations (kind `container-healthcheck`), so
 * the rule cites the same evidence the report does. Sorted by path.
 */
export function containerHealthchecks(query) {
  const section = containerSection(query);
  if (section === null || section.established !== true) return Object.freeze([]);
  return Object.freeze(
    (section.observations ?? [])
      .filter((observation) => observation.kind === "container-healthcheck" && typeof observation.path === "string")
      .map((observation) =>
        Object.freeze({
          path: observation.path,
          evidenceIds: Object.freeze([...(observation.evidenceIds ?? [])]),
        }),
      )
      .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)),
  );
}

/** The container definitions the inventory observed, with their evidence ids, sorted by path. */
export function containerDefinitions(query) {
  const section = containerSection(query);
  if (section === null || section.established !== true) return Object.freeze([]);
  return Object.freeze(
    (section.observations ?? [])
      .filter((observation) => observation.kind === "container-definition" && typeof observation.path === "string")
      .map((observation) =>
        Object.freeze({
          path: observation.path,
          evidenceIds: Object.freeze([...(observation.evidenceIds ?? [])]),
        }),
      )
      .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)),
  );
}

/**
 * Why the container inventory cannot support an absence conclusion, or `null` when it can.
 *
 * The report records `no-container-configuration-observed` as an `unknown` reason too: it is not an
 * uncertainty, it is the fact that the repository declares no container at all, so it is excluded
 * here. Every other reason (a Dockerfile that could not be read) leaves the inventory unable to
 * support an absence claim.
 */
export function containerCoverageGap(query) {
  const section = containerSection(query);
  if (section === null) return "the model carries no container inventory";
  if (section.established !== true) return `the container inventory is ${section.state}`;
  const uncertainties = (section.unknown ?? []).filter(
    (entry) => entry?.reason !== "no-container-configuration-observed",
  );
  if (uncertainties.length > 0) {
    return `${uncertainties.length} container configuration source(s) were not read completely`;
  }
  if (section.coverage?.truncated === true) return "the container inventory was truncated";
  return null;
}

/** The repository-relative paths the model established as test artifacts. */
export function testFilePaths(query) {
  const paths = new Set();
  for (const entity of query.listEntities(ENTITY_KINDS.TEST).entities) {
    if (typeof entity.path === "string" && entity.path !== "") paths.add(entity.path);
  }
  return paths;
}

// ── Runtime usage (the heart of the pack) ────────────────────────────────────

/** The `symbol-source` evidence id observed on a file entity, or `null`. */
export function symbolSourceEvidenceId(query, path) {
  if (typeof path !== "string" || path === "") return null;
  for (const record of query.getEvidenceForEntity(`file:${path}`).evidence ?? []) {
    if (record?.data?.signal === "symbol-source") return record.id;
  }
  return null;
}

/** Whether a module-scope symbol's name matches the closed local vocabulary. */
function localMatch(name) {
  return LOCAL_INDEX.get(String(name).toLowerCase()) ?? null;
}

/**
 * Every reliability-relevant *usage* the repository's modules establish, sorted and bounded.
 *
 * Three joining rules, all read from facts the model already recorded:
 *
 *   - an **imported binding** whose specifier is in the closed package vocabulary is a usage when
 *     the file also states a `call`/`construct`/`reference` occurrence of the name. The call and
 *     construct occurrences are recorded as *unresolved* records (an imported binding's value
 *     shape is not established), so the join reads `unresolvedSymbolReferences()`;
 *   - a **local module-scope callable** (`function`/`class`/function-valued `const`) whose name
 *     matches the closed local vocabulary is a usage when the file calls, constructs or
 *     references it;
 *   - usage in a **test file** is excluded: it is test-system behaviour, not application
 *     reliability (the Testing analyzer owns those semantics).
 *
 * Each record is `{ domain, dimension, name, packageName, local, usage, counts, path, symbolId,
 * evidenceIds, fingerprintKey, nameDerived }`.
 *
 * @param {object} query
 * @returns {{usages: object[], truncated: boolean}}
 */
export function runtimeUsages(query) {
  const graph = query.symbolGraph();
  if (graph.established !== true) return Object.freeze({ usages: Object.freeze([]), truncated: false });

  const testPaths = testFilePaths(query);

  // Occurrences withheld for an imported binding, keyed by path+name.
  const unresolvedResult = query.unresolvedSymbolReferences({
    maxResults: RELIABILITY_ANALYSIS_LIMITS.MAX_UNRESOLVED,
  });
  const importedOccurrence = new Map();
  for (const record of unresolvedResult.unresolved) {
    if (record.reason !== SYMBOL_UNRESOLVED_REASONS.CALLEE_NOT_ESTABLISHED) continue;
    if (record.kind !== "call" && record.kind !== "construct") continue;
    const key = `${record.path}\u0000${record.name}`;
    let entry = importedOccurrence.get(key);
    if (entry === undefined) {
      entry = { call: 0, construct: 0 };
      importedOccurrence.set(key, entry);
    }
    if (record.kind === "construct") entry.construct += 1;
    else entry.call += 1;
  }

  const coverage = query.symbolCoverage();
  const truncated =
    unresolvedResult.limited === true || coverage.unresolvedTruncated === true;

  const candidates = [];
  for (const node of graph.nodes) {
    if (testPaths.has(node.path)) continue;
    const binding = node.binding ?? null;

    if (binding !== null) {
      const vocabulary = PACKAGE_INDEX.get(binding.specifier);
      const isServiceRuntime = SERVICE_RUNTIME.has(binding.specifier);
      // A usage must belong to a reliability domain, or be a service-runtime package (which only
      // feeds the applicability decision, not a domain rule).
      if (vocabulary === undefined && !isServiceRuntime) continue;
      const specifier = binding.specifier;
      const occ = importedOccurrence.get(`${node.path}\u0000${node.name}`) ?? { call: 0, construct: 0 };
      const usage =
        occ.construct > 0
          ? "constructed"
          : occ.call > 0
            ? "called"
            : node.referenceCount > 0
              ? "referenced"
              : "imported";
      candidates.push(
        makeUsage(query, node, {
          domain: vocabulary === undefined ? "service-runtime" : vocabulary.domain,
          dimension: vocabulary?.dimension ?? null,
          usage,
          counts: { references: node.referenceCount, calls: occ.call, constructs: occ.construct },
          packageName: specifier,
          local: false,
          nameDerived: false,
        }),
      );
      continue;
    }

    // A local declaration: only a callable/constructable symbol can be a mechanism.
    if (node.callable !== true && node.constructable !== true) continue;
    const match = localMatch(node.name);
    if (match === null) continue;
    const occurrences = node.referenceCount + node.callCount + node.constructCount;
    if (occurrences <= 0) continue;
    const usage =
      node.constructCount > 0
        ? "constructed"
        : node.callCount > 0
          ? "called"
          : "referenced";
    candidates.push(
      makeUsage(query, node, {
        domain: match.domain,
        dimension: null,
        usage,
        counts: { references: node.referenceCount, calls: node.callCount, constructs: node.constructCount },
        packageName: null,
        local: true,
        nameDerived: true,
      }),
    );
  }

  candidates.sort((a, b) => {
    if (a.domain !== b.domain) return a.domain < b.domain ? -1 : 1;
    if (a.path !== b.path) return a.path < b.path ? -1 : 1;
    return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
  });

  const bounded = candidates.slice(0, RELIABILITY_ANALYSIS_LIMITS.MAX_USAGES);
  return Object.freeze({
    usages: Object.freeze(bounded),
    truncated: truncated || candidates.length > bounded.length,
  });
}

/** Build one frozen usage record. */
function makeUsage(query, node, extra) {
  const evidenceId = symbolSourceEvidenceId(query, node.path);
  return Object.freeze({
    domain: extra.domain,
    dimension: extra.dimension,
    name: node.name,
    packageName: extra.packageName,
    local: extra.local,
    usage: extra.usage,
    counts: Object.freeze({ ...extra.counts }),
    path: node.path,
    symbolId: node.id,
    evidenceIds: Object.freeze(evidenceId === null ? [] : [evidenceId]),
    fingerprintKey: `reliability:usage:${stabilityHash(node.id)}`,
    nameDerived: extra.nameDerived,
  });
}

/** Every usage belonging to one domain. */
export function usagesForDomain(query, domain) {
  const { usages, truncated } = runtimeUsages(query);
  return Object.freeze({
    usages: Object.freeze(usages.filter((usage) => usage.domain === domain)),
    truncated,
  });
}

/** Service-runtime usages, for the applicable/not-applicable decision. */
function serviceRuntimeUsage(query, usages) {
  return usages.some((usage) => usage.packageName !== null && SERVICE_RUNTIME.has(usage.packageName));
}

// ── Routes ───────────────────────────────────────────────────────────────────

/**
 * Every established route, reduced to the facts reliability cares about.
 *
 * `{ id, method, path, frameworks, sourcePaths, evidenceIds, fingerprintKey }`, sorted by id. The
 * route identity is the API graph's own `route:METHOD:/path`; nothing is re-derived.
 */
export function reliabilityRoutes(query) {
  const api = query.apiGraph();
  if (api.established !== true) return Object.freeze([]);
  return Object.freeze(
    api.nodes
      .map((node) =>
        Object.freeze({
          id: node.id,
          method: node.method,
          path: node.path,
          frameworks: Object.freeze([...node.frameworks]),
          sourcePaths: Object.freeze([...node.sourcePaths]),
          evidenceIds: Object.freeze([...node.evidenceIds]),
          fingerprintKey: `reliability:route:${stabilityHash(node.id)}`,
        }),
      )
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
  );
}

/** Whether a path contains one of the closed health-shaped segments as a whole segment. */
export function isHealthShapedPath(path) {
  const segments = String(path ?? "")
    .toLowerCase()
    .split("/")
    .filter((segment) => segment !== "");
  return segments.some((segment) => RELIABILITY_HEALTH_PATH_SEGMENTS.includes(segment));
}

/** The health-shaped routes, sorted by id. */
export function healthRoutes(query) {
  return Object.freeze(reliabilityRoutes(query).filter((route) => isHealthShapedPath(route.path)));
}

// ── The reliability subject ──────────────────────────────────────────────────

/**
 * Whether the repository is a reliability subject at all, and why.
 *
 * The roadmap's central applicability requirement — a CLI application should not receive service
 * findings — is answered from the model's own facts, never from a single signal:
 *
 *   - a **container definition** is declared; or
 *   - the **API graph** declares at least one route; or
 *   - the **module graph** uses a **service-runtime package** (a server, a queue, a worker).
 *
 * None of those present, and the substrate is not established → `unknown` (an unsupported
 * framework is never `not_applicable`). None present over an established, complete model →
 * `not_applicable` (a CLI tool or a pure library).
 *
 * @returns {{state: string, reason: string|null, routes: number, containers: number, services: number}}
 */
export function reliabilitySubject(query) {
  const container = containerFacts(query);
  const api = query.apiCoverage();
  const routes = Number.isInteger(api.routes) ? api.routes : 0;

  const symbolCoverage = query.symbolCoverage();
  const usageResult = runtimeUsages(query);
  const usages = usageResult.usages;
  const services = usages.filter((u) => u.packageName !== null && SERVICE_RUNTIME.has(u.packageName)).length;

  const base = {
    routes,
    containers: container.definitions,
    services,
  };

  if (container.definitions > 0) {
    return Object.freeze({ state: RELIABILITY_ANALYSIS_SUBJECTS.APPLICABLE, reason: null, ...base });
  }
  if (api.established === true && routes > 0) {
    return Object.freeze({ state: RELIABILITY_ANALYSIS_SUBJECTS.APPLICABLE, reason: null, ...base });
  }
  if (symbolCoverage.established === true && services > 0) {
    return Object.freeze({ state: RELIABILITY_ANALYSIS_SUBJECTS.APPLICABLE, reason: null, ...base });
  }

  // No positive signal. Can the model even decide?
  if (symbolCoverage.established !== true) {
    const reason =
      symbolCoverage.state === SYMBOL_GRAPH_STATES.UNSUPPORTED
        ? "every module source in this repository is in a format this build does not interpret, so no service subject could be established"
        : "the semantic graph was not established, so no service subject could be established";
    return Object.freeze({ state: RELIABILITY_ANALYSIS_SUBJECTS.UNKNOWN, reason, ...base });
  }
  if (api.established !== true) {
    return Object.freeze({
      state: RELIABILITY_ANALYSIS_SUBJECTS.UNKNOWN,
      reason: "the API graph was not established, so the repository may expose a service this build could not read",
      ...base,
    });
  }
  const scan = query.coverage();
  // `not_applicable` is a strong claim: it says the repository is not a service. Every substrate
  // that could hide a service must be complete before it can be made — an established but
  // truncated graph, or an unread route-shaped occurrence, leaves it `unknown`.
  const incomplete =
    scan.complete !== true ||
    scan.truncated === true ||
    symbolCoverage.truncated === true ||
    api.truncated === true ||
    api.unresolvedTruncated === true ||
    (api.unresolved ?? 0) > 0 ||
    (container.established === false && containerCoverageGap(query) !== null);
  if (incomplete) {
    return Object.freeze({
      state: RELIABILITY_ANALYSIS_SUBJECTS.UNKNOWN,
      reason: "the scan or a graph behind the service subject was incomplete, so no service subject could be established",
      ...base,
    });
  }

  return Object.freeze({ state: RELIABILITY_ANALYSIS_SUBJECTS.NOT_APPLICABLE, reason: null, ...base });
}

/** The middleware classifications reaching a route, read from the middleware graph. */
export function routeMiddleware(query) {
  const graph = query.middlewareGraph();
  if (graph.established !== true) return Object.freeze({ established: false, byRoute: new Map() });
  const nodeById = new Map(graph.nodes.map((node) => [node.id, node]));
  // A route's own declaration evidence lives on the API graph's route node, keyed by the same
  // `route:METHOD:/path` identity the middleware graph's route view uses. Read, never re-derived.
  const api = query.apiGraph();
  const routeEvidenceById = new Map(
    (api.established === true ? api.nodes : []).map((node) => [node.id, [...node.evidenceIds]]),
  );
  const byRoute = new Map();
  for (const view of graph.routes) {
    const chain = (view.middleware ?? [])
      .map((id) => nodeById.get(id))
      .filter((entry) => entry !== undefined)
      .map((entry) =>
        Object.freeze({
          id: entry.id,
          name: entry.name,
          classification: entry.classification,
          // The middleware node's own registration/classification provenance, carried through
          // rather than dropped so a consumer can cite it.
          evidenceIds: Object.freeze([...(entry.evidenceIds ?? [])]),
        }),
      );
    byRoute.set(view.route, {
      protection: view.protection,
      middleware: chain,
      evidenceIds: Object.freeze([...(routeEvidenceById.get(view.route) ?? [])]),
    });
  }
  return Object.freeze({ established: true, byRoute });
}

/** Whether any route is reached by a middleware the middleware graph classified `logging`. */
export function hasLoggingMiddleware(query) {
  const { established, byRoute } = routeMiddleware(query);
  if (!established) return false;
  for (const view of byRoute.values()) {
    if (view.middleware.some((entry) => entry.classification === MIDDLEWARE_CLASSIFICATIONS.LOGGING)) {
      return true;
    }
  }
  return false;
}

/**
 * The logging classification's provenance, read from the middleware graph.
 *
 * Reuses `routeMiddleware()` so the middleware rule and this signal can never disagree. The
 * evidence is the union of the route's own declaration evidence and each logging-classified
 * middleware node's registration evidence — both sides of the claim the observability rule makes —
 * unique and sorted so two runs over one RepositoryModel cite the same ids in the same order.
 *
 * @returns {{ middleware: boolean, evidenceIds: string[] }} Whether a logging middleware was
 *   observed, and the model evidence behind it (empty only if the model carries none).
 */
export function loggingMiddlewareEvidence(query) {
  const { established, byRoute } = routeMiddleware(query);
  if (!established) return Object.freeze({ middleware: false, evidenceIds: Object.freeze([]) });
  const ids = new Set();
  let observed = false;
  for (const view of byRoute.values()) {
    const logging = view.middleware.filter(
      (entry) => entry.classification === MIDDLEWARE_CLASSIFICATIONS.LOGGING,
    );
    if (logging.length === 0) continue;
    observed = true;
    for (const id of view.evidenceIds) ids.add(id);
    for (const entry of logging) for (const id of entry.evidenceIds) ids.add(id);
  }
  return Object.freeze({ middleware: observed, evidenceIds: Object.freeze([...ids].sort()) });
}

/**
 * The observability dimensions, each with the evidence the model establishes for it.
 *
 * Multi-dimensional on purpose (§54): logging, metrics, tracing and error reporting are separate,
 * and the pack never collapses them into a boolean. The logging dimension additionally reads the
 * middleware graph's existing `logging` classification (reused, not re-derived) and carries the
 * route/middleware provenance that classification rests on.
 *
 * @returns {object} `{ dimension: { established, usages, middleware, evidenceIds } }`.
 */
export function observabilityDimensions(query) {
  const { usages } = runtimeUsages(query);
  const obs = usages.filter((usage) => usage.domain === "observability");
  const loggingEvidence = loggingMiddlewareEvidence(query);
  const loggingMiddleware = loggingEvidence.middleware;
  const dimensions = {};
  for (const dimension of Object.keys(RELIABILITY_OBSERVABILITY_DIMENSIONS)) {
    const matched = obs.filter((usage) => usage.dimension === dimension);
    const middleware = dimension === "logging" ? loggingMiddleware : false;
    dimensions[dimension] = Object.freeze({
      established: matched.length > 0 || middleware,
      usages: Object.freeze(matched),
      middleware,
      // The logging dimension keeps the middleware/route provenance the finding must cite, so a
      // consumer never has to render a claim whose evidence the signal layer discarded.
      evidenceIds: Object.freeze(dimension === "logging" ? [...loggingEvidence.evidenceIds] : []),
    });
  }
  return Object.freeze(dimensions);
}

export { API_GRAPH_STATES, MIDDLEWARE_CLASSIFICATIONS };
