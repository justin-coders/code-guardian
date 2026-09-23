/**
 * Code Guardian — RepositoryModel Dependency Graph (Phase 14)
 *
 * The dependency graph is a **deterministic projection** of the facts Phase 13
 * already acquired. It is not a second parser, not a resolver and not a model:
 * every node is an existing `dependency:<ecosystem>:<name>` entity and every edge
 * is a `depends-on` relationship the acquisition layer already recorded from a
 * supported lockfile. This module adds the two things the raw entity list cannot
 * express — **per-edge provenance** and an explicit **coverage statement** — and
 * nothing else.
 *
 * ### What an edge means, exactly
 *
 *   `from --depends-on--> to`
 *
 * means *the repository's supported lockfile states that `from` depends on `to`*.
 * It is never inferred from:
 *
 *   - both names occurring in the same lockfile,
 *   - a version range that might require the other package,
 *   - both names occurring in the same manifest,
 *   - one being reachable from the other in the graph,
 *   - a package manager convention the parser did not read.
 *
 * Today exactly one format establishes edges: `package-lock.json` /
 * `npm-shrinkwrap.json` (v1 nested `requires` and the v2/v3 `packages` tree). A
 * repository whose only manifests are `requirements.txt` or `go.mod` therefore has
 * a graph that is *established and empty*, which is a different state from one
 * whose graph was never established — see `DEPENDENCY_GRAPH_STATES`.
 *
 * ### Declared, direct, resolved and connected are four different facts
 *
 * An edge says nothing about whether either endpoint is declared, direct or
 * resolved, and a path of length one does not make a package "direct". Those
 * remain the acquisition layer's facts, carried on the node summary and never
 * derived from topology here. A package that only appears in a lockfile is a node
 * with `declared: false, direct: false` — it is kept, not discarded, and never
 * promoted to a direct dependency.
 *
 * ### The version-instance limitation is exposed, not hidden
 *
 * Dependency identity is `(ecosystem, name)` (Phase 13 §Identity), so
 * `foo@1.0.0` and `foo@2.0.0` are *one* node carrying two resolution records.
 * This graph therefore does NOT distinguish version instances, and an edge
 * `a --depends-on--> foo` does not say *which* `foo` the lockfile meant. Rather
 * than pretend otherwise, every node whose resolution records disagree on the
 * version is listed in `versionInstances.packages`, so a consumer that needs
 * version-accurate answers can see that the graph cannot give it one. Fixing this
 * needs a version-instance identity model, which is a later phase's decision.
 *
 * ### Coverage is five-way, and empty is not unknown
 *
 *   complete     every dependency source was read and interpreted; the graph is
 *                whatever the repository establishes, including nothing
 *   partial      at least one source was interpreted, at least one was not (or a
 *                limit was reached) — the graph is real but incomplete
 *   unsupported  no source was interpreted because every one is a format this
 *                build does not parse
 *   unknown      nothing established a graph at all (acquisition never ran, every
 *                source failed, or the section predates this phase)
 *
 * `unknown` is never reported as an empty edge list with an all-clear: `established`
 * separates an established-but-empty graph from one that acquisition never
 * established at all.
 *
 * ### Determinism
 *
 * Nodes are sorted by id and edges by `(from, to, type)`. Nothing here reads the
 * clock, the environment, the filesystem or a random source, and no input is
 * iterated in insertion order.
 */

/** Version of the projection's shape (not of the model). */
export const DEPENDENCY_GRAPH_VERSION = "1";

/**
 * Graph coverage states. Closed vocabulary: a consumer switches on these values
 * and must not have to interpret a free-form string.
 */
export const DEPENDENCY_GRAPH_STATES = Object.freeze({
  /** Every dependency source was interpreted. The graph is complete. */
  COMPLETE: "complete",
  /** Some sources were interpreted, some were not. The graph is real but partial. */
  PARTIAL: "partial",
  /** No source was interpreted because every one is an unsupported format. */
  UNSUPPORTED: "unsupported",
  /** Nothing established a graph: acquisition never ran, or every source failed. */
  UNKNOWN: "unknown",
});

/** The state vocabulary as a list, for validation. */
export const DEPENDENCY_GRAPH_STATE_VALUES = Object.freeze(
  Object.values(DEPENDENCY_GRAPH_STATES),
);

/**
 * Graph edge types.
 *
 * One value, on purpose. Phase 13's relationship vocabulary already distinguishes
 * `declares-dependency`, `depends-on` and `resolved-by`; the graph exposes the
 * `depends-on` edge and re-derives neither of the other two, so
 * `declares-dependency`/`resolved-by` are never re-labelled as graph edges (that
 * would turn "a manifest declared this" into "this package depends on that one").
 */
export const DEPENDENCY_GRAPH_EDGE_TYPES = Object.freeze({
  DEPENDS_ON: "depends-on",
});

/** The edge-type vocabulary as a list, for validation. */
export const DEPENDENCY_GRAPH_EDGE_TYPE_VALUES = Object.freeze(
  Object.values(DEPENDENCY_GRAPH_EDGE_TYPES),
);

/**
 * Graph bounds.
 *
 * `MAX_NODES`/`MAX_EDGES` mirror the Phase 13 acquisition caps so a projection can
 * never describe more than the model's own contract permits; `MAX_AMBIGUOUS_PACKAGES`
 * bounds the version-instance report, which is a diagnostic rather than a dataset.
 */
export const DEPENDENCY_GRAPH_LIMITS = Object.freeze({
  MAX_NODES: 8000,
  MAX_EDGES: 12000,
  MAX_AMBIGUOUS_PACKAGES: 64,
});

/**
 * Source statuses the acquisition layer can record, re-declared so this module
 * does not import the scanner (the model must not depend on it).
 *
 * `parsed` is the only value that yields facts; the other two are why a graph can
 * be partial or absent.
 */
const PARSED_STATUS = "parsed";
const UNSUPPORTED_STATUS = "unsupported";

/**
 * Freeze a value and everything reachable from it.
 *
 * Needed here rather than left to the builder: this module returns an already frozen
 * top-level object, and a shallow `Object.freeze` on the outer object would make the
 * builder's own deep freeze stop at it — leaving the nodes, the edges and their
 * provenance arrays mutable inside a model whose contract says deeply frozen. A
 * mutable shared graph is exactly what would let one analyzer corrupt another's view.
 *
 * @param {unknown} value
 * @returns {unknown}
 */
function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const key of Object.keys(value)) deepFreeze(value[key]);
  return value;
}

/** Sort by a string field, then by id, so no two records compare equal. */
function compareByKeys(keys) {
  return (a, b) => {
    for (const key of keys) {
      const left = a?.[key];
      const right = b?.[key];
      if (left === right) continue;
      if (typeof left === "string" && typeof right === "string") {
        return left < right ? -1 : 1;
      }
      return left === undefined || left === null ? 1 : -1;
    }
    return 0;
  };
}

/**
 * A node's compact summary.
 *
 * Deliberately not the dependency entity: no declarations, resolutions, scopes or
 * evidence arrays are copied, so a graph node cannot drift from the entity it names
 * (the id is the link, and the query layer resolves it).
 */
function nodeSummary(dependency) {
  return {
    id: dependency.id,
    ecosystem: dependency.ecosystem,
    name: dependency.name,
    declared: dependency.declared === true,
    direct: dependency.direct === true,
    resolved: dependency.resolved === true,
  };
}

/**
 * Which packages the graph cannot distinguish by version.
 *
 * A package is ambiguous when its resolution records disagree about the version.
 * Bounded and sorted, and `count` is the true total so a caller can tell a
 * truncated report from a complete one.
 */
function versionInstancesFor(dependencies) {
  const packages = [];
  for (const dependency of dependencies) {
    const versions = new Set();
    for (const resolution of dependency.resolutions ?? []) {
      if (typeof resolution?.version === "string") versions.add(resolution.version);
    }
    if (versions.size > 1) {
      packages.push({ id: dependency.id, versions: versions.size });
    }
  }
  packages.sort(compareByKeys(["id"]));
  return {
    ambiguous: packages.length > 0,
    count: packages.length,
    packages: packages.slice(0, DEPENDENCY_GRAPH_LIMITS.MAX_AMBIGUOUS_PACKAGES),
  };
}

/**
 * The graph's coverage state.
 *
 * Read only from facts the model already validated: whether any source was
 * interpreted, whether every source was, whether a limit bit, and the sources
 * themselves. Nothing is inferred from the node or edge counts — an empty graph is
 * a *result*, not evidence of missing information.
 */
export function dependencyGraphState(coverage, sources) {
  const inspected = coverage.inspected === true;
  if (!inspected) {
    // A complete section with no source is the one honest "established and empty"
    // case: the acquisition ran, found no manifest, and interpreted everything
    // there was to interpret. `complete: true` is only reachable that way — a
    // section that never ran stays `complete: false`.
    if (coverage.complete === true && sources.length === 0) {
      return DEPENDENCY_GRAPH_STATES.COMPLETE;
    }
    if (sources.length > 0 && sources.every((source) => source.status === UNSUPPORTED_STATUS)) {
      return DEPENDENCY_GRAPH_STATES.UNSUPPORTED;
    }
    return DEPENDENCY_GRAPH_STATES.UNKNOWN;
  }
  if (coverage.complete === true && coverage.truncated !== true) {
    return DEPENDENCY_GRAPH_STATES.COMPLETE;
  }
  return DEPENDENCY_GRAPH_STATES.PARTIAL;
}

/**
 * Project a dependency source into the unestablished-source record.
 *
 * Shared with the query layer's `dependencyCoverage()` so "which files stopped the
 * graph being complete" has exactly one shape and one definition.
 *
 * @param {object} source A `model.dependencies.sources` entry.
 * @returns {object} Frozen record.
 */
export function unestablishedSourceRecord(source) {
  return Object.freeze({
    path: source.path,
    ecosystem: source.ecosystem,
    status: source.status,
    reason: source.reason ?? null,
    problems: Object.freeze([...(source.problems ?? [])]),
    evidenceId: source.evidenceId ?? null,
  });
}

/** Whether a source's facts were fully interpreted. */
export function isSourceEstablished(source) {
  return source.status === PARSED_STATUS && (source.problems ?? []).length === 0;
}

/**
 * Build the dependency graph from the model's projected dependency facts.
 *
 * @param {object} input
 * @param {object[]} input.dependencies Dependency entities (`entries`).
 * @param {object[]} input.edges Recorded dependency edges, each carrying the
 *   observations and lockfile paths that established it.
 * @param {object} input.coverage `model.dependencies.coverage`.
 * @param {object[]} input.sources `model.dependencies.sources`.
 * @returns {object} Deeply frozen `{ version, state, established, nodes, edges, coverage }`.
 *   Frozen here rather than only by the builder: the builder cannot deep-freeze a
 *   graph whose outer object is already frozen.
 */
export function buildDependencyGraph({ dependencies, edges, coverage, sources }) {
  const nodes = dependencies.map(nodeSummary).sort(compareByKeys(["id"]));
  const nodeIds = new Set(nodes.map((node) => node.id));

  const graphEdges = [];
  for (const edge of edges) {
    // An edge whose endpoint is not a node cannot be expressed; the builder rejects
    // that case before this point (see `contracts.js`), so this is belt-and-braces
    // rather than a silent drop.
    if (!nodeIds.has(edge.from) || !nodeIds.has(edge.to)) continue;
    graphEdges.push({
      from: edge.from,
      to: edge.to,
      type: DEPENDENCY_GRAPH_EDGE_TYPES.DEPENDS_ON,
      // Provenance: the lockfile observations that stated the relationship, and the
      // repository-relative lockfile paths that carried them. File-level, because
      // the acquisition layer records no line positions — a fabricated line number
      // would be provenance that does not exist.
      evidenceIds: [...new Set(edge.evidenceIds ?? [])].sort(),
      manifestPaths: [...new Set(edge.manifestPaths ?? [])].sort(),
    });
  }
  graphEdges.sort(compareByKeys(["from", "to", "type"]));

  const state = dependencyGraphState(coverage, sources);
  const established =
    state !== DEPENDENCY_GRAPH_STATES.UNKNOWN && state !== DEPENDENCY_GRAPH_STATES.UNSUPPORTED;

  const unestablished = sources
    .filter((source) => !isSourceEstablished(source))
    .map(unestablishedSourceRecord)
    .sort(compareByKeys(["path"]));

  const versionInstances = versionInstancesFor(dependencies);

  return deepFreeze({
    version: DEPENDENCY_GRAPH_VERSION,
    state,
    established,
    nodes,
    edges: graphEdges,
    coverage: {
      state,
      established,
      inspected: coverage.inspected === true,
      complete: coverage.complete === true,
      truncated: coverage.truncated === true,
      // Nodes and edges are counts of what the graph contains, never a claim that
      // the repository has no more.
      nodes: nodes.length,
      edges: graphEdges.length,
      declarations: Number.isInteger(coverage.declarations) ? coverage.declarations : 0,
      resolved: Number.isInteger(coverage.resolved) ? coverage.resolved : 0,
      // Why the graph is not complete, named file by file.
      unestablishedSources: unestablished,
      // The documented identity limitation, stated rather than hidden.
      versionInstances,
      limits: DEPENDENCY_GRAPH_LIMITS,
    },
  });
}
