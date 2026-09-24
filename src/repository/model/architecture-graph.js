/**
 * Code Guardian — RepositoryModel Architecture Graph (Phase 15)
 *
 * The architecture graph is a **deterministic projection** of facts the model
 * already holds. It is not a parser, not an analyzer and not a second model: every
 * node is an existing entity (plus the repository node the model already uses as
 * the root of its relationship list), and every edge re-states a relationship or a
 * container declaration the model already established. This module adds the two
 * things neither the entity list nor the flat relationship list can express —
 * **per-edge provenance** and an explicit **coverage statement** — and nothing else.
 *
 * ### What each edge means, exactly
 *
 *   `contains`            (repository | directory) → direct child entity
 *        The child sits directly in that container, because its own observed path
 *        (or its parent directory's path) says so. It is the model's existing
 *        containment fact (`located_in` for a nested entity, `contains` for a
 *        root-level one, `parent` for a nested directory) stated in one direction
 *        only, so the graph never states one fact twice.
 *
 *   `declares-dependency` manifest → dependency
 *        That manifest declared that dependency, in one of its own sections. The
 *        scope, specifier and directness stay on the dependency entity; the edge is
 *        the architectural "this component declares this package".
 *
 *   `framework`           test entity → framework entity
 *        That test artifact reported using that framework. The framework entity
 *        exists only because a test artifact named it.
 *
 *   `declares-build`      configuration (Compose file) → file (Dockerfile)
 *        That Compose service declares how that Dockerfile is built.
 *
 *   `build-context`       file (Dockerfile) → directory (the build context)
 *        The Dockerfile is built from that directory. The repository node stands for
 *        the repository root, which has no directory entity.
 *
 * The last two restate a container declaration the model records as a
 * `compose-build-context` observation, so their provenance is that observation —
 * never an inference. Each is a binary view of a four-part fact (Compose file,
 * service, Dockerfile, context), which is why the graph also carries the fact in
 * full under `buildContexts`.
 *
 * ### What the graph deliberately does not relate
 *
 * There is no import edge, no call edge, no inheritance edge and no
 * "file A is tested by file B" edge. Establishing those needs parsing and
 * resolution (an AST, a symbol table, a runner's own report), and this phase has
 * none of them: a path-naming convention like `app.test.js` is a *convention*, not
 * an observation, and turning it into an edge would put a guess where provenance
 * belongs. A tested-by relation therefore does not exist yet — not as a missing
 * feature, but as a fact this architecture cannot currently support. The same
 * reason keeps CI workflows unconnected to the files they may (or may not) run:
 * the scanner records *that* a workflow exists and for which provider, never what
 * it references.
 *
 * ### Coverage is four-way, and empty is not unknown
 *
 *   complete     the scan covered the repository, and every architecture-relevant
 *                source (every Compose file whose declarations would extend the
 *                graph) was interpreted
 *   partial      the graph is real but incomplete: the scan was truncated or did not
 *                finish, or a Compose file's build declarations could not be
 *                established
 *   unsupported  the inventory establishes no architectural entity at all, so there
 *                is nothing to relate
 *   unknown      the model records no scan state, so nothing could be established
 *
 * `established` separates *the repository establishes this architecture* (including
 * an architecture with no edges) from *nothing was established at all*.
 * An empty edge list is never reported as an all-clear on its own.
 *
 * ### Determinism
 *
 * Nodes are sorted by id; edges by `(from, to, type)`; build declarations by
 * `(source, service, dockerfile)`. Nothing here reads the clock, the environment,
 * the filesystem or a random source, and no input is iterated in insertion order.
 */

/** Version of the projection's shape (not of the model). */
export const ARCHITECTURE_GRAPH_VERSION = "1";

/** Entity kind of the repository node (the root every entity hangs from). */
export const REPOSITORY_NODE_KIND = "repository";

/**
 * Architecture graph coverage states.
 *
 * The vocabulary is the one Phase 14 established for the dependency graph, so a
 * consumer switches on the same four values for both graphs. What each value means
 * for *this* graph is documented in the module header and repeated per constant.
 */
export const ARCHITECTURE_GRAPH_STATES = Object.freeze({
  /** The scan covered the repository and every architecture source was interpreted. */
  COMPLETE: "complete",
  /** The graph is real but incomplete: an incomplete scan, or an uninterpreted source. */
  PARTIAL: "partial",
  /** The inventory establishes no architectural entity, so there is nothing to relate. */
  UNSUPPORTED: "unsupported",
  /** The model records no scan state, so nothing could be established. */
  UNKNOWN: "unknown",
});

/** The state vocabulary as a list, for validation. */
export const ARCHITECTURE_GRAPH_STATE_VALUES = Object.freeze(
  Object.values(ARCHITECTURE_GRAPH_STATES),
);

/**
 * Architecture edge types.
 *
 * Every value is either the model's own relationship vocabulary reused verbatim
 * (`contains`, `declares-dependency`, `framework` — no renamed duplicate of an
 * existing fact) or one of the two container-wiring types, for which the model has
 * no relationship at all: a Compose declaration is recorded as an observation, so
 * these two are the only edges whose provenance is an observation rather than a
 * relationship.
 */
export const ARCHITECTURE_EDGE_TYPES = Object.freeze({
  /** Container → direct child. */
  CONTAINS: "contains",
  /** Manifest → dependency it declared. */
  DECLARES_DEPENDENCY: "declares-dependency",
  /** Test artifact → framework it reported using. */
  FRAMEWORK: "framework",
  /** Compose file → Dockerfile its service builds. */
  DECLARES_BUILD: "declares-build",
  /** Dockerfile → the directory it is built from. */
  BUILD_CONTEXT: "build-context",
});

/** The edge-type vocabulary as a list, for validation. */
export const ARCHITECTURE_EDGE_TYPE_VALUES = Object.freeze(
  Object.values(ARCHITECTURE_EDGE_TYPES),
);

/**
 * Graph bounds.
 *
 * `MAX_NODES`/`MAX_EDGES` sit above the Phase 8C acquisition caps (at most ten
 * thousand files, each with its parent directory, plus the dependency entities the
 * acquisition caps), so a projection can never describe more than the model's own
 * contract permits while still being an explicit bound rather than an assumption.
 */
export const ARCHITECTURE_GRAPH_LIMITS = Object.freeze({
  MAX_NODES: 40000,
  MAX_EDGES: 80000,
  MAX_BUILD_DECLARATIONS: 512,
  MAX_UNESTABLISHED_SOURCES: 512,
});

/**
 * Signals recorded on container observations, re-declared here so this module does
 * not import the scanner (the model must not depend on it). A test in
 * `tests/architecture-graph.test.js` pins them against the model's own vocabulary.
 */
const BUILD_CONTEXT_SIGNAL = "compose-build-context";
const COMPOSE_UNPARSED_SIGNAL = "compose-unparsed";

/**
 * The entity kinds that take part in the architecture graph.
 *
 * Languages and ecosystems are deliberately absent: they are *classifications*, not
 * things the repository is built from, and every classification question is already
 * answered by the entity itself (`file.languageId`, `manifest.ecosystemId`) and by
 * the query layer's `filesByLanguage`/`manifestsByEcosystem`. The git entity is
 * absent for the same reason: it is one repository-level fact, not a component. Their
 * relationships (`signals`, `declares` a language, `ecosystem`) are therefore not
 * architecture edges either.
 */
export const ARCHITECTURE_NODE_KINDS = Object.freeze([
  "directory",
  "file",
  "symlink",
  "manifest",
  "framework",
  "test",
  "cicd",
  "documentation",
  "configuration",
  "dependency",
]);

/**
 * Freeze a value and everything reachable from it.
 *
 * Needed here rather than left to the builder: this module returns an already frozen
 * top-level object, and a shallow `Object.freeze` on the outer object would make the
 * builder's own deep freeze stop at it — leaving the nodes, the edges and their
 * provenance arrays mutable inside a model whose contract says deeply frozen.
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

/** Sort by a list of keys, so no two records compare equal. */
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
 * The graph's coverage state.
 *
 * Read only from facts the model already validated: whether any architectural entity
 * exists, whether the scan finished, and whether an architecture-relevant source was
 * left uninterpreted. Nothing is inferred from node or edge counts — an empty graph is
 * a *result*, not evidence of missing information.
 *
 * @param {object} input
 * @param {number} input.entityCount Architectural entities (excluding the repository node).
 * @param {boolean} input.scanComplete `scan.complete === true`.
 * @param {boolean} input.scanTruncated `scan.truncated === true`.
 * @param {boolean} input.hasScanState Whether the model records scan state at all.
 * @param {number} input.unestablishedSources Interpreted-gap count.
 * @returns {string} One of `ARCHITECTURE_GRAPH_STATES`.
 */
export function architectureGraphState({
  entityCount,
  scanComplete,
  scanTruncated,
  hasScanState,
  unestablishedSources,
}) {
  if (!hasScanState) return ARCHITECTURE_GRAPH_STATES.UNKNOWN;
  if (entityCount === 0) {
    // Nothing to relate. A scan that finished establishes that the repository has no
    // architectural entity; a scan that did not finish establishes nothing.
    return scanComplete && !scanTruncated
      ? ARCHITECTURE_GRAPH_STATES.UNSUPPORTED
      : ARCHITECTURE_GRAPH_STATES.UNKNOWN;
  }
  if (scanComplete === true && scanTruncated !== true && unestablishedSources === 0) {
    return ARCHITECTURE_GRAPH_STATES.COMPLETE;
  }
  return ARCHITECTURE_GRAPH_STATES.PARTIAL;
}

/** Whether a state means an architecture was established. */
export function isEstablishedState(state) {
  return (
    state === ARCHITECTURE_GRAPH_STATES.COMPLETE || state === ARCHITECTURE_GRAPH_STATES.PARTIAL
  );
}

/** Whether an entity is an architectural node of this graph. */
export function isArchitecturalEntity(entity) {
  return (
    entity !== null &&
    typeof entity === "object" &&
    ARCHITECTURE_NODE_KINDS.includes(entity.kind) &&
    typeof entity.id === "string" &&
    entity.id.trim() !== ""
  );
}

/**
 * The architectural entities in the model, sorted by id.
 *
 * @param {object} collections Entity collections from `entities.js`.
 * @returns {object[]} Entities that take part in the graph.
 */
export function collectArchitecturalEntities(collections) {
  const candidates = [
    ...(collections.directories ?? []),
    ...(collections.files ?? []),
    ...(collections.symlinks ?? []),
    ...(collections.manifests ?? []),
    ...(collections.frameworks ?? []),
    ...(collections.tests ?? []),
    ...(collections.cicd ?? []),
    ...(collections.documentation ?? []),
    ...(collections.configuration ?? []),
    ...(collections.dependencies ?? []),
  ];
  return candidates.filter(isArchitecturalEntity).sort(compareByKeys(["id"]));
}

/** A node's compact summary. Deliberately not the entity: the id is the link. */
function nodeSummary(entity) {
  return {
    id: entity.id,
    kind: entity.kind,
    name: typeof entity.name === "string" ? entity.name : null,
    path: typeof entity.path === "string" ? entity.path : null,
  };
}

function sortedUnique(values) {
  return [...new Set(values)].sort();
}

/**
 * Build the architecture graph from the model's entity collections.
 *
 * @param {object} input
 * @param {string} input.repositoryId The model's repository node id.
 * @param {object} input.collections Entity collections from `entities.js`.
 * @param {object[]} input.evidence The model's observation list.
 * @param {object} input.coverage `{ scanComplete, scanTruncated, hasScanState }`.
 * @returns {object} Deeply frozen
 *   `{ version, state, established, nodes, edges, buildContexts, coverage }`.
 */
export function buildArchitectureGraph({ repositoryId, collections, evidence, coverage }) {
  const entities = collectArchitecturalEntities(collections);

  const nodes = [
    { id: repositoryId, kind: REPOSITORY_NODE_KIND, name: null, path: null },
    ...entities.map(nodeSummary),
  ].sort(compareByKeys(["id"]));
  const nodeIds = new Set(nodes.map((node) => node.id));

  /** Edge accumulator: one record per `(from, to, type)`, provenance merged. */
  const edgeRecords = new Map();
  const addEdge = ({ from, to, type, evidenceIds, sourcePaths, services }) => {
    const key = `${from}\u0000${to}\u0000${type}`;
    let record = edgeRecords.get(key);
    if (record === undefined) {
      record = {
        from,
        to,
        type,
        evidenceIds: new Set(),
        sourcePaths: new Set(),
        services: new Set(),
      };
      edgeRecords.set(key, record);
    }
    for (const id of evidenceIds ?? []) record.evidenceIds.add(id);
    for (const path of sourcePaths ?? []) record.sourcePaths.add(path);
    for (const service of services ?? []) record.services.add(service);
  };

  // ── Containment ───────────────────────────────────────────────────────────
  //
  // One edge per entity, into the container its own path names: the parent directory
  // for a nested directory, the containing directory (or the repository node at the
  // root) for every other path-bearing entity. The provenance is the child's own
  // observations, because the child's observed path is what establishes where it is.
  for (const directory of collections.directories ?? []) {
    if (!nodeIds.has(directory.id)) continue;
    const containerId = directory.parentId === null ? repositoryId : directory.parentId;
    if (!nodeIds.has(containerId)) continue;
    addEdge({
      from: containerId,
      to: directory.id,
      type: ARCHITECTURE_EDGE_TYPES.CONTAINS,
      evidenceIds: directory.evidenceIds ?? [],
      sourcePaths: typeof directory.path === "string" ? [directory.path] : [],
    });
  }
  for (const entity of entities) {
    if (entity.kind === "directory") continue;
    if (typeof entity.directoryId !== "string") continue;
    if (!nodeIds.has(entity.directoryId)) continue;
    addEdge({
      from: entity.directoryId,
      to: entity.id,
      type: ARCHITECTURE_EDGE_TYPES.CONTAINS,
      evidenceIds: entity.evidenceIds ?? [],
      sourcePaths: typeof entity.path === "string" ? [entity.path] : [],
    });
  }

  // ── Manifest declarations and test frameworks ─────────────────────────────
  for (const dependency of collections.dependencies ?? []) {
    if (!nodeIds.has(dependency.id)) continue;
    for (const declaration of dependency.declarations ?? []) {
      if (!nodeIds.has(declaration.manifestId)) continue;
      addEdge({
        from: declaration.manifestId,
        to: dependency.id,
        type: ARCHITECTURE_EDGE_TYPES.DECLARES_DEPENDENCY,
        evidenceIds: declaration.evidenceIds ?? [],
        sourcePaths: typeof declaration.manifestPath === "string" ? [declaration.manifestPath] : [],
      });
    }
  }
  for (const test of collections.tests ?? []) {
    if (!nodeIds.has(test.id) || typeof test.frameworkId !== "string") continue;
    if (!nodeIds.has(test.frameworkId)) continue;
    addEdge({
      from: test.id,
      to: test.frameworkId,
      type: ARCHITECTURE_EDGE_TYPES.FRAMEWORK,
      evidenceIds: test.evidenceIds ?? [],
      sourcePaths: typeof test.path === "string" ? [test.path] : [],
    });
  }

  // ── Container build wiring ────────────────────────────────────────────────
  //
  // Read from the model's own container observations, never re-derived: each record
  // states a Compose file and service that build a Dockerfile from a context root.
  // A declaration whose Dockerfile or context is not a node cannot be an edge (an edge
  // needs two endpoints), so it is left to `buildContexts`, which states the fact in
  // full.
  const buildContexts = [];
  const unestablishedSources = [];
  for (const record of evidence ?? []) {
    const signal = record?.data?.signal;
    if (signal === BUILD_CONTEXT_SIGNAL) {
      const source = record.data.source;
      const service = record.data.service;
      const dockerfile = record.location?.path;
      const context = record.data.contextPath ?? null;
      if (
        typeof source !== "string" ||
        typeof service !== "string" ||
        typeof dockerfile !== "string"
      ) {
        continue;
      }
      buildContexts.push({
        source,
        service,
        dockerfile,
        // `null` is the repository root, exactly as the acquisition layer records it.
        context,
        evidenceId: record.id,
      });

      const sourceNodeId = nodeIds.has(`configuration:${source}`)
        ? `configuration:${source}`
        : nodeIds.has(`file:${source}`)
          ? `file:${source}`
          : null;
      const dockerfileNodeId = nodeIds.has(`file:${dockerfile}`) ? `file:${dockerfile}` : null;
      const contextNodeId =
        context === null
          ? repositoryId
          : nodeIds.has(`directory:${context}`)
            ? `directory:${context}`
            : null;
      if (sourceNodeId !== null && dockerfileNodeId !== null) {
        addEdge({
          from: sourceNodeId,
          to: dockerfileNodeId,
          type: ARCHITECTURE_EDGE_TYPES.DECLARES_BUILD,
          evidenceIds: [record.id],
          sourcePaths: [source],
          services: [service],
        });
      }
      if (dockerfileNodeId !== null && contextNodeId !== null) {
        addEdge({
          from: dockerfileNodeId,
          to: contextNodeId,
          type: ARCHITECTURE_EDGE_TYPES.BUILD_CONTEXT,
          evidenceIds: [record.id],
          sourcePaths: [source],
          services: [service],
        });
      }
      continue;
    }
    if (signal === COMPOSE_UNPARSED_SIGNAL) {
      const path = record.location?.path;
      if (typeof path !== "string") continue;
      unestablishedSources.push({
        path,
        reason: typeof record.data.reason === "string" ? record.data.reason : null,
        detail: typeof record.data.detail === "string" ? record.data.detail : null,
        evidenceId: record.id,
      });
    }
  }

  buildContexts.sort(compareByKeys(["source", "service", "dockerfile"]));
  const boundedBuildContexts = buildContexts.slice(0, ARCHITECTURE_GRAPH_LIMITS.MAX_BUILD_DECLARATIONS);
  const boundedUnestablished = unestablishedSources
    .sort(compareByKeys(["path"]))
    .slice(0, ARCHITECTURE_GRAPH_LIMITS.MAX_UNESTABLISHED_SOURCES);

  const edges = [...edgeRecords.values()]
    .map((record) => ({
      from: record.from,
      to: record.to,
      type: record.type,
      // Provenance: the observations that established the fact, and the
      // repository-relative paths whose observations stated it. File-level, because
      // the acquisition layer records no line positions — a fabricated line number
      // would be provenance that does not exist.
      evidenceIds: sortedUnique(record.evidenceIds),
      sourcePaths: sortedUnique(record.sourcePaths),
      services: sortedUnique(record.services),
    }))
    .sort(compareByKeys(["from", "to", "type"]));

  const state = architectureGraphState({
    entityCount: entities.length,
    scanComplete: coverage?.scanComplete === true,
    scanTruncated: coverage?.scanTruncated === true,
    hasScanState:
      typeof coverage?.scanComplete === "boolean" && typeof coverage?.scanTruncated === "boolean",
    unestablishedSources: unestablishedSources.length,
  });
  const established = isEstablishedState(state);

  return deepFreeze({
    version: ARCHITECTURE_GRAPH_VERSION,
    state,
    established,
    nodes,
    edges,
    // The one architectural fact whose arity is four (Compose file, service,
    // Dockerfile, context). It cannot be two binary edges without losing which service
    // declared what, so it is carried in full *and* projected into `declares-build` /
    // `build-context` edges for traversal. Both views come from the same observations.
    buildContexts: boundedBuildContexts,
    coverage: {
      state,
      established,
      complete: coverage?.scanComplete === true && coverage?.scanTruncated !== true,
      truncated: coverage?.scanTruncated === true,
      // Counts of what the graph contains, never a claim that the repository has no more.
      nodes: nodes.length,
      edges: edges.length,
      buildContexts: boundedBuildContexts.length,
      // Why the graph is not complete, named file by file: Compose files whose build
      // declarations could not be established. Every such file is a place a
      // relationship could exist and is not known to.
      unestablishedSources: boundedUnestablished,
      limits: ARCHITECTURE_GRAPH_LIMITS,
    },
  });
}
