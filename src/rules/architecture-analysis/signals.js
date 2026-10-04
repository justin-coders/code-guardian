/**
 * Code Guardian — Architecture Analysis Repository Signals (Official Roadmap Phase 14)
 *
 * The one place the architecture-analysis rules ask the repository questions. Every read goes
 * through the Phase 11 query API over the frozen RepositoryModel: no filesystem, no
 * `node:path`, no source parsing, no AST, no process, no clock. A rule that cannot answer a
 * question from the model reports `unknown` rather than going to look for itself.
 *
 * ### The module graph, and why it is evidence and not directory naming
 *
 * An architectural **module** here is a directory the repository's own observed structure
 * establishes as a container of *module sources* — files the import graph actually read. A
 * module exists because the import graph established at least one source file inside it, never
 * because a directory is named `services` or `controllers`. Excluded entirely: a directory with
 * no module source (a docs folder, an assets folder) is not a module, and a name is never read.
 *
 * A **module edge** `A → B` exists only because at least one file in `A` states an import the
 * resolver established as a file in `B`. The edge keeps the underlying file-level import edges
 * and their observations, so a finding can always answer "why did Code Guardian report this?".
 *
 * ### Coverage is carried, never collapsed
 *
 * An empty module graph is only an all-clear when the import graph was actually *complete*. The
 * graph's own five-way state is carried on every result, so a `partial` or `truncated` graph
 * makes a "no cycle" or "no coupling" answer `unknown` instead of a false clean.
 *
 * ### Determinism
 *
 * Modules are sorted by path; edges by `(from, to)`; evidence and source paths de-duplicated and
 * sorted. Nothing here reads the clock, the environment, the filesystem or a random source, and
 * no input is iterated in insertion order.
 */

import {
  ENTITY_KINDS,
  IMPORT_GRAPH_STATES,
  createRepositoryQuery,
} from "../../repository/model/index.js";

import { LOCAL_PACKAGE_SPEC_KINDS, ROOT_MODULE_PATH } from "./contracts.js";

/** Build the read-only query handle for an AnalysisContext. */
export function queryFor(context) {
  return createRepositoryQuery(context.repository);
}

/** Whether an import-graph state means the graph was established at all. */
export function isEstablishedImportState(state) {
  return (
    state === IMPORT_GRAPH_STATES.COMPLETE ||
    state === IMPORT_GRAPH_STATES.PARTIAL ||
    state === IMPORT_GRAPH_STATES.TRUNCATED
  );
}

/** The repository-relative directory of a path ('' for a root-level file). */
export function modulePathOf(path) {
  const text = typeof path === "string" ? path : "";
  const slash = text.lastIndexOf("/");
  return slash === -1 ? "" : text.slice(0, slash);
}

/** The display label of a module path. */
export function moduleLabelOf(modulePath) {
  return modulePath === "" ? ROOT_MODULE_PATH : modulePath;
}

/**
 * Whether a module path lies inside a package root.
 *
 * A declared dependency names a *package* (its manifest directory), while the module graph is
 * keyed by the directory that actually holds the module sources (`packages/a/src` versus
 * `packages/a`). This is the comparison that connects the two granularities: the empty string is
 * the repository root, which every path is under.
 *
 * @param {string} modulePath
 * @param {string} root
 * @returns {boolean}
 */
export function isUnder(modulePath, root) {
  if (root === "") return true;
  return modulePath === root || modulePath.startsWith(`${root}/`);
}

/** The repository-relative path behind a `file:<path>` node id, or `null`. */
function pathOfNodeId(id) {
  if (typeof id !== "string" || !id.startsWith("file:")) return null;
  return id.slice("file:".length);
}

function sortedUnique(values) {
  return [...new Set(values)].sort();
}

function byPath(a, b) {
  return a.path < b.path ? -1 : a.path > b.path ? 1 : 0;
}

function byFromTo(a, b) {
  if (a.from !== b.from) return a.from < b.from ? -1 : 1;
  if (a.to !== b.to) return a.to < b.to ? -1 : 1;
  return 0;
}

/**
 * Build the module graph over the import graph.
 *
 * @param {object} query A repository query handle.
 * @returns {object} Frozen
 *   `{ established, complete, truncated, state, modules, edges, moduleByPath, evidenceByModule }`.
 */
export function buildModuleGraph(query) {
  const graph = query.importGraph();
  const state = graph.state;
  const established = graph.established === true;
  const complete = state === IMPORT_GRAPH_STATES.COMPLETE;
  const truncated = state === IMPORT_GRAPH_STATES.TRUNCATED;

  const files = query.listEntities(ENTITY_KINDS.FILE).entities;
  const evidenceByPath = new Map(files.map((file) => [file.path, sortedUnique(file.evidenceIds ?? [])]));

  // ── Module membership ─────────────────────────────────────────────────────
  // A module is established by a module *source* the import graph read, never by a
  // directory the scan walked past.
  const membersByModule = new Map();
  for (const node of graph.nodes ?? []) {
    if (node.module !== true || typeof node.path !== "string") continue;
    const modulePath = modulePathOf(node.path);
    const set = membersByModule.get(modulePath);
    if (set === undefined) membersByModule.set(modulePath, new Set([node.path]));
    else set.add(node.path);
  }

  // ── Declarations, when the symbol graph establishes them ──────────────────
  const symbolGraph = query.symbolGraph();
  const declarationsComplete = symbolGraph.established === true;
  const declarationsByFile = new Map();
  for (const node of symbolGraph.nodes ?? []) {
    if (typeof node.path !== "string") continue;
    declarationsByFile.set(node.path, (declarationsByFile.get(node.path) ?? 0) + 1);
  }

  const modules = [...membersByModule.entries()]
    .map(([path, memberSet]) => {
      const filesInModule = [...memberSet].sort();
      let declarations = 0;
      for (const filePath of filesInModule) declarations += declarationsByFile.get(filePath) ?? 0;
      return {
        path,
        label: moduleLabelOf(path),
        files: filesInModule,
        fileCount: filesInModule.length,
        declarations,
        declarationsComplete,
      };
    })
    .sort(byPath);

  const modulePaths = new Set(modules.map((module) => module.path));

  // ── Module edges and per-module connectivity ──────────────────────────────
  const edgeRecords = new Map();
  const internalByModule = new Map();
  const outgoingByModule = new Map();
  const incomingByModule = new Map();

  for (const edge of graph.edges ?? []) {
    const fromPath = pathOfNodeId(edge.from);
    const toPath = pathOfNodeId(edge.to);
    if (fromPath === null || toPath === null) continue;
    const fromModule = modulePathOf(fromPath);
    const toModule = modulePathOf(toPath);
    if (!modulePaths.has(fromModule) || !modulePaths.has(toModule)) continue;

    if (fromModule === toModule) {
      internalByModule.set(fromModule, (internalByModule.get(fromModule) ?? 0) + 1);
      continue;
    }

    outgoingByModule.set(fromModule, (outgoingByModule.get(fromModule) ?? 0) + 1);
    incomingByModule.set(toModule, (incomingByModule.get(toModule) ?? 0) + 1);

    const key = `${fromModule}\u0000${toModule}`;
    let record = edgeRecords.get(key);
    if (record === undefined) {
      record = { from: fromModule, to: toModule, evidenceIds: new Set(), sourcePaths: new Set(), fileEdges: [] };
      edgeRecords.set(key, record);
    }
    for (const id of edge.evidenceIds ?? []) record.evidenceIds.add(id);
    for (const sourcePath of edge.sourcePaths ?? []) record.sourcePaths.add(sourcePath);
    record.fileEdges.push({ from: fromPath, to: toPath });
  }

  const edges = [...edgeRecords.values()]
    .map((record) => ({
      from: record.from,
      to: record.to,
      count: record.fileEdges.length,
      evidenceIds: [...record.evidenceIds].sort(),
      sourcePaths: [...record.sourcePaths].sort(),
      fileEdges: record.fileEdges
        .slice()
        .sort((a, b) => (a.from < b.from ? -1 : a.from > b.from ? 1 : a.to < b.to ? -1 : a.to > b.to ? 1 : 0)),
    }))
    .sort(byFromTo);

  const outgoingModules = new Map();
  const incomingModules = new Map();
  for (const edge of edges) {
    if (!outgoingModules.has(edge.from)) outgoingModules.set(edge.from, new Set());
    outgoingModules.get(edge.from).add(edge.to);
    if (!incomingModules.has(edge.to)) incomingModules.set(edge.to, new Set());
    incomingModules.get(edge.to).add(edge.from);
  }

  const augmented = modules.map((module) => ({
    ...module,
    evidenceIds: sortedUnique(module.files.flatMap((filePath) => evidenceByPath.get(filePath) ?? [])),
    internalEdges: internalByModule.get(module.path) ?? 0,
    outgoingEdges: outgoingByModule.get(module.path) ?? 0,
    incomingEdges: incomingByModule.get(module.path) ?? 0,
    outgoingModuleCount: (outgoingModules.get(module.path) ?? new Set()).size,
    incomingModuleCount: (incomingModules.get(module.path) ?? new Set()).size,
  }));

  return Object.freeze({
    established,
    complete,
    truncated,
    state,
    modules: Object.freeze(augmented.map((module) => Object.freeze({ ...module, files: Object.freeze([...module.files]), evidenceIds: Object.freeze([...module.evidenceIds]) }))),
    edges: Object.freeze(edges.map((edge) => Object.freeze({ ...edge, evidenceIds: Object.freeze([...edge.evidenceIds]), sourcePaths: Object.freeze([...edge.sourcePaths]), fileEdges: Object.freeze(edge.fileEdges.map((f) => Object.freeze(f))) }))),
  });
}

/**
 * The direction the repository *declares* between its own local packages.
 *
 * A `workspace:`/`file:`/`link:` dependency declaration is a manifest stating that one package
 * depends on another; when the referenced package is one this repository defines (a manifest
 * whose own metadata names it), that is a repository-**declared** direction between two local
 * modules. This is the only layer/direction model this build tests against: nothing here
 * imposes a stereotype, and a repository that declares no local dependency direction simply has
 * no model to test (see the layer rule).
 *
 * @param {object} query A repository query handle.
 * @returns {object[]} Frozen rows `{from, to, dependencyName, specKind, evidenceIds}`, sorted.
 */
export function declaredLocalDirections(query) {
  const manifests = query.listEntities(ENTITY_KINDS.MANIFEST).entities;
  const moduleByName = new Map();
  for (const manifest of manifests) {
    const name = manifest.parse?.metadata?.name;
    if (typeof name !== "string" || name === "") continue;
    moduleByName.set(name, modulePathOf(manifest.path));
  }

  const rows = [];
  for (const dependency of query.listEntities(ENTITY_KINDS.DEPENDENCY).entities) {
    if (typeof dependency.name !== "string") continue;
    const targetModule = moduleByName.get(dependency.name);
    if (targetModule === undefined) continue;
    for (const declaration of dependency.declarations ?? []) {
      if (!LOCAL_PACKAGE_SPEC_KINDS.includes(declaration.specKind)) continue;
      const from = modulePathOf(declaration.manifestPath);
      if (from === targetModule) continue;
      rows.push({
        from,
        to: targetModule,
        dependencyName: dependency.name,
        specKind: declaration.specKind,
        evidenceIds: sortedUnique(declaration.evidenceIds ?? []),
      });
    }
  }

  // De-duplicate identical declared directions, then order deterministically.
  const unique = new Map();
  for (const row of rows) {
    const key = `${row.from}\u0000${row.to}\u0000${row.dependencyName}`;
    if (!unique.has(key)) unique.set(key, row);
  }

  return Object.freeze(
    [...unique.values()].sort((a, b) => {
      if (a.from !== b.from) return a.from < b.from ? -1 : 1;
      if (a.to !== b.to) return a.to < b.to ? -1 : 1;
      return a.dependencyName < b.dependencyName ? -1 : a.dependencyName > b.dependencyName ? 1 : 0;
    }).map((row) => Object.freeze({ ...row, evidenceIds: Object.freeze([...row.evidenceIds]) })),
  );
}

/**
 * The facts a conservative architecture-pattern claim can rest on.
 *
 * A pattern needs *multiple independent* pieces of evidence. For the one pattern this build
 * establishes — a workspace monorepo — that is: a manifest that declares `workspaces`, **and**
 * at least two distinct sub-directories each declaring its own named package. One of those
 * facts alone establishes nothing, which is exactly what the ambiguous fixture checks.
 *
 * @param {object} query A repository query handle.
 * @returns {object} Frozen `{manifestCount, workspacesDeclared, workspacesDeclaredBy, named}`.
 */
export function workspacePatternFacts(query) {
  const manifests = query.listEntities(ENTITY_KINDS.MANIFEST).entities;
  const workspacesDeclaredBy = [];
  const named = [];

  for (const manifest of manifests) {
    const metadata = manifest.parse?.metadata ?? null;
    if (metadata?.workspaces === true) {
      workspacesDeclaredBy.push({
        path: manifest.path,
        evidenceIds: sortedUnique(manifest.evidenceIds ?? []),
      });
    }
    const name = metadata?.name;
    if (typeof name !== "string" || name === "") continue;
    named.push({
      path: manifest.path,
      module: modulePathOf(manifest.path),
      name,
      evidenceIds: sortedUnique(manifest.evidenceIds ?? []),
    });
  }

  named.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  workspacesDeclaredBy.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  return Object.freeze({
    manifestCount: manifests.length,
    workspacesDeclared: workspacesDeclaredBy.length > 0,
    workspacesDeclaredBy: Object.freeze(
      workspacesDeclaredBy.map((entry) => Object.freeze({ ...entry, evidenceIds: Object.freeze([...entry.evidenceIds]) })),
    ),
    named: Object.freeze(named.map((entry) => Object.freeze({ ...entry, evidenceIds: Object.freeze([...entry.evidenceIds]) }))),
  });
}

/**
 * The union of model evidence behind a set of repository-relative file paths.
 *
 * @param {object} query
 * @param {string[]} paths
 * @returns {string[]} Sorted, de-duplicated evidence ids.
 */
export function evidenceForPaths(query, paths) {
  const ids = new Set();
  for (const path of paths) {
    const result = query.getEvidenceForEntity(`${ENTITY_KINDS.FILE}:${path}`);
    for (const record of result.evidence ?? []) {
      if (typeof record?.id === "string") ids.add(record.id);
    }
  }
  return [...ids].sort();
}
