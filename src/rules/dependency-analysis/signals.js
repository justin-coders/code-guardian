/**
 * Code Guardian — Dependency Analysis Repository Signals (Official Roadmap Phase 15)
 *
 * The one place the dependency-analysis rules ask the repository questions. Every read goes
 * through the Phase 11 query API over the frozen RepositoryModel: no filesystem, no lockfile
 * parsing, no package manager, no registry, no network, no process. A rule that cannot answer
 * from the model reports `unknown` rather than going to look for itself.
 *
 * ### What this module reuses instead of rebuilding
 *
 * The dependency substrate already established the facts every domain needs:
 *
 *   `query.listDependencies()`          declarations, resolutions, scopes, directness
 *   `query.dependencyGraph()`           lockfile-stated `depends-on` relationships
 *   `query.dependencyCoverage()`        what acquisition established, and what stopped it
 *   `query.dependencyGraphCoverage()`   the graph's five-way state and its version limitation
 *   `query.listEntities("manifest")`    manifests and lockfiles (with their basenames)
 *
 * Nothing here re-parses a manifest, re-derives an edge or promotes a lockfile relationship to a
 * declaration. The distinction the substrate keeps — declaration vs resolution vs relationship —
 * is preserved all the way into the findings.
 */

import {
  ENTITY_KINDS,
  DEPENDENCY_GRAPH_STATES,
  createRepositoryQuery,
  stabilityHash,
} from "../../repository/model/index.js";

import { PACKAGE_MANAGER_BY_LOCKFILE } from "./contracts.js";

/** Build the read-only query handle for an AnalysisContext. */
export function queryFor(context) {
  return createRepositoryQuery(context.repository);
}

/** Every dependency entity, in id order. */
export function dependencyEntities(query) {
  return query.listDependencies().entities;
}

/**
 * Every declaration the repository's manifests made, flattened with provenance.
 *
 * Sorted by `(manifestPath, ecosystem, name)` so the order never depends on entity id order.
 */
export function dependencyDeclarations(query) {
  const declarations = [];
  for (const dependency of dependencyEntities(query)) {
    for (const declaration of dependency.declarations ?? []) {
      declarations.push({
        dependencyId: dependency.id,
        ecosystem: dependency.ecosystem,
        name: dependency.name,
        manifestId: declaration.manifestId,
        manifestPath: declaration.manifestPath,
        scope: declaration.scope,
        spec: declaration.spec ?? null,
        specKind: declaration.specKind,
        direct: declaration.direct === true,
        conditional: declaration.conditional === true,
        evidenceIds: [...(declaration.evidenceIds ?? [])],
      });
    }
  }
  return declarations.sort(compareDeclarations);
}

/**
 * Every resolution a lockfile established, flattened with provenance.
 *
 * A resolution is a *resolved version* — never inferred from a declared range. Sorted by
 * `(manifestPath, ecosystem, name, version)`.
 */
export function dependencyResolutions(query) {
  const resolutions = [];
  for (const dependency of dependencyEntities(query)) {
    for (const resolution of dependency.resolutions ?? []) {
      resolutions.push({
        dependencyId: dependency.id,
        ecosystem: dependency.ecosystem,
        name: dependency.name,
        manifestId: resolution.manifestId,
        manifestPath: resolution.manifestPath,
        version: resolution.version,
        evidenceIds: [...(resolution.evidenceIds ?? [])],
      });
    }
  }
  return resolutions.sort((a, b) => {
    if (a.manifestPath !== b.manifestPath) return a.manifestPath < b.manifestPath ? -1 : 1;
    if (a.ecosystem !== b.ecosystem) return a.ecosystem < b.ecosystem ? -1 : 1;
    if (a.name !== b.name) return a.name < b.name ? -1 : 1;
    return a.version < b.version ? -1 : a.version > b.version ? 1 : 0;
  });
}

function compareDeclarations(a, b) {
  if (a.manifestPath !== b.manifestPath) return a.manifestPath < b.manifestPath ? -1 : 1;
  if (a.ecosystem !== b.ecosystem) return a.ecosystem < b.ecosystem ? -1 : 1;
  if (a.name === b.name) return 0;
  return a.name < b.name ? -1 : 1;
}

/** Every dependency relationship a lockfile recorded, with provenance. */
export function dependencyGraphEdges(query) {
  const graph = query.dependencyGraph();
  const nodeById = new Map(graph.nodes.map((node) => [node.id, node]));
  const edges = [];
  for (const edge of graph.edges) {
    const from = nodeById.get(edge.from);
    const to = nodeById.get(edge.to);
    edges.push({
      from: edge.from,
      fromName: from?.name ?? null,
      to: edge.to,
      toName: to?.name ?? null,
      ecosystem: from?.ecosystem ?? to?.ecosystem ?? null,
      type: edge.type,
      evidenceIds: [...(edge.evidenceIds ?? [])],
      manifestPaths: [...(edge.manifestPaths ?? [])],
      fingerprintKey: `edge:${stabilityHash(`${edge.from}|${edge.to}|${edge.type}`)}`,
    });
  }
  return edges.sort((a, b) => {
    if (a.from !== b.from) return a.from < b.from ? -1 : 1;
    if (a.to !== b.to) return a.to < b.to ? -1 : 1;
    return a.type < b.type ? -1 : a.type > b.type ? 1 : 0;
  });
}

/** What dependency acquisition established, and every source that stopped it. */
export function dependencyAcquisitionCoverage(query) {
  return query.dependencyCoverage();
}

/** The dependency graph's own coverage statement. */
export function dependencyGraphCoverage(query) {
  return query.dependencyGraphCoverage();
}

/** Every manifest entity (manifests and lockfiles), in id order. */
export function manifestEntities(query) {
  return query.listEntities(ENTITY_KINDS.MANIFEST).entities;
}

/** The basename of a repository-relative path (POSIX, no `node:path`). */
export function basenameOf(path) {
  const parts = String(path ?? "").split("/");
  return parts.length === 0 ? "" : parts[parts.length - 1];
}

/**
 * Every lockfile the inventory observed, with the package manager it names.
 *
 * Manager identity comes from the basename through a closed map: a lockfile this build has no
 * entry for establishes no manager identity (it is still reported, with `manager: null`), so a
 * rule never guesses a manager from a file name it does not recognize.
 */
export function lockfileFacts(query) {
  const lockfiles = [];
  for (const manifest of manifestEntities(query)) {
    if (manifest.manifestKind !== "lockfile") continue;
    const basename = basenameOf(manifest.path);
    lockfiles.push({
      id: manifest.id,
      path: manifest.path,
      basename,
      ecosystem: (manifest.ecosystemId ?? "").replace(/^ecosystem:/, "") || null,
      manager: PACKAGE_MANAGER_BY_LOCKFILE[basename] ?? null,
      evidenceIds: [...(manifest.evidenceIds ?? [])],
    });
  }
  lockfiles.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return lockfiles;
}

/**
 * Whether dependency acquisition covers the repository completely enough for an absence claim.
 *
 * Mirrors the substrate's own `dependencyAbsence`: the acquisition must be complete, no
 * dependency source may be unestablished, and the scan itself must have covered the repository.
 */
export function dependencyCoverageEstablished(query) {
  const coverage = dependencyAcquisitionCoverage(query);
  const inventory = query.coverage();
  const reasons = [];
  if (coverage.complete !== true) reasons.push("dependency acquisition is not complete");
  if ((coverage.unestablishedSources ?? []).length > 0) {
    reasons.push(`${coverage.unestablishedSources.length} dependency source(s) were not fully interpreted`);
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
  });
}

/** Whether the dependency graph is established and complete (an absence claim is supported). */
export function dependencyGraphEstablished(query) {
  const graph = dependencyGraphCoverage(query);
  const inventory = query.coverage();
  const reasons = [];
  if (graph.established !== true) {
    reasons.push(
      graph.state === DEPENDENCY_GRAPH_STATES.UNSUPPORTED
        ? "no dependency source uses a format this build interprets"
        : "dependency acquisition did not establish a graph",
    );
  } else if (graph.state !== DEPENDENCY_GRAPH_STATES.COMPLETE) {
    reasons.push("dependency acquisition interpreted only part of the repository's dependency sources");
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
