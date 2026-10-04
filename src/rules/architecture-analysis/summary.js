/**
 * Code Guardian — Architecture Analysis Summary (Official Roadmap Phase 14)
 *
 * The analyzer's structured answer to "what architecture does this repository establish?". It is
 * a pure function of the frozen RepositoryModel, so two runs over the same model produce the same
 * map — no clock, no random source, no unordered iteration.
 *
 * Each of the nine official domains carries a `state` drawn from the pack's vocabulary plus the
 * domain's own measured facts:
 *
 *   established     the repository establishes the subject the domain reports
 *   detected        an indicator was observed (a large module, a cohesion shape)
 *   unknown         the domain applies but the evidence does not establish the answer — an
 *                   incomplete import graph, or no repository-declared layer model
 *   not_applicable  the domain genuinely has no subject over established coverage
 *
 * `unknown` is never clean, and `not_applicable` is never used because evidence is missing.
 * Nothing here is a score: there is no aggregate architecture grade or percentage.
 */

import {
  ARCHITECTURE_ANALYSIS_LIMITS,
  ARCHITECTURE_ANALYSIS_STATES,
  ARCHITECTURE_PATTERNS,
} from "./contracts.js";
import { findModuleCycles, isEntryFile } from "./graph.js";
import {
  buildModuleGraph,
  declaredLocalDirections,
  isUnder,
  queryFor,
  workspacePatternFacts,
} from "./signals.js";

const STATES = ARCHITECTURE_ANALYSIS_STATES;
const LIMITS = ARCHITECTURE_ANALYSIS_LIMITS;

/** The state of a graph-shaped domain when the import graph was not established. */
function graphState(established, complete, subjectPresent) {
  if (!established) return STATES.UNKNOWN;
  if (subjectPresent) return STATES.ESTABLISHED;
  return complete ? STATES.NOT_APPLICABLE : STATES.UNKNOWN;
}

/** The declared-direction violations, the same way the layer rule reads them. */
function layerViolations(graph, declared) {
  const violations = [];
  for (const edge of graph.edges) {
    for (const direction of declared) {
      const forward = isUnder(edge.from, direction.from) && isUnder(edge.to, direction.to);
      const reverse = isUnder(edge.from, direction.to) && isUnder(edge.to, direction.from);
      if (reverse && !forward) {
        violations.push({ from: edge.from, to: edge.to, dependency: direction.dependencyName });
        break;
      }
    }
  }
  return violations;
}

/** The published boundaries and leaks, the same way the leakage rule reads them. */
function boundaryLeakage(graph) {
  const entryFilesByModule = new Map();
  for (const module of graph.modules) {
    const entries = module.files.filter((path) => isEntryFile(path));
    if (entries.length > 0) entryFilesByModule.set(module.path, new Set(entries));
  }
  const boundaries = new Set();
  for (const edge of graph.edges) {
    for (const fileEdge of edge.fileEdges) {
      const entries = entryFilesByModule.get(edge.to);
      if (entries !== undefined && entries.has(fileEdge.to)) boundaries.add(edge.to);
    }
  }
  const leaks = [];
  for (const edge of graph.edges) {
    if (!boundaries.has(edge.to)) continue;
    const entries = entryFilesByModule.get(edge.to) ?? new Set();
    let leaked = 0;
    for (const fileEdge of edge.fileEdges) if (!entries.has(fileEdge.to)) leaked += 1;
    if (leaked > 0) leaks.push({ from: edge.from, to: edge.to, leaked });
  }
  return { boundaries: boundaries.size, leaks };
}

/**
 * Build the architecture summary for an AnalysisContext.
 *
 * @param {object} context A validated AnalysisContext.
 * @returns {object} Frozen summary with one entry per roadmap domain.
 */
export function summarizeArchitecture(context) {
  const query = queryFor(context);
  const graph = buildModuleGraph(query);
  const modules = graph.modules;
  const edges = graph.edges;
  const declared = declaredLocalDirections(query);
  const patterns = workspacePatternFacts(query);

  const complete = graph.complete;
  const established = graph.established;

  // ── Module boundaries ─────────────────────────────────────────────────────
  const moduleBoundaries = {
    state: !established
      ? STATES.UNKNOWN
      : modules.length > 0
        ? STATES.ESTABLISHED
        : complete
          ? STATES.NOT_APPLICABLE
          : STATES.UNKNOWN,
    modules: modules.map((module) => module.label),
    count: modules.length,
  };

  // ── Dependency direction ──────────────────────────────────────────────────
  const dependencyDirection = {
    state: graphState(established, complete, edges.length > 0),
    directions: edges.map((edge) => ({ from: edge.from, to: edge.to, count: edge.count })),
    count: edges.length,
  };

  // ── Circular dependencies ─────────────────────────────────────────────────
  const cycles = established ? findModuleCycles(graph) : [];
  const circularDependencies = {
    state: graphState(established, complete, cycles.length > 0),
    cycles: cycles.map((component) => [...component]),
    count: cycles.length,
  };

  // ── Layer violations ──────────────────────────────────────────────────────
  const violations = established ? layerViolations(graph, declared) : [];
  const layerViolationsEntry = {
    state: !established
      ? STATES.UNKNOWN
      : declared.length === 0
        ? STATES.UNKNOWN
        : STATES.ESTABLISHED,
    model: declared.length === 0 ? "not-established" : "declared-local-package-direction",
    declaredDirections: declared.map((direction) => ({
      from: direction.from,
      to: direction.to,
      dependency: direction.dependencyName,
      specKind: direction.specKind,
    })),
    violations,
    count: violations.length,
  };

  // ── Coupling ──────────────────────────────────────────────────────────────
  const couplingThreshold = LIMITS.COUPLING_OUTGOING;
  const coupled = modules.filter((module) => module.outgoingModuleCount >= couplingThreshold);
  const coupling = {
    state: !established
      ? STATES.UNKNOWN
      : coupled.length > 0
        ? STATES.DETECTED
        : complete
          ? STATES.NOT_APPLICABLE
          : STATES.UNKNOWN,
    threshold: couplingThreshold,
    modules: coupled.map((module) => module.label),
    count: coupled.length,
  };

  // ── Cohesion indicators ───────────────────────────────────────────────────
  const cohesionMinMembers = LIMITS.COHESION_MIN_MEMBERS;
  const lowCohesion = modules.filter(
    (module) =>
      module.fileCount >= cohesionMinMembers &&
      module.internalEdges === 0 &&
      module.outgoingModuleCount + module.incomingModuleCount > 0,
  );
  const cohesion = {
    state: !established
      ? STATES.UNKNOWN
      : lowCohesion.length > 0
        ? STATES.DETECTED
        : modules.length > 0
          ? STATES.NOT_APPLICABLE
          : complete
            ? STATES.NOT_APPLICABLE
            : STATES.UNKNOWN,
    minMembers: cohesionMinMembers,
    modules: lowCohesion.map((module) => module.label),
    count: lowCohesion.length,
  };

  // ── Large modules ─────────────────────────────────────────────────────────
  const fileThreshold = LIMITS.LARGE_MODULE_FILES;
  const declarationThreshold = LIMITS.LARGE_MODULE_DECLARATIONS;
  const large = modules.filter(
    (module) =>
      module.fileCount >= fileThreshold ||
      (module.declarationsComplete && module.declarations >= declarationThreshold),
  );
  const largeModules = {
    state: !established
      ? STATES.UNKNOWN
      : large.length > 0
        ? STATES.DETECTED
        : modules.length > 0
          ? STATES.NOT_APPLICABLE
          : complete
            ? STATES.NOT_APPLICABLE
            : STATES.UNKNOWN,
    fileThreshold,
    declarationThreshold,
    modules: large.map((module) => module.label),
    count: large.length,
  };

  // ── Boundary leakage ──────────────────────────────────────────────────────
  const leakage = established ? boundaryLeakage(graph) : { boundaries: 0, leaks: [] };
  const boundaryLeakageEntry = {
    state: !established
      ? STATES.UNKNOWN
      : leakage.leaks.length > 0
        ? STATES.ESTABLISHED
        : leakage.boundaries > 0 || complete
          ? STATES.NOT_APPLICABLE
          : STATES.UNKNOWN,
    boundaries: leakage.boundaries,
    leaks: leakage.leaks,
    count: leakage.leaks.length,
  };

  // ── Architecture patterns ─────────────────────────────────────────────────
  const namedModules = [...new Set(patterns.named.map((entry) => entry.module))].sort();
  const workspaceEstablished = patterns.workspacesDeclared && namedModules.length >= 2;
  const architecturePatterns = {
    state:
      patterns.manifestCount === 0
        ? STATES.NOT_APPLICABLE
        : workspaceEstablished
          ? STATES.ESTABLISHED
          : STATES.UNKNOWN,
    patterns: workspaceEstablished ? [ARCHITECTURE_PATTERNS.WORKSPACE_MONOREPO] : [],
    manifests: patterns.manifestCount,
  };

  const coverageBasis = {
    importGraphState: graph.state,
    complete,
    truncated: graph.truncated,
    modules: modules.length,
    edges: edges.length,
    declaredDirections: declared.length,
    manifests: patterns.manifestCount,
  };

  return Object.freeze({
    coverageBasis: Object.freeze(coverageBasis),
    moduleBoundaries: Object.freeze(moduleBoundaries),
    dependencyDirection: Object.freeze(dependencyDirection),
    circularDependencies: Object.freeze(circularDependencies),
    layerViolations: Object.freeze(layerViolationsEntry),
    coupling: Object.freeze(coupling),
    cohesion: Object.freeze(cohesion),
    largeModules: Object.freeze(largeModules),
    boundaryLeakage: Object.freeze(boundaryLeakageEntry),
    architecturePatterns: Object.freeze(architecturePatterns),
  });
}
