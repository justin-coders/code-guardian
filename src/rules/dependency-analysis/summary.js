/**
 * Code Guardian — Dependency Analysis Summary (Official Roadmap Phase 15)
 *
 * The analyzer's structured answer to "what does dependency analysis establish?". It is a pure
 * function of the frozen RepositoryModel and the supplied external dataset, so two runs over the
 * same inputs produce the same map — no clock, no random source, no unordered iteration.
 *
 * Each of the eight official domains carries a `state` from the pack's vocabulary plus the
 * domain's measured facts. The external dataset's own state (`absent`/`valid`/`invalid`) is
 * reported separately, so a consumer can see that the outdated and vulnerability domains are
 * `unknown` because the data was missing rather than because the repository was clean.
 *
 * `unknown` is never clean, and `not_applicable` is never used because evidence is missing.
 * Nothing here is a score: there is no dependency grade or percentage.
 */

import {
  DEPENDENCY_ANALYSIS_LIMITS,
  DEPENDENCY_ANALYSIS_STATES,
  DEPENDENCY_INTELLIGENCE_STATES,
} from "./contracts.js";
import {
  advisoriesByPackage,
  readDependencyIntelligence,
  releasesByPackage,
  sourceById,
} from "./intelligence.js";
import {
  dependencyCoverageEstablished,
  dependencyDeclarations,
  dependencyEntities,
  dependencyGraphEstablished,
  dependencyGraphEdges,
  lockfileFacts,
  manifestEntities,
  queryFor,
} from "./signals.js";
import { isReferenced, usageEvidence } from "./usage.js";
import { compareVersions, isComparableEcosystem, satisfiesRange } from "./versions.js";
import { versionInstances } from "./rules/comparison.js";

const STATES = DEPENDENCY_ANALYSIS_STATES;
const INTELLIGENCE = DEPENDENCY_INTELLIGENCE_STATES;

/** The external-versioned domains, summarized from the dataset and the instances. */
function externalDomain(context, query, kind) {
  const intelligence = readDependencyIntelligence(context);
  const instances = versionInstances(query);
  const dependencies = dependencyEntities(query);

  const base = {
    dataState: intelligence.state,
    instances: instances.length,
    reported: 0,
    uncovered: 0,
  };

  if (intelligence.state !== INTELLIGENCE.VALID) {
    return { ...base, state: STATES.UNKNOWN, reason: `external data is "${intelligence.state}"` };
  }
  if (instances.length === 0) {
    return {
      ...base,
      state: dependencies.length === 0 ? STATES.NOT_APPLICABLE : STATES.UNKNOWN,
      reason: dependencies.length === 0 ? null : "no version instance was established",
    };
  }

  const index = kind === "advisory" ? advisoriesByPackage(intelligence) : releasesByPackage(intelligence);
  let reported = 0;
  let uncovered = 0;
  let sources = new Set();

  for (const instance of instances) {
    if (!isComparableEcosystem(instance.ecosystem)) {
      uncovered += 1;
      continue;
    }
    const records = index.get(`${instance.ecosystem}:${instance.name}`);
    if (kind === "advisory") {
      if (records === undefined) continue;
      for (const advisory of records) {
        const satisfied = satisfiesRange(instance.ecosystem, instance.version, advisory.affectedRange);
        if (satisfied === null) uncovered += 1;
        else if (satisfied === true) {
          reported += 1;
          sources.add(advisory.sourceId);
        }
      }
      continue;
    }
    const releases = records ?? [];
    if (releases.length !== 1) {
      uncovered += 1;
      continue;
    }
    const comparison = compareVersions(instance.ecosystem, instance.version, releases[0].latest);
    if (comparison === null) uncovered += 1;
    else if (comparison < 0) {
      reported += 1;
      sources.add(releases[0].sourceId);
    }
  }

  const state = reported > 0 ? STATES.DETECTED : uncovered > 0 ? STATES.UNKNOWN : STATES.ESTABLISHED;
  return {
    ...base,
    state,
    reported,
    uncovered,
    sources: [...sources].sort(),
  };
}

/** Build the dependency-analysis summary for an AnalysisContext. */
export function summarizeDependencyAnalysis(context) {
  const query = queryFor(context);
  const dependencies = dependencyEntities(query);
  const intelligence = readDependencyIntelligence(context);

  const outdated = externalDomain(context, query, "release");
  const vulnerabilities = externalDomain(context, query, "advisory");

  // ── Unused ────────────────────────────────────────────────────────────────
  const usage = usageEvidence(query);
  const nodeDeclarations = dependencyDeclarations(query).filter(
    (declaration) => declaration.ecosystem === "node" && declaration.direct,
  );
  let unusedReported = 0;
  if (usage.complete) {
    for (const declaration of nodeDeclarations) {
      if (!isReferenced(usage, declaration.name)) unusedReported += 1;
    }
  }
  const unused = {
    state: !usage.complete
      ? nodeDeclarations.length === 0
        ? STATES.NOT_APPLICABLE
        : STATES.UNKNOWN
      : unusedReported > 0
        ? STATES.DETECTED
        : STATES.ESTABLISHED,
    importGraphState: usage.state,
    reported: unusedReported,
  };

  // ── Duplicate resolved versions ───────────────────────────────────────────
  const duplicateCandidates = dependencies.filter(
    (dependency) => new Set((dependency.resolutions ?? []).map((entry) => entry.version)).size >= 2,
  );
  const duplicateVersions = {
    state:
      duplicateCandidates.length > 0
        ? STATES.ESTABLISHED
        : dependencies.length === 0
          ? STATES.NOT_APPLICABLE
          : STATES.ESTABLISHED,
    reported: duplicateCandidates.length,
  };

  // ── Concentration ─────────────────────────────────────────────────────────
  const graph = dependencyGraphEstablished(query);
  const edges = graph.established ? dependencyGraphEdges(query) : [];
  const dependentsByNode = new Map();
  for (const edge of edges) {
    const set = dependentsByNode.get(edge.to);
    if (set === undefined) dependentsByNode.set(edge.to, new Set([edge.from]));
    else set.add(edge.from);
  }
  const concentrationThreshold = DEPENDENCY_ANALYSIS_LIMITS.CONCENTRATION_INDEGREE;
  const concentrated = [...dependentsByNode.entries()].filter(
    ([, dependents]) => dependents.size >= concentrationThreshold,
  );
  const concentration = {
    state: !graph.established
      ? STATES.UNKNOWN
      : edges.length === 0
        ? STATES.NOT_APPLICABLE
        : concentrated.length > 0
          ? STATES.DETECTED
          : STATES.ESTABLISHED,
    graphState: graph.state,
    threshold: concentrationThreshold,
    reported: concentrated.length,
  };

  // ── Lockfile integrity ────────────────────────────────────────────────────
  const lockfiles = lockfileFacts(query);
  const nodeLockfiles = lockfiles.filter((lockfile) => lockfile.ecosystem === "node");
  const manifests = manifestEntities(query);
  const coverage = dependencyCoverageEstablished(query);
  const declared = dependencyDeclarations(query);
  const declaredRuntimeByManifest = declared.filter(
    (declaration) => declaration.ecosystem === "node" && declaration.scope === "runtime",
  );
  const resolvedKeys = new Set(
    dependencies
      .filter((dependency) => (dependency.resolutions ?? []).length > 0)
      .map((dependency) => `${dependency.ecosystem}\u0000${dependency.name}`),
  );
  const unresolvedDeclarations = declared.filter(
    (declaration) =>
      declaration.ecosystem === "node" &&
      declaration.direct &&
      !resolvedKeys.has(`${declaration.ecosystem}\u0000${declaration.name}`),
  );
  const nodeManifests = manifests.filter(
    (manifest) => manifest.manifestKind === "manifest" && manifest.ecosystemId === "ecosystem:node",
  );
  const missingLockfile =
    nodeLockfiles.length === 0 &&
    nodeManifests.some(
      (manifest) => declaredRuntimeByManifest.some((declaration) => declaration.manifestPath === manifest.path),
    );
  const integrityConditions = [
    ...(missingLockfile ? ["lockfile-missing"] : []),
    ...(nodeLockfiles.length > 0 && unresolvedDeclarations.length > 0 ? ["declaration-unresolved"] : []),
  ];
  const lockfileIntegrity = {
    state:
      integrityConditions.length > 0
        ? STATES.DETECTED
        : !coverage.established
          ? STATES.UNKNOWN
          : declared.length === 0
            ? STATES.NOT_APPLICABLE
            : STATES.ESTABLISHED,
    conditions: integrityConditions,
    lockfiles: lockfiles.length,
  };

  // ── Package manager consistency ───────────────────────────────────────────
  const managersByEcosystem = new Map();
  for (const lockfile of lockfiles) {
    if (lockfile.manager === null || lockfile.ecosystem === null) continue;
    const set = managersByEcosystem.get(lockfile.ecosystem);
    if (set === undefined) managersByEcosystem.set(lockfile.ecosystem, new Set([lockfile.manager]));
    else set.add(lockfile.manager);
  }
  const conflictingEcosystems = [...managersByEcosystem.entries()]
    .filter(([, managers]) => managers.size >= 2)
    .map(([ecosystem, managers]) => ({ ecosystem, managers: [...managers].sort() }));
  const managerConsistency = {
    state:
      lockfiles.length === 0
        ? STATES.NOT_APPLICABLE
        : conflictingEcosystems.length > 0
          ? STATES.DETECTED
          : STATES.ESTABLISHED,
    managers: [...managersByEcosystem.entries()]
      .map(([ecosystem, managers]) => ({ ecosystem, managers: [...managers].sort() }))
      .sort((a, b) => (a.ecosystem < b.ecosystem ? -1 : 1)),
    conflicting: conflictingEcosystems,
  };

  // ── Supply-chain indicators ───────────────────────────────────────────────
  const unusual = declared.filter((declaration) =>
    ["git", "url", "alias"].includes(declaration.specKind),
  );
  const supplyChain = {
    state:
      unusual.length > 0
        ? STATES.DETECTED
        : declared.length === 0
          ? STATES.NOT_APPLICABLE
          : coverage.established
            ? STATES.ESTABLISHED
            : STATES.UNKNOWN,
    reported: unusual.length,
  };

  const coverageBasis = {
    dependencies: dependencies.length,
    declarations: declared.length,
    lockfiles: lockfiles.length,
    dependencyAcquisitionComplete: coverage.established,
    dependencyGraphState: graph.state,
    intelligenceState: intelligence.state,
  };

  return Object.freeze({
    coverageBasis: Object.freeze(coverageBasis),
    outdated: Object.freeze(outdated),
    vulnerabilities: Object.freeze(vulnerabilities),
    unused: Object.freeze(unused),
    duplicateVersions: Object.freeze(duplicateVersions),
    concentration: Object.freeze(concentration),
    lockfileIntegrity: Object.freeze(lockfileIntegrity),
    managerConsistency: Object.freeze(managerConsistency),
    supplyChain: Object.freeze(supplyChain),
  });
}
