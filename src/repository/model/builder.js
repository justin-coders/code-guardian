/**
 * Code Guardian — RepositoryModel Builder (Phase 8D)
 *
 * `buildRepositoryModel(scanResult)` is the whole public entry point of this
 * phase, and it is a **pure transformation of a validated `ScanResult`**:
 *
 *     Repository  →  Phase 8A filesystem boundary  →  Phase 8C scanner
 *                 →  ScanResult  →  [this builder]  →  RepositoryModel
 *
 * The builder never touches the filesystem, never spawns a process, never
 * resolves a dependency, and never consults a clock. It does not rescan: the
 * scanner's observations are the only input, so the model can never disagree with
 * the scan that produced it, and building a model is cheap enough to repeat.
 *
 * Steps, in order:
 *
 *   1. validate the ScanResult (scanner contract — malformed input fails here);
 *   2. derive the repository identity from the observed inventory;
 *   3. build entities and their observations (rejecting anything incoherent);
 *   4. derive relationships from those entities;
 *   5. derive the lookup indexes;
 *   6. assemble the Core-shaped model, preserving completeness state;
 *   7. deep-freeze it (an analyzer cannot corrupt a shared model);
 *   8. validate graph invariants, then the Core contract.
 *
 * Steps 3 and 8 are fail-closed: a ScanResult that contradicts itself, or a
 * builder regression, produces a `ValidationError` rather than a model that is
 * subtly wrong. "Subtly wrong" is the one outcome a security analyzer must never
 * be handed.
 */

import {
  REPOSITORY_MODEL_VERSION,
  createRepositoryModel,
  validateRepositoryModel,
} from "../../core/index.js";

import { validateScanResult } from "../scanner/index.js";

import {
  MODEL_IMMUTABILITY,
  REPOSITORY_MODEL_BUILDER,
  REPOSITORY_MODEL_BUILDER_VERSION,
  validateRepositoryModelGraph,
} from "./contracts.js";
import { buildArchitectureGraph } from "./architecture-graph.js";
import { buildEntities } from "./entities.js";
import { buildDependencyGraph } from "./dependency-graph.js";
import { buildIndexes, buildRelationships } from "./graph.js";
import { repositoryId as repositoryIdOf } from "./identity.js";
import { COVERAGE_GUARANTEES } from "./query.js";
import { requireRepositoryRelativePath } from "./paths.js";

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const key of Object.keys(value)) deepFreeze(value[key]);
  return value;
}

/**
 * Build the coverage statement.
 *
 * This is where 8C's distinctions are preserved rather than flattened: ignored
 * paths (policy), unreadable paths (I/O failure) and truncation (limits) are
 * reported separately, and the overall guarantee is `partial` unless the scan
 * actually completed. `unknown` coverage is therefore never silently reported as
 * "empty".
 */
function buildCoverage(scanResult, truncatedReasons) {
  const ignoredPaths = scanResult.ignored.map((entry) => ({
    path: requireRepositoryRelativePath(entry.path, "scanResult.ignored[].path"),
    policy: String(entry.policy),
  }));

  const unreadablePaths = scanResult.scan.errors
    .filter((error) => typeof error.path === "string")
    .map((error) => {
      const path = requireRepositoryRelativePath(error.path, "scanResult.scan.errors[].path");
      return { path };
    });

  const complete = scanResult.scan.complete === true && scanResult.scan.truncated !== true;

  return {
    guarantee: complete ? COVERAGE_GUARANTEES.COMPLETE : COVERAGE_GUARANTEES.PARTIAL,
    observed: {
      files: scanResult.statistics.filesScanned,
      directories: scanResult.statistics.directoriesScanned,
      symlinks: scanResult.statistics.symlinksScanned,
    },
    ignored: { count: ignoredPaths.length, paths: ignoredPaths },
    unreadable: { count: unreadablePaths.length, paths: unreadablePaths },
    truncatedBy: [...truncatedReasons],
  };
}

/** Project the scan errors into a bounded, path-safe shape. */
function projectScanErrors(scanResult) {
  return scanResult.scan.errors.map((error) => {
    const path =
      typeof error.path === "string"
        ? requireRepositoryRelativePath(error.path, "scanResult.scan.errors[].path")
        : null;
    return {
      kind: typeof error.kind === "string" ? error.kind : "filesystem-error",
      code: typeof error.code === "string" ? error.code : null,
      operation: typeof error.operation === "string" ? error.operation : null,
      path,
    };
  });
}

/**
 * Build a RepositoryModel from a validated ScanResult.
 *
 * @param {object} scanResult Output of `scanRepository` (or any object satisfying
 *   `validateScanResult`).
 * @returns {object} A deeply frozen, fully indexed RepositoryModel.
 * @throws {ValidationError} When the ScanResult is malformed or contradicts itself.
 */
export function buildRepositoryModel(scanResult) {
  const scan = validateScanResult(scanResult);

  const inventoryPaths = [
    ...scan.files.map((entry) => entry.path),
    ...scan.directories.map((entry) => entry.path),
    ...scan.symlinks.map((entry) => entry.path),
  ].sort();

  const repositoryIdValue = repositoryIdOf({
    paths: inventoryPaths,
    manifestPaths: scan.manifests.map((entry) => entry.path).sort(),
    languageIds: scan.languages.map((entry) => entry.id).sort(),
  });

  const collections = buildEntities(scan, repositoryIdValue);

  // Phase 14 — the dependency graph. A projection of the facts buildEntities just
  // projected: same nodes (`(ecosystem, name)` dependency entities), same edges (the
  // `depends-on` relationships), plus the per-edge provenance and the coverage
  // statement the entity list cannot express. It parses nothing, resolves nothing
  // and reads nothing; it is derived here rather than on demand so the model stays
  // the single frozen source of truth and validation can reject an incoherent graph.
  const dependencyGraph = buildDependencyGraph({
    dependencies: collections.dependencies,
    edges: collections.dependencyEdges,
    coverage: collections.dependencyCoverage,
    sources: collections.dependencySources,
  });

  const relationships = buildRelationships(collections, repositoryIdValue);
  const indexes = buildIndexes(collections, relationships, collections.evidence);

  const coverage = buildCoverage(scan, scan.statistics.truncatedBy);

  // Phase 15 — the architecture graph. Another projection of the same facts: the
  // containment tree the entity paths already establish, the declarations and test
  // frameworks the model already records, and the container wiring the scanner already
  // observed, with per-edge provenance and a coverage statement. It parses nothing, runs
  // nothing and infers no import, call or tested-by relation — those need phases this
  // architecture does not have.
  const architectureGraph = buildArchitectureGraph({
    repositoryId: repositoryIdValue,
    collections,
    evidence: collections.evidence,
    coverage: {
      scanComplete: scan.scan.complete === true,
      scanTruncated: scan.scan.truncated === true,
    },
  });

  // The Core factory supplies the contracted skeleton (every required area,
  // contract-shaped defaults including the optional areas). The model is then
  // assembled explicitly from that skeleton, so an area can never be omitted and
  // the 8D-specific sub-fields live next to the area they belong to.
  const skeleton = createRepositoryModel();
  const model = {
    ...skeleton,
    identity: {
      repositoryId: repositoryIdValue,
      // The single absolute path in the model: the scan root itself, which is
      // explicitly declared root metadata rather than an entity path.
      root: scan.root,
      name: null,
      modelVersion: REPOSITORY_MODEL_VERSION,
      provenance: {
        scanResultVersion: scan.version,
        scannedAt: scan.scannedAt,
      },
    },
    files: {
      ...skeleton.files,
      entries: collections.files,
      directories: collections.directories,
      symlinks: collections.symlinks,
      count: collections.files.length,
      directoryCount: collections.directories.length,
      symlinkCount: collections.symlinks.length,
      truncated: scan.scan.truncated === true,
    },
    languages: collections.languages,
    frameworks: collections.frameworks,
    manifests: {
      ...skeleton.manifests,
      entries: collections.manifests,
      ecosystems: collections.ecosystems,
      count: collections.manifests.length,
      ecosystemCount: collections.ecosystems.length,
    },
    // Phase 13 — the dependency substrate. `entries` are `(ecosystem, name)`
    // entities carrying one declaration record per manifest and one resolution
    // record per lockfile, so multi-manifest provenance and contradictory
    // declarations survive; `sources` states what each manifest turned out to be as
    // a dependency source, which is what makes `unknown` coverage expressible.
    // Scripts remain the empty contracted skeleton: no script inventory exists yet.
    dependencies: {
      ...skeleton.dependencies,
      detected: collections.dependencies.length > 0,
      entries: collections.dependencies,
      count: collections.dependencies.length,
      coverage: { ...collections.dependencyCoverage },
      sources: collections.dependencySources,
      // The graph projection: nodes, edges with provenance, and a coverage state that
      // keeps an established-but-empty graph apart from a graph acquisition never
      // established at all.
      graph: dependencyGraph,
    },
    scripts: skeleton.scripts,
    // Phase 15 — the architecture substrate. `graph` is the deterministic projection
    // (`nodes`, `edges` with per-edge provenance, the container build wiring, and the
    // four-way coverage state); no judgment about layering, cohesion or quality is
    // attached, and none can be: the model records what the repository establishes.
    architecture: {
      ...skeleton.architecture,
      // Whether the graph has any node besides the repository node — the same
      // "the scan observed something" statement `dependencies.detected` makes.
      detected: architectureGraph.nodes.length > 1,
      graph: architectureGraph,
    },
    configuration: {
      detected: scan.configuration.detected,
      entries: collections.configuration,
      evidenceTruncated: scan.configuration.evidenceTruncated === true,
    },
    git: {
      detected: scan.git.detected,
      head: collections.git.head,
      entity: collections.git,
    },
    tests: {
      detected: scan.tests.detected,
      // Derived from the framework *entities*, not copied from the scan summary:
      // a framework the model cannot trace to an observation must not appear in
      // the model's vocabulary at all.
      frameworks: collections.frameworks.map((framework) => framework.name),
      entries: collections.tests,
      evidenceTruncated: scan.tests.evidenceTruncated === true,
    },
    ci: {
      detected: scan.cicd.detected,
      providers: [...new Set(collections.cicd.map((entry) => entry.provider))].sort(),
      entries: collections.cicd,
      evidenceTruncated: scan.cicd.evidenceTruncated === true,
    },
    // Optional area (Core `REPOSITORY_MODEL_OPTIONAL_AREAS`): the documentation
    // artifacts the scan observed. No quality judgment is attached to them.
    documentation: {
      detected: scan.documentation.detected,
      entries: collections.documentation,
      evidenceTruncated: scan.documentation.evidenceTruncated === true,
    },
    scan: {
      ...skeleton.scan,
      complete: scan.scan.complete,
      truncated: scan.scan.truncated,
      limits: { ...scan.scan.limits },
      errors: projectScanErrors(scan),
      coverage,
    },
    metadata: {
      builder: REPOSITORY_MODEL_BUILDER,
      builderVersion: REPOSITORY_MODEL_BUILDER_VERSION,
      scanResultVersion: scan.version,
      scanScannedAt: scan.scannedAt,
      immutability: MODEL_IMMUTABILITY,
      entityCount: Object.values(indexes.entityIdsByKind).reduce(
        (total, ids) => total + ids.length,
        0,
      ),
    },
    relationships,
    evidence: collections.evidence,
    indexes,
  };

  deepFreeze(model);
  validateRepositoryModelGraph(model);
  return validateRepositoryModel(model);
}
