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
import { buildApiGraph } from "./api-graph.js";
import { buildMiddlewareGraph } from "./middleware-graph.js";
import { buildArchitectureGraph } from "./architecture-graph.js";
import { buildEntities } from "./entities.js";
import { buildDependencyGraph } from "./dependency-graph.js";
import { buildImportGraph, isInterpretedLanguage } from "./import-graph.js";
import { buildSymbolGraph } from "./symbol-graph.js";
import { buildIndexes, buildRelationships } from "./graph.js";
import { buildComplianceReport } from "./compliance-report.js";
import { buildPolicyArea } from "./policy.js";
import { buildProductionReport } from "./production-report.js";
import { buildProductionRiskReport } from "./production-risk-report.js";
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

  // Phase 16 — the import graph, built before the relationship list because its
  // edges are the one new relationship type this phase adds. Resolution happens
  // here, against the *observed* inventory only: never the filesystem, never a
  // package resolver, never a configured alias. Each edge states one file-to-file
  // reference with the observation behind it, references that resolve to nothing are
  // kept apart from the edges, and a five-way coverage state says how complete the
  // answer is. It parses nothing and runs nothing.
  //
  // The second half of that statement: the source files this graph does not read at
  // all. Their languages were already observed by the scan, so the projection needs
  // no language table of its own — a file whose `languageId` is neither JavaScript nor
  // TypeScript is read by nothing in this phase, and a repository made only of such
  // files is `unsupported` rather than a complete, empty import graph.
  const uninterpretedFiles = collections.files.filter(
    (file) => typeof file.languageId === "string" && !isInterpretedLanguage(file.languageId),
  );

  const importGraph = buildImportGraph({
    files: collections.files,
    sources: collections.importSources,
    coverage: {
      scanComplete: scan.scan.complete === true,
      scanTruncated: scan.scan.truncated === true,
    },
    uninterpreted: {
      sources: uninterpretedFiles.length,
      extensions: uninterpretedFiles.map((file) => file.extension),
    },
  });

  // Phase 17 — the symbol graph. Built from the same two inputs as the import graph
  // (the observed file entities and this phase's own acquisition records), with the
  // Phase 16 module resolver reused for repository-relative paths so one resolver
  // decides what a specifier points at. Resolution here is *same-file* for references
  // and calls — the acquisition layer proved the name unique, and nothing weaker is
  // accepted — and *cross-file* only for exports and import bindings, where the target
  // module's own export table establishes the name. It parses nothing and runs nothing.
  const symbolGraph = buildSymbolGraph({
    files: collections.files,
    sources: collections.semanticsSources,
    coverage: {
      scanComplete: scan.scan.complete === true,
      scanTruncated: scan.scan.truncated === true,
    },
    uninterpreted: {
      sources: uninterpretedFiles.length,
      extensions: uninterpretedFiles.map((file) => file.extension),
    },
  });

  // Phase 18 — the API graph. Built from this phase's own acquisition records and the
  // symbol graph above, so a route handler points at a Phase 17 symbol node rather than
  // duplicating it. It reads only the model's already-frozen facts: no file, no parser,
  // no runtime router, no HTTP.
  const apiGraph = buildApiGraph({
    sources: collections.apiSources,
    semanticsSources: collections.semanticsSources,
    symbolGraph,
    coverage: {
      scanComplete: scan.scan.complete === true,
      scanTruncated: scan.scan.truncated === true,
    },
    uninterpreted: {
      sources: uninterpretedFiles.length,
      extensions: uninterpretedFiles.map((file) => file.extension),
    },
  });

  // Phase 19 — the middleware graph. Built from this phase's own acquisition records, the
  // API graph above (whose route nodes and whose `middleware` edges are the *resolved*
  // route-scope middleware, so the two graphs cannot disagree about it) and the symbol
  // graph (whose nodes are the middleware identities, never duplicated here). It reads only
  // the model's already-frozen facts: no file, no parser, no request pipeline, no runtime.
  const middlewareGraph = buildMiddlewareGraph({
    sources: collections.middlewareSources,
    apiSources: collections.apiSources,
    apiGraph,
    semanticsSources: collections.semanticsSources,
    symbolGraph,
    coverage: {
      scanComplete: scan.scan.complete === true,
      scanTruncated: scan.scan.truncated === true,
    },
    uninterpreted: {
      sources: uninterpretedFiles.length,
      extensions: uninterpretedFiles.map((file) => file.extension),
    },
  });

  const relationships = buildRelationships(
    { ...collections, importEdges: importGraph.edges },
    repositoryIdValue,
  );
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

  // Phase 20 — the production-readiness report. A projection over the collections and the
  // six graphs above, built here (rather than on demand) so the model stays the single
  // frozen source of truth and so validation can reject a report that cites evidence the
  // model does not carry. It reads nothing new: no file, no parser, no network, no clock.
  const productionReport = buildProductionReport({
    configuration: collections.configuration,
    cicd: collections.cicd,
    files: collections.files,
    dockerfileStructures: collections.dockerfileStructures,
    buildContexts: architectureGraph.buildContexts,
    unestablishedComposeSources: architectureGraph.coverage.unestablishedSources,
    dependencyEntities: collections.dependencies,
    dependencySources: collections.dependencySources,
    manifests: collections.manifests,
    dependencyGraph,
    architectureGraph,
    apiGraph,
    middlewareGraph,
    importGraph,
    symbolGraph,
    evidence: collections.evidence,
    // The model-shaped scan state, not the raw ScanResult: the report reads `complete`,
    // `truncated` and the coverage statement, which live on the model's own `scan` area.
    scan: { complete: scan.scan.complete, truncated: scan.scan.truncated, coverage },
    configurationEvidenceTruncated: scan.configuration.evidenceTruncated === true,
    ciEvidenceTruncated: scan.cicd.evidenceTruncated === true,
  });

  // Phase 21 — the production **risk** report. A projection over the report above and three
  // of the graphs, built here for the same reasons: the model stays the single frozen source
  // of truth, and validation can reject a finding that cites evidence the model does not
  // carry. It states engineering gaps, each one backed by the observations that prove it, with
  // a severity from a closed three-word table and no aggregate of any kind.
  const productionRiskReport = buildProductionRiskReport({
    report: productionReport,
    evidence: collections.evidence,
    unobservedBuildDeclarations: collections.unobservedBuildDeclarations,
    serviceImageDeclarations: collections.serviceImageDeclarations,
    unestablishedComposeSources: architectureGraph.coverage.unestablishedSources,
    middlewareGraph,
    apiGraph,
    architectureGraph,
    importGraph,
  });

  // Phase 22 — the repository's own declared requirements, and the compliance report that
  // measures them. The policy area is built first because it is an *input*: it turns the one
  // document the repository declares into a first-class observation, so a compliance violation
  // can cite the declaration that makes a condition wrong beside the observation that proves the
  // condition. The compliance report then compares the two — and it reads the accepted
  // production report rather than re-deriving any fact, so there is no second notion of which
  // routes, Dockerfiles or manifests the repository contains.
  const policyArea = buildPolicyArea({ policy: collections.policy, scan: { complete: scan.scan.complete, truncated: scan.scan.truncated, coverage } });

  const complianceReport = buildComplianceReport({
    policy: policyArea,
    report: productionReport,
    evidence: collections.evidence,
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
    // Phase 16 — the import substrate. `entries` is one record per module source
    // (what the file was, why it could not be parsed, how many references were
    // established and how many module-shaped expressions could not be), and `graph`
    // is the resolved projection over the observed file entities: nodes, `imports`
    // edges with provenance, the references that are not edges, and the coverage
    // state. No reachability, coupling or dead-code judgment is attached, and none
    // can be: the model records what the repository establishes.
    imports: {
      ...skeleton.imports,
      // Whether any module source was observed — the same "the scan saw something to
      // interpret" statement `dependencies.detected` makes.
      detected: collections.importSources.length > 0,
      entries: collections.importSources,
      count: collections.importSources.length,
      coverage: {
        ...collections.importCoverage,
        // Resolution is the graph's answer, so its total lives with the graph; the
        // summary repeats it here so the two views of one fact cannot disagree.
        unresolved: importGraph.coverage.unresolved,
      },
      graph: importGraph,
    },
    // Phase 17 — the semantic substrate. `entries` is one record per module source
    // (what it declares, exports, references and calls, and which of those three
    // classes of claim the scanner could establish), and `graph` is the resolved
    // projection over the observed file entities: symbol nodes, `declares` /
    // `exports` / `references` / `calls` / `imports-binding` edges with provenance, the
    // occurrences that are not edges, and the coverage state. No complexity, dead
    // code, coupling or quality judgment is attached, and none can be: the model
    // records what the repository establishes.
    symbols: {
      ...skeleton.symbols,
      // Whether any module source was observed — the same "the scan saw something to
      // interpret" statement `imports.detected` makes.
      detected: collections.semanticsSources.length > 0,
      entries: collections.semanticsSources,
      count: collections.semanticsSources.length,
      coverage: {
        ...collections.semanticsCoverage,
        unresolved: symbolGraph.coverage.unresolved,
      },
      graph: symbolGraph,
    },
    // Phase 18 — the API substrate. `entries` is one record per module source (the
    // frameworks it established, the routes it declared and the route-shaped
    // occurrences it could not establish), and `graph` is the resolved projection over
    // the observed file entities and the symbol nodes: route nodes, `declares` /
    // `handled-by` / `middleware` edges, the occurrences that are not edges, and the
    // coverage state. No reachability, authentication, quality or request-flow judgment
    // is attached, and none can be: the model records what the repository declares.
    api: {
      ...skeleton.api,
      detected: collections.apiSources.length > 0,
      entries: collections.apiSources,
      count: collections.apiSources.length,
      coverage: {
        ...collections.apiCoverage,
        unresolved: apiGraph.coverage.unresolved,
      },
      graph: apiGraph,
    },
    // Phase 19 — the middleware substrate. `entries` is one record per module source (the
    // receivers it bound, the registrations it declared and the middleware-shaped
    // occurrences it could not establish), and `graph` is the resolved projection over the
    // API graph's routes and the symbol graph's nodes: middleware nodes, `protects` /
    // `applies-to` / `registered-on` / `precedes` edges with provenance, the occurrences
    // that are not registrations, each route's structural protection state, and the coverage
    // state. No judgment about whether the protection is correct, sufficient or correctly
    // ordered is attached, and none can be: the model records the declared structure.
    middleware: {
      ...skeleton.middleware,
      detected: collections.middlewareSources.length > 0,
      entries: collections.middlewareSources,
      count: collections.middlewareSources.length,
      coverage: {
        ...collections.middlewareCoverage,
        unresolved: middlewareGraph.coverage.unresolved,
      },
      graph: middlewareGraph,
    },
    configuration: {
      detected: scan.configuration.detected,
      entries: collections.configuration,
      evidenceTruncated: scan.configuration.evidenceTruncated === true,
    },
    // Phase 20 — the production-readiness substrate. `report` is the six-section,
    // evidence-backed projection; `detected` says whether it established any observation at
    // all, which is the same "the scan saw something to report" statement
    // `dependencies.detected` makes. No score, grade, percentage or traffic light is
    // attached to it, and none can be: the report records what the repository establishes
    // and names what it could not.
    production: {
      ...skeleton.production,
      detected: productionReport.coverage.observations > 0,
      state: productionReport.state,
      established: productionReport.established,
      report: productionReport,
      coverage: { ...productionReport.coverage },
    },
    // Phase 21 — the production-risk substrate: the same six domains, read for the engineering
    // gaps the inventory's own evidence proves. `detected` says whether it established any
    // finding at all. There is no score, no percentage, no grade and no aggregate: it carries
    // findings (each with its evidence ids, its closed severity and the basis it rests on),
    // the domains' coverage states, and the reasons each domain withheld a detection.
    productionRisk: {
      ...skeleton.productionRisk,
      detected: productionRiskReport.coverage.findings > 0,
      state: productionRiskReport.state,
      established: productionRiskReport.established,
      report: productionRiskReport,
      coverage: { ...productionRiskReport.coverage },
    },
    // Phase 22/23 — the declared-requirements substrate. `document` carries the **effective**
    // policy (the applied preset with the repository's own values on top) or `null`, and `state`
    // says what the reading established: a policy, the absence of one, or one of the three ways
    // this build could not tell. `declared` keeps what the repository literally wrote, `preset`
    // names the built-in preset that was applied, and `provenance` records, for every effective
    // value, whether the repository or the preset stated it. No setting is interpreted here — the
    // area states what the repository *requires*, never whether it complies.
    policy: {
      detected: policyArea.detected,
      established: policyArea.established,
      state: policyArea.state,
      document: policyArea.document,
      declared: policyArea.declared,
      preset: policyArea.preset,
      provenance: policyArea.provenance,
      coverage: { ...policyArea.coverage },
    },
    // Phase 22 — the compliance substrate: one section per policy domain, each item citing the
    // repository observation and the policy declaration it was measured against. `detected`
    // says whether any policy requirement was stated at all, which is the same "the repository
    // declared something to measure" statement every other area makes. There is no score, no
    // percentage and no grade: the report carries items with `pass` / `violation` / `unknown`
    // and the reasons nothing could be measured.
    compliance: {
      detected: complianceReport.coverage.items > 0,
      state: complianceReport.state,
      established: complianceReport.established,
      report: complianceReport,
      coverage: { ...complianceReport.coverage },
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
