/**
 * Code Guardian — Guardian Engine (Official Roadmap Phase 19)
 *
 * The canonical analysis engine. Phase 19's conceptual operation is
 * `guardian.audit(repository, options)`, and this module implements exactly the
 * pipeline the roadmap lists — no more, and nothing that an accepted layer already
 * owns:
 *
 *   audit(repository, options)
 *     1. load configuration            resolveAuditOptions
 *     2. build RepositoryModel         resolveRepositoryModel → scanner → builder
 *     3. select analyzers              selectAnalyzers → AnalyzerRegistry.select
 *     4. determine applicable rules    delegated to the accepted Rule Engine /
 *                                      Analyzer Engine (never re-implemented here)
 *     5. run analyzers                 createAnalyzerEngine → run(selected)
 *     6. collect evidence              the analyzer run's resolved evidence
 *     7. aggregate findings            the analyzer run's canonical findings
 *     8. calculate risk                calculateRisk (documented profile)
 *     9. generate canonical result     createGuardianResult → validate → freeze
 *
 * ### It orchestrates; it does not re-implement
 *
 * The Core builds the AnalysisContext with `buildAnalysisContext`, executes
 * analyzers with `createAnalyzerEngine`, and consumes the accepted
 * AnalysisRunResult. Analyzer applicability, isolation, failure capture, evidence
 * provenance enforcement, finding normalization, fingerprinting and deduplication
 * all stay where they are. Guardian never calls `analyzer.analyze()` itself.
 *
 * ### It is transport-independent
 *
 * This module imports the Core contracts, the repository scanner/model boundary,
 * the analysis framework and the rule layer — nothing else. It never imports
 * `tools.js`, `tool-registry`, `stdio-server`, `http-server`, MCP or the CLI, so
 * the Core can be driven from any interface without an MCP server existing.
 *
 * ### It does not hide failures
 *
 * An analyzer failure is recorded inside the run and remains visible in the result
 * (`analyzers[].status`, `analyzers[].errors`, `risk.limitations`); it is never
 * thrown, because throwing would erase the other analyzers' work and the failure's
 * own visibility. A framework-level misconfiguration (an unknown option, an
 * unknown analyzer id, an empty selection, an invalid repository input) throws,
 * because no meaningful audit can be produced.
 */

import {
  ANALYZER_RUN_STATUSES,
  FINDING_FINGERPRINT_ALGORITHM,
  buildAnalysisContext,
  createAnalyzerEngine,
  createAnalyzerRegistry,
} from "../analysis/index.js";

import { GUARDIAN_ENGINE_VERSION } from "./contracts.js";
import { resolveAuditOptions } from "./configuration.js";
import { resolveRepositoryModel } from "./repository.js";
import {
  createGuardianResult,
  freezeGuardianResult,
  guardianEngineIdentity,
  validateGuardianResult,
} from "./result.js";
import { calculateRisk } from "./risk.js";
import { selectAnalyzers } from "./selection.js";

/** A compact, serializable description of the analysed repository. */
function repositorySummary(model) {
  return {
    repositoryId: model.identity.repositoryId,
    root: model.identity.root,
    modelVersion: model.version,
    coverage: {
      complete: model.scan.coverage.guarantee === "complete",
      truncated: model.scan.truncated === true,
      guarantee: model.scan.coverage.guarantee,
    },
    fileCount: model.files.count,
    evidenceCount: model.evidence.length,
  };
}

/** The scan/coverage statement the result carries. */
function scanSummary(model) {
  return {
    complete: model.scan.complete === true,
    truncated: model.scan.truncated === true,
    guarantee: model.scan.coverage.guarantee,
  };
}

/** Status counts over the analysis run's analyzer results. */
function statusCounts(analysisRun) {
  const statuses = analysisRun.analyzers.map((result) => result.status);
  const count = (status) => statuses.filter((value) => value === status).length;
  return {
    selected: statuses.length,
    completed: count(ANALYZER_RUN_STATUSES.COMPLETED),
    notApplicable: count(ANALYZER_RUN_STATUSES.NOT_APPLICABLE),
    failed: count(ANALYZER_RUN_STATUSES.FAILED),
    skipped: count(ANALYZER_RUN_STATUSES.SKIPPED),
  };
}

/** One per-analyzer attribution summary derived from the accepted run result. */
function analyzerSummary(result) {
  return {
    id: result.analyzer.id,
    name: result.analyzer.name,
    version: result.analyzer.version,
    scope: result.analyzer.scope,
    status: result.status,
    applicability: result.applicability,
    findings: result.findings.map((finding) => finding.fingerprint).sort(),
    evidence: result.evidence.map((record) => record.id).sort(),
    metrics: result.metrics,
    errors: result.errors,
  };
}

/**
 * Assemble the canonical result from the run facts.
 *
 * Evidence is resolved to whole records so a consumer never has to look one up:
 * the result carries every record any analyzer emitted or any finding cited.
 */
function assembleGuardianResult({ model, analysisRun, risk, fingerprintAlgorithm }) {
  const evidenceById = new Map(model.evidence.map((record) => [record.id, record]));
  for (const result of analysisRun.analyzers) {
    for (const record of result.evidence) evidenceById.set(record.id, record);
  }

  const evidenceIds = new Set();
  for (const finding of analysisRun.findings) {
    for (const reference of finding.evidence) evidenceIds.add(reference);
  }
  for (const result of analysisRun.analyzers) {
    for (const record of result.evidence) evidenceIds.add(record.id);
  }
  const evidence = [...evidenceIds]
    .sort()
    .map((id) => evidenceById.get(id))
    .filter((record) => record !== undefined);

  const counts = statusCounts(analysisRun);
  const analyzers = analysisRun.analyzers.map(analyzerSummary);

  return createGuardianResult({
    engine: guardianEngineIdentity(fingerprintAlgorithm),
    repository: repositorySummary(model),
    scan: scanSummary(model),
    analyzers,
    findings: analysisRun.findings,
    evidence,
    risk,
    analysis: {
      complete: analysisRun.complete,
      selectedAnalyzers: analyzers.map((entry) => entry.id),
      analyzers: counts,
      failFast: analysisRun.metadata.failFast === true,
      durationMs: analysisRun.durationMs,
    },
    metrics: {
      analyzers: counts,
      findings: { total: analysisRun.findings.length, duplicates: analysisRun.duplicates.length },
      evidence: { total: evidence.length },
    },
  });
}

/**
 * Create a guardian engine bound to a set of analyzers.
 *
 * @param {object} [options]
 * @param {object} [options.registry] A registry from `createAnalyzerRegistry`. When
 *   omitted, one is created from `analyzers`.
 * @param {object[]} [options.analyzers] Analyzers to register when no registry is given.
 * @param {boolean} [options.failFast] Default fail-fast behaviour; an audit may override it.
 * @param {Function} [options.clock] Millisecond clock (metadata only).
 * @param {string} [options.fingerprintAlgorithm] Fingerprint algorithm identity.
 * @returns {object} A frozen engine handle with `audit`, `registry` and `version`.
 */
export function createGuardianEngine({
  registry,
  analyzers,
  failFast = false,
  clock = null,
  fingerprintAlgorithm = FINDING_FINGERPRINT_ALGORITHM,
} = {}) {
  const analyzerRegistry = registry ?? createAnalyzerRegistry(analyzers ?? []);
  const defaultClock = clock ?? (() => Date.now());

  const engine = {
    /** Version of the Guardian Core. */
    version: GUARDIAN_ENGINE_VERSION,

    /** The analyzer registry this engine owns (read-only by convention). */
    registry: analyzerRegistry,

    /**
     * Run a canonical audit.
     *
     * @param {string|object} repository A repository root path, a `ScanResult`, or a
     *   built `RepositoryModel`.
     * @param {object} [options] Audit options (see `AUDIT_OPTION_KEYS`).
     * @returns {Promise<object>} A validated, deeply frozen canonical Guardian result.
     * @throws {GuardianConfigurationError} For an invalid option, repository input,
     *   selection or framework configuration.
     * @throws {AnalyzerConfigurationError} For an unknown analyzer id.
     */
    async audit(repository, options = {}) {
      // 1. load configuration
      const configuration = resolveAuditOptions(options);
      const effectiveClock = configuration.clock ?? defaultClock;
      const effectiveFailFast = configuration.failFast ?? failFast;

      // 2. build RepositoryModel (path → scanner → builder; ScanResult → builder;
      //    RepositoryModel → validated as-is)
      const model = await resolveRepositoryModel(repository, configuration.scan);

      // 3. select analyzers (deterministic; unknown/empty → throw)
      const selected = selectAnalyzers(analyzerRegistry, configuration.analyzers);

      // 4. AnalysisContext — the only thing an analyzer receives. Rule and analyzer
      //    applicability are decided inside the accepted engines, not here.
      const context = buildAnalysisContext({
        repository: model,
        configuration: configuration.configuration,
        execution: configuration.execution,
        rules: configuration.rules,
        evidence: configuration.evidence,
        options: configuration.analysis,
      });

      // 5. run the selected analyzers through the accepted Analyzer Engine
      const analyzerEngine = createAnalyzerEngine({
        registry: analyzerRegistry,
        failFast: effectiveFailFast,
        clock: effectiveClock,
      });
      const analysisRun = await analyzerEngine.run(
        selected.map((analyzer) => analyzer.id),
        context,
        { failFast: effectiveFailFast },
      );

      // 6./7. evidence and canonical findings are carried by the accepted run.
      // 8. calculate the risk profile.
      const risk = calculateRisk({ repository: model, analysisRun });

      // 9. generate the canonical result.
      const result = assembleGuardianResult({
        model,
        analysisRun,
        risk,
        fingerprintAlgorithm,
      });

      return freezeGuardianResult(validateGuardianResult(result));
    },
  };

  return Object.freeze(engine);
}
