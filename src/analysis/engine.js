/**
 * Code Guardian — Analyzer Engine (Phase 9)
 *
 * The engine owns the *pipeline*, and nothing else. It knows nothing about
 * security, testing or architecture; it knows how to take a validated
 * AnalysisContext, decide which analyzers apply, run them without letting one
 * corrupt another, push their output through the Finding Engine, and report
 * exactly what happened.
 *
 *   AnalysisContext
 *         │
 *         ▼
 *   selection ──► applicability ──► analyze() ──► normalize/fingerprint
 *         │            │                │                  │
 *         │       not-applicable    failure           canonical findings
 *         ▼            ▼                ▼                  ▼
 *      skipped      result           result             result
 *         └────────────┴────────────────┴──────────────────┘
 *                              │
 *                              ▼
 *                    analysis run result
 *
 * Invariants the engine enforces:
 *
 *   - **Isolation.** Every analyzer runs inside its own boundary: one throwing,
 *     one returning nonsense and one producing a malformed finding do not stop
 *     the others, and each failure is recorded against the analyzer that caused
 *     it. `failFast` is opt-in and reports the analyzers it never reached as
 *     `skipped`, so an aborted run never looks complete.
 *   - **No fabrication.** Findings may only cite evidence that exists in the
 *     RepositoryModel or that the *same* analyzer produced in this run. Reference
 *     scope is per analyzer, so a finding's evidence can never depend on which
 *     other analyzers happened to run first.
 *   - **Fail-closed findings.** A finding that cannot be represented as a
 *     canonical Finding never enters the output; the analyzer's run is marked
 *     `failed` instead.
 *   - **Determinism.** Selection, execution, results, findings, duplicates and
 *     errors all have documented orderings that do not depend on object key
 *     order, analyzer scheduling or discovery order.
 *
 * The engine performs no I/O, spawns nothing, and never touches the filesystem:
 * the only repository knowledge available to it is the frozen RepositoryModel
 * inside the context.
 */

import {
  validateAnalysisContext,
  validateAnalyzer,
  validateAnalyzerResult,
} from "../core/index.js";
import { isRepositoryRelativePath } from "../repository/model/index.js";

import { evaluateApplicability } from "./applicability.js";
import {
  ABNORMAL_ANALYZER_STATUSES,
  ANALYZER_ENGINE_VERSION,
  ANALYZER_FAILURE_KINDS,
  ANALYZER_RUN_STATUSES,
  FINDING_FINGERPRINT_ALGORITHM,
} from "./contracts.js";
import { indexRulesById, modelEvidenceIds } from "./context.js";
import { AnalyzerFrameworkError, failureEntry } from "./errors.js";
import { deduplicateFindings, normalizeFinding, orderFindings } from "./findings.js";
import {
  analyzerResultDraftIssues,
  createAnalysisRunResult,
  createAnalyzerRunResult,
  stableAnalysisView,
  validateAnalysisRunResult,
  validateAnalyzerRunResult,
} from "./results.js";
import { deepFreeze, sanitizeDeclarativeValue } from "./values.js";

/** Default engine options. */
export const DEFAULT_ENGINE_OPTIONS = Object.freeze({
  /** Stop after the first analyzer failure (opt-in). */
  failFast: false,
  /** Millisecond clock. Injected so runs can be made fully deterministic. */
  clock: () => Date.now(),
});

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function analyzerSummary(analyzer) {
  return {
    id: analyzer.id,
    name: analyzer.name,
    version: analyzer.version,
    scope: analyzer.scope,
  };
}

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

/**
 * Validate the evidence an analyzer emitted, and reject anything that could
 * forge provenance.
 *
 * An analyzer may legitimately record a *new* observation (a rule that reads two
 * model observations and needs to cite the combination). It may not reuse an
 * existing id — from the model, from another analyzer earlier in this run, or
 * from itself — because that would let it silently replace provenance another
 * component relies on, and it may not point outside the repository.
 *
 * Two distinct sets are consulted, and the distinction is deliberate:
 *
 *   - `ownEvidence` is the producing analyzer's local set. It only exists so a
 *     single analyzer cannot emit the same id twice, and so the analyzer's
 *     reference scope can be computed after resolution.
 *   - `runEvidence` is the **run-global registry**, seeded with the model's
 *     reserved ids before any analyzer runs and extended as analyzers emit new
 *     observations. It is the authority for cross-analyzer uniqueness: an id
 *     accepted from Analyzer A is reserved for the remainder of the run, so
 *     Analyzer B reusing it fails even though B's local set is empty.
 */
function resolveAnalyzerEvidence(result, analyzer, ownEvidence, runEvidence) {
  const accepted = [];
  for (const record of result.evidence) {
    const id = record?.id;
    if (ownEvidence.has(id) || runEvidence.has(id)) {
      throw new AnalyzerFrameworkError(
        ANALYZER_FAILURE_KINDS.DUPLICATE_EVIDENCE_ID,
        "an analyzer emitted evidence reusing an existing evidence id",
        { analyzerId: analyzer.id, evidenceId: String(id) },
      );
    }
    const path = record?.location?.path;
    if (!isRepositoryRelativePath(path)) {
      throw new AnalyzerFrameworkError(
        ANALYZER_FAILURE_KINDS.UNSAFE_EVIDENCE_PATH,
        "analyzer-emitted evidence must locate a repository-relative path",
        { analyzerId: analyzer.id, evidenceId: String(id) },
      );
    }
    // Reserve in both: locally for diagnostics/reference scope, globally so no
    // later analyzer in this run can reuse the id.
    ownEvidence.add(id);
    runEvidence.add(id);
    accepted.push(record);
  }
  return accepted;
}

/**
 * Turn a validated analyzer result into canonical findings.
 *
 * Validated findings are kept even when a sibling finding is rejected, so a
 * single malformed finding neither smuggles itself into the output nor silently
 * erases the analyzer's sound work. The run is marked `failed` either way, which
 * is what makes the abnormality visible.
 */
function canonicalizeFindings(rawFindings, { analyzer, rulesById, allowedEvidenceIds }) {
  const findings = [];
  const errors = [];

  for (const raw of rawFindings) {
    try {
      findings.push(
        normalizeFinding(raw, {
          analyzer,
          rule: rulesById.get(raw?.ruleId) ?? null,
          allowedEvidenceIds,
        }),
      );
    } catch (error) {
      errors.push(
        failureEntry(error, {
          kind:
            error?.kind === ANALYZER_FAILURE_KINDS.UNKNOWN_EVIDENCE_REFERENCE
              ? ANALYZER_FAILURE_KINDS.UNKNOWN_EVIDENCE_REFERENCE
              : ANALYZER_FAILURE_KINDS.INVALID_FINDING,
          analyzerId: analyzer.id,
          details: { ruleId: raw?.ruleId ?? null },
        }),
      );
    }
  }

  return { findings: orderFindings(findings), errors };
}

/**
 * Create an analyzer engine bound to a registry.
 *
 * @param {object} options
 * @param {object} options.registry A registry from `createAnalyzerRegistry`.
 * @param {boolean} [options.failFast] Default fail-fast behaviour for runs.
 * @param {Function} [options.clock] Millisecond clock (metadata only).
 * @returns {object} An engine handle with `run` and `runAll`.
 */
export function createAnalyzerEngine({ registry, failFast = false, clock = DEFAULT_ENGINE_OPTIONS.clock } = {}) {
  if (registry === null || typeof registry !== "object" || typeof registry.list !== "function") {
    throw new AnalyzerFrameworkError(
      ANALYZER_FAILURE_KINDS.UNKNOWN_ANALYZER,
      "createAnalyzerEngine requires an analyzer registry",
    );
  }

  const engine = {
    /**
     * Run every registered analyzer.
     *
     * @param {object} context A validated AnalysisContext.
     * @param {object} [options]
     * @param {boolean} [options.failFast] Overrides the engine default.
     * @returns {Promise<object>} A validated, frozen analysis run result.
     */
    async runAll(context, options = {}) {
      return engine.run(registry.ids(), context, options);
    },

    /**
     * Run the selected analyzers, sorted by id.
     *
     * @param {string[]} ids Analyzer ids to run.
     * @param {object} context A validated AnalysisContext.
     * @param {object} [options]
     * @param {boolean} [options.failFast] Overrides the engine default.
     * @returns {Promise<object>} A validated, frozen analysis run result.
     * @throws {AnalyzerConfigurationError} When an id is not registered.
     */
    async run(ids, context, options = {}) {
      const selected = registry.select(ids);
      const effectiveFailFast = options.failFast ?? failFast;
      // Validated here as well as in `buildAnalysisContext`: an engine called
      // with a hand-built context must fail closed rather than hand analyzers
      // something that is not a contract instance.
      const validatedContext = validateAnalysisContext(context);
      return runSelected({
        selected,
        context: validatedContext,
        failFast: effectiveFailFast,
        clock,
      });
    },
  };

  return Object.freeze(engine);
}

/**
 * Execute one selection.
 *
 * Kept as a function rather than a method body so the pipeline reads as a
 * sequence of clearly-scoped steps instead of one long closure over mutable state.
 */
async function runSelected({ selected, context, failFast, clock }) {
  const startedAt = clock();
  const repository = context.repository;
  const rulesById = indexRulesById(context);
  // Model evidence ids are reserved *before* any analyzer executes.
  const modelEvidence = modelEvidenceIds(context);
  // Run-global evidence-id registry. Uniqueness spans the whole analysis run rather
  // than one analyzer: seeded with the model's reserved ids, then extended by every
  // observation an analyzer successfully emits. The per-analyzer sets stay for
  // diagnostics and reference scope, but they are not the uniqueness authority.
  const runEvidenceIds = new Set(modelEvidence);

  const selfEvidenceIds = new Map();
  for (const analyzer of selected) selfEvidenceIds.set(analyzer.id, new Set());

  const analyzerResults = [];
  let aborted = false;

  for (const analyzer of selected) {
    if (aborted) {
      analyzerResults.push(
        skippedResult(analyzer, {
          kind: ANALYZER_FAILURE_KINDS.FAIL_FAST_ABORT,
          message: "skipped because an earlier analyzer failed and fail-fast is enabled",
        }),
      );
      continue;
    }

    const analyzerStartedAt = clock();
    const result = await runOne({
      analyzer,
      context,
      rulesById,
      modelEvidence,
      runEvidenceIds,
      // The analyzer's own observations are resolved *before* its findings are
      // canonicalized, so a rule may cite the evidence it just emitted.
      ownEvidence: selfEvidenceIds.get(analyzer.id),
      durationMs: () => clock() - analyzerStartedAt,
    });

    analyzerResults.push(result);
    if (failFast && result.status === ANALYZER_RUN_STATUSES.FAILED) aborted = true;
  }

  const allFindings = analyzerResults.flatMap((result) => result.findings);
  const { findings, duplicates } = deduplicateFindings(allFindings);

  const abnormal = analyzerResults.filter((result) =>
    ABNORMAL_ANALYZER_STATUSES.includes(result.status),
  );

  const aggregate = createAnalysisRunResult({
    version: ANALYZER_ENGINE_VERSION,
    repository: repositorySummary(repository),
    analyzers: analyzerResults,
    findings,
    duplicates,
    errors: collectErrors(analyzerResults),
    metadata: {
      engineVersion: ANALYZER_ENGINE_VERSION,
      fingerprintAlgorithm: FINDING_FINGERPRINT_ALGORITHM,
      selectedAnalyzers: selected.map((analyzer) => analyzer.id),
      selectedCount: selected.length,
      completed: analyzerResults.filter(
        (result) => result.status === ANALYZER_RUN_STATUSES.COMPLETED,
      ).length,
      notApplicable: analyzerResults.filter(
        (result) => result.status === ANALYZER_RUN_STATUSES.NOT_APPLICABLE,
      ).length,
      failed: analyzerResults.filter((result) => result.status === ANALYZER_RUN_STATUSES.FAILED)
        .length,
      skipped: analyzerResults.filter((result) => result.status === ANALYZER_RUN_STATUSES.SKIPPED)
        .length,
      failFast,
      repositoryCoverage: repository.scan.coverage.guarantee,
    },
    durationMs: clock() - startedAt,
    complete: abnormal.length === 0,
  });

  const validated = validateAnalysisRunResult(aggregate);
  return deepFreeze(validated);
}

/** A defined outcome for an analyzer the run never reached. */
function skippedResult(analyzer, { kind, message }) {
  return deepFreeze(
    createAnalyzerRunResult({
      analyzer: analyzerSummary(analyzer),
      status: ANALYZER_RUN_STATUSES.SKIPPED,
      applicability: null,
      findings: [],
      evidence: [],
      metrics: {},
      metadata: {},
      errors: [failureEntry(message, { kind, analyzerId: analyzer.id })],
      durationMs: 0,
    }),
  );
}

/**
 * Run one analyzer, converting every possible outcome into a result object.
 *
 * This is the isolation boundary: nothing an analyzer does — throw, return
 * nonsense, produce a bad finding, try to mutate the model — escapes as an
 * exception that would stop the run.
 */
async function runOne({ analyzer, context, rulesById, modelEvidence, runEvidenceIds, ownEvidence, durationMs }) {
  const summary = analyzerSummary(analyzer);

  // Defense in depth: a descriptor can be corrupted between registration and a
  // run, and an analyzer that cannot be executed is a framework finding about
  // that analyzer, not a crash.
  try {
    validateAnalyzer(analyzer);
  } catch (error) {
    return deepFreeze(
      createAnalyzerRunResult({
        analyzer: summary,
        status: ANALYZER_RUN_STATUSES.FAILED,
        applicability: null,
        findings: [],
        evidence: [],
        metrics: {},
        metadata: {},
        errors: [
          failureEntry(error, {
            kind: ANALYZER_FAILURE_KINDS.INVALID_ANALYZER,
            analyzerId: analyzer?.id ?? null,
          }),
        ],
        durationMs: durationMs(),
      }),
    );
  }

  let applicability;
  try {
    applicability = await evaluateApplicability(analyzer, context);
  } catch (error) {
    return failedResult(summary, {
      kind: error?.kind ?? ANALYZER_FAILURE_KINDS.INVALID_APPLICABILITY,
      error,
      analyzerId: analyzer.id,
      durationMs: durationMs(),
    });
  }

  if (applicability.applicable !== true) {
    return deepFreeze(
      createAnalyzerRunResult({
        analyzer: summary,
        status: ANALYZER_RUN_STATUSES.NOT_APPLICABLE,
        applicability,
        findings: [],
        evidence: [],
        metrics: {},
        metadata: {},
        errors: [],
        durationMs: durationMs(),
      }),
    );
  }

  let rawResult;
  try {
    rawResult = await analyzer.analyze(context);
  } catch (error) {
    return failedResult(summary, {
      kind: ANALYZER_FAILURE_KINDS.ANALYZER_FAILURE,
      error,
      analyzerId: analyzer.id,
      durationMs: durationMs(),
    });
  }

  // The analyzer's return value is a *draft*: the Finding Engine fills what the
  // analyzer legitimately omitted (finding ids, status, description, static fields
  // from the matched rule), so only the container shape is checked here. The
  // completed result is validated against the Core contract below, once
  // normalization has finished — Core stays the authority, the framework is what
  // makes a draft satisfy it.
  const draftIssues = analyzerResultDraftIssues(rawResult);
  if (draftIssues.length > 0) {
    return failedResult(summary, {
      kind: ANALYZER_FAILURE_KINDS.INVALID_ANALYSIS_RESULT,
      error: new Error("analyzer result is not interpretable"),
      analyzerId: analyzer.id,
      details: { issues: draftIssues },
      durationMs: durationMs(),
    });
  }

  let evidence;
  try {
    evidence = resolveAnalyzerEvidence(rawResult, analyzer, ownEvidence, runEvidenceIds);
  } catch (error) {
    return failedResult(summary, {
      kind: error?.kind ?? ANALYZER_FAILURE_KINDS.DUPLICATE_EVIDENCE_ID,
      error,
      analyzerId: analyzer.id,
      durationMs: durationMs(),
    });
  }

  // The reference scope is fixed here, after the analyzer's own observations are
  // known: model evidence plus this analyzer's new evidence, and nothing else.
  const allowedEvidenceIds = new Set([...modelEvidence, ...ownEvidence]);

  const { findings, errors } = canonicalizeFindings(rawResult.findings ?? [], {
    analyzer,
    rulesById,
    allowedEvidenceIds,
  });

  // The result carries the observations its findings actually rest on — its own new
  // observations plus the model observations they cite, resolved to whole records so
  // a consumer never has to look them up. Sorted by id for determinism.
  const cited = new Set(evidence.map((record) => record.id));
  for (const finding of findings) for (const id of finding.evidence) cited.add(id);
  const evidenceById = new Map(context.repository.evidence.map((record) => [record.id, record]));
  for (const record of evidence) evidenceById.set(record.id, record);
  const resolvedEvidence = [...cited]
    .sort()
    .map((id) => evidenceById.get(id))
    .filter((record) => record !== undefined);

  // Final proof against the Core contract, on the *completed* result: findings are
  // now canonical (fingerprinted) and the evidence list is the resolved one.
  try {
    validateAnalyzerResult({
      findings,
      evidence: resolvedEvidence,
      metrics: sanitizeDeclarativeValue(rawResult.metrics) ?? {},
      metadata: sanitizeDeclarativeValue(rawResult.metadata) ?? {},
    });
  } catch (error) {
    return failedResult(summary, {
      kind: ANALYZER_FAILURE_KINDS.INVALID_ANALYSIS_RESULT,
      error,
      analyzerId: analyzer.id,
      durationMs: durationMs(),
    });
  }

  return deepFreeze(
    createAnalyzerRunResult({
      analyzer: summary,
      status:
        errors.length > 0 ? ANALYZER_RUN_STATUSES.FAILED : ANALYZER_RUN_STATUSES.COMPLETED,
      applicability,
      findings,
      evidence: resolvedEvidence,
      metrics: sanitizeDeclarativeValue(rawResult.metrics) ?? {},
      metadata: sanitizeDeclarativeValue(rawResult.metadata) ?? {},
      errors,
      durationMs: durationMs(),
    }),
  );
}

function failedResult(summary, { kind, error, analyzerId, details = {}, durationMs: duration }) {
  return deepFreeze(
    createAnalyzerRunResult({
      analyzer: summary,
      status: ANALYZER_RUN_STATUSES.FAILED,
      applicability: null,
      findings: [],
      evidence: [],
      metrics: {},
      metadata: {},
      errors: [failureEntry(error, { kind, analyzerId, details })],
      durationMs: duration,
    }),
  );
}

/** Aggregate every analyzer failure into one deterministically ordered list. */
function collectErrors(analyzerResults) {
  const errors = [];
  for (const result of analyzerResults) {
    for (const entry of result.errors) errors.push(entry);
  }
  return errors.sort((a, b) => {
    const keyA = `${a.analyzerId ?? ""}\u0000${a.kind}\u0000${a.code}\u0000${a.message}`;
    const keyB = `${b.analyzerId ?? ""}\u0000${b.kind}\u0000${b.code}\u0000${b.message}`;
    return keyA < keyB ? -1 : keyA > keyB ? 1 : 0;
  });
}

/** Re-exported so callers can compare or baseline results without importing two modules. */
export { stableAnalysisView };

/** Convenience predicate: did every selected analyzer produce a clean outcome? */
export function isRunComplete(result) {
  return isPlainObject(result) && result.complete === true;
}

/** The findings one analyzer contributed to an aggregate result. */
export function findingsForAnalyzer(result, analyzerId) {
  const entry = result.analyzers.find((candidate) => candidate.analyzer.id === analyzerId);
  return entry === undefined ? [] : [...entry.findings];
}
