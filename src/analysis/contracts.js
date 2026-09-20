/**
 * Code Guardian — Analyzer Framework Contracts (Phase 9)
 *
 * Vocabulary for the analyzer *framework*: what can happen to an analyzer during
 * a run, and why. Domain vocabulary (severities, categories, rule metadata)
 * belongs to the Core contracts, and nothing here redefines it.
 *
 * The vocabulary is deliberately closed. A status or failure kind that is not
 * listed does not exist, so consumers can exhaustively switch on them, and adding
 * one is a visible contract change rather than an accidental new string.
 */

/**
 * Version of the analyzer framework (result shapes, ordering, semantics).
 * Semver, matching the Core convention for analyzers, rules and versions.
 */
export const ANALYZER_ENGINE_VERSION = "1.0.0";

/**
 * Terminal and non-terminal states of one analyzer in one run.
 *
 *   completed       the analyzer ran and produced a validated result
 *   not-applicable  the analyzer declined this repository; not a failure
 *   failed          the analyzer (or its output) violated the contract
 *   skipped         the run stopped before reaching it (fail-fast only)
 *
 * `skipped` exists so an aborted run is never reported as if every selected
 * analyzer had been evaluated; it is not a failure of the analyzer itself.
 */
export const ANALYZER_RUN_STATUSES = Object.freeze({
  COMPLETED: "completed",
  NOT_APPLICABLE: "not-applicable",
  FAILED: "failed",
  SKIPPED: "skipped",
});

/** Terminal states: the analyzer was actually evaluated. */
export const TERMINAL_ANALYZER_STATUSES = Object.freeze([
  ANALYZER_RUN_STATUSES.COMPLETED,
  ANALYZER_RUN_STATUSES.NOT_APPLICABLE,
  ANALYZER_RUN_STATUSES.FAILED,
]);

/** Statuses that make an aggregate run incomplete. */
export const ABNORMAL_ANALYZER_STATUSES = Object.freeze([
  ANALYZER_RUN_STATUSES.FAILED,
  ANALYZER_RUN_STATUSES.SKIPPED,
]);

/**
 * Why an analyzer did not produce a clean result.
 *
 * The four failure semantics the framework must keep apart (not-applicable is a
 * *status*, not a kind, and never appears here):
 *
 *   invalid-analyzer        the registered descriptor was corrupted after
 *                           registration (framework guard)
 *   invalid-applicability   `canAnalyze()` returned something other than the
 *                           contracted applicability object
 *   invalid-analysis-result `analyze()` returned something other than the
 *                           contracted analysis result
 *   analyzer-failure        the analyzer threw or rejected
 *   invalid-finding         a finding violated the Finding contract, or tried to
 *                           set its own canonical fingerprint
 *   unknown-evidence-reference  a finding cited evidence that does not exist
 *   unsafe-evidence-path    an analyzer emitted evidence outside the repository
 *   duplicate-evidence-id   an analyzer emitted evidence reusing another
 *                           record's id (which would forge provenance)
 *   fail-fast-abort         recorded on analyzers skipped because a previous
 *                           analyzer failed and fail-fast was requested
 */
export const ANALYZER_FAILURE_KINDS = Object.freeze({
  INVALID_ANALYZER: "invalid-analyzer",
  DUPLICATE_ANALYZER: "duplicate-analyzer",
  UNKNOWN_ANALYZER: "unknown-analyzer",
  INVALID_APPLICABILITY: "invalid-applicability",
  INVALID_ANALYSIS_RESULT: "invalid-analysis-result",
  ANALYZER_FAILURE: "analyzer-failure",
  INVALID_FINDING: "invalid-finding",
  UNKNOWN_EVIDENCE_REFERENCE: "unknown-evidence-reference",
  UNSAFE_EVIDENCE_PATH: "unsafe-evidence-path",
  DUPLICATE_EVIDENCE_ID: "duplicate-evidence-id",
  FAIL_FAST_ABORT: "fail-fast-abort",
});

/**
 * Stable codes carried by recorded failures.
 *
 * `analysis` codes mean an analyzer produced bad output; `configuration` codes
 * mean the framework was asked to do something impossible (an unknown analyzer id,
 * for example). The split mirrors the Core error categories so interface layers
 * can map a failure to an HTTP status or an MCP error without guessing.
 */
export const ANALYZER_FAILURE_CODES = Object.freeze({
  invalidAnalyzer: "CG_ANALYZER_INVALID",
  invalidApplicability: "CG_ANALYZER_APPLICABILITY_INVALID",
  invalidAnalysisResult: "CG_ANALYZER_RESULT_INVALID",
  threw: "CG_ANALYZER_THREW",
  invalidFinding: "CG_ANALYZER_FINDING_INVALID",
  unknownEvidence: "CG_ANALYZER_EVIDENCE_UNKNOWN",
  unsafeEvidencePath: "CG_ANALYZER_EVIDENCE_PATH_UNSAFE",
  duplicateEvidenceId: "CG_ANALYZER_EVIDENCE_ID_DUPLICATE",
  failFastAbort: "CG_ANALYZER_SKIPPED",
  unknownAnalyzer: "CG_ANALYZER_UNKNOWN",
  duplicateAnalyzer: "CG_ANALYZER_DUPLICATE",
});

/**
 * Finding fingerprint algorithm identity.
 *
 * Recorded on every fingerprint so a future algorithm change is detectable
 * instead of silently invalidating stored baselines.
 */
export const FINDING_FINGERPRINT_ALGORITHM = "cg-fp1";

/** Prefix of a canonical finding fingerprint. */
export const FINDING_FINGERPRINT_PREFIX = `${FINDING_FINGERPRINT_ALGORITHM}-`;

/** Prefix of a canonical finding id derived from its fingerprint. */
export const FINDING_ID_PREFIX = "finding:";

/** Metadata key an analyzer may use to disambiguate two findings at one location. */
export const FINGERPRINT_KEY_METADATA_KEY = "fingerprintKey";

/** Bounds applied to analyzer-supplied identity text. */
export const MAX_IDENTIFIER_LENGTH = 120;
export const MAX_FINGERPRINT_KEY_LENGTH = 120;
export const MAX_ERROR_MESSAGE_LENGTH = 500;

/**
 * Analyzer id shape: lower-case, dot-separated namespaces (`security.node`,
 * `test.finding`). Enforced at registration so ids stay stable, sortable and
 * usable as namespaced selectors — never random, never host-derived.
 */
export const ANALYZER_ID_PATTERN = /^[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)*$/;

/**
 * Scope shape: a plain domain namespace (`security`, `testing`, `architecture`).
 *
 * Deliberately **not** a closed vocabulary: adding a domain (say `licensing`)
 * must not require a framework change. The value is validated for shape only.
 */
export const ANALYZER_SCOPE_PATTERN = /^[a-z][a-z0-9-]*$/;

/**
 * Keys that must never appear on a framework result.
 *
 * The framework reports what was observed and what failed. Turning that into a
 * score, grade or verdict is domain interpretation that belongs to a later phase,
 * and a result contract that permitted it would invite exactly the "72% secure"
 * output the architecture forbids.
 */
export const ANALYSIS_JUDGMENT_KEYS = Object.freeze([
  "score",
  "grade",
  "verdict",
  "productionReady",
  "risk",
  "quality",
]);

/** Version pattern shared with the Core (rules, analyzers, models). */
export const VERSION_PATTERN = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)*$/;
