/**
 * Code Guardian — Analyzer Framework Failures (Phase 9)
 *
 * Two different things can go wrong, and they are handled differently on purpose:
 *
 *   framework failure  the framework cannot do what it was asked (unknown
 *                      analyzer id, duplicate registration, invalid context).
 *                      Thrown, because the run cannot start meaningfully.
 *
 *   analyzer failure   one analyzer produced bad output or crashed. Recorded in
 *                      the run result, never thrown, so the remaining analyzers
 *                      still run and the failure is visible in the report.
 *
 * Error *entries* are sanitized: no stack traces, no `cause` chains, bounded
 * messages, and structured details copied into plain JSON-safe data. An analyzer
 * that throws an error containing a host path or a secret must not be able to put
 * it into a serializable result — and because the entry is built from an explicit
 * allowlist of fields, nothing else can leak in either.
 */

import {
  AnalysisError,
  ConfigurationError,
  ERROR_CATEGORIES,
  ValidationError,
} from "../core/index.js";

import {
  ANALYZER_FAILURE_CODES,
  ANALYZER_FAILURE_KINDS,
  MAX_ERROR_MESSAGE_LENGTH,
} from "./contracts.js";
import { sanitizeDeclarativeValue } from "./values.js";

/** Which stable code belongs to each failure kind. */
export const FAILURE_CODE_BY_KIND = Object.freeze({
  [ANALYZER_FAILURE_KINDS.INVALID_ANALYZER]: ANALYZER_FAILURE_CODES.invalidAnalyzer,
  [ANALYZER_FAILURE_KINDS.DUPLICATE_ANALYZER]: ANALYZER_FAILURE_CODES.duplicateAnalyzer,
  [ANALYZER_FAILURE_KINDS.UNKNOWN_ANALYZER]: ANALYZER_FAILURE_CODES.unknownAnalyzer,
  [ANALYZER_FAILURE_KINDS.INVALID_APPLICABILITY]: ANALYZER_FAILURE_CODES.invalidApplicability,
  [ANALYZER_FAILURE_KINDS.INVALID_ANALYSIS_RESULT]: ANALYZER_FAILURE_CODES.invalidAnalysisResult,
  [ANALYZER_FAILURE_KINDS.ANALYZER_FAILURE]: ANALYZER_FAILURE_CODES.threw,
  [ANALYZER_FAILURE_KINDS.INVALID_FINDING]: ANALYZER_FAILURE_CODES.invalidFinding,
  [ANALYZER_FAILURE_KINDS.UNKNOWN_EVIDENCE_REFERENCE]: ANALYZER_FAILURE_CODES.unknownEvidence,
  [ANALYZER_FAILURE_KINDS.UNSAFE_EVIDENCE_PATH]: ANALYZER_FAILURE_CODES.unsafeEvidencePath,
  [ANALYZER_FAILURE_KINDS.DUPLICATE_EVIDENCE_ID]: ANALYZER_FAILURE_CODES.duplicateEvidenceId,
  [ANALYZER_FAILURE_KINDS.FAIL_FAST_ABORT]: ANALYZER_FAILURE_CODES.failFastAbort,
});

/**
 * A framework-level failure that prevents or corrupts a run.
 *
 * Thrown for: registering an invalid analyzer, registering a duplicate id, and
 * requesting an unknown analyzer id. The `details.kind` carries the framework
 * vocabulary so callers can branch without parsing messages.
 */
export class AnalyzerFrameworkError extends AnalysisError {
  /**
   * @param {string} kind One of `ANALYZER_FAILURE_KINDS`.
   * @param {string} message Safe, framework-authored summary.
   * @param {object} [details] Structured, serializable context.
   */
  constructor(kind, message, details = {}) {
    super(message, {
      code: FAILURE_CODE_BY_KIND[kind] ?? ANALYZER_FAILURE_CODES.threw,
      details: { kind, ...sanitizeDeclarativeValue(details) },
      expose: true,
    });
    this.kind = kind;
  }
}

/** A framework-level *configuration* problem (unknown analyzer id, duplicate id). */
export class AnalyzerConfigurationError extends ConfigurationError {
  /**
   * @param {string} kind One of `ANALYZER_FAILURE_KINDS`.
   * @param {string} message Safe, framework-authored summary.
   * @param {object} [details] Structured, serializable context.
   */
  constructor(kind, message, details = {}) {
    super(message, {
      code: FAILURE_CODE_BY_KIND[kind] ?? ANALYZER_FAILURE_CODES.unknownAnalyzer,
      category: ERROR_CATEGORIES.CONFIGURATION,
      details: { kind, ...sanitizeDeclarativeValue(details) },
      expose: true,
    });
    this.kind = kind;
  }
}

/** A malformed analyzer descriptor at registration time. */
export class AnalyzerRegistrationError extends ValidationError {
  /**
   * @param {string[]} issues Human-readable contract violations.
   * @param {object} [details] Structured, serializable context.
   */
  constructor(issues, details = {}) {
    super("Invalid analyzer", {
      code: ANALYZER_FAILURE_CODES.invalidAnalyzer,
      details: {
        kind: ANALYZER_FAILURE_KINDS.INVALID_ANALYZER,
        contract: "Analyzer",
        issues: issues.map((issue) => String(issue).slice(0, MAX_ERROR_MESSAGE_LENGTH)),
        ...sanitizeDeclarativeValue(details),
      },
      expose: true,
    });
    this.kind = ANALYZER_FAILURE_KINDS.INVALID_ANALYZER;
  }
}

/** Strip control characters and bound a message so it is always safe to store. */
export function sanitizeMessage(value) {
  const text = typeof value === "string" ? value : String(value ?? "");
  /* eslint-disable-next-line no-control-regex */
  const cleaned = text.replace(/[\u0000-\u001f\u007f]+/g, " ").trim();
  if (cleaned === "") return "analyzer failed without a message";
  return cleaned.length > MAX_ERROR_MESSAGE_LENGTH
    ? `${cleaned.slice(0, MAX_ERROR_MESSAGE_LENGTH)}…`
    : cleaned;
}

/**
 * Turn anything an analyzer threw into a sanitized failure entry.
 *
 * Deliberately field-by-field: `stack`, `cause` and the raw error are never
 * copied, and `details` is sanitized rather than trusted. A Core error keeps its
 * stable code; anything else gets the "threw" code.
 *
 * @param {unknown} error
 * @param {object} context
 * @param {string} context.kind Failure kind.
 * @param {string} [context.analyzerId]
 * @param {object} [context.details] Framework-authored details to merge.
 * @returns {{kind: string, code: string, analyzerId: string|null, message: string, details?: object}}
 */
export function failureEntry(error, { kind, analyzerId = null, details = {} } = {}) {
  const entry = {
    kind,
    code: FAILURE_CODE_BY_KIND[kind] ?? ANALYZER_FAILURE_CODES.threw,
    analyzerId,
    message: sanitizeMessage(error instanceof Error ? error.message : error),
  };

  const merged = { ...details };
  if (error !== null && typeof error === "object") {
    if (typeof error.code === "string") entry.code = error.code;
    if (error.details !== undefined) merged.reported = error.details;
  }
  const sanitized = sanitizeDeclarativeValue(merged);
  if (sanitized !== undefined && Object.keys(sanitized).length > 0) {
    entry.details = sanitized;
  }

  return entry;
}
