/**
 * Code Guardian — Rule Engine Failures (Phase 10)
 *
 * Two different things can go wrong, handled differently on purpose:
 *
 *   framework failure  the engine cannot do what it was asked (unknown rule id,
 *                      duplicate registration, malformed descriptor). Thrown,
 *                      because the run cannot start meaningfully.
 *
 *   rule failure       one rule produced bad output or crashed. Recorded in the
 *                      rule run result, never thrown, so the remaining rules still
 *                      run and the failure stays observable.
 *
 * Error *entries* are sanitized exactly as in Phase 9: no stack traces, no `cause`
 * chains, bounded messages, and structured details copied into plain JSON-safe
 * data through an explicit allowlist. A rule that throws an error containing a
 * host path or a secret must not be able to put it into a serializable result.
 */

import {
  AnalysisError,
  ConfigurationError,
  ERROR_CATEGORIES,
  ValidationError,
} from "../core/index.js";
import { sanitizeDeclarativeValue } from "../analysis/index.js";

import {
  MAX_ERROR_MESSAGE_LENGTH,
  RULE_FAILURE_CODES,
  RULE_FAILURE_KINDS,
} from "./contracts.js";

/** Which stable code belongs to each failure kind. */
export const FAILURE_CODE_BY_KIND = Object.freeze({
  [RULE_FAILURE_KINDS.INVALID_RULE]: RULE_FAILURE_CODES.invalidRule,
  [RULE_FAILURE_KINDS.DUPLICATE_RULE]: RULE_FAILURE_CODES.duplicateRule,
  [RULE_FAILURE_KINDS.UNKNOWN_RULE]: RULE_FAILURE_CODES.unknownRule,
  [RULE_FAILURE_KINDS.INVALID_APPLICABILITY]: RULE_FAILURE_CODES.invalidApplicability,
  [RULE_FAILURE_KINDS.RULE_FAILURE]: RULE_FAILURE_CODES.threw,
  [RULE_FAILURE_KINDS.INVALID_RULE_RESULT]: RULE_FAILURE_CODES.invalidRuleResult,
  [RULE_FAILURE_KINDS.INVALID_FINDING]: RULE_FAILURE_CODES.invalidFinding,
  [RULE_FAILURE_KINDS.INVALID_EVIDENCE]: RULE_FAILURE_CODES.invalidEvidence,
  [RULE_FAILURE_KINDS.UNSAFE_EVIDENCE_PATH]: RULE_FAILURE_CODES.unsafeEvidencePath,
  [RULE_FAILURE_KINDS.DUPLICATE_EVIDENCE_ID]: RULE_FAILURE_CODES.duplicateEvidenceId,
  [RULE_FAILURE_KINDS.FAIL_FAST_ABORT]: RULE_FAILURE_CODES.failFastAbort,
});

/**
 * A framework-level failure that prevents or corrupts a rule run.
 *
 * Thrown for: registering an invalid rule, registering a duplicate id, and
 * selecting an unknown rule id. `details.kind` carries the framework vocabulary so
 * callers can branch without parsing messages.
 */
export class RuleFrameworkError extends AnalysisError {
  /**
   * @param {string} kind One of `RULE_FAILURE_KINDS`.
   * @param {string} message Safe, framework-authored summary.
   * @param {object} [details] Structured, serializable context.
   */
  constructor(kind, message, details = {}) {
    super(message, {
      code: FAILURE_CODE_BY_KIND[kind] ?? RULE_FAILURE_CODES.threw,
      details: { kind, ...sanitizeDeclarativeValue(details) },
      expose: true,
    });
    this.kind = kind;
  }
}

/** A framework-level *configuration* problem (unknown rule id, duplicate id). */
export class RuleConfigurationError extends ConfigurationError {
  /**
   * @param {string} kind One of `RULE_FAILURE_KINDS`.
   * @param {string} message Safe, framework-authored summary.
   * @param {object} [details] Structured, serializable context.
   */
  constructor(kind, message, details = {}) {
    super(message, {
      code: FAILURE_CODE_BY_KIND[kind] ?? RULE_FAILURE_CODES.unknownRule,
      category: ERROR_CATEGORIES.CONFIGURATION,
      details: { kind, ...sanitizeDeclarativeValue(details) },
      expose: true,
    });
    this.kind = kind;
  }
}

/** A malformed rule descriptor at registration time. */
export class RuleRegistrationError extends ValidationError {
  /**
   * @param {string[]} issues Human-readable contract violations.
   * @param {object} [details] Structured, serializable context.
   */
  constructor(issues, details = {}) {
    super("Invalid rule", {
      code: RULE_FAILURE_CODES.invalidRule,
      details: {
        kind: RULE_FAILURE_KINDS.INVALID_RULE,
        contract: "Rule",
        issues: issues.map((issue) => String(issue).slice(0, MAX_ERROR_MESSAGE_LENGTH)),
        ...sanitizeDeclarativeValue(details),
      },
      expose: true,
    });
    this.kind = RULE_FAILURE_KINDS.INVALID_RULE;
  }
}

/** Strip control characters and bound a message so it is always safe to store. */
export function sanitizeMessage(value) {
  const text = typeof value === "string" ? value : String(value ?? "");
  /* eslint-disable-next-line no-control-regex */
  const cleaned = text.replace(/[\u0000-\u001f\u007f]+/g, " ").trim();
  if (cleaned === "") return "rule failed without a message";
  return cleaned.length > MAX_ERROR_MESSAGE_LENGTH
    ? `${cleaned.slice(0, MAX_ERROR_MESSAGE_LENGTH)}…`
    : cleaned;
}

/**
 * Turn anything a rule threw into a sanitized failure entry.
 *
 * Deliberately field-by-field: `stack`, `cause` and the raw error are never
 * copied, and `details` is sanitized rather than trusted. A Core error keeps its
 * stable code; anything else gets the "threw" code.
 *
 * @param {unknown} error
 * @param {object} context
 * @param {string} context.kind Failure kind.
 * @param {string} [context.ruleId]
 * @param {object} [context.details] Framework-authored details to merge.
 * @returns {{kind: string, code: string, ruleId: string|null, message: string, details?: object}}
 */
export function ruleFailureEntry(error, { kind, ruleId = null, details = {} } = {}) {
  const entry = {
    kind,
    code: FAILURE_CODE_BY_KIND[kind] ?? RULE_FAILURE_CODES.threw,
    ruleId,
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

/**
 * Reduce a failure entry to the fields safe to surface through an analyzer result.
 *
 * Phase 9 bounds analyzer metadata with `sanitizeDeclarativeValue` regardless, but
 * picking an explicit allowlist here means a rule failure can never grow a field
 * that leaks by accident.
 *
 * @param {{ruleId?: string|null, kind: string, code: string, message: string}} entry
 * @returns {{ruleId: string|null, kind: string, code: string, message: string}}
 */
export function sanitizeRuleFailure(entry) {
  return {
    ruleId: entry?.ruleId ?? null,
    kind: String(entry?.kind ?? ""),
    code: String(entry?.code ?? ""),
    message: sanitizeMessage(entry?.message ?? ""),
  };
}
