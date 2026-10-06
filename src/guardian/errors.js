/**
 * Code Guardian — Guardian Core Failures (Official Roadmap Phase 19)
 *
 * One distinction governs this module, and it mirrors the accepted layers below:
 *
 *   the Core cannot do what it was asked   an unknown option key, an invalid
 *     repository input, an unknown analyzer id, an empty selection, a malformed
 *     result. Thrown, because no meaningful audit can be produced.
 *
 *   an analyzer failed                     recorded *inside* the canonical result
 *     (the accepted Analyzer Engine owns analyzer failures). The Core never turns
 *     one analyzer's failure into a thrown exception, because that would erase the
 *     other analyzers' work and the failure's own visibility.
 *
 * Every error carries a stable machine-readable `code` and structured, serializable
 * `details`, so an interface layer can map it to a transport response without
 * parsing prose. No stack trace, `cause` chain or host detail is ever exposed.
 */

import { ConfigurationError, ERROR_CATEGORIES, ValidationError } from "../core/index.js";

import { sanitizeDeclarativeValue } from "../analysis/index.js";

/** Stable codes carried by Guardian Core failures. */
export const GUARDIAN_FAILURE_CODES = Object.freeze({
  invalidRequest: "CG_GUARDIAN_REQUEST_INVALID",
  invalidConfiguration: "CG_GUARDIAN_CONFIGURATION_INVALID",
  invalidRepository: "CG_GUARDIAN_REPOSITORY_INVALID",
  invalidSelection: "CG_GUARDIAN_SELECTION_INVALID",
  emptySelection: "CG_GUARDIAN_SELECTION_EMPTY",
  invalidResult: "CG_GUARDIAN_RESULT_INVALID",
});

/**
 * A Guardian Core *configuration* failure: the audit was asked to do something
 * impossible (an unknown option key, a malformed option value, an unknown or empty
 * analyzer selection). Safe to surface to a client.
 */
export class GuardianConfigurationError extends ConfigurationError {
  /**
   * @param {string} message Safe, framework-authored summary.
   * @param {object} [options]
   * @param {string} [options.code] One of `GUARDIAN_FAILURE_CODES`.
   * @param {object} [options.details] Structured, serializable context.
   */
  constructor(message, { code = GUARDIAN_FAILURE_CODES.invalidConfiguration, details = {} } = {}) {
    super(message, {
      code,
      category: ERROR_CATEGORIES.CONFIGURATION,
      details: sanitizeDeclarativeValue(details) ?? {},
      expose: true,
    });
  }
}

/**
 * A Guardian Core *validation* failure: a canonical result the Core assembled did
 * not satisfy its own contract. This is a framework defect, not a client error, so
 * it is raised as a `ValidationError` rather than a configuration error.
 */
export class GuardianValidationError extends ValidationError {
  /**
   * @param {string} message Safe summary.
   * @param {object} [options]
   * @param {string[]} [options.issues] Human-readable contract violations.
   */
  constructor(message, { issues = [] } = {}) {
    super(message, {
      code: GUARDIAN_FAILURE_CODES.invalidResult,
      details: {
        contract: "GuardianResult",
        issues: issues.map((issue) => String(issue)).slice(0, 200),
      },
      expose: true,
    });
  }
}
