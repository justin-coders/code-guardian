/**
 * Code Guardian Core — Structured Errors
 *
 * Small, transport-independent error hierarchy for the Core contract layer.
 *
 * Design rules (Phase 7 / Architecture Specification §48):
 * - Errors must be distinguishable: analysis finding vs tool failure vs
 *   repository error vs execution failure vs configuration error.
 * - Every error carries a stable machine-readable `code`, a `category`, and
 *   structured `details` so interfaces can present useful errors.
 * - Internal stack traces and `cause` chains are never exposed by `toJSON()`;
 *   callers decide whether an error is safe to surface (`expose`).
 *
 * This module must not import MCP, HTTP, CLI, or child-process facilities.
 */

/** Coarse error categories used across the Core. */
export const ERROR_CATEGORIES = Object.freeze({
  CORE: "core",
  VALIDATION: "validation",
  CONFIGURATION: "configuration",
  REPOSITORY: "repository",
  EXECUTION: "execution",
  ANALYSIS: "analysis",
});

/** Stable, machine-readable error codes. */
export const ERROR_CODES = Object.freeze({
  CORE: "CG_CORE_ERROR",
  VALIDATION: "CG_VALIDATION_ERROR",
  CONFIGURATION: "CG_CONFIGURATION_ERROR",
  REPOSITORY: "CG_REPOSITORY_ERROR",
  EXECUTION: "CG_EXECUTION_ERROR",
  ANALYSIS: "CG_ANALYSIS_ERROR",
});

/**
 * Base class for all Code Guardian Core errors.
 *
 * Subclasses declare `category`, `code` and `expose` as static defaults that
 * individual instances may override.
 */
export class CoreError extends Error {
  /** Category for the base error. */
  static category = ERROR_CATEGORIES.CORE;
  /** Default machine-readable code for the base error. */
  static code = ERROR_CODES.CORE;
  /** Whether `message`/`details` are safe to present to remote clients. */
  static expose = false;

  /**
   * @param {string} message Human-readable summary.
   * @param {object} [options]
   * @param {string} [options.code] Override the class default code.
   * @param {string} [options.category] Override the class default category.
   * @param {object} [options.details] Structured, serializable context.
   * @param {Error} [options.cause] Underlying error (never auto-exposed).
   * @param {boolean} [options.expose] Override the class default exposure.
   */
  constructor(message, options = {}) {
    super(message);
    this.name = new.target.name;
    this.code = options.code ?? new.target.code ?? ERROR_CODES.CORE;
    this.category =
      options.category ?? new.target.category ?? ERROR_CATEGORIES.CORE;
    this.details =
      options.details && typeof options.details === "object"
        ? options.details
        : {};
    this.expose = options.expose ?? new.target.expose ?? false;
    if (options.cause !== undefined) {
      this.cause = options.cause;
    }
    if (typeof Error.captureStackTrace === "function") {
      Error.captureStackTrace(this, new.target);
    }
  }

  /**
   * Safe, serializable representation for interfaces/reports.
   * Intentionally omits `stack` and `cause` so internal details are never
   * leaked automatically to remote clients.
   * @returns {{name: string, code: string, category: string, message: string, details: object, expose: boolean}}
   */
  toJSON() {
    return {
      name: this.name,
      code: this.code,
      category: this.category,
      message: this.message,
      details: this.details,
      expose: this.expose,
    };
  }
}

/** Invalid contract/model input. Safe to surface to clients. */
export class ValidationError extends CoreError {
  static category = ERROR_CATEGORIES.VALIDATION;
  static code = ERROR_CODES.VALIDATION;
  static expose = true;
}

/** Invalid or inconsistent configuration. Safe to surface to clients. */
export class ConfigurationError extends CoreError {
  static category = ERROR_CATEGORIES.CONFIGURATION;
  static code = ERROR_CODES.CONFIGURATION;
  static expose = true;
}

/** Repository access/scan failure. Internal by default. */
export class RepositoryError extends CoreError {
  static category = ERROR_CATEGORIES.REPOSITORY;
  static code = ERROR_CODES.REPOSITORY;
  static expose = false;
}

/** Command execution failure. Internal by default. */
export class ExecutionError extends CoreError {
  static category = ERROR_CATEGORIES.EXECUTION;
  static code = ERROR_CODES.EXECUTION;
  static expose = false;
}

/** Analysis failure. Internal by default. */
export class AnalysisError extends CoreError {
  static category = ERROR_CATEGORIES.ANALYSIS;
  static code = ERROR_CODES.ANALYSIS;
  static expose = false;
}

/**
 * Narrowing helper for consumers that need to branch on Core errors.
 * @param {unknown} value
 * @returns {value is CoreError}
 */
export function isCoreError(value) {
  return value instanceof CoreError;
}
