/**
 * Code Guardian — Repository Query Errors (Phase 11)
 *
 * The query layer is a *read-only* view over an already-validated RepositoryModel,
 * so almost nothing that a caller asks it can fail: an unknown entity is `null`, an
 * absent relationship is `[]`. Those are ordinary query *results*, not errors, and
 * turning them into exceptions would push callers into try/catch for normal
 * control flow.
 *
 * What remains are **programmer errors** — a typo'd entity kind, a negative
 * traversal depth, an unknown relationship type, a query object with a bogus field.
 * Silently ignoring those is the dangerous failure mode this codebase keeps
 * rejecting: `listEntities("framwork")` returning `[]` would read as "no frameworks
 * exist" and let a rule assert an absence that was really a typo. So those throw a
 * `RepositoryQueryError`.
 *
 * The error follows the established Phase 8A/Rule pattern:
 *
 *   - a stable `kind` and machine-readable `code`;
 *   - a message *derived* from the kind, never a copied raw value;
 *   - structured `details` that are path-safe (an echoed value is kept only when it
 *     is a short identifier, so a hostile path can never be reflected into a
 *     serializable error);
 *   - `expose: true`, because a query misuse is safe to surface.
 */

import { ConfigurationError, ERROR_CATEGORIES } from "../../core/index.js";

/** Coarse query failure kinds. */
export const QUERY_ERROR_KINDS = Object.freeze({
  INVALID_MODEL: "invalid-model",
  INVALID_QUERY: "invalid-query",
  INVALID_ENTITY_KIND: "invalid-entity-kind",
  INVALID_DIRECTION: "invalid-direction",
  INVALID_RELATIONSHIP_TYPE: "invalid-relationship-type",
  INVALID_LIMIT: "invalid-limit",
});

/** Stable, machine-readable codes for each query failure kind. */
export const QUERY_ERROR_CODES = Object.freeze({
  [QUERY_ERROR_KINDS.INVALID_MODEL]: "CG_QUERY_INVALID_MODEL",
  [QUERY_ERROR_KINDS.INVALID_QUERY]: "CG_QUERY_INVALID",
  [QUERY_ERROR_KINDS.INVALID_ENTITY_KIND]: "CG_QUERY_ENTITY_KIND_INVALID",
  [QUERY_ERROR_KINDS.INVALID_DIRECTION]: "CG_QUERY_DIRECTION_INVALID",
  [QUERY_ERROR_KINDS.INVALID_RELATIONSHIP_TYPE]: "CG_QUERY_RELATIONSHIP_TYPE_INVALID",
  [QUERY_ERROR_KINDS.INVALID_LIMIT]: "CG_QUERY_LIMIT_INVALID",
});

/** Deterministic message fragments, keyed by failure kind. */
const KIND_MESSAGES = Object.freeze({
  [QUERY_ERROR_KINDS.INVALID_MODEL]: "a RepositoryModel is required",
  [QUERY_ERROR_KINDS.INVALID_QUERY]: "invalid query",
  [QUERY_ERROR_KINDS.INVALID_ENTITY_KIND]: "unknown entity kind",
  [QUERY_ERROR_KINDS.INVALID_DIRECTION]: "invalid relationship direction",
  [QUERY_ERROR_KINDS.INVALID_RELATIONSHIP_TYPE]: "unknown relationship type",
  [QUERY_ERROR_KINDS.INVALID_LIMIT]: "invalid traversal limit",
});

/** Maximum length kept when a value is echoed back into structured details. */
export const MAX_QUERY_TOKEN_LENGTH = 64;

const SAFE_TOKEN = /^[a-z0-9][a-z0-9_:.-]*$/;

/**
 * Keep a caller-supplied token only when it is a short, lower-case identifier.
 *
 * This is what stops a hostile value (an absolute path, a traversal) from being
 * reflected into a serialized error: anything containing `/`, `\`, a leading dot or
 * an unexpected character is dropped to `null`. Numbers are kept when finite.
 *
 * @param {unknown} value
 * @returns {string|number|null}
 */
export function safeQueryToken(value) {
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value !== "string") return null;
  if (value.length === 0 || value.length > MAX_QUERY_TOKEN_LENGTH) return null;
  return SAFE_TOKEN.test(value) ? value : null;
}

/** Normalise an unknown kind to a known one, defaulting to `invalid-query`. */
function normaliseKind(kind) {
  return Object.values(QUERY_ERROR_KINDS).includes(kind)
    ? kind
    : QUERY_ERROR_KINDS.INVALID_QUERY;
}

/**
 * A structured, sanitized query failure.
 *
 * Thrown only for programmer errors (unknown kind/type/direction, invalid limits,
 * a malformed query object, a missing model). Ordinary "not found" results never
 * throw.
 */
export class RepositoryQueryError extends ConfigurationError {
  /**
   * @param {string} kind One of `QUERY_ERROR_KINDS`.
   * @param {object} [details] Structured, path-safe context.
   */
  constructor(kind, details = {}) {
    const resolved = normaliseKind(kind);
    super(KIND_MESSAGES[resolved], {
      code: QUERY_ERROR_CODES[resolved],
      category: ERROR_CATEGORIES.CONFIGURATION,
      details: { kind: resolved, ...details },
      expose: true,
    });
    /** The distinguished failure kind. */
    this.kind = resolved;
  }
}
