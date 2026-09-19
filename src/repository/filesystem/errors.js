/**
 * Code Guardian — Filesystem Error Semantics (Phase 8A)
 *
 * Filesystem failures must stay observable. The legacy helpers returned `null`
 * or `[]` from a bare `catch`, which silently turned "permission denied" into
 * "file does not exist". This module gives every failure a stable, structured
 * representation instead.
 *
 * Boundary note (Phase 8A §8): `src/core` must never learn about filesystem
 * details, so this layer depends on Core — never the other way around. The
 * structured error extends the Core `RepositoryError`, which keeps it
 * distinguishable (category `repository`) while living entirely in the
 * filesystem infrastructure.
 *
 * Error objects intentionally carry only `operation`, `relative`/`path` and the
 * failing code. File contents, absolute paths and `cause` chains are never
 * surfaced by `toJSON()`, which the Core base class already guarantees.
 */

import { RepositoryError } from "../../core/index.js";

/** Coarse filesystem failure kinds the infrastructure distinguishes. */
export const FILESYSTEM_ERROR_KINDS = Object.freeze({
  NOT_FOUND: "NOT_FOUND",
  PERMISSION_DENIED: "PERMISSION_DENIED",
  INVALID_PATH: "INVALID_PATH",
  FILESYSTEM_ERROR: "FILESYSTEM_ERROR",
});

/** Stable, machine-readable codes for each filesystem failure kind. */
export const FILESYSTEM_ERROR_CODES = Object.freeze({
  NOT_FOUND: "CG_FS_NOT_FOUND",
  PERMISSION_DENIED: "CG_FS_PERMISSION_DENIED",
  INVALID_PATH: "CG_FS_INVALID_PATH",
  FILESYSTEM_ERROR: "CG_FS_ERROR",
});

/**
 * Map of Node `errno` codes to filesystem failure kinds.
 *
 * `ENOTDIR` is treated as NOT_FOUND because it means the path does not lead to
 * the expected node (a non-directory sits where a directory was required).
 * Anything unmapped is reported as the generic FILESYSTEM_ERROR rather than
 * being guessed at.
 */
const ERRNO_KIND_MAP = Object.freeze({
  ENOENT: FILESYSTEM_ERROR_KINDS.NOT_FOUND,
  ENOTDIR: FILESYSTEM_ERROR_KINDS.NOT_FOUND,
  EACCES: FILESYSTEM_ERROR_KINDS.PERMISSION_DENIED,
  EPERM: FILESYSTEM_ERROR_KINDS.PERMISSION_DENIED,
  EINVAL: FILESYSTEM_ERROR_KINDS.INVALID_PATH,
  ENAMETOOLONG: FILESYSTEM_ERROR_KINDS.INVALID_PATH,
  ELOOP: FILESYSTEM_ERROR_KINDS.FILESYSTEM_ERROR,
  EISDIR: FILESYSTEM_ERROR_KINDS.FILESYSTEM_ERROR,
});

/**
 * A structured filesystem failure.
 *
 * `details` always records `{ kind, operation, path }` so future Evidence can
 * reference the failure without re-deriving it.
 */
export class FilesystemError extends RepositoryError {
  /**
   * @param {string} message Human-readable summary.
   * @param {object} [options]
   * @param {string} [options.kind] One of `FILESYSTEM_ERROR_KINDS`.
   * @param {string} [options.code] Override the derived machine code.
   * @param {string} [options.operation] Operation that failed (e.g. "readFile").
   * @param {string} [options.path] Repository-relative path, when known.
   * @param {Error} [options.cause] Underlying error (never auto-exposed).
   */
  constructor(message, options = {}) {
    const kind = normaliseKind(options.kind);
    super(message, {
      code: options.code ?? FILESYSTEM_ERROR_CODES[kind],
      details: {
        kind,
        operation: options.operation ?? null,
        path: options.path ?? null,
      },
      cause: options.cause,
    });
    /** The distinguished failure kind. */
    this.kind = kind;
  }
}

/** Coerce an unknown kind to a known one, defaulting to FILESYSTEM_ERROR. */
function normaliseKind(kind) {
  return Object.values(FILESYSTEM_ERROR_KINDS).includes(kind)
    ? kind
    : FILESYSTEM_ERROR_KINDS.FILESYSTEM_ERROR;
}

/**
 * Classify a thrown Node error into a `FILESYSTEM_ERROR_KINDS` value.
 * @param {unknown} error
 * @returns {string}
 */
export function classifyFilesystemError(error) {
  const code = error && typeof error === "object" ? error.code : undefined;
  return ERRNO_KIND_MAP[code] ?? FILESYSTEM_ERROR_KINDS.FILESYSTEM_ERROR;
}

/**
 * Convert any thrown value into a structured `FilesystemError`.
 *
 * An existing `FilesystemError` is passed through unchanged; everything else is
 * classified from its `errno` code. The original error is attached as `cause`
 * only — it is never serialized.
 *
 * @param {unknown} error
 * @param {{ operation?: string, path?: string|null }} [context]
 * @returns {FilesystemError}
 */
export function toFilesystemError(error, context = {}) {
  if (error instanceof FilesystemError) return error;
  const kind = classifyFilesystemError(error);
  const message =
    error && typeof error === "object" && typeof error.message === "string"
      ? error.message
      : "filesystem operation failed";
  return new FilesystemError(message, {
    kind,
    operation: context.operation,
    path: context.path ?? null,
    cause: error,
  });
}
