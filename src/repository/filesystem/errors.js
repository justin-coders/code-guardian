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
 * Sanitization guarantee (Phase 8A correction 2): a `FilesystemError` message is
 * *derived* from the failure kind and operation and never copies a raw Node
 * message, which can embed absolute paths. `details.path` is only ever a
 * repository-relative path; absolute inputs (POSIX, drive-letter or UNC) are
 * dropped to `null`. The original low-level error is retained only as an
 * internal `cause` and is never serialized (the Core base class omits `cause`
 * and `stack` from `toJSON()`).
 */

import nodePath from "node:path";

import { RepositoryError } from "../../core/index.js";

/** Coarse filesystem failure kinds the infrastructure distinguishes. */
export const FILESYSTEM_ERROR_KINDS = Object.freeze({
  NOT_FOUND: "NOT_FOUND",
  PERMISSION_DENIED: "PERMISSION_DENIED",
  INVALID_PATH: "INVALID_PATH",
  SYMLINK_NOT_ALLOWED: "SYMLINK_NOT_ALLOWED",
  FILESYSTEM_ERROR: "FILESYSTEM_ERROR",
});

/** Stable, machine-readable codes for each filesystem failure kind. */
export const FILESYSTEM_ERROR_CODES = Object.freeze({
  NOT_FOUND: "CG_FS_NOT_FOUND",
  PERMISSION_DENIED: "CG_FS_PERMISSION_DENIED",
  INVALID_PATH: "CG_FS_INVALID_PATH",
  SYMLINK_NOT_ALLOWED: "CG_FS_SYMLINK_NOT_ALLOWED",
  FILESYSTEM_ERROR: "CG_FS_ERROR",
});

/** Deterministic message fragments, keyed by failure kind. */
const KIND_MESSAGES = Object.freeze({
  [FILESYSTEM_ERROR_KINDS.NOT_FOUND]: "filesystem path not found",
  [FILESYSTEM_ERROR_KINDS.PERMISSION_DENIED]: "filesystem permission denied",
  [FILESYSTEM_ERROR_KINDS.INVALID_PATH]: "invalid filesystem path",
  [FILESYSTEM_ERROR_KINDS.SYMLINK_NOT_ALLOWED]:
    "symlink traversal is not allowed",
  [FILESYSTEM_ERROR_KINDS.FILESYSTEM_ERROR]: "filesystem operation failed",
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

const WINDOWS_DRIVE_PATH = /^[a-zA-Z]:[\\/]/;
const UNC_PATH = /^\\\\/;

/** Coerce an unknown kind to a known one, defaulting to FILESYSTEM_ERROR. */
function normaliseKind(kind) {
  return Object.values(FILESYSTEM_ERROR_KINDS).includes(kind)
    ? kind
    : FILESYSTEM_ERROR_KINDS.FILESYSTEM_ERROR;
}

/**
 * Build the deterministic, path-free message for a failure.
 * @param {string} kind One of `FILESYSTEM_ERROR_KINDS`.
 * @param {string} [operation]
 * @returns {string}
 */
export function filesystemErrorMessage(kind, operation) {
  const base = KIND_MESSAGES[normaliseKind(kind)];
  return typeof operation === "string" && operation !== ""
    ? `${operation}: ${base}`
    : base;
}

/**
 * Keep only repository-relative paths.
 *
 * Absolute POSIX paths, Windows drive-letter paths and UNC paths are all
 * dropped, so a serialized error can never reveal a local absolute location.
 * @param {unknown} value
 * @returns {string|null}
 */
export function sanitizeFilesystemPath(value) {
  if (typeof value !== "string" || value.trim() === "") return null;
  if (value.includes("\0")) return null;
  if (nodePath.isAbsolute(value)) return null;
  if (WINDOWS_DRIVE_PATH.test(value)) return null;
  if (UNC_PATH.test(value)) return null;
  return value;
}

/**
 * A structured, sanitized filesystem failure.
 *
 * The message is always derived from `kind` + `operation`; no raw message is
 * accepted, so an absolute path can never reach the serialized error.
 * `details` records `{ kind, operation, path }` where `path` is a
 * repository-relative path or `null`.
 */
export class FilesystemError extends RepositoryError {
  /**
   * @param {object} [options]
   * @param {string} [options.kind] One of `FILESYSTEM_ERROR_KINDS`.
   * @param {string} [options.code] Override the derived machine code.
   * @param {string} [options.operation] Operation that failed (e.g. "readFile").
   * @param {string} [options.path] Repository-relative path, when known.
   * @param {Error} [options.cause] Underlying error (never auto-exposed).
   */
  constructor(options = {}) {
    const kind = normaliseKind(options.kind);
    const operation =
      typeof options.operation === "string" && options.operation !== ""
        ? options.operation
        : null;
    super(filesystemErrorMessage(kind, operation), {
      code: options.code ?? FILESYSTEM_ERROR_CODES[kind],
      details: {
        kind,
        operation,
        path: sanitizeFilesystemPath(options.path),
      },
      cause: options.cause,
    });
    /** The distinguished failure kind. */
    this.kind = kind;
  }
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
 * classified from its `errno` code. The raw error is attached as `cause` only —
 * its message is never copied, because Node filesystem messages can embed
 * absolute paths.
 *
 * @param {unknown} error
 * @param {{ operation?: string, path?: string|null }} [context]
 * @returns {FilesystemError}
 */
export function toFilesystemError(error, context = {}) {
  if (error instanceof FilesystemError) return error;
  const kind = classifyFilesystemError(error);
  return new FilesystemError({
    kind,
    operation: context.operation,
    path: context.path ?? null,
    cause: error,
  });
}
