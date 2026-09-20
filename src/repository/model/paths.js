/**
 * Code Guardian — RepositoryModel Path Semantics (Phase 8D)
 *
 * The model is built from a validated `ScanResult`, whose paths the Phase 8A
 * boundary already contained. This module is nevertheless a **strict guard**, not
 * a normalizer that forgives: it is the last place before untrusted scanner text
 * becomes a model identity, so a path that is not already a canonical
 * repository-relative POSIX path is *rejected* rather than silently repaired.
 *
 * What counts as repository-relative:
 *
 *   `src/app.ts`            accepted (canonical)
 *   `src/app.ts`            rejected if it had a trailing `/`, `./`, `//`,
 *                           a `.`/`..` segment, a `\`, a leading `/`, a Windows
 *                           drive prefix (`C:`), a UNC prefix (`\\host\share`),
 *                           a NUL byte or any other control character.
 *
 * Repairing such input would be the wrong failure mode: `a/../b` normalizes to
 * `b`, which means a model could be made to claim a file exists somewhere the
 * scanner never observed. Rejection is deterministic and fail-closed.
 *
 * This module performs no filesystem access of any kind — it is pure string
 * handling over already-collected facts.
 */

import { ValidationError } from "../../core/index.js";

/** Maximum length accepted for a single repository-relative path. */
export const MAX_RELATIVE_PATH_LENGTH = 4096;

const DRIVE_PREFIX = /^[A-Za-z]:/;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;

/**
 * Whether a value is a canonical repository-relative POSIX path.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isRepositoryRelativePath(value) {
  if (typeof value !== "string") return false;
  if (value === "" || value.length > MAX_RELATIVE_PATH_LENGTH) return false;
  if (value.includes("\\")) return false;
  if (value.startsWith("/") || DRIVE_PREFIX.test(value)) return false;
  if (value.endsWith("/")) return false;
  // Control characters (including NUL) are never legitimate path content, but
  // otherwise the guard is deliberately Unicode-transparent: real repositories
  // contain non-ASCII file names, and rejecting them would fail valid scans
  // without improving safety. The escapes that matter are the structural ones
  // checked above and below.
  if (CONTROL_CHARACTERS.test(value)) return false;

  const segments = value.split("/");
  for (const segment of segments) {
    if (segment === "" || segment === "." || segment === "..") return false;
  }
  return true;
}

/**
 * Canonicalize a repository-relative path, rejecting anything else.
 *
 * Canonicalization is the identity function for already-canonical input, so the
 * guard and the canonical form are deliberately the same operation: a caller
 * cannot normalize a hostile path into an acceptable one.
 *
 * @param {unknown} value
 * @returns {string|null} The canonical relative path, or `null` when rejected.
 */
export function toRepositoryRelativePath(value) {
  return isRepositoryRelativePath(value) ? value : null;
}

/**
 * Guard a path that is about to become a model identity.
 *
 * The message never echoes the rejected value: scanner text may itself be the
 * attack (an absolute host path, a traversal), so it must not be copied into an
 * error that a caller can serialize.
 *
 * @param {unknown} value
 * @param {string} label Where the path came from, for the issue list.
 * @returns {string} The canonical relative path.
 * @throws {ValidationError} When the value is not repository-relative.
 */
export function requireRepositoryRelativePath(value, label) {
  const canonical = toRepositoryRelativePath(value);
  if (canonical !== null) return canonical;
  throw new ValidationError("Invalid repository model path", {
    details: {
      contract: "RepositoryModelPath",
      issues: [`${label}: must be a canonical repository-relative POSIX path`],
    },
  });
}

/**
 * Depth of a repository-relative path (root-level entries are depth 1).
 * @param {string} relativePath
 * @returns {number}
 */
export function depthOfPath(relativePath) {
  return relativePath.split("/").length;
}

/**
 * Parent directory of a repository-relative path, or `null` at the root.
 * @param {string} relativePath
 * @returns {string|null}
 */
export function parentPathOf(relativePath) {
  const index = relativePath.lastIndexOf("/");
  return index === -1 ? null : relativePath.slice(0, index);
}

/**
 * Base name of a repository-relative path.
 * @param {string} relativePath
 * @returns {string}
 */
export function basenameOfPath(relativePath) {
  const index = relativePath.lastIndexOf("/");
  return index === -1 ? relativePath : relativePath.slice(index + 1);
}

