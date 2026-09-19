/**
 * Code Guardian — Working Directory Resolution (Phase 8B)
 *
 * The working directory is security-sensitive: `spawn({ cwd })` runs the child
 * *there*, so a cwd outside the authorized roots is a policy escape.
 *
 * Containment is decided by the accepted Phase 8A path layer
 * (`isContained`/`resolvePath`/`normalizeRoot`) — this module never re-implements
 * string-prefix containment. A lexical check alone is not enough, because a
 * symlinked `cwd` can point outside the root while looking contained, so the
 * resolved (`realpath`) forms are cross-checked as well.
 *
 * Outcomes are distinguishable: missing root config, outside-root, invalid
 * path, missing directory, non-directory, and permission failure each map to a
 * distinct rejection kind. Nothing here is collapsed into "command failed".
 */

import { realpath, stat } from "node:fs/promises";

import {
  FILESYSTEM_ERROR_KINDS,
  classifyFilesystemError,
  isContained,
  normalizeRoot,
  resolvePath,
  toRepositoryRelative,
} from "../repository/filesystem/index.js";

import { EXECUTION_ERROR_KINDS } from "./errors.js";

const FS_KIND_TO_REJECTION = Object.freeze({
  [FILESYSTEM_ERROR_KINDS.NOT_FOUND]: EXECUTION_ERROR_KINDS.CWD_NOT_FOUND,
  [FILESYSTEM_ERROR_KINDS.PERMISSION_DENIED]:
    EXECUTION_ERROR_KINDS.CWD_PERMISSION_DENIED,
  [FILESYSTEM_ERROR_KINDS.INVALID_PATH]: EXECUTION_ERROR_KINDS.CWD_INVALID,
  [FILESYSTEM_ERROR_KINDS.FILESYSTEM_ERROR]: EXECUTION_ERROR_KINDS.CWD_INVALID,
});

function rejectionFromFilesystemError(error) {
  return (
    FS_KIND_TO_REJECTION[classifyFilesystemError(error)] ??
    EXECUTION_ERROR_KINDS.CWD_INVALID
  );
}

/** Best-effort repository-relative form; `null` when the path is outside. */
function safeRelative(root, absolute) {
  try {
    return toRepositoryRelative(root, absolute);
  } catch {
    return null;
  }
}

/**
 * Resolve and authorize a working directory.
 *
 * When `cwd` is omitted the primary allowed root (the first entry) is used, so
 * an omitted cwd is never inherited from the runner's own process.
 *
 * @param {string|undefined} cwd Requested working directory.
 * @param {string[]} allowedRoots Authorized execution roots.
 * @returns {Promise<
 *   { ok: true, absolute: string, relative: string, root: string }
 *   | { ok: false, kind: string, cwd: string|null }>}
 */
export async function resolveExecutionCwd(cwd, allowedRoots) {
  if (!Array.isArray(allowedRoots) || allowedRoots.length === 0) {
    return { ok: false, kind: EXECUTION_ERROR_KINDS.NO_ALLOWED_ROOTS, cwd: null };
  }

  let roots;
  try {
    roots = allowedRoots.map((root) => normalizeRoot(root));
  } catch {
    return { ok: false, kind: EXECUTION_ERROR_KINDS.CWD_INVALID, cwd: null };
  }
  const primary = roots[0];

  const requested =
    cwd === undefined || cwd === null || cwd === "" ? primary : cwd;

  let absolute;
  try {
    absolute = resolvePath(primary, requested);
  } catch {
    return { ok: false, kind: EXECUTION_ERROR_KINDS.CWD_INVALID, cwd: null };
  }

  const reportedCwd = safeRelative(primary, absolute);

  if (!roots.some((root) => isContained(root, absolute))) {
    return {
      ok: false,
      kind: EXECUTION_ERROR_KINDS.CWD_OUTSIDE_ROOT,
      cwd: reportedCwd,
    };
  }

  let realCwd;
  try {
    realCwd = await realpath(absolute);
  } catch (error) {
    return {
      ok: false,
      kind: rejectionFromFilesystemError(error),
      cwd: reportedCwd,
    };
  }

  let realRoots;
  try {
    realRoots = await Promise.all(roots.map((root) => realpath(root)));
  } catch (error) {
    return {
      ok: false,
      kind: rejectionFromFilesystemError(error),
      cwd: reportedCwd,
    };
  }

  // Symlink cross-check: the *real* cwd must sit inside a *real* allowed root.
  if (!realRoots.some((root) => isContained(root, realCwd))) {
    return {
      ok: false,
      kind: EXECUTION_ERROR_KINDS.CWD_OUTSIDE_ROOT,
      cwd: reportedCwd,
    };
  }

  let stats;
  try {
    stats = await stat(realCwd);
  } catch (error) {
    return {
      ok: false,
      kind: rejectionFromFilesystemError(error),
      cwd: reportedCwd,
    };
  }

  if (!stats.isDirectory()) {
    return {
      ok: false,
      kind: EXECUTION_ERROR_KINDS.CWD_NOT_DIRECTORY,
      cwd: reportedCwd,
    };
  }

  return {
    ok: true,
    absolute: realCwd,
    relative: safeRelative(primary, realCwd),
    root: primary,
  };
}
