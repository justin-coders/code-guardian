/**
 * Code Guardian — Filesystem Operations (Phase 8A)
 *
 * Reusable read/list primitives. Both return an explicit discriminated result
 * rather than `null`/`[]`:
 *
 *   { ok: true,  path, relative, content | entries }
 *   { ok: false, path, relative, error: FilesystemError }
 *
 * That split is deliberate — callers can tell "file does not exist" from
 * "permission denied" without a `try/catch`, and no failure is ever collapsed
 * into an empty success.
 *
 * Path arguments are always resolved against the repository root and must stay
 * inside it; an escape is reported as `INVALID_PATH`.
 *
 * Symlink policy (Phase 8A correction 1): the no-follow policy is enforced
 * here, not only by `walk`. Before reading or listing, every component of the
 * resolved repository-relative path is `lstat`ed; if any component is a symlink
 * the operation is refused with `SYMLINK_NOT_ALLOWED`. A lexical containment
 * check alone is not enough: `repo/link -> /outside` is lexically inside the
 * repository but would resolve outside it. Rejecting symlinks (file or
 * directory, inside or outside the root) keeps reads, listings and traversal
 * consistent with `SYMLINK_POLICY`.
 */

import {
  lstat as fsLstat,
  readFile as fsReadFile,
  readdir as fsReaddir,
} from "node:fs/promises";
import { join as joinPath } from "node:path";

import {
  FILESYSTEM_ERROR_KINDS,
  FilesystemError,
  toFilesystemError,
} from "./errors.js";
import {
  normalizeRoot,
  resolveWithin,
  toRepositoryRelative,
} from "./paths.js";

/** Explicit, documented symlink policy. Enforced by every operation here. */
export const SYMLINK_POLICY = "not-followed";

/** Entry types a directory listing can report. */
export const DIRECTORY_ENTRY_TYPES = Object.freeze({
  FILE: "file",
  DIRECTORY: "directory",
  SYMLINK: "symlink",
  OTHER: "other",
});

function describeEntry(entry) {
  if (entry.isSymbolicLink()) return DIRECTORY_ENTRY_TYPES.SYMLINK;
  if (entry.isDirectory()) return DIRECTORY_ENTRY_TYPES.DIRECTORY;
  if (entry.isFile()) return DIRECTORY_ENTRY_TYPES.FILE;
  return DIRECTORY_ENTRY_TYPES.OTHER;
}

/** Deterministic byte-order comparison of entry names. */
function compareByName(a, b) {
  if (a.name < b.name) return -1;
  if (a.name > b.name) return 1;
  return 0;
}

/**
 * Whether any component of a repository-relative path is a symlink.
 *
 * Uses `lstat`, which inspects the link itself rather than its target, so a
 * broken symlink is still detected. If a component cannot be `lstat`ed the
 * check reports "no symlink" and lets the real operation surface that error, so
 * genuine `NOT_FOUND`/`PERMISSION_DENIED` results are never masked.
 *
 * @param {string} resolvedRoot Absolute repository root.
 * @param {string} relative POSIX repository-relative path ("." for the root).
 * @returns {Promise<boolean>}
 */
async function traversesSymlink(resolvedRoot, relative) {
  if (relative === ".") return false;
  const segments = relative.split("/");
  let current = resolvedRoot;
  for (const segment of segments) {
    current = joinPath(current, segment);
    let stats;
    try {
      stats = await fsLstat(current);
    } catch {
      return false;
    }
    if (stats.isSymbolicLink()) return true;
  }
  return false;
}

function failure(operation, error, target, extra = {}) {
  return {
    ok: false,
    path: extra.path ?? null,
    relative: extra.relative ?? null,
    error: toFilesystemError(error, {
      operation,
      path: extra.reportPath ?? target,
    }),
  };
}

function symlinkRefused(operation, absolute, relative) {
  return {
    ok: false,
    path: absolute ?? null,
    relative: relative ?? null,
    error: new FilesystemError({
      kind: FILESYSTEM_ERROR_KINDS.SYMLINK_NOT_ALLOWED,
      operation,
      path: relative ?? null,
    }),
  };
}

/** Resolve a target for an operation, returning a failure object on error. */
function resolveForOperation(operation, root, target) {
  let resolvedRoot;
  try {
    resolvedRoot = normalizeRoot(root);
  } catch (error) {
    return { failure: failure(operation, error, target) };
  }

  let absolute;
  let relative;
  try {
    absolute = resolveWithin(resolvedRoot, target);
    relative = toRepositoryRelative(resolvedRoot, absolute);
  } catch (error) {
    return { failure: failure(operation, error, target) };
  }

  return { resolvedRoot, absolute, relative };
}

/**
 * Read a text file from inside the repository.
 *
 * @param {string} root Repository root.
 * @param {string} target Repository-relative or absolute path.
 * @param {object} [options]
 * @param {BufferEncoding|null} [options.encoding] Pass `null` for a Buffer.
 * @returns {Promise<{ok: true, path: string, relative: string, content: string|Buffer}|{ok: false, path: string|null, relative: string|null, error: import("./errors.js").FilesystemError}>}
 */
export async function readFile(root, target, options = {}) {
  const encoding = options.encoding === undefined ? "utf8" : options.encoding;

  const resolved = resolveForOperation("readFile", root, target);
  if (resolved.failure) return resolved.failure;

  const { resolvedRoot, absolute, relative } = resolved;

  if (await traversesSymlink(resolvedRoot, relative)) {
    return symlinkRefused("readFile", absolute, relative);
  }

  try {
    const content = await fsReadFile(absolute, { encoding });
    return { ok: true, path: absolute, relative, content };
  } catch (error) {
    return failure("readFile", error, target, {
      path: absolute,
      relative,
      reportPath: relative,
    });
  }
}

/**
 * List a directory inside the repository.
 *
 * Entries are returned sorted by name with their type, so consumers never have
 * to re-stat. Errors are reported, never converted to `[]`.
 *
 * @param {string} root Repository root.
 * @param {string} [target] Repository-relative or absolute directory path.
 * @returns {Promise<{ok: true, path: string, relative: string, entries: Array<{name: string, type: string, path: string, relative: string}>}|{ok: false, path: string|null, relative: string|null, error: import("./errors.js").FilesystemError}>}
 */
export async function listDirectory(root, target = ".") {
  const resolved = resolveForOperation("listDirectory", root, target);
  if (resolved.failure) return resolved.failure;

  const { resolvedRoot, absolute, relative } = resolved;

  if (await traversesSymlink(resolvedRoot, relative)) {
    return symlinkRefused("listDirectory", absolute, relative);
  }

  try {
    const dirents = await fsReaddir(absolute, { withFileTypes: true });
    const entries = dirents
      .map((entry) => {
        const entryPath = joinPath(absolute, entry.name);
        return {
          name: entry.name,
          type: describeEntry(entry),
          path: entryPath,
          relative: toRepositoryRelative(resolvedRoot, entryPath),
        };
      })
      .sort(compareByName);
    return { ok: true, path: absolute, relative, entries };
  } catch (error) {
    return failure("listDirectory", error, target, {
      path: absolute,
      relative,
      reportPath: relative,
    });
  }
}
