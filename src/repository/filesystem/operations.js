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
 */

import {
  readFile as fsReadFile,
  readdir as fsReaddir,
} from "node:fs/promises";
import { join as joinPath } from "node:path";

import { toFilesystemError } from "./errors.js";
import {
  normalizeRoot,
  resolveWithin,
  toRepositoryRelative,
} from "./paths.js";

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

function failure(operation, error, target, extra = {}) {
  return {
    ok: false,
    path: extra.path ?? null,
    relative: extra.relative ?? null,
    error: toFilesystemError(error, { operation, path: extra.reportPath ?? target }),
  };
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

  let resolvedRoot;
  try {
    resolvedRoot = normalizeRoot(root);
  } catch (error) {
    return failure("readFile", error, target);
  }

  let absolute;
  let relative;
  try {
    absolute = resolveWithin(resolvedRoot, target);
    relative = toRepositoryRelative(resolvedRoot, absolute);
  } catch (error) {
    return failure("readFile", error, target);
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
  let resolvedRoot;
  try {
    resolvedRoot = normalizeRoot(root);
  } catch (error) {
    return failure("listDirectory", error, target);
  }

  let absolute;
  let relative;
  try {
    absolute = resolveWithin(resolvedRoot, target);
    relative = toRepositoryRelative(resolvedRoot, absolute);
  } catch (error) {
    return failure("listDirectory", error, target);
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
