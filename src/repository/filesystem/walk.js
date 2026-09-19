/**
 * Code Guardian — Repository Walk (Phase 8A)
 *
 * Low-level directory traversal for future Phase 8C/8D consumers. It makes the
 * two things the legacy scanner got wrong explicit:
 *
 *   1. A traversal that returned is NOT necessarily a complete scan. If any
 *      directory could not be read, or a limit stopped the walk, `complete` is
 *      `false` and the reason is reported (`errors` / `truncated`).
 *   2. Limits are recorded, never guessed at. Defaults come from the Phase 7
 *      `DEFAULT_SCAN_LIMITS` baseline (maxFiles 10000, maxDepth 20); callers may
 *      override them, and invalid limits are rejected rather than ignored.
 *
 * Symlink policy (Phase 8A §14): symlinks are **never followed**. Every
 * symlink is recorded in `symlinks` but never descended into and never treated
 * as a regular file. That keeps the walk free of cycles and prevents traversal
 * escaping the repository through a link. The policy is enforced by
 * `listDirectory`/`readFile` too (Phase 8A correction 1), not only here, and is
 * reported on the result as `symlinkPolicy`.
 *
 * Invalid options throw a Core `ValidationError`; filesystem conditions are
 * reported as structured data inside the result.
 */

import { DEFAULT_SCAN_LIMITS, ValidationError } from "../../core/index.js";

import {
  DIRECTORY_ENTRY_TYPES,
  SYMLINK_POLICY,
  listDirectory,
} from "./operations.js";
import { normalizeRoot } from "./paths.js";

// Re-exported so the policy constant keeps a single definition (in the module
// that enforces it) while remaining part of the walk surface.
export { SYMLINK_POLICY };

/** Default walk options, aligned with the Phase 7 scan-limit baseline. */
export const DEFAULT_WALK_OPTIONS = Object.freeze({
  maxFiles: DEFAULT_SCAN_LIMITS.maxFiles,
  maxDepth: DEFAULT_SCAN_LIMITS.maxDepth,
  ignore: Object.freeze([]),
});

function isPositiveInteger(value) {
  return Number.isInteger(value) && value > 0;
}

/**
 * Validate and normalize walk options.
 * @throws {ValidationError} When a limit or the ignore list is invalid.
 */
function normalizeWalkOptions(options) {
  const issues = [];
  const maxFiles = options.maxFiles ?? DEFAULT_WALK_OPTIONS.maxFiles;
  const maxDepth = options.maxDepth ?? DEFAULT_WALK_OPTIONS.maxDepth;
  const ignore = options.ignore ?? [];

  if (!isPositiveInteger(maxFiles)) {
    issues.push("options.maxFiles: must be a positive integer");
  }
  if (!isPositiveInteger(maxDepth)) {
    issues.push("options.maxDepth: must be a positive integer");
  }
  if (
    !Array.isArray(ignore) ||
    !ignore.every((entry) => typeof entry === "string" && entry !== "")
  ) {
    issues.push("options.ignore: must be an array of non-empty directory names");
  }

  if (issues.length > 0) {
    throw new ValidationError("Invalid walk options", {
      details: { contract: "WalkOptions", issues },
    });
  }

  return { maxFiles, maxDepth, ignore: [...ignore] };
}

/**
 * Recursively walk a repository tree.
 *
 * Depth semantics: the root is level 0. A directory at level L is *opened*
 * only when `L < maxDepth`; entries discovered at level `L + 1` are still
 * recorded. Declining to open a directory at the boundary conservatively marks
 * the walk `truncated`, because its contents were not inspected.
 *
 * @param {string} root Repository root.
 * @param {object} [options]
 * @param {number} [options.maxFiles] Maximum regular files to collect.
 * @param {number} [options.maxDepth] Maximum directory level to open.
 * @param {string[]} [options.ignore] Directory names to exclude entirely.
 * @returns {Promise<object>} The walk result (see module docs).
 */
export async function walk(root, options = {}) {
  const resolvedRoot = normalizeRoot(root);
  const { maxFiles, maxDepth, ignore } = normalizeWalkOptions(options);
  const ignoreSet = new Set(ignore);

  const result = {
    root: resolvedRoot,
    files: [],
    directories: [],
    symlinks: [],
    ignored: [],
    errors: [],
    complete: false,
    truncated: false,
    limits: { maxFiles, maxDepth },
    symlinkPolicy: SYMLINK_POLICY,
  };

  const queue = [{ absolute: resolvedRoot, depth: 0 }];
  let truncated = false;
  let stop = false;

  while (queue.length > 0 && !stop) {
    const current = queue.shift();
    const listing = await listDirectory(resolvedRoot, current.absolute);

    if (!listing.ok) {
      result.errors.push(listing.error);
      continue;
    }

    for (const entry of listing.entries) {
      if (entry.type === DIRECTORY_ENTRY_TYPES.DIRECTORY) {
        if (ignoreSet.has(entry.name)) {
          result.ignored.push({
            path: entry.path,
            relative: entry.relative,
            name: entry.name,
          });
          continue;
        }
        result.directories.push({
          path: entry.path,
          relative: entry.relative,
          name: entry.name,
          depth: current.depth + 1,
        });
        if (current.depth + 1 < maxDepth) {
          queue.push({ absolute: entry.path, depth: current.depth + 1 });
        } else {
          truncated = true;
        }
      } else if (entry.type === DIRECTORY_ENTRY_TYPES.FILE) {
        if (result.files.length >= maxFiles) {
          truncated = true;
          stop = true;
          break;
        }
        result.files.push({
          path: entry.path,
          relative: entry.relative,
          name: entry.name,
        });
      } else if (entry.type === DIRECTORY_ENTRY_TYPES.SYMLINK) {
        // Recorded but never followed: no cycles, no escaping the root.
        result.symlinks.push({
          path: entry.path,
          relative: entry.relative,
          name: entry.name,
        });
      }
    }
  }

  result.truncated = truncated;
  result.complete = result.errors.length === 0 && truncated === false;
  return result;
}
