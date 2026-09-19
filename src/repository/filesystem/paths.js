/**
 * Code Guardian — Path Utilities (Phase 8A)
 *
 * Central, platform-aware path handling for repository access. Every future
 * consumer (8B command boundary, 8C scanner, 8D repository model) must route
 * path decisions through here rather than concatenating strings.
 *
 * Containment is *semantic*: it is decided by path resolution and
 * `path.relative`, never by `startsWith(root)`. That distinction matters because
 * string prefixes mis-classify siblings:
 *
 *   root   = /root/project
 *   target = /root/project-other   → NOT contained (string prefix would say it is)
 *
 * Repository-relative output is always POSIX-style (`/`) because repository
 * paths are a portable, Git-compatible representation. Absolute paths returned
 * by this module use the platform separator.
 *
 * The pure path math is exposed through `createPathTools(pathImpl)` so Windows
 * semantics can be exercised deterministically with `node:path.win32` on any
 * platform. Production callers use the default-bound exports below.
 *
 * Invalid *inputs* (bad types, containment escapes) throw `FilesystemError`
 * with kind `INVALID_PATH`; filesystem *conditions* are reported by the
 * operations module instead.
 */

import nodePath from "node:path";

import {
  FILESYSTEM_ERROR_CODES,
  FILESYSTEM_ERROR_KINDS,
  FilesystemError,
} from "./errors.js";

function invalidPathError(message, operation, path) {
  return new FilesystemError(message, {
    kind: FILESYSTEM_ERROR_KINDS.INVALID_PATH,
    code: FILESYSTEM_ERROR_CODES.INVALID_PATH,
    operation,
    path: typeof path === "string" ? path : null,
  });
}

/**
 * Build path utilities bound to a specific `node:path` implementation.
 * @param {typeof import("node:path")} path
 */
export function createPathTools(path) {
  /** True when `relative` points outside the base directory. */
  function escapesBase(base, absolute) {
    const rel = path.relative(base, absolute);
    if (rel === "") return false;
    if (path.isAbsolute(rel)) return true;
    return rel === ".." || rel.startsWith(".." + path.sep);
  }

  /**
   * Resolve a repository root to an absolute, normalized path.
   * A relative root is resolved against the current working directory.
   * @param {string} root
   * @returns {string}
   */
  function normalizeRoot(root) {
    if (typeof root !== "string" || root.trim() === "") {
      throw invalidPathError(
        "repository root must be a non-empty string",
        "normalizeRoot",
        root,
      );
    }
    return path.resolve(root);
  }

  /**
   * Resolve `target` to an absolute path. Absolute targets are used as-is;
   * relative targets are resolved against the normalized root.
   * @param {string} root
   * @param {string} target
   * @returns {string}
   */
  function resolvePath(root, target) {
    const resolvedRoot = normalizeRoot(root);
    if (typeof target !== "string" || target.trim() === "") {
      throw invalidPathError(
        "path must be a non-empty string",
        "resolvePath",
        target,
      );
    }
    return path.isAbsolute(target)
      ? path.resolve(target)
      : path.resolve(resolvedRoot, target);
  }

  /**
   * Whether `target` resolves inside `root`. The root is contained in itself.
   * @param {string} root
   * @param {string} target
   * @returns {boolean}
   */
  function isContained(root, target) {
    const resolvedRoot = normalizeRoot(root);
    const absolute = resolvePath(resolvedRoot, target);
    return !escapesBase(resolvedRoot, absolute);
  }

  /**
   * Resolve `target` and require it to stay inside `root`.
   * @throws {FilesystemError} With kind `INVALID_PATH` when it escapes.
   * @returns {string} Absolute, contained path.
   */
  function resolveWithin(root, target) {
    const resolvedRoot = normalizeRoot(root);
    const absolute = resolvePath(resolvedRoot, target);
    if (escapesBase(resolvedRoot, absolute)) {
      throw invalidPathError(
        `path escapes repository root: ${target}`,
        "resolveWithin",
        target,
      );
    }
    return absolute;
  }

  /**
   * Join path segments onto `root` and require the result to stay inside.
   * Absolute segments do not bypass the containment check.
   * @param {string} root
   * @param {...string} segments
   * @returns {string} Absolute, contained path.
   */
  function joinWithin(root, ...segments) {
    const resolvedRoot = normalizeRoot(root);
    if (segments.length === 0) return resolvedRoot;
    for (const segment of segments) {
      if (typeof segment !== "string" || segment.trim() === "") {
        throw invalidPathError(
          "path segments must be non-empty strings",
          "joinWithin",
          segment,
        );
      }
    }
    const joined = path.resolve(resolvedRoot, ...segments);
    if (escapesBase(resolvedRoot, joined)) {
      throw invalidPathError(
        `path escapes repository root: ${segments.join("/")}`,
        "joinWithin",
        segments.join("/"),
      );
    }
    return joined;
  }

  /**
   * Convert `target` to a POSIX repository-relative path.
   * The root itself converts to `"."`.
   * @throws {FilesystemError} With kind `INVALID_PATH` when it escapes.
   * @returns {string}
   */
  function toRepositoryRelative(root, target) {
    const resolvedRoot = normalizeRoot(root);
    const absolute = resolvePath(resolvedRoot, target);
    if (escapesBase(resolvedRoot, absolute)) {
      throw invalidPathError(
        `path escapes repository root: ${target}`,
        "toRepositoryRelative",
        target,
      );
    }
    const relative = path.relative(resolvedRoot, absolute);
    if (relative === "") return ".";
    return relative.split(path.sep).join("/");
  }

  return Object.freeze({
    normalizeRoot,
    resolvePath,
    isContained,
    resolveWithin,
    joinWithin,
    toRepositoryRelative,
  });
}

const defaultTools = createPathTools(nodePath);

/** Resolve a repository root to an absolute, normalized path. */
export const normalizeRoot = defaultTools.normalizeRoot;
/** Resolve a target path against a repository root. */
export const resolvePath = defaultTools.resolvePath;
/** Whether a target path resolves inside the repository root. */
export const isContained = defaultTools.isContained;
/** Resolve a target path and require it to stay inside the root. */
export const resolveWithin = defaultTools.resolveWithin;
/** Join segments onto the root with a containment guard. */
export const joinWithin = defaultTools.joinWithin;
/** Convert a target path to a POSIX repository-relative path. */
export const toRepositoryRelative = defaultTools.toRepositoryRelative;
