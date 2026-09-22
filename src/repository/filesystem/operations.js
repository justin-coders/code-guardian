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
 *
 * `readLink` is the one operation that is *about* a symlink, so it inspects the
 * link itself (its parent components are still symlink-checked, so a link inside
 * a linked directory is never inspected) and never resolves or follows it. It
 * classifies the link's target into a closed vocabulary and reports the target as
 * a **repository-relative** path when it resolves inside; an absolute or escaping
 * target is reduced to `outside` without ever carrying the raw text. That keeps
 * "does this link leave the repository?" answerable from repository evidence
 * while the policy — links are never followed — stays intact.
 */

import {
  lstat as fsLstat,
  open as fsOpen,
  readFile as fsReadFile,
  readdir as fsReaddir,
  readlink as fsReadlink,
} from "node:fs/promises";
import {
  dirname as dirnamePath,
  isAbsolute as isAbsolutePath,
  join as joinPath,
} from "node:path";

import {
  FILESYSTEM_ERROR_KINDS,
  FilesystemError,
  toFilesystemError,
} from "./errors.js";
import {
  isContained,
  normalizeRoot,
  resolvePath,
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

/**
 * Where a symlink's target resolves, relative to the repository root.
 *
 *   inside   the target resolves inside the repository; `path` carries it as a
 *            repository-relative path (`null` only when the target *is* the
 *            repository root, which has no relative form)
 *   outside  the target resolves outside the repository, or is an absolute path
 *            that no longer points into it; nothing about it is recorded
 *   unknown  the target could not be established at all (the link itself is
 *            unreadable), so neither claim can be made
 */
export const LINK_TARGET_KINDS = Object.freeze({
  INSIDE: "inside",
  OUTSIDE: "outside",
  UNKNOWN: "unknown",
});

/**
 * Why a link target is `unknown`. Closed vocabulary, never free text.
 *
 * `UNREADABLE` is produced here (the link itself could not be read). The other
 * three describe chain resolution, which is a policy above this layer —
 * `not-inspected` when nothing was ever read, `cycle` when following recorded
 * link facts loops, `depth-exceeded` when a chain is longer than the policy
 * allows. The vocabulary lives here so every layer names the same reasons.
 */
export const LINK_UNKNOWN_REASONS = Object.freeze({
  UNREADABLE: "unreadable",
  NOT_INSPECTED: "not-inspected",
  CYCLE: "cycle",
  DEPTH_EXCEEDED: "depth-exceeded",
});

/**
 * Classify a raw link target without following it.
 *
 * The target text is used only to *decide* containment; it is never returned. A
 * relative target is resolved against the link's own directory and an absolute
 * target is resolved as-is, then both are tested for containment, so an absolute
 * host path is reduced to `outside` rather than being echoed.
 *
 * @param {string} resolvedRoot Absolute repository root.
 * @param {string} linkAbsolute Absolute path of the link itself.
 * @param {string} rawTarget The link's target text.
 * @returns {{kind: string, path: string|null, reason: string|null}}
 */
export function classifyLinkTarget(resolvedRoot, linkAbsolute, rawTarget) {
  const unknown = { kind: LINK_TARGET_KINDS.UNKNOWN, path: null, reason: LINK_UNKNOWN_REASONS.UNREADABLE };
  if (typeof rawTarget !== "string" || rawTarget === "" || rawTarget.includes("\0")) {
    return unknown;
  }

  let absolute;
  try {
    absolute = isAbsolutePath(rawTarget)
      ? resolvePath(resolvedRoot, rawTarget)
      : resolvePath(resolvedRoot, joinPath(dirnamePath(linkAbsolute), rawTarget));
  } catch {
    return unknown;
  }

  if (!isContained(resolvedRoot, absolute)) {
    return { kind: LINK_TARGET_KINDS.OUTSIDE, path: null, reason: null };
  }

  let relative;
  try {
    relative = toRepositoryRelative(resolvedRoot, absolute);
  } catch {
    return { kind: LINK_TARGET_KINDS.OUTSIDE, path: null, reason: null };
  }

  // `toRepositoryRelative` renders the root itself as `.`, which is not a
  // repository-relative path: the root has no relative form.
  return {
    kind: LINK_TARGET_KINDS.INSIDE,
    path: relative === "." ? null : relative,
    reason: null,
  };
}


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
 * @param {object} [options]
 * @param {boolean} [options.includeFinal] Whether the final component counts.
 *   `readLink` is *about* the final component, so it checks parents only.
 * @returns {Promise<boolean>}
 */
async function traversesSymlink(resolvedRoot, relative, options = {}) {
  if (relative === ".") return false;
  const includeFinal = options.includeFinal !== false;
  const segments = relative.split("/");
  const last = includeFinal ? segments.length - 1 : segments.length - 2;
  let current = resolvedRoot;
  for (let index = 0; index <= last; index += 1) {
    current = joinPath(current, segments[index]);
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
 * @param {number} [options.maxBytes] When given, read at most this many bytes.
 *   The result then reports `truncated`, and `bytesRead` is the number of bytes
 *   actually returned. Omitting it preserves the unbounded read.
 * @returns {Promise<{ok: true, path: string, relative: string, content: string|Buffer, truncated: boolean, bytesRead: number}|{ok: false, path: string|null, relative: string|null, error: import("./errors.js").FilesystemError}>}
 */
export async function readFile(root, target, options = {}) {
  const encoding = options.encoding === undefined ? "utf8" : options.encoding;
  const maxBytes = options.maxBytes;

  if (maxBytes !== undefined && (!Number.isSafeInteger(maxBytes) || maxBytes < 0)) {
    return {
      ok: false,
      path: null,
      relative: null,
      error: new FilesystemError({
        kind: FILESYSTEM_ERROR_KINDS.INVALID_PATH,
        operation: "readFile",
        path: null,
      }),
    };
  }

  const resolved = resolveForOperation("readFile", root, target);
  if (resolved.failure) return resolved.failure;

  const { resolvedRoot, absolute, relative } = resolved;

  if (await traversesSymlink(resolvedRoot, relative)) {
    return symlinkRefused("readFile", absolute, relative);
  }

  try {
    if (maxBytes === undefined) {
      const content = await fsReadFile(absolute, { encoding });
      const bytesRead =
        typeof content === "string" ? Buffer.byteLength(content) : content.length;
      return { ok: true, path: absolute, relative, content, truncated: false, bytesRead };
    }

    const { bytes, truncated } = await readBounded(absolute, maxBytes);
    const content = encoding === null ? bytes : bytes.toString(encoding);
    return { ok: true, path: absolute, relative, content, truncated, bytesRead: bytes.length };
  } catch (error) {
    return failure("readFile", error, target, {
      path: absolute,
      relative,
      reportPath: relative,
    });
  }
}

/**
 * Read at most `maxBytes` bytes through an explicit file handle.
 *
 * One extra byte is requested so "exactly at the limit" and "over the limit"
 * are distinguishable without reading the rest of the file: a large file costs
 * one bounded buffer, never its full size.
 *
 * @returns {Promise<{bytes: Buffer, truncated: boolean}>}
 */
async function readBounded(absolute, maxBytes) {
  const handle = await fsOpen(absolute, "r");
  try {
    const buffer = Buffer.allocUnsafe(maxBytes + 1);
    let read = 0;
    while (read < buffer.length) {
      const result = await handle.read(
        buffer,
        read,
        buffer.length - read,
        read,
      );
      if (result.bytesRead === 0) break;
      read += result.bytesRead;
    }
    const truncated = read > maxBytes;
    return { bytes: buffer.subarray(0, Math.min(read, maxBytes)), truncated };
  } finally {
    await handle.close();
  }
}

/**
 * Inspect a symlink *without following it*.
 *
 * This is the only operation whose subject is a symlink. Parent components are
 * still symlink-checked (so nothing behind a linked directory is inspected) but
 * the final component must be a link; a regular file or directory is rejected
 * with `NOT_A_SYMLINK` rather than silently reported as one.
 *
 * The returned `target` is the closed classification from
 * `classifyLinkTarget`: `{ kind, path, reason }`. A target that resolves inside
 * the repository is reported repository-relative; a target that escapes —
 * including an absolute host path — is reduced to `outside` and its text is
 * discarded, so no host location can travel with the model.
 *
 * @param {string} root Repository root.
 * @param {string} target Repository-relative or absolute path of the link.
 * @returns {Promise<{ok: true, path: string, relative: string, target: {kind: string, path: string|null, reason: string|null}}|{ok: false, path: string|null, relative: string|null, error: import("./errors.js").FilesystemError}>}
 */
export async function readLink(root, target) {
  const resolved = resolveForOperation("readLink", root, target);
  if (resolved.failure) return resolved.failure;

  const { resolvedRoot, absolute, relative } = resolved;

  if (await traversesSymlink(resolvedRoot, relative, { includeFinal: false })) {
    return symlinkRefused("readLink", absolute, relative);
  }

  try {
    const stats = await fsLstat(absolute);
    if (!stats.isSymbolicLink()) {
      return {
        ok: false,
        path: absolute,
        relative,
        error: new FilesystemError({
          kind: FILESYSTEM_ERROR_KINDS.NOT_A_SYMLINK,
          operation: "readLink",
          path: relative,
        }),
      };
    }

    const rawTarget = await fsReadlink(absolute);
    return {
      ok: true,
      path: absolute,
      relative,
      target: classifyLinkTarget(resolvedRoot, absolute, rawTarget),
    };
  } catch (error) {
    return failure("readLink", error, target, {
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
