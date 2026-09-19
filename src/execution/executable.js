/**
 * Code Guardian — Executable Resolution (Phase 8B)
 *
 * Command authorization must not be defeated by *moving* an executable: a file
 * called `node` in `/tmp/attacker` is not the `node` a policy author meant when
 * they wrote `allowCommands: ["node"]`. This module supplies the two facts the
 * policy needs to distinguish them:
 *
 *   - the executable *identity* (basename, Windows extension stripped and
 *     case-folded) — used for name matching, and
 *   - the canonical *location* the command actually resolves to — used for the
 *     location check.
 *
 * Executable lookup is deliberately **not** repository containment: `node`,
 * `npm`, `git` and `python` legitimately live on the system `PATH` (Phase 8B
 * §12). Repository containment (Phase 8A) governs the *working directory*; this
 * module governs *which file* a name denotes.
 *
 * Trusted executable roots come from the **trusted environment** — the runner's
 * own inherited `PATH` — plus the directory of the running Node executable
 * itself. The caller can never supply the environment used here, so a caller
 * cannot steer resolution by handing the runner a different `PATH`.
 *
 * Containment uses the accepted Phase 8A path layer (`isContained`); this module
 * never re-implements path containment with string prefixes.
 */

import { accessSync, constants, realpathSync, statSync } from "node:fs";
import nodePath from "node:path";

import { isContained, normalizeRoot } from "../repository/filesystem/index.js";

const WINDOWS = process.platform === "win32";
const WINDOWS_EXECUTABLE_EXTENSION = /\.(exe|cmd|bat|com)$/i;
// Extensions `spawn` (shell: false) can actually launch on Windows. `.cmd`/`.bat`
// require a shell and are deliberately not offered.
const WINDOWS_SPAWNABLE_EXTENSIONS = [".exe", ".com"];

/**
 * Normalize a command or allow/deny entry to a comparable executable identity.
 *
 * `path.basename` plus a Windows extension strip and case-fold. Matching is
 * exact, so `node-malicious` can never satisfy an entry of `node`.
 *
 * @param {string} command
 * @returns {string}
 */
export function commandIdentity(command) {
  const base = nodePath.basename(String(command));
  const stripped = WINDOWS
    ? base.replace(WINDOWS_EXECUTABLE_EXTENSION, "")
    : base;
  return WINDOWS ? stripped.toLowerCase() : stripped;
}

/**
 * Whether a command/entry names a path rather than a bare executable name.
 *
 * A backslash counts as path-like on every platform: on POSIX a `\` is a legal
 * filename character, and treating it as a path only makes authorization
 * stricter (an explicit location is required), never looser.
 *
 * @param {unknown} command
 * @returns {boolean}
 */
export function isPathLikeExecutable(command) {
  if (typeof command !== "string" || command === "") return false;
  return (
    nodePath.isAbsolute(command) ||
    command.includes("/") ||
    command.includes("\\")
  );
}

/** Comparison key for set membership (case-insensitive on Windows). */
export function executablePathKey(value) {
  return WINDOWS ? String(value).toLowerCase() : String(value);
}

/**
 * Canonicalize an executable path.
 *
 * With `requireExisting`, the path must currently resolve to a regular file;
 * that is what makes a *resolved* command safe to spawn. Without it (allow/deny
 * entries), a non-existent path falls back to a plain absolute normalization so
 * the entry is still comparable and can never accidentally match a bare name.
 *
 * @param {string} value
 * @param {object} [options]
 * @param {boolean} [options.requireExisting]
 * @returns {string|null} Canonical absolute path, or `null` when unresolved.
 */
export function canonicalizeExecutablePath(
  value,
  { requireExisting = false } = {},
) {
  if (typeof value !== "string" || value.trim() === "") return null;
  const absolute = nodePath.resolve(value);
  let canonical;
  try {
    canonical = realpathSync(absolute);
  } catch {
    return requireExisting ? null : absolute;
  }
  if (!requireExisting) return canonical;
  try {
    return statSync(canonical).isFile() ? canonical : null;
  } catch {
    return null;
  }
}

/**
 * Canonicalize an executable *directory* (an authorized executable root).
 * @param {string} value
 * @returns {string|null} Canonical directory, or `null` when unusable.
 */
export function canonicalizeExecutableRoot(value) {
  if (typeof value !== "string" || value.trim() === "") return null;
  try {
    const canonical = realpathSync(nodePath.resolve(value));
    return statSync(canonical).isDirectory() ? canonical : null;
  } catch {
    return null;
  }
}

/** Case-insensitive (Windows) `PATH` lookup on a plain environment object. */
function executableSearchPath(environment) {
  if (environment === null || typeof environment !== "object") return [];
  const name = WINDOWS
    ? Object.keys(environment).find((key) => key.toUpperCase() === "PATH")
    : "PATH";
  const value = name === undefined ? undefined : environment[name];
  if (typeof value !== "string") return [];
  return value.split(nodePath.delimiter);
}

/**
 * Compute the trusted executable roots.
 *
 * Uses the environment it is handed; the runner always hands it the *trusted*
 * (inherited) environment, never caller-supplied overrides.
 *
 * @param {Record<string, string|undefined>} [environment]
 * @returns {string[]} Canonical, de-duplicated directory paths.
 */
export function trustedExecutableRoots(environment = process.env) {
  const roots = [];
  const seen = new Set();

  const add = (directory) => {
    const canonical = canonicalizeExecutableRoot(directory);
    if (canonical === null) return;
    const key = executablePathKey(canonical);
    if (seen.has(key)) return;
    seen.add(key);
    roots.push(canonical);
  };

  for (const directory of executableSearchPath(environment)) add(directory);
  // The running runtime is trusted by definition: if it were hostile, the
  // runner itself would already be compromised.
  add(nodePath.dirname(process.execPath));

  return roots;
}

function isExecutableFile(candidate) {
  let stats;
  try {
    stats = statSync(candidate);
  } catch {
    return false;
  }
  if (!stats.isFile()) return false;
  if (WINDOWS) return true;
  try {
    accessSync(candidate, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function executableCandidateNames(command, identity) {
  const names = new Set([command, identity]);
  if (WINDOWS) {
    for (const extension of WINDOWS_SPAWNABLE_EXTENSIONS) {
      names.add(`${identity}${extension}`);
    }
  }
  return [...names];
}

/**
 * Resolve a command to the canonical file an execution would launch.
 *
 * - explicit path → its canonical absolute form (must exist)
 * - bare name     → first match on the *trusted* search path (must be an
 *                   executable regular file)
 *
 * @param {string} command
 * @param {string[]} [trustedRoots] Result of `trustedExecutableRoots`.
 * @returns {{ identity: string, resolvedPath: string|null, source: "path"|"explicit" }}
 */
export function resolveCommandExecutable(command, trustedRoots = []) {
  const identity = commandIdentity(command);

  if (isPathLikeExecutable(command)) {
    return {
      identity,
      resolvedPath: canonicalizeExecutablePath(command, {
        requireExisting: true,
      }),
      source: "explicit",
    };
  }

  for (const root of trustedRoots) {
    for (const name of executableCandidateNames(command, identity)) {
      const candidate = nodePath.join(root, name);
      if (!isExecutableFile(candidate)) continue;
      const resolved = canonicalizeExecutablePath(candidate, {
        requireExisting: true,
      });
      if (resolved !== null) {
        return { identity, resolvedPath: resolved, source: "path" };
      }
    }
  }

  return { identity, resolvedPath: null, source: "path" };
}

/**
 * Whether a resolved executable sits inside any of `roots`.
 *
 * Delegates to the Phase 8A `isContained` check so no second containment
 * implementation exists.
 *
 * @param {string|null} resolvedPath
 * @param {string[]} roots
 * @returns {boolean}
 */
export function isWithinExecutableRoots(resolvedPath, roots) {
  if (typeof resolvedPath !== "string" || resolvedPath === "") return false;
  return (roots ?? []).some((root) => {
    try {
      return isContained(normalizeRoot(root), resolvedPath);
    } catch {
      return false;
    }
  });
}
