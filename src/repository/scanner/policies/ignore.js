/**
 * Code Guardian — Scanner Ignore Policy (Phase 8C)
 *
 * Two outcomes are deliberately kept apart, because conflating them would hide
 * a security-relevant fact:
 *
 *   IGNORED  a path the *policy* chose not to inventory (this module).
 *   SKIPPED  a path that *could not* be inventoried because of a limit or a
 *            filesystem error (reported by `scan.truncated` / `scan.errors`).
 *
 * An ignored path was seen and consciously excluded; a skipped path was not
 * inspected at all. The scanner reports them in different places and never
 * counts one as the other.
 *
 * Policy, version 1 (deliberately small and documented):
 *
 *   1. Generated/dependency directories are excluded by *name* at any depth
 *      (`DEFAULT_IGNORED_DIRECTORIES`). This is the same mechanism the Phase 8A
 *      `walk` exposes, so no second traversal policy exists.
 *   2. A **`.gitignore` at the repository root** is applied on top, using the
 *      subset below. Nested `.gitignore` files, `.git/info/exclude` and global
 *      git excludes are deliberately NOT consulted.
 *   3. Anything outside that subset is *not applied* and is reported in
 *      `ignore.unsupported` so a partially honoured ignore file is visible
 *      rather than silently half-enforced.
 *
 * Supported `.gitignore` syntax:
 *
 *   `name`        basename match at any depth (files and directories)
 *   `name/`       directory-only match at any depth
 *   `/name`       anchored to the repository root
 *   `a/b`         anchored relative path
 *   `*.log`       `*` and `?` wildcards inside a segment
 *   `# comment`   ignored; blank lines ignored
 *
 * Unsupported (reported, never half-applied):
 *
 *   `!pattern`    negation
 *   `**`          double-star (cross-segment) wildcards
 *   `\x`          escaping
 *
 * A pattern that matches a directory also excludes everything beneath it, which
 * is git's own rule and is implemented here by checking every ancestor.
 */

import nodePath from "node:path";

/** Generated/dependency directories no repository inventory should walk into. */
export const DEFAULT_IGNORED_DIRECTORIES = Object.freeze([
  ".git",
  "node_modules",
  "bower_components",
  ".venv",
  "venv",
  "__pycache__",
  ".mypy_cache",
  ".pytest_cache",
  ".tox",
  ".ruff_cache",
  "dist",
  "build",
  "out",
  "target",
  "coverage",
  ".next",
  ".nuxt",
  ".turbo",
  ".parcel-cache",
  ".dart_tool",
  ".gradle",
  "vendor",
]);

/** The only ignore file this version understands. */
export const GITIGNORE_FILENAME = ".gitignore";

/** Reasons a `.gitignore` line is not applied. */
export const GITIGNORE_UNSUPPORTED_REASONS = Object.freeze({
  NEGATION: "negation-unsupported",
  DOUBLE_STAR: "double-star-unsupported",
  ESCAPE: "escape-unsupported",
});

/** Ignore-policy names recorded on every ignored entry. */
export const IGNORE_POLICIES = Object.freeze({
  DEFAULT_DIRECTORY: "default-directory",
  GITIGNORE: "gitignore",
});

/**
 * Translate a single-segment glob into a regular expression.
 *
 * Only `*` and `?` are meaningful; every other character is escaped, so a
 * pattern can never inject regex behaviour.
 *
 * @param {string} pattern
 * @returns {RegExp}
 */
export function segmentGlobToRegExp(pattern) {
  let source = "^";
  for (const character of pattern) {
    if (character === "*") source += "[^/]*";
    else if (character === "?") source += "[^/]";
    else source += character.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`${source}$`);
}

/**
 * Parse `.gitignore` text into applied patterns plus reported limitations.
 *
 * @param {string} text
 * @param {string} [source] Path the text came from (for reporting).
 * @returns {{ patterns: object[], unsupported: object[] }}
 */
export function parseGitignore(text, source = GITIGNORE_FILENAME) {
  const patterns = [];
  const unsupported = [];
  const lines = String(text).split(/\r?\n/);

  lines.forEach((rawLine, index) => {
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#")) return;
    const lineNumber = index + 1;

    if (line.startsWith("!")) {
      unsupported.push({
        path: source,
        line: lineNumber,
        reason: GITIGNORE_UNSUPPORTED_REASONS.NEGATION,
      });
      return;
    }
    if (line.includes("**")) {
      unsupported.push({
        path: source,
        line: lineNumber,
        reason: GITIGNORE_UNSUPPORTED_REASONS.DOUBLE_STAR,
      });
      return;
    }
    if (line.includes("\\")) {
      unsupported.push({
        path: source,
        line: lineNumber,
        reason: GITIGNORE_UNSUPPORTED_REASONS.ESCAPE,
      });
      return;
    }

    const anchored = line.startsWith("/");
    const withoutAnchor = anchored ? line.slice(1) : line;
    const directoryOnly = withoutAnchor.endsWith("/");
    const body = directoryOnly
      ? withoutAnchor.slice(0, -1)
      : withoutAnchor;
    if (body === "") return;

    const hasSeparator = body.includes("/");
    patterns.push({
      source,
      line: lineNumber,
      raw: line,
      anchored,
      directoryOnly,
      // An unanchored pattern without a separator matches a basename at any
      // depth; anything else is matched against the repository-relative path.
      matchPath: anchored || hasSeparator,
      matcher: segmentGlobToRegExp(body),
    });
  });

  return { patterns, unsupported };
}

/**
 * Build the ignore policy used by one scan.
 *
 * @param {object} [input]
 * @param {string|null} [input.gitignoreText] Root `.gitignore` contents, if read.
 * @returns {{ ignoredDirectories: string[], patterns: object[], unsupported: object[], sources: string[] }}
 */
export function buildIgnorePolicy({ gitignoreText = null } = {}) {
  const parsed =
    typeof gitignoreText === "string"
      ? parseGitignore(gitignoreText)
      : { patterns: [], unsupported: [] };

  return {
    ignoredDirectories: [...DEFAULT_IGNORED_DIRECTORIES],
    patterns: parsed.patterns,
    unsupported: parsed.unsupported,
    applied: typeof gitignoreText === "string",
  };
}

function pathSegments(relativePath) {
  return relativePath.split("/");
}

/**
 * Whether any ancestor directory of `relativePath` is matched by a pattern.
 *
 * Ancestors are tested without the directory-only requirement: a pattern that
 * matches a directory excludes its contents whether or not it ended in `/`.
 */
function ancestorIsIgnored(patterns, relativePath) {
  const segments = pathSegments(relativePath);
  for (let index = 1; index < segments.length; index += 1) {
    const ancestor = segments.slice(0, index).join("/");
    const ancestorName = segments[index - 1];
    for (const pattern of patterns) {
      if (pattern.matchPath) {
        if (pattern.matcher.test(ancestor)) return true;
      } else if (pattern.matcher.test(ancestorName)) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Whether an entry is excluded by policy.
 *
 * @param {object} policy Result of `buildIgnorePolicy`.
 * @param {object} entry `{ path, name, isDirectory }` with a POSIX relative path.
 * @returns {boolean}
 */
export function isIgnored(policy, entry) {
  if (ancestorIsIgnored(policy.patterns, entry.path)) return true;

  for (const pattern of policy.patterns) {
    if (pattern.directoryOnly && !entry.isDirectory) continue;
    if (pattern.matchPath) {
      if (pattern.matcher.test(entry.path)) return true;
    } else if (pattern.matcher.test(entry.name)) {
      return true;
    }
  }
  return false;
}

/**
 * Split a POSIX relative path into its parent directory (`.` at the root).
 * @param {string} relativePath
 * @returns {string}
 */
export function parentDirectory(relativePath) {
  const parent = nodePath.posix.dirname(relativePath);
  return parent === "." || parent === "" ? "." : parent;
}
