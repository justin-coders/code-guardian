/**
 * Code Guardian — Repository Scanner (Phase 8C)
 *
 * Answers one question: **what actually exists in this repository?**
 *
 * It does not answer — and must never answer — whether what exists is good,
 * secure, tested or production-ready. There is no scoring, no severity, no
 * verdict and no recommendation anywhere in this layer.
 *
 * Construction rules:
 *
 *   - **Reuse, never re-implement.** Traversal, containment, symlink refusal and
 *     error classification all come from the accepted Phase 8A filesystem
 *     boundary (`walk`, `readFile`, `listDirectory`). The scanner adds no second
 *     path implementation, never uses string-prefix containment, and never
 *     follows a symlink.
 *   - **Bounded.** `maxFiles` / `maxDepth` come from the Core scan-limit
 *     baseline. A scan that stopped early reports `truncated: true` and
 *     `complete: false`; it can never be mistaken for a full inventory.
 *   - **Read-only.** The target repository is never modified, and no process is
 *     spawned.
 *   - **Deterministic.** Every collection is ordered by path (or id), and nothing
 *     depends on filesystem enumeration order. Two scans of an unchanged
 *     repository are structurally identical apart from `scannedAt`.
 *   - **Evidence-oriented.** Every signal records the repository-relative path it
 *     was observed at, so a later phase can trace a conclusion back to a file.
 *
 * Content reading is bounded and deliberate. Exactly three detectors read a file's
 * bytes: manifests (the shallow `package.json` subset), git (`.git/HEAD`) and the
 * content detector, which inspects a closed candidate set under an explicit byte and
 * file budget and reports *which pattern shape* it observed — never a matched value,
 * line or byte. Nothing else in this layer parses source. File sizes and modification
 * times are still not recorded, and Git history, status and refs are out of scope —
 * see the git detector.
 *
 * Failure policy: invalid *arguments* throw a Core `ValidationError`; filesystem
 * *conditions* (missing root, unreadable subdirectory, unparsable manifest) are
 * returned as structured, classified observations so one bad file can never
 * destroy the whole scan.
 */

import nodePath from "node:path";

import { ValidationError } from "../../core/index.js";

import {
  FILESYSTEM_ERROR_KINDS,
  listDirectory,
  normalizeRoot,
  readFile,
  walk,
} from "../filesystem/index.js";

import { createScanResult, validateScanResult } from "./contracts.js";
import { runDetectors } from "./detectors/index.js";
import {
  GITIGNORE_FILENAME,
  IGNORE_POLICIES,
  buildIgnorePolicy,
  isIgnored,
} from "./policies/ignore.js";
import { uninspectedTarget, resolveSymlinkTargets } from "./policies/symlinks.js";
import { DEFAULT_SCANNER_LIMITS, resolveScanLimits } from "./policies/limits.js";

export { DEFAULT_SCANNER_LIMITS };

/** Options `scanRepository` accepts. Unknown options are rejected. */
export const SCAN_OPTION_KEYS = Object.freeze(["maxFiles", "maxDepth"]);

/** Why a scan was truncated (recorded in `statistics.truncatedBy`). */
export const TRUNCATION_REASONS = Object.freeze({
  FILE_LIMIT: "file-limit",
  DEPTH_LIMIT: "depth-limit",
});

/** Recorded status of the root `.gitignore` as an input to the ignore policy. */
const IGNORE_SOURCE_STATUS = Object.freeze({
  APPLIED: "applied",
  ABSENT: "absent",
  UNREADABLE: "unreadable",
});

function validateScanOptions(root, options) {
  const issues = [];

  if (typeof root !== "string" || root.trim() === "") {
    issues.push("root: must be a non-empty string");
  }
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    issues.push("options: must be a plain object");
  } else {
    for (const key of Object.keys(options)) {
      if (!SCAN_OPTION_KEYS.includes(key)) {
        issues.push(`options.${key}: unknown option`);
      }
    }
  }

  if (issues.length > 0) {
    throw new ValidationError("Invalid scan request", {
      details: { contract: "ScanRequest", issues },
    });
  }
}

function extensionOf(name) {
  return nodePath.extname(name).toLowerCase();
}

/** Depth of a repository-relative path (root-level entries are depth 1). */
function depthOf(relativePath) {
  return relativePath.split("/").length;
}

function toEntry(relativePath, isDirectory) {
  const name = relativePath.split("/").pop();
  return {
    path: relativePath,
    name,
    isDirectory,
    extension: isDirectory ? "" : extensionOf(name),
    depth: depthOf(relativePath),
  };
}

/**
 * Build the detector view from the (already ignore-filtered) inventory.
 *
 * `read` and `list` go through the Phase 8A boundary, so every detector read is
 * contained, symlink-refused and classified. `read` forwards its options, which is
 * how the content detector expresses its byte budget — no detector reaches the
 * filesystem directly.
 */
function buildView(root, files, directories) {
  return {
    root,
    files,
    directories,
    read: (relativePath, options) => readFile(root, relativePath, options),
    list: (relativePath) => listDirectory(root, relativePath),
  };
}

/**
 * Read the root `.gitignore`, if present, as ignore-policy input.
 *
 * A refused or unreadable ignore file is *reported* rather than ignored
 * silently, so a partial policy is never invisible.
 */
async function readIgnoreSource(root) {
  const result = await readFile(root, GITIGNORE_FILENAME);
  if (result.ok) {
    return { text: result.content, source: { path: GITIGNORE_FILENAME, status: IGNORE_SOURCE_STATUS.APPLIED } };
  }
  if (result.error.kind === FILESYSTEM_ERROR_KINDS.NOT_FOUND) {
    return { text: null, source: { path: GITIGNORE_FILENAME, status: IGNORE_SOURCE_STATUS.ABSENT } };
  }
  return {
    text: null,
    source: {
      path: GITIGNORE_FILENAME,
      status: IGNORE_SOURCE_STATUS.UNREADABLE,
      reason: result.error.kind,
    },
  };
}

/**
 * Apply the ignore policy to the walked inventory.
 *
 * `walk` has already pruned the default ignored directories, so this step:
 *   1. records those pruned directories as ignored policy entries,
 *   2. removes anything the root `.gitignore` excludes, and
 *   3. prunes descendants of an ignored directory.
 *
 * Descendants of an ignored directory are *not* listed individually — the
 * directory itself is the recorded observation, which matches how `walk` reports
 * ignored directories and keeps `statistics.ignored` meaningful.
 */
function applyIgnorePolicy(policy, walkResult) {
  const ignored = [];
  const ignoredDirectories = [];

  for (const entry of walkResult.ignored) {
    ignored.push({
      path: entry.relative,
      name: entry.name,
      isDirectory: true,
      policy: IGNORE_POLICIES.DEFAULT_DIRECTORY,
    });
    ignoredDirectories.push(entry.relative);
  }

  const files = [];
  const directories = [];

  const entries = [
    ...walkResult.directories.map((entry) => ({
      relative: entry.relative,
      isDirectory: true,
    })),
    ...walkResult.files.map((entry) => ({
      relative: entry.relative,
      isDirectory: false,
    })),
  ].sort((a, b) =>
    a.relative < b.relative ? -1 : a.relative > b.relative ? 1 : 0,
  );

  for (const entry of entries) {
    const depthPruned = ignoredDirectories.some((dir) =>
      entry.relative.startsWith(`${dir}/`),
    );
    if (depthPruned) continue;

    const view = toEntry(entry.relative, entry.isDirectory);
    if (isIgnored(policy, view)) {
      ignored.push({
        path: entry.relative,
        name: view.name,
        isDirectory: entry.isDirectory,
        policy: IGNORE_POLICIES.GITIGNORE,
      });
      if (entry.isDirectory) ignoredDirectories.push(entry.relative);
      continue;
    }

    if (entry.isDirectory) directories.push(view);
    else files.push(view);
  }

  ignored.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  return { files, directories, ignored };
}

function classifyScanErrors(walkResult) {
  return walkResult.errors.map((error) => ({
    kind: error.kind,
    code: error.code,
    operation: error.details?.operation ?? null,
    path: error.details?.path ?? null,
  }));
}

function truncationReasons(walkResult, limits) {
  const reasons = [];
  if (
    walkResult.truncated &&
    walkResult.files.length >= limits.maxFiles
  ) {
    reasons.push(TRUNCATION_REASONS.FILE_LIMIT);
  }
  const depthBoundaryNotOpened = walkResult.directories.some(
    (directory) => directory.depth >= limits.maxDepth,
  );
  if (depthBoundaryNotOpened) reasons.push(TRUNCATION_REASONS.DEPTH_LIMIT);
  return reasons;
}

/**
 * Scan a repository and return a structured inventory.
 *
 * @param {string} root Repository root (absolute or relative to the process).
 * @param {object} [options]
 * @param {number} [options.maxFiles] Maximum files to inventory.
 * @param {number} [options.maxDepth] Maximum directory level to open.
 * @returns {Promise<object>} A valid `ScanResult` (see `validateScanResult`).
 * @throws {ValidationError} When the root or options are malformed.
 */
export async function scanRepository(root, options = {}) {
  validateScanOptions(root, options);
  const limits = resolveScanLimits(options);
  const resolvedRoot = normalizeRoot(root);

  const { text: gitignoreText, source: gitignoreSource } =
    await readIgnoreSource(resolvedRoot);
  const policy = buildIgnorePolicy({ gitignoreText });

  const walkResult = await walk(resolvedRoot, {
    maxFiles: limits.maxFiles,
    maxDepth: limits.maxDepth,
    ignore: policy.ignoredDirectories,
  });

  const { files, directories, ignored } = applyIgnorePolicy(policy, walkResult);

  // Where each link points, established by reading the links themselves (never by
  // following them). A link's target is part of the inventory, so it is resolved
  // before the detectors run.
  const symlinkTargets = await resolveSymlinkTargets(resolvedRoot, walkResult.symlinks);

  const view = buildView(resolvedRoot, files, directories);
  const detection = await runDetectors(view);

  const symlinks = walkResult.symlinks
    .map((entry) => ({
      path: entry.relative,
      name: entry.name,
      depth: depthOf(entry.relative),
      target: symlinkTargets.get(entry.relative) ?? uninspectedTarget(),
    }))
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  const result = createScanResult({
    root: resolvedRoot,
    scannedAt: new Date().toISOString(),
    files,
    directories,
    symlinks,
    ignored,
    languages: detection.languages,
    manifests: detection.manifests,
    tests: detection.tests,
    cicd: detection.cicd,
    documentation: detection.documentation,
    configuration: detection.configuration,
    git: detection.git,
    content: detection.content,
    statistics: {
      filesScanned: files.length,
      directoriesScanned: directories.length,
      symlinksScanned: symlinks.length,
      ignored: ignored.length,
      unreadable: walkResult.errors.length,
      truncatedBy: truncationReasons(walkResult, limits),
    },
    ignore: {
      sources: [gitignoreSource],
      defaultIgnoredDirectories: policy.ignoredDirectories,
      unsupported: policy.unsupported,
    },
    scan: {
      complete: walkResult.complete,
      truncated: walkResult.truncated,
      limits: { maxFiles: limits.maxFiles, maxDepth: limits.maxDepth },
      errors: classifyScanErrors(walkResult),
    },
  });

  // The scanner produces the contract it declares; validating before returning
  // keeps a regression in this layer from reaching Phase 8D as malformed facts.
  return validateScanResult(result);
}
