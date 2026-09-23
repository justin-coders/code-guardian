/**
 * Code Guardian — Dependency Acquisition Detector (Phase 13)
 *
 * The scanner's dependency detector: it decides which inventory manifests declare
 * dependencies, reads each one through the Phase 8A boundary under an explicit
 * byte budget, hands the text to the pure parsers in `policies/dependencies.js`,
 * and returns one record per manifest.
 *
 * ### Acquisition, not evaluation
 *
 * This detector answers "which dependencies does this repository declare, which
 * packages does its lockfile resolve, and which relationships does the lockfile
 * state". It never asks whether a dependency is outdated, vulnerable, licensed
 * correctly or safe: there is no registry lookup, no advisory database, no network
 * socket, no package manager and no process in this file. A version range is
 * recorded as text; nothing is resolved against reality.
 *
 * ### It reuses the slice of the scanner that already exists
 *
 * The manifest inventory was produced by the Phase 8C manifest detector, so the
 * parser table here is keyed by *that* record's `ecosystem`, `kind` and
 * `parse.format` — no second directory walk, no filename guessing, and a manifest
 * the scanner did not observe can never be read. Every read goes through
 * `view.read`, which is the accepted filesystem boundary: contained, symlink-
 * refused, byte-capped and classified.
 *
 * ### Bounded, deterministic, honest about what it could not do
 *
 * Files, bytes, declarations, resolved packages and edges are all capped; a cap
 * that bites sets `truncated`, and a manifest whose format this phase does not
 * interpret is recorded as `unsupported` with a bounded reason. That is what makes
 * the section's `complete` flag meaningful: it is true only when *every* dependency
 * source in the repository was read and interpreted without dropping anything, so
 * "no dependencies" is never claimed over a manifest nobody could read.
 */

import {
  DEPENDENCY_LIMITS,
  DEPENDENCY_SOURCE_REASONS,
  DEPENDENCY_SOURCE_STATUSES,
  compareDeclarations,
  compareEdges,
  compareProblems,
  compareResolved,
  dependencySourceFor,
  runDependencyParser,
} from "../policies/dependencies.js";

/** Whether `status` is a documented dependency source status. */
function sourceRecord(manifest, status, extra) {
  return {
    path: manifest.path,
    ecosystem: manifest.ecosystem,
    kind: manifest.kind,
    format: manifest.parse?.format ?? "unknown",
    status,
    reason: null,
    detail: null,
    dependencies: [],
    resolved: [],
    edges: [],
    truncated: false,
    problems: [],
    ...extra,
  };
}

/**
 * Detect dependency information across the manifest inventory.
 *
 * @param {object} view Repository view built by the scanner.
 * @param {object[]} manifests Manifest entries from `detectManifests`.
 * @returns {Promise<object>} The scan result's `dependencies` section.
 */
export async function detectDependencies(view, manifests) {
  const records = [];
  let totalBytes = 0;
  let inspected = 0;
  let declarationsRetained = 0;
  let resolvedRetained = 0;
  let edgesRetained = 0;

  for (const manifest of manifests) {
    const source = dependencySourceFor({
      ecosystem: manifest.ecosystem,
      kind: manifest.kind,
      format: manifest.parse?.format ?? "unknown",
    });

    if (source.mode === "unsupported") {
      records.push(
        sourceRecord(manifest, DEPENDENCY_SOURCE_STATUSES.UNSUPPORTED, {
          reason: source.reason,
          detail: manifest.parse?.format ?? null,
        }),
      );
      continue;
    }

    const fileBudgetLeft = DEPENDENCY_LIMITS.maxManifests - inspected;
    const byteBudgetLeft = DEPENDENCY_LIMITS.maxTotalBytes - totalBytes;
    if (fileBudgetLeft <= 0 || byteBudgetLeft <= 0) {
      records.push(
        sourceRecord(manifest, DEPENDENCY_SOURCE_STATUSES.FAILED, {
          reason: DEPENDENCY_SOURCE_REASONS.BUDGET_EXHAUSTED,
        }),
      );
      continue;
    }

    const maxBytes = Math.min(DEPENDENCY_LIMITS.maxManifestBytes, byteBudgetLeft);
    const read = await view.read(manifest.path, { maxBytes });
    if (!read.ok) {
      records.push(
        sourceRecord(manifest, DEPENDENCY_SOURCE_STATUSES.FAILED, {
          reason: DEPENDENCY_SOURCE_REASONS.UNREADABLE,
        }),
      );
      continue;
    }

    inspected += 1;
    totalBytes += read.bytesRead;

    if (read.truncated === true) {
      records.push(
        sourceRecord(manifest, DEPENDENCY_SOURCE_STATUSES.FAILED, {
          reason: DEPENDENCY_SOURCE_REASONS.TOO_LARGE,
        }),
      );
      continue;
    }

    const text = typeof read.content === "string" ? read.content : "";
    const parsed = runDependencyParser(source.parser, text);
    if (!parsed.ok) {
      records.push(
        sourceRecord(
          manifest,
          parsed.reason === DEPENDENCY_SOURCE_REASONS.FORMAT_NOT_INTERPRETED
            ? DEPENDENCY_SOURCE_STATUSES.UNSUPPORTED
            : DEPENDENCY_SOURCE_STATUSES.FAILED,
          { reason: parsed.reason, detail: parsed.detail },
        ),
      );
      continue;
    }

    // Global caps are applied in the manifest's own path order, so the retained
    // subset is the same on every scan of the same repository.
    const declarationsRoom = Math.max(0, DEPENDENCY_LIMITS.maxDeclarations - declarationsRetained);
    const resolvedRoom = Math.max(0, DEPENDENCY_LIMITS.maxResolved - resolvedRetained);
    const edgesRoom = Math.max(0, DEPENDENCY_LIMITS.maxEdges - edgesRetained);

    const declarations = [...parsed.declarations].sort(compareDeclarations);
    const resolved = [...parsed.resolved].sort(compareResolved);
    const edges = [...parsed.edges].sort(compareEdges);

    const retainedDeclarations = declarations.slice(0, declarationsRoom);
    const retainedResolved = resolved.slice(0, resolvedRoom);
    const retainedEdges = edges.slice(0, edgesRoom);
    const truncated =
      retainedDeclarations.length < declarations.length ||
      retainedResolved.length < resolved.length ||
      retainedEdges.length < edges.length;

    declarationsRetained += retainedDeclarations.length;
    resolvedRetained += retainedResolved.length;
    edgesRetained += retainedEdges.length;

    records.push({
      path: manifest.path,
      ecosystem: manifest.ecosystem,
      kind: manifest.kind,
      format: manifest.parse?.format ?? "unknown",
      status: DEPENDENCY_SOURCE_STATUSES.PARSED,
      reason: null,
      detail: null,
      dependencies: retainedDeclarations,
      resolved: retainedResolved,
      edges: retainedEdges,
      truncated,
      problems: [...parsed.problems].sort(compareProblems),
    });
  }

  // "Every dependency source in this repository was read and interpreted" is
  // vacuously true when the inventory contains no manifest at all — and *only* then
  // is it true without a parsed source, which is why `inspected` and `complete` are
  // separate facts. An acquisition that never ran cannot reach this code, so a
  // default-constructed section stays `complete: false`.
  const complete = records.every(
    (record) =>
      record.status === DEPENDENCY_SOURCE_STATUSES.PARSED &&
      record.truncated !== true &&
      record.problems.length === 0,
  );

  return {
    inspected: records.some((record) => record.status === DEPENDENCY_SOURCE_STATUSES.PARSED),
    complete,
    // Truncation covers every way the acquisition was cut short: a retained subset
    // of a source's facts, a file larger than the per-file cap, and a source that
    // was never read because the file or byte budget was already spent.
    truncated: records.some(
      (record) =>
        record.truncated === true ||
        record.reason === DEPENDENCY_SOURCE_REASONS.BUDGET_EXHAUSTED ||
        record.reason === DEPENDENCY_SOURCE_REASONS.TOO_LARGE,
    ),
    manifests: records,
    limits: { ...DEPENDENCY_LIMITS },
  };
}
