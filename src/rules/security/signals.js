/**
 * Code Guardian — Security Repository Signals (Phase 12)
 *
 * The one place the security rules ask the repository questions. Every read goes
 * through the Phase 11 query API over the frozen RepositoryModel: no filesystem, no
 * `node:path`, no process, no network, no scan. A rule that cannot answer a question
 * from the model reports `unknown` rather than going to look for itself.
 *
 * ### The absence question, and why it has an answer at all
 *
 * Six of the eight rules can only conclude "not present", and "not present" is a
 * claim, not an observation. `inventoryAbsence()` decides whether the model supports
 * it, and it is deliberately conservative:
 *
 *   - the scan must have covered the repository completely (the query envelope's
 *     `coverage: "complete"`, which the model derives from `scan.complete` and
 *     `scan.truncated`), and
 *   - no path may have failed to read.
 *
 * Anything else leaves the answer `unknown`, which the Rule Engine records as an
 * incomplete outcome instead of a clean pass.
 *
 * ### Ignored paths: why they do not make the answer `unknown`
 *
 * The scanner records two kinds of *deliberate* exclusion: generated/dependency
 * directories (`.git`, `node_modules`, `dist`, `vendor`, …) and paths matched by the
 * repository's own root `.gitignore`. Both are policy decisions with a recorded
 * reason, and neither describes a path the statement "a sensitive file is committed
 * to this repository" is about: a `.gitignore`d `.env` is by definition not
 * committed, and a dependency directory's contents belong to the dependency.
 *
 * Treating them as unknown would make every rule permanently inconclusive — every
 * realistic repository ignores `.git` — and would trade a real, checkable claim for
 * a permanently useless one. The choice is therefore recorded rather than hidden:
 * `inventoryAbsence()` returns the ignored count, and the rules put it in the
 * result metadata so a consumer can see exactly what basis the answer rests on.
 */

import {
  CONTAINER_SIGNALS,
  CONTENT_SIGNALS,
  CONTENT_STATUSES,
  COVERAGE_GUARANTEES,
  ENTITY_KINDS,
  SYMLINK_TARGET_KINDS,
  createRepositoryQuery,
} from "../../repository/model/index.js";

import { matchesFileSpec } from "./matching.js";

/**
 * Build the read-only query handle for an AnalysisContext.
 *
 * The context carries the frozen RepositoryModel — the only repository knowledge a
 * rule is allowed to have — and the query layer is a pure view over it.
 *
 * @param {object} context A validated AnalysisContext.
 * @returns {object} A frozen query handle.
 */
export function queryFor(context) {
  return createRepositoryQuery(context.repository);
}

/**
 * The observed file inventory: entities plus the model's coverage guarantee.
 *
 * @param {object} query
 * @returns {{entities: object[], coverage: string, truncated: boolean}}
 */
export function fileInventory(query) {
  return query.listEntities(ENTITY_KINDS.FILE);
}

/**
 * Observed files matching a filename spec, in the inventory's deterministic id
 * order. Matching is by name only; no content is read.
 *
 * @param {object} query
 * @param {object} spec A spec from `defineFileSpec`.
 * @returns {object[]} File entities.
 */
export function filesMatching(query, spec) {
  return fileInventory(query).entities.filter((file) => matchesFileSpec(spec, file));
}

/**
 * Configuration entities the scanner reported with one signal, in id order.
 *
 * @param {object} query
 * @param {string} signal A `CONFIGURATION_SIGNALS` value.
 * @returns {object[]} Configuration entities carrying that signal.
 */
export function configurationEntities(query, signal) {
  return query
    .listEntities(ENTITY_KINDS.CONFIGURATION)
    .entities.filter((entity) => entity.signal === signal);
}

/**
 * Symlink entities the inventory recorded, in deterministic id order.
 *
 * Every entity carries its classified `target`, so a rule can tell an escaping link
 * (`outside`) from one that stays inside the repository and from one the scanner
 * could not classify (`unknown`). The two shapes are deliberately distinct values:
 * "we looked and it points out" is a finding, "we could not look" is not.
 *
 * @param {object} query
 * @returns {{entities: object[], coverage: string, truncated: boolean}}
 */
export function symlinkInventory(query) {
  return query.listEntities(ENTITY_KINDS.SYMLINK);
}

/**
 * The content inspection the model recorded for one observed file.
 *
 * Returns `null` when the file has no inspection observation at all — an older scan,
 * or an acquisition path that ran no content inspection. That is *not* "the content
 * is clean": the caller must treat it as `unknown`, which is why "nothing was
 * recorded" and "recorded as inspected" are different return values rather than two
 * fields of one.
 *
 * @param {object} query
 * @param {object} file A `file` entity.
 * @returns {{status: string, reason: string|null, bytesInspected: number|null,
 *   patterns: Array<{pattern: string, evidenceId: string}>}|null} Frozen, or null.
 */
export function contentInspectionFor(query, file) {
  const result = query.getEvidenceForEntity(file.id);
  const records = result.evidence ?? [];

  let inspection = null;
  const patterns = [];
  for (const record of records) {
    const signal = record?.data?.signal;
    if (signal === CONTENT_SIGNALS.INSPECTION && inspection === null) {
      inspection = record;
    } else if (signal === CONTENT_SIGNALS.PATTERN) {
      const pattern = record?.data?.pattern;
      if (typeof pattern === "string" && pattern !== "") {
        patterns.push({ pattern, evidenceId: record.id });
      }
    }
  }

  if (inspection === null) return null;

  return Object.freeze({
    status: typeof inspection.data.status === "string" ? inspection.data.status : null,
    reason: typeof inspection.data.reason === "string" ? inspection.data.reason : null,
    bytesInspected:
      Number.isInteger(inspection.data.bytesInspected) ? inspection.data.bytesInspected : null,
    evidenceId: inspection.id,
    patterns: Object.freeze(patterns.sort((a, b) => (a.evidenceId < b.evidenceId ? -1 : 1))),
  });
}

/** Whether a content inspection establishes a conclusion about a file's contents. */
export function isCompleteContentInspection(inspection) {
  return inspection !== null && inspection.status === CONTENT_STATUSES.INSPECTED;
}

/**
 * The symlinks whose target escapes the repository, and those that are unresolved.
 *
 * Unresolved covers both `unknown` classifications and a missing `target` field: a
 * model built from a scan that did not classify its links must not be read as one
 * whose links are all inside.
 *
 * @param {object} query
 * @returns {{escaping: object[], unresolved: object[], inside: object[], total: number,
 *   reasons: string[]}}
 */
export function symlinkTargets(query) {
  const inventory = symlinkInventory(query);
  const escaping = [];
  const unresolved = [];
  const inside = [];
  const reasons = new Set();

  for (const entity of inventory.entities) {
    const kind = entity.target?.kind;
    if (kind === SYMLINK_TARGET_KINDS.OUTSIDE) {
      escaping.push(entity);
    } else if (kind === SYMLINK_TARGET_KINDS.INSIDE) {
      inside.push(entity);
    } else {
      unresolved.push(entity);
      const reason = entity.target?.reason;
      if (typeof reason === "string" && reason !== "") reasons.add(reason);
    }
  }

  return Object.freeze({
    escaping: Object.freeze(escaping),
    unresolved: Object.freeze(unresolved),
    inside: Object.freeze(inside),
    total: inventory.entities.length,
    coverage: inventory.coverage,
    truncated: inventory.truncated === true,
    reasons: Object.freeze([...reasons].sort()),
  });
}

/**
 * The build context roots the repository *states* for one Dockerfile.
 *
 * Read from the Compose declarations the acquisition layer recorded on the Dockerfile
 * itself. Zero contexts means "nothing in the model ties this Dockerfile to a
 * context" — which the rule must treat as unknown rather than assume, and which is why
 * this returns a list rather than a single best guess: two declarations with different
 * roots are a contradiction, not a choice.
 *
 * A `null` recorded context is the repository root, which has no repository-relative
 * form; it is normalized to `.` here so callers compare context roots with the same
 * token a root-level `.dockerignore` produces.
 *
 * @param {object} query
 * @param {object} dockerfile A `dockerfile` configuration entity.
 * @returns {{contexts: string[], evidenceIds: string[]}} Frozen.
 */
export function declaredBuildContexts(query, dockerfile) {
  const contexts = new Set();
  const evidenceIds = new Set();

  for (const record of query.getEvidenceForEntity(dockerfile.id).evidence ?? []) {
    if (record?.data?.signal !== CONTAINER_SIGNALS.BUILD_CONTEXT) continue;
    const contextPath = record.data.contextPath;
    if (contextPath !== null && (typeof contextPath !== "string" || contextPath === "")) {
      continue;
    }
    contexts.add(contextPath ?? ".");
    evidenceIds.add(record.id);
  }

  return Object.freeze({
    contexts: Object.freeze([...contexts].sort()),
    evidenceIds: Object.freeze([...evidenceIds].sort()),
  });
}

/**
 * Compose files whose build declarations could not be interpreted.
 *
 * A file in this list *might* have declared a context for any Dockerfile, so an
 * undeclared Dockerfile is unknown rather than unauthored. Returned in path order with
 * the bounded reason the acquisition layer recorded.
 *
 * @param {object} query
 * @returns {Array<{path: string, reason: string}>}
 */
export function uninterpretableComposeFiles(query) {
  const files = [];

  for (const entity of configurationEntities(query, "compose-file")) {
    for (const record of query.getEvidenceForEntity(entity.id).evidence ?? []) {
      if (record?.data?.signal !== CONTAINER_SIGNALS.UNPARSED) continue;
      files.push({
        path: entity.path,
        reason: typeof record.data.reason === "string" ? record.data.reason : "uninterpretable",
      });
      break;
    }
  }

  return files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

/**
 * Whether the model supports an absence claim over the file inventory.
 *
 * @param {object} query
 * @returns {{established: boolean, reason: string|null, observedFiles: number, ignoredPaths: number}}
 *   Frozen. `reason` is a bounded, safe explanation when `established` is false.
 */
export function inventoryAbsence(query) {
  const inventory = fileInventory(query);
  const summary = query.coverage();
  const reasons = [];

  if (inventory.coverage !== COVERAGE_GUARANTEES.COMPLETE) {
    reasons.push(
      summary.truncated === true
        ? "the scan stopped at a limit before the inventory was complete"
        : "the scan did not cover the repository completely",
    );
  }
  if (summary.unreadableCount > 0) {
    reasons.push(`${summary.unreadableCount} path(s) could not be read`);
  }

  return Object.freeze({
    established: reasons.length === 0,
    reason: reasons.length === 0 ? null : reasons.join("; "),
    observedFiles: inventory.entities.length,
    ignoredPaths: summary.ignoredCount,
  });
}
