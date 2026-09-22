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
  COVERAGE_GUARANTEES,
  ENTITY_KINDS,
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
