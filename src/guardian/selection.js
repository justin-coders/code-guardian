/**
 * Code Guardian — Analyzer Selection (Official Roadmap Phase 19)
 *
 * Pipeline stage 3 is "select analyzers". This module is that stage, built
 * entirely on the accepted `createAnalyzerRegistry`:
 *
 *   "all" (default)   every registered analyzer, id-sorted
 *   explicit ids      exactly those analyzers, id-sorted and de-duplicated
 *
 * Selection is deterministic and never depends on registration order, on the
 * order the caller listed ids, or on object key order: the registry sorts and
 * de-duplicates, and this layer delegates to it rather than re-sorting.
 *
 * Two refusals matter, and both exist so a misconfiguration cannot look like a
 * clean audit:
 *
 *   - an unknown explicitly requested id fails through the registry
 *     (`AnalyzerConfigurationError`), rather than silently producing an audit of
 *     the ids that happened to exist;
 *   - an empty selection — from an empty registry or an explicit empty list —
 *     fails here, because a run that analysed nothing must never read as a run
 *     that found nothing wrong.
 */

import { GUARDIAN_SELECTION_ALL } from "./contracts.js";
import { GUARDIAN_FAILURE_CODES, GuardianConfigurationError } from "./errors.js";

function isRegistry(value) {
  return value !== null && typeof value === "object" && typeof value.select === "function";
}

/**
 * Resolve the selection to a deterministic, non-empty list of analyzers.
 *
 * @param {object} registry An analyzer registry from `createAnalyzerRegistry`.
 * @param {string[]|"all"} selection Resolved selection (see `resolveAuditOptions`).
 * @returns {object[]} Registered analyzers, id-sorted and de-duplicated.
 * @throws {AnalyzerConfigurationError} When an explicitly requested id is unknown.
 * @throws {GuardianConfigurationError} When the selection is empty.
 */
export function selectAnalyzers(registry, selection) {
  if (!isRegistry(registry)) {
    throw new GuardianConfigurationError(
      "selectAnalyzers requires an analyzer registry with a select method",
      { details: { field: "registry" } },
    );
  }

  const requested = selection === GUARDIAN_SELECTION_ALL ? registry.ids() : selection;

  if (!Array.isArray(requested) || requested.length === 0) {
    throw new GuardianConfigurationError(
      "no analyzers were selected: an audit must run at least one analyzer",
      { code: GUARDIAN_FAILURE_CODES.emptySelection, details: { field: "options.analyzers" } },
    );
  }

  // `registry.select` de-duplicates, sorts and rejects unknown ids; delegating to
  // it keeps exactly one authority on what "selected" means.
  const selected = registry.select(requested);

  if (selected.length === 0) {
    throw new GuardianConfigurationError(
      "no analyzers were selected: an audit must run at least one analyzer",
      { code: GUARDIAN_FAILURE_CODES.emptySelection, details: { field: "options.analyzers" } },
    );
  }

  return selected;
}
