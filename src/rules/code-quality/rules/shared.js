/**
 * Code Guardian — Code Quality Rule Shared Helpers (Official Roadmap Phase 12)
 *
 * Small pure helpers the code-quality rule families share: the union of the model evidence
 * behind a set of entities, the one conditional every gap-shaped rule needs, and the
 * bounded-list helper the structural rules use so no rule can emit unbounded output.
 *
 * Nothing here decides a conclusion on its own, and nothing reads outside the frozen model.
 * A gap rule calls `absenceOutcome` only after it has decided its subject is genuinely
 * absent, so the policy lives in one place and every gap rule answers the same way.
 */

import { APPLICABILITY_COVERAGE } from "../../contracts.js";
import { createRuleDetection } from "../../evaluation.js";

import { sourceAbsence } from "../signals.js";

/** The union of the evidence ids the given entities cite, sorted and de-duplicated. */
export function evidenceIdsFor(entities) {
  const ids = new Set();
  for (const entity of entities) {
    for (const id of entity.evidenceIds ?? []) ids.add(id);
  }
  return [...ids].sort();
}

/**
 * The outcome for a gap the rule observed over the repository's coverage.
 *
 *   `{ established: true, absence }`  the scan covered the repository: the caller may assert
 *                                     the gap as a finding or a clean pass.
 *   `{ outcome }`                     the gap cannot be concluded: a Rule-Engine `unknown`
 *                                     detection carrying the model's own reason.
 *
 * @param {object} context A validated AnalysisContext.
 * @param {string} because Bounded explanation prefixed to the model's reason.
 * @returns {{established: true, absence: object}|{outcome: object}}
 */
export function absenceOutcome(context, because) {
  const absence = sourceAbsence(context);
  if (absence.established) return { established: true, absence };
  return {
    outcome: createRuleDetection({
      findings: [],
      coverage: APPLICABILITY_COVERAGE.UNKNOWN,
      reason: `${because}, but ${absence.reason}`,
    }),
  };
}

/**
 * The first `limit` entries of a deterministic list, and whether the list was capped.
 *
 * The roadmap forbids unbounded output, so every structural rule reports at most
 * `CODE_QUALITY_LIMITS.MAX_STRUCTURAL_FINDINGS` indicators and records the cap rather than
 * silently dropping the rest.
 *
 * @param {object[]} entries
 * @param {number} limit
 * @returns {{entries: object[], truncated: boolean}}
 */
export function capFindings(entries, limit) {
  if (entries.length <= limit) return { entries, truncated: false };
  return { entries: entries.slice(0, limit), truncated: true };
}

/** Whether a readiness flag any of the given entities carries is `true` for all of them. */
export function everyFlag(entities, flag) {
  return entities.length > 0 && entities.every((entity) => entity[flag] === true);
}

/**
 * Sanitize a value into the bounded character set a finding `fingerprintKey` allows.
 *
 * The fingerprint key is what keeps two findings from one rule — an export and another
 * export in the same file — from colliding into one fingerprint. A repository-relative path
 * contains `/`, which the key pattern refuses, so it is folded to `.`; the result is a stable,
 * readable discriminator.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function keyFragment(value) {
  const text = typeof value === "string" ? value : String(value ?? "");
  return text.replace(/[^A-Za-z0-9._:-]/g, ".").slice(0, 120);
}
