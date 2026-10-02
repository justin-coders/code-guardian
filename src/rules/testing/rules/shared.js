/**
 * Code Guardian — Testing Rule Shared Helpers (Official Roadmap Phase 11)
 *
 * Small pure helpers the testing rule families share: the union of the model
 * evidence behind a set of entities, and the one conditional every gap-shaped rule
 * needs — "no artifact was observed; is that a clean absence, or an unknown?".
 *
 * Nothing here decides a conclusion on its own, and nothing reads outside the frozen
 * model. A gap rule calls `absenceOutcome` only after it has decided its subject is
 * genuinely absent, so the policy lives in one place and every gap rule answers the
 * same way.
 */

import { APPLICABILITY_COVERAGE } from "../../contracts.js";
import { createRuleDetection } from "../../evaluation.js";

import { testInventory, testingAbsence } from "../signals.js";

/** The union of the evidence ids the given entities cite, sorted and de-duplicated. */
export function evidenceIdsFor(entities) {
  const ids = new Set();
  for (const entity of entities) {
    for (const id of entity.evidenceIds ?? []) ids.add(id);
  }
  return [...ids].sort();
}

/** A compact, consistent view of the testing model facts a rule reasons from. */
export function testScope(query) {
  const tests = testInventory(query).entities;
  return {
    tests,
    files: tests.filter((entity) => entity.testKind === "file"),
    directories: tests.filter((entity) => entity.testKind === "directory"),
    configurations: tests.filter((entity) => entity.testKind === "configuration"),
    anyTests: tests.length > 0,
  };
}

/**
 * The outcome for a gap the rule observed over the repository's coverage.
 *
 *   `{ established: true }`  the scan covered the repository: the caller may assert
 *                            the absence as a finding or a pass.
 *   `{ outcome }`            the absence cannot be concluded: a Rule-Engine `unknown`
 *                            detection carrying the model's own reason.
 *
 * @param {object} context A validated AnalysisContext.
 * @param {string} because Bounded explanation prefixed to the model's reason.
 * @returns {{established: true}|{outcome: object}}
 */
export function absenceOutcome(context, because) {
  const absence = testingAbsence(context);
  if (absence.established) return { established: true, absence };
  return {
    outcome: createRuleDetection({
      findings: [],
      coverage: APPLICABILITY_COVERAGE.UNKNOWN,
      reason: `${because}, but ${absence.reason}`,
    }),
  };
}
