/**
 * Code Guardian — Testing Rule Set (Official Roadmap Phase 11)
 *
 * The shipped rules, frozen and sorted by id. Ordering is stated here (and again by
 * the registry) so no consumer can inherit an ordering from module-evaluation order:
 * two runs over the same model must evaluate, report and fingerprint in the same
 * sequence.
 */

import { ciRules } from "./ci.js";
import { configurationRules } from "./configuration.js";
import { coverageRules } from "./coverage.js";
import { flakyRules } from "./flaky.js";
import { frameworkRules } from "./framework.js";
import { levelRules } from "./levels.js";
import { scriptRules } from "./scripts.js";

function byId(a, b) {
  if (a.id === b.id) return 0;
  return a.id < b.id ? -1 : 1;
}

/** Every rule this pack ships, sorted by rule id. */
export const testingRules = Object.freeze(
  [
    ...frameworkRules,
    ...configurationRules,
    ...scriptRules,
    ...ciRules,
    ...coverageRules,
    ...levelRules,
    ...flakyRules,
  ].sort(byId),
);
