/**
 * Code Guardian — Code Quality Rule Set (Official Roadmap Phase 12)
 *
 * The shipped rules, frozen and sorted by id. Ordering is stated here (and again by the
 * registry) so no consumer can inherit an ordering from module-evaluation order: two runs over
 * the same model must evaluate, report and fingerprint in the same sequence.
 *
 * The families live under `common/` because none of them names a language: the language-specific
 * knowledge is the tool vocabulary in `languages/`, which `common/tooling.js` reads as a union.
 */

import { complexityRules } from "./common/complexity.js";
import { configurationRules } from "./common/configuration.js";
import { deadCodeRules } from "./common/dead-code.js";
import { duplicationRules } from "./common/duplication.js";
import { maintainabilityRules } from "./common/maintainability.js";
import { toolingRules } from "./common/tooling.js";
import { unsafePatternRules } from "./common/unsafe-pattern.js";

function byId(a, b) {
  if (a.id === b.id) return 0;
  return a.id < b.id ? -1 : 1;
}

/** Every rule this pack ships, sorted by rule id. */
export const codeQualityRules = Object.freeze(
  [
    ...toolingRules,
    ...deadCodeRules,
    ...complexityRules,
    ...duplicationRules,
    ...unsafePatternRules,
    ...maintainabilityRules,
    ...configurationRules,
  ].sort(byId),
);
