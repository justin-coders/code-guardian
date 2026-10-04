/**
 * Code Guardian — Dependency Analysis Rule Set (Official Roadmap Phase 15)
 *
 * The eight official-roadmap domain rules, frozen and sorted by id. Ordering is stated here (and
 * again by the registry) so no consumer can inherit an ordering from module-evaluation order:
 * two runs over the same model and dataset must evaluate, report and fingerprint in the same
 * sequence.
 */

import { dependencyConcentrationRules } from "./concentration.js";
import { dependencyDuplicateRules } from "./duplicates.js";
import { dependencyLockfileRules } from "./lockfile.js";
import { dependencyManagerRules } from "./manager.js";
import { dependencyOutdatedRules } from "./outdated.js";
import { dependencySupplyChainRules } from "./supply-chain.js";
import { dependencyUnusedRules } from "./unused.js";
import { dependencyVulnerabilityRules } from "./vulnerability.js";

function byId(a, b) {
  if (a.id === b.id) return 0;
  return a.id < b.id ? -1 : 1;
}

/** Every rule this pack ships, sorted by rule id. */
export const dependencyAnalysisRules = Object.freeze(
  [
    ...dependencyOutdatedRules,
    ...dependencyVulnerabilityRules,
    ...dependencyUnusedRules,
    ...dependencyDuplicateRules,
    ...dependencyConcentrationRules,
    ...dependencyLockfileRules,
    ...dependencyManagerRules,
    ...dependencySupplyChainRules,
  ].sort(byId),
);

export {
  dependencyConcentrationRules,
  dependencyDuplicateRules,
  dependencyLockfileRules,
  dependencyManagerRules,
  dependencyOutdatedRules,
  dependencySupplyChainRules,
  dependencyUnusedRules,
  dependencyVulnerabilityRules,
};
