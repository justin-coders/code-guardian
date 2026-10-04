/**
 * Code Guardian — Architecture Analysis Rule Set (Official Roadmap Phase 14)
 *
 * The nine official-roadmap domain rules, frozen and sorted by id. Ordering is stated here (and
 * again by the registry) so no consumer can inherit an ordering from module-evaluation order:
 * two runs over the same model must evaluate, report and fingerprint in the same sequence.
 */

import { architectureCouplingRules } from "./coupling.js";
import { architectureDependencyRules } from "./dependency.js";
import { architectureLayerRules } from "./layer.js";
import { architectureLeakageRules } from "./leakage.js";
import { architectureModuleRules } from "./modules.js";
import { architecturePatternRules } from "./patterns.js";

function byId(a, b) {
  if (a.id === b.id) return 0;
  return a.id < b.id ? -1 : 1;
}

/** Every rule this pack ships, sorted by rule id. */
export const architectureAnalysisRules = Object.freeze(
  [
    ...architectureModuleRules,
    ...architectureDependencyRules,
    ...architectureLayerRules,
    ...architectureCouplingRules,
    ...architectureLeakageRules,
    ...architecturePatternRules,
  ].sort(byId),
);

export {
  architectureCouplingRules,
  architectureDependencyRules,
  architectureLayerRules,
  architectureLeakageRules,
  architectureModuleRules,
  architecturePatternRules,
};
