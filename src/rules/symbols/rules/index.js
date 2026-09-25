/**
 * Code Guardian — Symbol Rule Aggregation (Phase 17)
 *
 * The pack's rules in their declared order. One rule, so the module exists to keep the
 * pack's shape identical to the security, dependency, architecture and import packs
 * (a registry built from `rules/index.js` rather than from the rule files directly), and
 * to make adding a second symbol rule a one-line change.
 */

import { symbolRules } from "./inventory.js";

export { symbolRules };

/** The informational inventory rules, in the order they are declared. */
export const symbolInventoryRules = Object.freeze([...symbolRules]);
