/**
 * Code Guardian — API Rule Aggregation (Phase 18)
 *
 * The pack's rules in their declared order. One rule, so the module exists to keep the
 * pack's shape identical to the security, dependency, architecture, import and symbol
 * packs (a registry built from `rules/index.js` rather than from the rule files
 * directly), and to make adding a second API rule a one-line change.
 */

import { apiRules } from "./inventory.js";

export { apiRules };

/** The informational inventory rules, in the order they are declared. */
export const apiInventoryRules = Object.freeze([...apiRules]);
