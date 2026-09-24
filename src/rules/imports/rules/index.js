/**
 * Code Guardian — Import Rule Aggregation (Phase 16)
 *
 * The pack's rules in their declared order. One rule, so the module exists to keep
 * the pack's shape identical to the security, dependency and architecture packs
 * (a registry built from `rules/index.js` rather than from the rule files directly),
 * and to make adding a second import rule a one-line change.
 */

import { importRules } from "./inventory.js";

export { importRules };

/** The informational inventory rules, in the order they are declared. */
export const importInventoryRules = Object.freeze([...importRules]);
