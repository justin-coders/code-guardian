/**
 * Code Guardian — Production Rule Aggregation (Phase 20)
 *
 * The pack's rules in their declared order: one per audit domain, in the order the report
 * declares its sections. The module exists so the registry is built from `rules/index.js`
 * rather than from the rule files directly — the same shape every other pack uses — and so
 * adding a domain is a one-line change.
 */

import { productionRules } from "./inventory.js";

export { productionRules };

/** The informational inventory rules, in the order they are declared. */
export const productionInventoryRules = Object.freeze([...productionRules]);
