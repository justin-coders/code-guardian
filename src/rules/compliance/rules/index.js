/**
 * Code Guardian — Compliance Rule Aggregation (Phase 22)
 *
 * The pack's rules in their declared order: one per policy domain, in the order the compliance
 * report declares its sections. The module exists so the registry is built from `rules/index.js`
 * rather than from the rule file directly — the same shape every other pack uses — and so adding a
 * domain is a one-line change.
 */

import { complianceRules } from "./audit.js";

export { complianceRules };

/** The domain rules, in the order they are declared. */
export const complianceDomainRules = Object.freeze([...complianceRules]);
