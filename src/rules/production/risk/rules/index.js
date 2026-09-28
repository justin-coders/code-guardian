/**
 * Code Guardian — Production Risk Rule Aggregation (Phase 21)
 *
 * The pack's rules in their declared order: one per audit domain, in the order the risk report
 * declares its sections. The module exists so the registry is built from `rules/index.js`
 * rather than from the rule files directly — the same shape every other pack uses — and so
 * adding a domain is a one-line change.
 */

import { productionRiskRules } from "./audit.js";

export { productionRiskRules };

/** The audit rules, in the order they are declared. */
export const productionRiskAuditRules = Object.freeze([...productionRiskRules]);
