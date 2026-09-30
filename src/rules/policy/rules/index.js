/**
 * Code Guardian — Policy Rule Aggregation (Phase 23)
 *
 * The pack's rules in their declared order — one, informational. The module exists so the registry
 * is built from `rules/index.js` rather than from the rule file directly, the same shape every other
 * pack uses, and so adding a rule is a one-line change.
 */

import { policyRules } from "./audit.js";

export { policyRules };

/** The audit rules, in the order they are declared. */
export const policyAuditRules = Object.freeze([...policyRules]);
