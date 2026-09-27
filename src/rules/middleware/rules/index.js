/**
 * Code Guardian — Middleware Rule Aggregation (Phase 19)
 *
 * The pack's rules in their declared order. One rule, so the module exists to keep the pack's
 * shape identical to the security, dependency, architecture, import, symbol and API packs (a
 * registry built from `rules/index.js` rather than from the rule files directly), and to make
 * adding a second middleware rule a one-line change.
 */

import { middlewareRules } from "./inventory.js";

export { middlewareRules };

/** The informational inventory rules, in the order they are declared. */
export const middlewareInventoryRules = Object.freeze([...middlewareRules]);
