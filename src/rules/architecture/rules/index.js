/**
 * Code Guardian — Architecture Rule Set (Phase 15)
 *
 * The pack's rules, sorted by id so the exported order never depends on the order
 * they happen to be listed in. The registry validates and sorts again; this exists so
 * a consumer importing the rules directly still gets a deterministic set.
 */

import { architectureRules as shipped } from "./inventory.js";

export { architectureRules as architectureInventoryRules } from "./inventory.js";

export const architectureRules = Object.freeze(
  [...shipped].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
);
