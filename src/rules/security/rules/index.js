/**
 * Code Guardian — Security Rule Set (Phase 12)
 *
 * The shipped rules, frozen and sorted by id. Ordering is stated here (and again by
 * the registry) so no consumer can inherit an ordering from module-evaluation order:
 * two runs over the same model must evaluate, report and fingerprint in the same
 * sequence regardless of how the process loaded this file.
 */

import { configurationRules } from "./configuration.js";
import { exposureRules } from "./exposure.js";
import { sensitiveContentRules } from "./sensitive-content.js";
import { sensitiveFileRules } from "./sensitive-files.js";

function byId(a, b) {
  if (a.id === b.id) return 0;
  return a.id < b.id ? -1 : 1;
}

/** Every rule this pack ships, sorted by rule id. */
export const securityRules = Object.freeze(
  [...sensitiveFileRules, ...configurationRules, ...sensitiveContentRules, ...exposureRules].sort(
    byId,
  ),
);
