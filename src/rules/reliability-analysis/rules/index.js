/**
 * Code Guardian — Reliability Analysis Rule Set (Official Roadmap Phase 17)
 *
 * The ten official-roadmap domain rules, frozen and sorted by id. Ordering is stated here (and
 * again by the registry) so no consumer can inherit an ordering from module-evaluation order: two
 * runs over the same model must evaluate, report and fingerprint in the same sequence.
 *
 * Eight domains read an observed usage (a package import plus an occurrence, or a local named
 * helper), one is a structural domain (health checks) and one is multi-dimensional (observability).
 * All ten are addressed, which is what the roadmap asks; none claims more than the model
 * establishes.
 */

import { circuitBreakingRules } from "./circuit-breaking.js";
import { failureHandlingRules } from "./failure-handling.js";
import { gracefulShutdownRules } from "./graceful-shutdown.js";
import { healthChecksRules } from "./health-checks.js";
import { observabilityRules } from "./observability.js";
import { queueBehaviorRules } from "./queue-behavior.js";
import { resourceCleanupRules } from "./resource-cleanup.js";
import { retryBehaviorRules } from "./retry-behavior.js";
import { timeoutsRules } from "./timeouts.js";
import { transactionHandlingRules } from "./transaction-handling.js";

function byId(a, b) {
  if (a.id === b.id) return 0;
  return a.id < b.id ? -1 : 1;
}

/** Every rule this pack ships, sorted by rule id. */
export const reliabilityAnalysisRules = Object.freeze(
  [
    ...timeoutsRules,
    ...retryBehaviorRules,
    ...circuitBreakingRules,
    ...gracefulShutdownRules,
    ...healthChecksRules,
    ...failureHandlingRules,
    ...resourceCleanupRules,
    ...transactionHandlingRules,
    ...queueBehaviorRules,
    ...observabilityRules,
  ].sort(byId),
);

export {
  circuitBreakingRules,
  failureHandlingRules,
  gracefulShutdownRules,
  healthChecksRules,
  observabilityRules,
  queueBehaviorRules,
  resourceCleanupRules,
  retryBehaviorRules,
  timeoutsRules,
  transactionHandlingRules,
};
