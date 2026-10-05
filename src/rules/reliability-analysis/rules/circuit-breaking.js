/**
 * Code Guardian — Reliability Circuit Breaking Rule (Official Roadmap Phase 17)
 *
 * The "circuit breaking" domain. Circuit breaking is a distinct mechanism: a retry, a timeout or a
 * `catch` is *not* one, so the rule reads only an observed usage of a circuit-breaker package or a
 * callable whose name matches the closed circuit-breaker vocabulary.
 *
 * A repository that establishes no upstream dependency may legitimately need no circuit breaker
 * (§50), so the absence of an established circuit breaker is `unknown` — the rule never claims
 * "no circuit breaker" from the mere existence of a dependency call, which this build cannot even
 * see.
 */

import {
  RELIABILITY_ANALYSIS_CATEGORY,
  RELIABILITY_ANALYSIS_RULE_IDS,
  RELIABILITY_ANALYSIS_RULE_VERSION,
} from "../contracts.js";

import { createUsageRule, usageSentence } from "./usage.js";

export const circuitBreakingRules = Object.freeze([
  createUsageRule({
    id: RELIABILITY_ANALYSIS_RULE_IDS.CIRCUIT_BREAKING,
    version: RELIABILITY_ANALYSIS_RULE_VERSION,
    category: RELIABILITY_ANALYSIS_CATEGORY,
    domain: "circuit-breaking",
    severity: "info",
    ruleTitle: "A circuit-breaker mechanism is used by the repository",
    ruleDescription:
      "The repository imports a circuit-breaker package and the symbol graph observed the module using the imported binding, or declares and uses a callable whose name matches the closed circuit-breaker vocabulary. The finding states the usage and cites the module's own semantic observation; it does not claim any threshold, state machine or upstream dependency is configured correctly. A retry, a timeout or a `catch` is not a circuit breaker, so none of those establishes this domain, and an established absence is not claimed because the relationship between the service and its upstream dependencies is not read.",
    establishedTitle: "A circuit-breaker mechanism is used by the repository",
    establishedDescription: (usage) => usageSentence(usage),
    absenceState: "unknown",
    absentReason: () =>
      "the repository establishes no circuit-breaker usage, and neither the repository's upstream dependencies nor an inline breaker implementation can be established from the model, so no circuit-breaking conclusion can be drawn",
    falsePositives: [
      "a retry or timeout mistaken for a circuit breaker",
      "a circuit breaker configured inline rather than through an imported package",
    ],
    tags: ["reliability", "circuit-breaking"],
  }),
]);
