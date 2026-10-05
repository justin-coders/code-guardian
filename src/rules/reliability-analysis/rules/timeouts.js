/**
 * Code Guardian — Reliability Timeouts Rule (Official Roadmap Phase 17)
 *
 * The "timeouts" domain. The model establishes a timeout only when the repository imports a
 * timeout-shaped package and the symbol graph observes it calling/constructing the imported
 * binding, or declares and uses a callable whose name matches the closed timeout vocabulary.
 *
 * Inline and framework timeouts (`server.setTimeout(…)`, an axios `timeout:` option, a driver
 * `connectTimeout`) are *method calls or option objects this build does not read*. Their absence
 * is therefore `unknown` with a reason — never a clean pass and never an invented gap. Code
 * Guardian's own execution timeout is not repository evidence and is never read here.
 */

import {
  RELIABILITY_ANALYSIS_CATEGORY,
  RELIABILITY_ANALYSIS_RULE_IDS,
  RELIABILITY_ANALYSIS_RULE_VERSION,
} from "../contracts.js";

import { createUsageRule, usageSentence } from "./usage.js";

export const timeoutsRules = Object.freeze([
  createUsageRule({
    id: RELIABILITY_ANALYSIS_RULE_IDS.TIMEOUTS,
    version: RELIABILITY_ANALYSIS_RULE_VERSION,
    category: RELIABILITY_ANALYSIS_CATEGORY,
    domain: "timeouts",
    severity: "info",
    ruleTitle: "A timeout mechanism is used by the repository",
    ruleDescription:
      "The repository imports a timeout-shaped package and the symbol graph observed the module using the imported binding, or declares and uses a callable whose name matches the closed timeout vocabulary. The finding states the usage and cites the module's own semantic observation; it does not claim the timeout is configured with a sensible value, covers every dependency, or fires at runtime. Inline and framework timeouts are not read by this build, so when no usage is established the domain is `unknown` rather than clean.",
    establishedTitle: "A timeout mechanism is used by the repository",
    establishedDescription: (usage) => usageSentence(usage),
    absenceState: "unknown",
    absentReason: () =>
      "the repository establishes no package- or helper-shaped timeout, and inline/framework timeout configuration is not read by this build, so no timeout conclusion can be drawn",
    falsePositives: [
      "a timeout configured inline (`server.setTimeout`, a client option) rather than through an imported package",
      "a timeout-shaped package imported for a purpose other than request/dependency timeouts",
    ],
    tags: ["reliability", "timeouts"],
  }),
]);
