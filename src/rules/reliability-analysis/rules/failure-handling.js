/**
 * Code Guardian — Reliability Failure Handling Rule (Official Roadmap Phase 17)
 *
 * The "failure handling" domain. The rule reads an observed usage of a failure-handling package
 * (an async-error bridge) or a callable whose name matches the closed failure-handler vocabulary.
 *
 * The API model deliberately does not read handler bodies, so a route **existing** establishes
 * nothing about its failure path, and a `try`/`catch` somewhere in a source file is not API failure
 * handling. This rule therefore reads only a *named, used* failure-handling mechanism, and the
 * absence of one is `unknown` because an inline error handler is not read.
 */

import {
  RELIABILITY_ANALYSIS_CATEGORY,
  RELIABILITY_ANALYSIS_RULE_IDS,
  RELIABILITY_ANALYSIS_RULE_VERSION,
} from "../contracts.js";

import { createUsageRule, usageSentence } from "./usage.js";

export const failureHandlingRules = Object.freeze([
  createUsageRule({
    id: RELIABILITY_ANALYSIS_RULE_IDS.FAILURE_HANDLING,
    version: RELIABILITY_ANALYSIS_RULE_VERSION,
    category: RELIABILITY_ANALYSIS_CATEGORY,
    domain: "failure-handling",
    severity: "info",
    ruleTitle: "A failure-handling mechanism is used by the repository",
    ruleDescription:
      "The repository imports a failure-handling package and the symbol graph observed the module using the imported binding, or declares and uses a callable whose name matches the closed failure-handler vocabulary. The finding states a named failure-handling mechanism is used and cites the module's observation. It does not claim every failure path is covered, and a route existing or a `try`/`catch` existing is not read as failure handling. When no mechanism is established the domain is `unknown`.",
    establishedTitle: "A failure-handling mechanism is used by the repository",
    establishedDescription: (usage) => usageSentence(usage),
    absenceState: "unknown",
    absentReason: () =>
      "the repository establishes no failure-handling package or named failure handler, handler bodies are not read by this build, and an inline error handler cannot be established, so no failure-handling conclusion can be drawn",
    falsePositives: [
      "an inline error handler rather than a named binding",
      "a `try`/`catch` in a source file that is not on a request/consumer failure path",
      "a route existing, which establishes nothing about its failure path",
    ],
    tags: ["reliability", "failure-handling"],
  }),
]);
