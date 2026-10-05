/**
 * Code Guardian — Reliability Retry Behavior Rule (Official Roadmap Phase 17)
 *
 * The "retry behavior" domain, scoped to *application* retry. The model establishes a retry
 * mechanism only when the repository imports a retry-shaped package and the symbol graph observed
 * it using the imported binding, or declares and uses a callable whose name matches the closed
 * retry vocabulary.
 *
 * The Testing analyzer already owns the test-retry signal (`retry-configuration`); this rule does
 * not read it, and usage in a test file is excluded, so a test-only retry wrapper never becomes an
 * application retry finding. There is deliberately no universal rule "no retries = unreliable":
 * retry is meaningful only for operations that state it, and inline retry loops are not read, so
 * the absence of an established retry mechanism is `unknown`.
 */

import {
  RELIABILITY_ANALYSIS_CATEGORY,
  RELIABILITY_ANALYSIS_RULE_IDS,
  RELIABILITY_ANALYSIS_RULE_VERSION,
} from "../contracts.js";

import { createUsageRule, usageSentence } from "./usage.js";

export const retryBehaviorRules = Object.freeze([
  createUsageRule({
    id: RELIABILITY_ANALYSIS_RULE_IDS.RETRY_BEHAVIOR,
    version: RELIABILITY_ANALYSIS_RULE_VERSION,
    category: RELIABILITY_ANALYSIS_CATEGORY,
    domain: "retry-behavior",
    severity: "info",
    ruleTitle: "An application retry mechanism is used by the repository",
    ruleDescription:
      "The repository imports a retry-shaped package and the symbol graph observed the module using the imported binding, or declares and uses a callable whose name matches the closed retry vocabulary. The finding states an application-side retry usage and cites the module's own semantic observation. It is not the Testing analyzer's test-retry signal: test-file usage is excluded. It makes no claim that retries are idempotent, bounded or appropriate, and an inline retry loop is not read, so when no usage is established the domain is `unknown`.",
    establishedTitle: "An application retry mechanism is used by the repository",
    establishedDescription: (usage) => usageSentence(usage),
    absenceState: "unknown",
    absentReason: () =>
      "the repository establishes no package- or helper-shaped application retry, and inline retry configuration is not read by this build; test retry configuration is a separate, test-system fact and is not application evidence",
    falsePositives: [
      "a retry configured inline rather than through an imported package",
      "a retry used only in tests (excluded from this analysis)",
      "a package used for a non-retry purpose under a retry-shaped name",
    ],
    tags: ["reliability", "retry-behavior"],
  }),
]);
