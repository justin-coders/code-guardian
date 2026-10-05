/**
 * Code Guardian — Reliability Resource Cleanup Rule (Official Roadmap Phase 17)
 *
 * The "resource cleanup" domain. Cleanup is not a repository-wide boolean: it is tied to concrete
 * resources (connections, streams, handles, subscriptions, workers, listeners). The model cannot
 * establish a resource lifecycle relationship from a handler body, so the rule reads only an
 * observed usage of a cleanup-shaped package or a callable whose name matches the closed cleanup
 * vocabulary.
 *
 * A `finally` block somewhere, or a `close()` method call, is *not* read by this build. The rule
 * never claims "resources are cleaned up" and never claims an absence: a repository that
 * establishes no named cleanup mechanism is `unknown`.
 */

import {
  RELIABILITY_ANALYSIS_CATEGORY,
  RELIABILITY_ANALYSIS_RULE_IDS,
  RELIABILITY_ANALYSIS_RULE_VERSION,
} from "../contracts.js";

import { createUsageRule, usageSentence } from "./usage.js";

export const resourceCleanupRules = Object.freeze([
  createUsageRule({
    id: RELIABILITY_ANALYSIS_RULE_IDS.RESOURCE_CLEANUP,
    version: RELIABILITY_ANALYSIS_RULE_VERSION,
    category: RELIABILITY_ANALYSIS_CATEGORY,
    domain: "resource-cleanup",
    severity: "info",
    ruleTitle: "A resource-cleanup mechanism is used by the repository",
    ruleDescription:
      "The repository imports a cleanup-shaped package and the symbol graph observed the module using the imported binding, or declares and uses a callable whose name matches the closed cleanup vocabulary. The finding states that a named cleanup mechanism is used and cites the module's observation. It does not claim that every resource is released, or tie the mechanism to a resource relationship the model cannot establish, and a `finally` block or a `close()` method call is not read. When no mechanism is established the domain is `unknown`.",
    establishedTitle: "A resource-cleanup mechanism is used by the repository",
    establishedDescription: (usage) => usageSentence(usage),
    absenceState: "unknown",
    absentReason: () =>
      "the repository establishes no cleanup package or named cleanup helper, and handler bodies and `finally` blocks are not read by this build, so no resource-cleanup conclusion can be drawn",
    falsePositives: [
      "a `finally` block or a `close()`/`dispose()` method call rather than a named binding",
      "a cleanup helper for resources the model cannot establish",
    ],
    tags: ["reliability", "resource-cleanup"],
  }),
]);
