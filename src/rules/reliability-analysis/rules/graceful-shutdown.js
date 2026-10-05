/**
 * Code Guardian — Reliability Graceful Shutdown Rule (Official Roadmap Phase 17)
 *
 * The "graceful shutdown" domain. The rule reads an observed usage of a graceful-shutdown package
 * (a terminus/stoppable/http-terminator style lifecycle helper) or a callable whose name matches
 * the closed shutdown vocabulary.
 *
 * It deliberately does **not** treat any `process.on(…)` as graceful shutdown: the symbol graph
 * records `process.on` only as an undeclared-name reference, and a signal handler existing is
 * weaker than resources being drained. The finding therefore states that the repository uses a
 * shutdown-shaped mechanism, not that resources are drained before exit, and a repository that
 * declares no shutdown mechanism is `unknown` — a shutdown handler configured as an inline
 * anonymous function is not read.
 */

import {
  RELIABILITY_ANALYSIS_CATEGORY,
  RELIABILITY_ANALYSIS_RULE_IDS,
  RELIABILITY_ANALYSIS_RULE_VERSION,
} from "../contracts.js";

import { createUsageRule, usageSentence } from "./usage.js";

export const gracefulShutdownRules = Object.freeze([
  createUsageRule({
    id: RELIABILITY_ANALYSIS_RULE_IDS.GRACEFUL_SHUTDOWN,
    version: RELIABILITY_ANALYSIS_RULE_VERSION,
    category: RELIABILITY_ANALYSIS_CATEGORY,
    domain: "graceful-shutdown",
    severity: "info",
    ruleTitle: "A graceful-shutdown mechanism is used by the repository",
    ruleDescription:
      "The repository imports a shutdown-lifecycle package and the symbol graph observed the module using the imported binding, or declares and uses a callable whose name matches the closed shutdown vocabulary. The finding states that a shutdown-shaped mechanism is used and cites the module's semantic observation. It does not claim resources are drained before exit — a shutdown handler existing is weaker than resources being released — and a bare `process.on(…)` is not read as graceful shutdown. When no mechanism is established the domain is `unknown`, because an inline anonymous handler is not read by this build.",
    establishedTitle: "A graceful-shutdown mechanism is used by the repository",
    establishedDescription: (usage) => usageSentence(usage),
    absenceState: "unknown",
    absentReason: () =>
      "the repository establishes no shutdown-lifecycle package or shutdown-shaped helper, and an inline signal handler is not read by this build, so no graceful-shutdown conclusion can be drawn",
    falsePositives: [
      "a shutdown handler registered as an inline anonymous function rather than a named binding",
      "a shutdown helper for a library that is not a long-running service",
      "a signal handler that logs but does not drain resources",
    ],
    tags: ["reliability", "graceful-shutdown"],
  }),
]);
