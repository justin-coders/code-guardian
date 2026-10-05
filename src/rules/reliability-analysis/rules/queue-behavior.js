/**
 * Code Guardian — Reliability Queue Behavior Rule (Official Roadmap Phase 17)
 *
 * The "queue behavior" domain. A queue needs a **subject** first (§48): a dependency named `bull`
 * in `package.json` is weaker than an established registration, so the domain reads a *usage* — the
 * module imports a queue package and the symbol graph observed it constructing/calling the imported
 * binding (a queue client, a worker), or declares and uses a callable whose name matches the closed
 * consumer vocabulary.
 *
 * A repository that establishes no queue subject is `not_applicable` over a complete semantic
 * graph — queue reliability is not expected of a repository with no queue — and `unknown` when the
 * graph is incomplete. The finding never claims acknowledgement, dead-lettering or retry
 * correctness, none of which this build reads.
 */

import {
  RELIABILITY_ANALYSIS_CATEGORY,
  RELIABILITY_ANALYSIS_RULE_IDS,
  RELIABILITY_ANALYSIS_RULE_VERSION,
} from "../contracts.js";

import { createUsageRule, usageSentence } from "./usage.js";

export const queueBehaviorRules = Object.freeze([
  createUsageRule({
    id: RELIABILITY_ANALYSIS_RULE_IDS.QUEUE_BEHAVIOR,
    version: RELIABILITY_ANALYSIS_RULE_VERSION,
    category: RELIABILITY_ANALYSIS_CATEGORY,
    domain: "queue-behavior",
    severity: "info",
    ruleTitle: "A queue/worker mechanism is used by the repository",
    ruleDescription:
      "The repository imports a queue/worker package and the symbol graph observed the module constructing or calling the imported binding, or declares and uses a callable whose name matches the closed consumer vocabulary. The finding states an established queue subject and cites the module's observation; it does not claim acknowledgement, dead-letter, visibility-timeout or retry correctness, none of which the model reads. A queue package present only as a dependency, with no observed use, does not establish the subject. A repository that establishes no queue subject is `not_applicable` over a complete graph.",
    establishedTitle: "A queue/worker mechanism is used by the repository",
    establishedDescription: (usage) => usageSentence(usage),
    absenceState: "not_applicable",
    absentReason: () =>
      "the repository establishes no queue subject, so queue behavior is not applicable",
    falsePositives: [
      "a queue package declared as a dependency but never imported or used",
      "a data structure named `queue` that is not a message broker client",
    ],
    tags: ["reliability", "queue-behavior"],
  }),
]);
