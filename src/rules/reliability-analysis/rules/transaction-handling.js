/**
 * Code Guardian — Reliability Transaction Handling Rule (Official Roadmap Phase 17)
 *
 * The "transaction handling" domain. A transaction needs a **subject** first (§49): a Git
 * operation, a filesystem write, a lockfile, or a queue acknowledgement is not a database
 * transaction, and using a database client is not using a transaction — which is why the closed
 * package vocabulary lists no database client here.
 *
 * The model reads no handler body, and a transaction API is almost always a method call
 * (`db.transaction(…)`), so the domain rests on a *named* transaction helper the repository
 * declares and uses (`withTransaction`, `runInTransaction`, …). A repository that establishes no
 * such subject concludes `not_applicable` over a complete semantic graph — transaction handling is
 * not expected of every backend — and `unknown` when the graph is incomplete.
 */

import {
  RELIABILITY_ANALYSIS_CATEGORY,
  RELIABILITY_ANALYSIS_RULE_IDS,
  RELIABILITY_ANALYSIS_RULE_VERSION,
} from "../contracts.js";

import { createUsageRule, usageSentence } from "./usage.js";

export const transactionHandlingRules = Object.freeze([
  createUsageRule({
    id: RELIABILITY_ANALYSIS_RULE_IDS.TRANSACTION_HANDLING,
    version: RELIABILITY_ANALYSIS_RULE_VERSION,
    category: RELIABILITY_ANALYSIS_CATEGORY,
    domain: "transaction-handling",
    severity: "info",
    ruleTitle: "A transaction-handling mechanism is used by the repository",
    ruleDescription:
      "The repository declares and uses a callable whose name matches the closed transaction-helper vocabulary, or imports a transaction-abstraction package and the symbol graph observed its use. The finding states that a named transaction mechanism is used and cites the module's observation; it does not claim the transaction is correct, complete or isolated. A Git operation, a filesystem write, a lockfile or a queue acknowledgement is not a database transaction, and a database client is not a transaction, so none of those establishes this domain. A repository that establishes no transaction subject is `not_applicable` over a complete graph.",
    establishedTitle: "A transaction-handling mechanism is used by the repository",
    establishedDescription: (usage) => usageSentence(usage),
    absenceState: "not_applicable",
    absentReason: () =>
      "the repository establishes no transaction subject, so transaction handling is not applicable",
    falsePositives: [
      "a variable, parameter or column named `transaction` that is not a transaction helper",
      "a database client dependency mistaken for a transaction",
      "a `ROLLBACK` word in documentation or a migration file",
    ],
    tags: ["reliability", "transaction-handling"],
  }),
]);
