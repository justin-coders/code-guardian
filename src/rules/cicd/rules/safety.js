/**
 * Code Guardian — Rollback & Deployment-Protection Rules (Official Roadmap Phase 13)
 *
 * The two domains where the roadmap demands the most conservative semantics, and both are
 * **relation** rules rather than absence rules:
 *
 *   rollback               a workflow deploys and establishes no rollback evidence. The roadmap
 *                          is explicit that a `git revert`, a `git reset` or a source-control
 *                          revert is *not* deployment rollback, so the acquisition vocabulary
 *                          contains only deployment-restoration shapes (a rollback job, a
 *                          rollback command, a previous-version target, a provider rollback
 *                          action). The finding says no rollback was **established** — it never
 *                          says rollback is impossible, and nothing here executes anything.
 *   deployment protection   a workflow deploys and establishes no protected environment, no
 *                          required reviewer, no manual gate and no concurrency gate. This is
 *                          the one domain where a finding is worth a `medium` severity, because
 *                          an unprotected deploy path is a consequential configuration fact —
 *                          but the finding still reports configuration, not incident risk, and
 *                          it does not duplicate the provider's branch-protection system, which
 *                          this build cannot read.
 */

import { CICD_RULE_IDS } from "../contracts.js";

import { createRelationRule } from "./factories.js";

export const safetyRules = Object.freeze([
  createRelationRule({
    id: CICD_RULE_IDS.ROLLBACK_NOT_ESTABLISHED,
    domain: "rollback",
    title: "A deploying workflow establishes no rollback behavior",
    description:
      "The workflow deploys and its content establishes no rollback evidence — no rollback job, no rollback command, no previous-version target and no provider rollback action — over a complete read of the file. The finding reports that absence precisely: it does not claim rollback is impossible (a pipeline may be rolled back by an operator, by a provider console, or by a workflow this repository does not contain), and a source-control revert is deliberately not counted, because reverting a commit is not deploying the previous release.",
    premise: (workflow) => workflow.deployments,
    conclusion: (workflow) => workflow.rollbacks,
    severity: "low",
    tags: ["rollback"],
    falsePositives: [
      "a rollback performed outside the repository (an operator, a provider console, a separate pipeline)",
      "a provider whose rollback primitive this build's vocabulary does not document",
    ],
  }),

  createRelationRule({
    id: CICD_RULE_IDS.DEPLOYMENT_PROTECTION_NOT_ESTABLISHED,
    domain: "deployment-protection",
    title: "A deploying workflow establishes no deployment protection",
    description:
      "The workflow deploys and its content establishes no deployment protection — no protected environment declaration or environment gate, no required reviewer, no manual approval and no concurrency gate — over a complete read of the file. The finding reports a configuration fact about the deploy path; it does not assert that the deployment is unsafe, and it does not read or replicate the provider's branch-protection or organization policy settings, which are outside a repository scan.",
    premise: (workflow) => workflow.deployments,
    conclusion: (workflow) => workflow.deploymentProtection,
    severity: "medium",
    tags: ["deployment-protection"],
    falsePositives: [
      "protection configured at the provider or organization level rather than in the workflow file",
      "an environment class the workflow declares without a gate, which is separation rather than protection",
    ],
  }),
]);
