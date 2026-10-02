/**
 * Code Guardian — Workflow-Trigger Rule (Official Roadmap Phase 13)
 *
 * The roadmap's "workflow triggers" domain. A workflow that establishes no trigger is a
 * concrete, checkable observation — but only over a read that actually saw the whole file, which
 * is why the rule is built from `createAbsenceRule` and abstains otherwise.
 *
 * Trigger *semantics* are deliberately not judged: the rule never says a trigger is too broad,
 * too narrow or wrong, because "good CI" has no universal definition and the roadmap forbids
 * inventing one. It reports what the workflow establishes, and the restriction facts (branches,
 * paths, tags) stay in the summary where a consumer can read them without a verdict.
 */

import { CICD_RULE_IDS } from "../contracts.js";

import { createAbsenceRule } from "./factories.js";

export const triggerRules = Object.freeze([
  createAbsenceRule({
    id: CICD_RULE_IDS.TRIGGERS_UNESTABLISHED,
    domain: "triggers",
    title: "A workflow establishes no trigger",
    description:
      "The workflow's content was read in full and establishes no trigger event the acquisition layer recognises. The finding says exactly that: no trigger was established by this read, over a complete read of the file. It does not claim a trigger is missing — a provider-specific form this bounded read does not evaluate (for example a GitLab `rules:` expression) would be invisible to it — and it makes no statement about whether a trigger is too broad or too narrow, because this phase deliberately does not define a universal \"good\" trigger.",
    behavior: (workflow) => workflow.triggers,
    absenceReason: "the workflow was read in full and establishes no trigger event",
    severity: "low",
    tags: ["triggers"],
    falsePositives: [
      "a provider-specific trigger form this bounded read does not evaluate (for example GitLab `rules:`/`only:` expressions)",
      "a workflow reached only as a reusable/called workflow",
    ],
  }),
]);
