/**
 * Code Guardian — Permission & Secret-Handling Rules (Official Roadmap Phase 13)
 *
 * Two roadmap domains that are deliberately kept on the *structural* side of the security
 * boundary:
 *
 *   permissions       whether a workflow declares its permissions explicitly. The roadmap says
 *                     not to treat a missing explicit block as a vulnerability, so the rule
 *                     reports only the CI/CD configuration fact — no permissions key was
 *                     established — and never a severity, an exposure or an attack path. A
 *                     security conclusion belongs to the Security Analyzer (Official Phase 10).
 *   secret handling   the *shapes* of the secret references a workflow states: a `secrets.`
 *                     context, an OIDC request, a vault command, a cloud secret manager. The
 *                     rule never sees, stores or prints a secret's name or value — only the
 *                     closed reference id — so it cannot leak anything the repository did not
 *                     already publish, and it makes no claim about whether a secret is exposed.
 */

import { CICD_RULE_IDS } from "../contracts.js";

import { createAbsenceRule, createPresenceRule } from "./factories.js";

export const permissionRules = Object.freeze([
  createAbsenceRule({
    id: CICD_RULE_IDS.PERMISSIONS_NOT_DECLARED,
    domain: "permissions",
    title: "A workflow declares no explicit permissions",
    description:
      "The workflow's content was read in full and establishes no explicit `permissions` block. This is a CI/CD configuration observation, not a security finding: the provider's default permissions apply and this build cannot read them, so the finding states only that an explicit declaration was not established. Whether that default is too broad is a security judgment, and it belongs to the Security Analyzer, not here.",
    behavior: (workflow) => (workflow.permissionsMode === "explicit" ? ["explicit"] : []),
    // A provider with no permissions concept (GitLab) has no subject in this domain: the rule
    // reports `not_applicable` rather than a finding, because provider knowledge lives in the
    // acquisition profile and not in the rule.
    appliesTo: (workflow) => workflow.permissionsConfigurable === true,
    absenceReason: "the workflow was read in full and declares no explicit permissions block",
    severity: "low",
    tags: ["permissions"],
    falsePositives: [
      "permissions declared at the job level in a form this bounded read does not match",
      "a provider whose default permissions the workflow legitimately relies on",
    ],
  }),

  createPresenceRule({
    id: CICD_RULE_IDS.SECRETS_REFERENCED,
    domain: "secrets",
    title: "A workflow references secrets",
    description:
      "The workflow's content references secrets through the documented shapes the acquisition layer recognises (a `secrets.` context, an OIDC token request, a vault command, a cloud secret manager). The finding lists the *shapes* observed — never a secret's name or value, which this analyzer never reads — so secret handling can be reviewed structurally. It makes no claim that a secret is exposed, misused or securely stored; those are security conclusions.",
    behavior: (workflow) => workflow.secretRefs,
    extra: {
      note: "structural reference shapes only — no secret name or value is read, stored or printed",
    },
    severity: "info",
    tags: ["secrets"],
    falsePositives: ["a reference shape the acquisition layer does not document for this provider"],
  }),
]);
