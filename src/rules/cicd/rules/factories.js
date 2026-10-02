/**
 * Code Guardian — CI/CD Rule Factories (Official Roadmap Phase 13)
 *
 * Three of the phase's four finding shapes are structural, so they are built from one factory
 * each and their policy lives in exactly one place:
 *
 *   `createAbsenceRule`   eight domains: *a workflow read in full establishes none of this
 *                         domain's behavior*.
 *   `createPresenceRule`  an observation worth reporting in its own right (a referenced secret,
 *                         an observed deployment), worded as an observation, not a verdict.
 *   `createRelationRule`  two observations compared (a workflow that deploys and establishes no
 *                         rollback, no environment separation, no deployment protection).
 *
 * ### The coverage ladder, in one place
 *
 * The factory is where the phase's hard rule is enforced: an absence may only be asserted over a
 * workflow whose content was **interpreted in full**.
 *
 *   no workflow at all        → `not_applicable` (and `unknown` if the scan could not establish
 *                               that there are none)
 *   no full read anywhere     → the rule abstains with the Rule Engine's `unknown`
 *   a full read, no behavior  → a finding, and the domain's state is `detected`
 *   a full read, behavior     → no finding — the domain is present
 *
 * A *truncated* read is deliberately not enough to assert an absence: the behavior may sit in the
 * bytes the cap skipped.
 */

import { createRule } from "../../../core/index.js";

import {
  CICD_BASES,
  CICD_CATEGORY,
  CICD_RULE_VERSION,
  CICD_STATES,
} from "../contracts.js";
import { ciWorkflows, queryFor } from "../signals.js";

import {
  absenceFinding,
  absenceOutcome,
  capWorkflows,
  observationFinding,
  relationFinding,
  workflowSubject,
} from "./shared.js";

/**
 * Build one absence-shaped CI/CD rule.
 *
 * @param {object} input
 * @param {string} input.id The stable rule id.
 * @param {string} input.domain The roadmap domain.
 * @param {string} input.title Finding title.
 * @param {string} input.description Finding description (states the false-positive boundary).
 * @param {(workflow: object) => string[]} input.behavior The ids the workflow established, or an
 *   empty list when it established none.
 * @param {(workflow: object) => boolean} [input.appliesTo] Workflows the domain genuinely has a
 *   subject in — a provider that has no such concept is excluded, so the rule reports
 *   `not_applicable` instead of a finding. Defaults to every workflow.
 * @param {string} input.absenceReason The bounded reason recorded on each finding.
 * @param {string} [input.severity]
 * @param {string[]} [input.tags]
 * @param {string[]} [input.falsePositives]
 * @returns {object} A Core Rule.
 */
export function createAbsenceRule({
  id,
  domain,
  title,
  description,
  behavior,
  appliesTo = () => true,
  absenceReason,
  severity = "low",
  tags = [],
  falsePositives = [],
}) {
  return createRule({
    id,
    version: CICD_RULE_VERSION,
    category: CICD_CATEGORY,
    title,
    description,
    severity,
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const observed = ciWorkflows(query);
      const workflows = observed.filter((workflow) => appliesTo(workflow));

      if (observed.length === 0) {
        const gap = absenceOutcome(context, "no CI/CD workflow was observed");
        if (gap.outcome) return gap.outcome;
        return {
          findings: [],
          evidence: [],
          metadata: {
            basis: CICD_BASES.WORKFLOW_INVENTORY,
            domain,
            state: CICD_STATES.NOT_APPLICABLE,
            workflows: 0,
          },
        };
      }

      // The repository has CI/CD, but none of it gives this domain a subject — a provider that
      // has no such concept (GitLab and permissions) is *not applicable*, never a finding.
      if (workflows.length === 0) {
        return {
          findings: [],
          evidence: [],
          metadata: {
            basis: CICD_BASES.WORKFLOW_INVENTORY,
            domain,
            state: CICD_STATES.NOT_APPLICABLE,
            workflows: observed.length,
            applies: 0,
          },
        };
      }

      // Only a workflow read in full can support an absence claim.
      const interpreted = workflows.filter((workflow) => workflow.interpreted);
      if (interpreted.length === 0) {
        return {
          findings: [],
          evidence: [],
          coverage: "unknown",
          reason:
            "no observed workflow's content was interpreted in full, so this domain's absence is not established",
          metadata: {
            basis: CICD_BASES.WORKFLOW_COVERAGE,
            domain,
            state: CICD_STATES.UNKNOWN,
            workflows: workflows.length,
          },
        };
      }

      const absent = interpreted.filter((workflow) => behavior(workflow).length === 0);
      const { entries, truncated } = capWorkflows(absent);
      const findings = entries.map((workflow) =>
        absenceFinding(workflow, { domain, reason: absenceReason }),
      );

      return {
        findings,
        evidence: [],
        metadata: {
          basis: CICD_BASES.WORKFLOW_CONTENT,
          domain,
          state: findings.length > 0 ? CICD_STATES.DETECTED : CICD_STATES.NOT_APPLICABLE,
          observedWorkflows: interpreted.length - absent.length,
          interpretedWorkflows: interpreted.length,
          reported: findings.length,
          truncated,
        },
      };
    },
    remediation: {},
    metadata: { tags: ["cicd", ...tags], falsePositives },
  });
}

/**
 * Build one presence-shaped CI/CD rule.
 *
 * A presence rule reports that a workflow establishes the domain's behavior. It cannot assert an
 * absence, so it never needs a full read: presence is established by whatever was read. It emits
 * no finding when nothing was observed, and its state is `not_applicable` then — absence of an
 * observation is not an observation of absence.
 *
 * @param {object} input
 * @param {string} input.id The stable rule id.
 * @param {string} input.domain The roadmap domain.
 * @param {string} input.title Finding title.
 * @param {string} input.description Finding description.
 * @param {(workflow: object) => string[]} input.behavior The ids the workflow established.
 * @param {object} [input.extra] Static metadata attached to each finding.
 * @param {string} [input.severity]
 * @param {string[]} [input.tags]
 * @param {string[]} [input.falsePositives]
 * @returns {object} A Core Rule.
 */
export function createPresenceRule({
  id,
  domain,
  title,
  description,
  behavior,
  extra = {},
  severity = "info",
  tags = [],
  falsePositives = [],
}) {
  return createRule({
    id,
    version: CICD_RULE_VERSION,
    category: CICD_CATEGORY,
    title,
    description,
    severity,
    applicability: {},
    detect: (context) => {
      const subject = workflowSubject(context, "no CI/CD workflow was observed");
      if (subject.outcome) return subject.outcome;
      if (subject.none) {
        return {
          findings: [],
          evidence: [],
          metadata: {
            basis: CICD_BASES.WORKFLOW_INVENTORY,
            domain,
            state: CICD_STATES.NOT_APPLICABLE,
            workflows: 0,
          },
        };
      }

      const observed = subject.workflows.filter((workflow) => behavior(workflow).length > 0);
      const { entries, truncated } = capWorkflows(observed);
      const findings = entries.map((workflow) =>
        observationFinding(workflow, { domain, ids: behavior(workflow), extra }),
      );

      return {
        findings,
        evidence: [],
        metadata: {
          basis: CICD_BASES.WORKFLOW_CONTENT,
          domain,
          state: findings.length > 0 ? CICD_STATES.DETECTED : CICD_STATES.NOT_APPLICABLE,
          observedWorkflows: findings.length,
          interpretedWorkflows: subject.interpreted.length,
          reported: findings.length,
          truncated,
        },
      };
    },
    remediation: {},
    metadata: { tags: ["cicd", ...tags], falsePositives },
  });
}

/**
 * Build one relation-shaped CI/CD rule.
 *
 * A relation rule compares two observations: the `premise` (what the workflow does) and the
 * `conclusion` (what it does not establish). It only reasons over workflows read in full — a
 * truncated read could hide the conclusion — and its state is `not_applicable` when no workflow
 * establishes the premise.
 *
 * @param {object} input
 * @param {string} input.id The stable rule id.
 * @param {string} input.domain The roadmap domain.
 * @param {string} input.title Finding title.
 * @param {string} input.description Finding description.
 * @param {(workflow: object) => string[]} input.premise The ids that establish the precondition.
 * @param {(workflow: object) => string[]} input.conclusion The ids that would satisfy the rule.
 * @param {string} [input.severity]
 * @param {string[]} [input.tags]
 * @param {string[]} [input.falsePositives]
 * @returns {object} A Core Rule.
 */
export function createRelationRule({
  id,
  domain,
  title,
  description,
  premise,
  conclusion,
  severity = "low",
  tags = [],
  falsePositives = [],
}) {
  return createRule({
    id,
    version: CICD_RULE_VERSION,
    category: CICD_CATEGORY,
    title,
    description,
    severity,
    applicability: {},
    detect: (context) => {
      const subject = workflowSubject(context, "no CI/CD workflow was observed");
      if (subject.outcome) return subject.outcome;
      if (subject.none) {
        return {
          findings: [],
          evidence: [],
          metadata: {
            basis: CICD_BASES.WORKFLOW_INVENTORY,
            domain,
            state: CICD_STATES.NOT_APPLICABLE,
            workflows: 0,
          },
        };
      }

      const candidates = subject.interpreted.filter(
        (workflow) => premise(workflow).length > 0 && conclusion(workflow).length === 0,
      );
      const { entries, truncated } = capWorkflows(candidates);
      const findings = entries.map((workflow) =>
        relationFinding(workflow, { domain, premise: premise(workflow) }),
      );

      return {
        findings,
        evidence: [],
        metadata: {
          basis: CICD_BASES.WORKFLOW_CONTENT,
          domain,
          state: findings.length > 0 ? CICD_STATES.DETECTED : CICD_STATES.NOT_APPLICABLE,
          interpretedWorkflows: subject.interpreted.length,
          reported: findings.length,
          truncated,
        },
      };
    },
    remediation: {},
    metadata: { tags: ["cicd", ...tags], falsePositives },
  });
}
