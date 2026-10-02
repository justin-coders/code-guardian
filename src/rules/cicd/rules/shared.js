/**
 * Code Guardian — CI/CD Rule Shared Helpers (Official Roadmap Phase 13)
 *
 * The small pure helpers every CI/CD rule family shares: the one conditional an absence-shaped
 * rule needs, the bounded-list helper that keeps output finite, the fingerprint discriminator,
 * and the two finding shapes — an observation and an established absence — so the twelve rules
 * word and identify their findings identically.
 *
 * Nothing here decides a conclusion on its own, and nothing reads outside the frozen model.
 */

import { APPLICABILITY_COVERAGE } from "../../contracts.js";
import { createRuleDetection } from "../../evaluation.js";

import {
  CICD_BASES,
  CICD_CONFIDENCE,
  CICD_LIMITS,
  CICD_STATES,
} from "../contracts.js";
import { ciWorkflows, cicdAbsence, evidenceIdsForWorkflows, queryFor } from "../signals.js";

/**
 * The CI/CD subject a rule reasons over, or the outcome that stops it.
 *
 *   `{ workflows, interpreted, none }`  the repository has workflows: `interpreted` are those
 *                                       read in full, and `none` is `true` only when there are
 *                                       no workflows at all over established coverage.
 *   `{ outcome }`                       there are no workflows *and* the scan cannot establish
 *                                       that (so the rule abstains with `unknown`).
 *
 * @param {object} context A validated AnalysisContext.
 * @param {string} because Bounded explanation for the abstention.
 * @returns {object}
 */
export function workflowSubject(context, because) {
  const workflows = ciWorkflows(queryFor(context));
  if (workflows.length > 0) {
    return {
      workflows,
      interpreted: workflows.filter((workflow) => workflow.interpreted),
      none: false,
    };
  }
  const gap = absenceOutcome(context, because);
  if (gap.outcome) return { outcome: gap.outcome };
  return { workflows, interpreted: [], none: true };
}

/**
 * The outcome for a CI/CD gap over the repository's coverage.
 *
 *   `{ established: true, absence }`  the scan covered the repository: the caller may assert
 *                                     the gap as a finding or a clean pass.
 *   `{ outcome }`                     the gap cannot be concluded: a Rule-Engine `unknown`
 *                                     detection carrying the model's own reason.
 *
 * @param {object} context A validated AnalysisContext.
 * @param {string} because Bounded explanation prefixed to the model's reason.
 * @returns {{established: true, absence: object}|{outcome: object}}
 */
export function absenceOutcome(context, because) {
  const absence = cicdAbsence(context);
  if (absence.established) return { established: true, absence };
  return {
    outcome: createRuleDetection({
      findings: [],
      coverage: APPLICABILITY_COVERAGE.UNKNOWN,
      reason: `${because}, but ${absence.reason}`,
    }),
  };
}

/**
 * The first `limit` entries of a deterministic list, and whether the list was capped.
 *
 * The roadmap forbids unbounded output, so every per-workflow rule reports at most
 * `CICD_LIMITS.MAX_WORKFLOW_FINDINGS` findings and records the cap rather than dropping the
 * rest silently.
 *
 * @param {object[]} entries
 * @param {number} limit
 * @returns {{entries: object[], truncated: boolean}}
 */
export function capWorkflows(entries, limit = CICD_LIMITS.MAX_WORKFLOW_FINDINGS) {
  if (entries.length <= limit) return { entries, truncated: false };
  return { entries: entries.slice(0, limit), truncated: true };
}

/**
 * Sanitize a value into the bounded character set a finding `fingerprintKey` allows.
 *
 * The fingerprint key keeps two findings from one rule — two workflows, or one workflow with
 * two observations — from colliding into one fingerprint. A repository-relative path contains
 * `/`, which the key pattern refuses, so it is folded to `.`.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function keyFragment(value) {
  const text = typeof value === "string" ? value : String(value ?? "");
  return text.replace(/[^A-Za-z0-9._:-]/g, ".").slice(0, 120);
}

/**
 * An observation finding: the workflow's content established the domain's behavior.
 *
 * @param {object} workflow A workflow record.
 * @param {object} input
 * @param {string} input.domain The roadmap domain.
 * @param {string[]} input.ids The closed-vocabulary ids observed.
 * @param {object} [input.extra] Additional metadata.
 * @returns {object} A raw finding draft.
 */
export function observationFinding(workflow, { domain, ids, extra = {} }) {
  return {
    confidence: CICD_CONFIDENCE.OBSERVED_CONTENT,
    evidence: [...workflow.evidenceIds],
    metadata: {
      basis: CICD_BASES.WORKFLOW_CONTENT,
      // A full read establishes the observation; a truncated read still establishes presence,
      // but the phase's state ladder puts it one rung lower.
      state: workflow.interpreted ? CICD_STATES.VERIFIED : CICD_STATES.DETECTED,
      fingerprintKey: `${domain}:${keyFragment(workflow.path)}`,
      domain,
      provider: workflow.provider,
      path: workflow.path,
      observed: ids,
      contentState: workflow.contentState,
      ...extra,
    },
  };
}

/**
 * An established-absence finding: a workflow read in full establishes none of the domain's
 * behavior.
 *
 * @param {object} workflow A workflow record (interpreted in full).
 * @param {object} input
 * @param {string} input.domain The roadmap domain.
 * @param {string} [input.reason] A bounded explanation recorded on the finding.
 * @returns {object} A raw finding draft.
 */
export function absenceFinding(workflow, { domain, reason = null }) {
  return {
    confidence: CICD_CONFIDENCE.ESTABLISHED_ABSENCE,
    evidence: [...workflow.evidenceIds],
    metadata: {
      basis: CICD_BASES.WORKFLOW_CONTENT,
      state: CICD_STATES.DETECTED,
      fingerprintKey: `${domain}:${keyFragment(workflow.path)}`,
      domain,
      provider: workflow.provider,
      path: workflow.path,
      observed: [],
      established: "absence",
      contentState: workflow.contentState,
      reason,
    },
  };
}

/**
 * A derived-relation finding: two observations compared (a deployment with no rollback).
 *
 * @param {object} workflow A workflow record.
 * @param {object} input
 * @param {string} input.domain The roadmap domain.
 * @param {string[]} input.premise The ids that establish the relation's precondition.
 * @returns {object} A raw finding draft.
 */
export function relationFinding(workflow, { domain, premise, extra = {} }) {
  return {
    confidence: CICD_CONFIDENCE.DERIVED_RELATION,
    evidence: [...workflow.evidenceIds],
    metadata: {
      basis: CICD_BASES.WORKFLOW_CONTENT,
      state: CICD_STATES.DETECTED,
      fingerprintKey: `${domain}:${keyFragment(workflow.path)}`,
      domain,
      provider: workflow.provider,
      path: workflow.path,
      observed: premise,
      established: "absence",
      contentState: workflow.contentState,
      ...extra,
    },
  };
}

/** The shared evidence set of a workflow list, for a rule's own metadata. */
export function evidenceOf(workflows) {
  return evidenceIdsForWorkflows(workflows);
}
