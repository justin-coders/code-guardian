/**
 * Code Guardian — Reliability Analysis Rule Shared Helpers (Official Roadmap Phase 17)
 *
 * Small pure helpers the reliability-analysis rules share: the bounded-list helper so no rule can
 * emit unbounded output, the sanitizer that keeps a fingerprint key inside the Finding Engine's
 * character set, the two abstention shapes, and the applicability gate every rule runs first.
 * Nothing here decides a conclusion on its own.
 */

import { APPLICABILITY_COVERAGE } from "../../contracts.js";
import { createRuleDetection } from "../../evaluation.js";

import {
  RELIABILITY_ANALYSIS_LIMITS,
  RELIABILITY_ANALYSIS_STATES,
  RELIABILITY_ANALYSIS_SUBJECTS,
} from "../contracts.js";
import { reliabilitySubject } from "../signals.js";

/** Sanitize a value into the bounded character set a finding `fingerprintKey` allows. */
export function keyFragment(value) {
  const text = typeof value === "string" ? value : String(value ?? "");
  return text.replace(/[^A-Za-z0-9._:-]/g, ".").slice(0, 120);
}

/** The first `limit` entries of a deterministic list, and whether the list was capped. */
export function capFindings(entries, limit = RELIABILITY_ANALYSIS_LIMITS.MAX_FINDINGS) {
  if (entries.length <= limit) return { entries, truncated: false };
  return { entries: entries.slice(0, limit), truncated: true };
}

/**
 * The Rule-Engine `unknown` detection carrying the reason.
 *
 * Used by every rule that cannot settle its answer from the evidence the model establishes.
 * `unknown` is never clean, and this is the only shape that says so.
 */
export function unknownDetection(reason) {
  return createRuleDetection({
    findings: [],
    coverage: APPLICABILITY_COVERAGE.UNKNOWN,
    reason,
  });
}

/** The clean `not_applicable` detection: no reliability subject, so no claim and no finding. */
export function notApplicable(basis, extra = {}) {
  return {
    findings: [],
    evidence: [],
    metadata: { basis, state: RELIABILITY_ANALYSIS_STATES.NOT_APPLICABLE, ...extra },
  };
}

/**
 * Run the reliability-subject gate every rule shares.
 *
 * Returns `null` when the subject is `applicable` and the rule should proceed, or a detection
 * object to return directly when it should not.
 */
export function gateOnReliabilitySubject(query, basis) {
  const subject = reliabilitySubject(query);
  if (subject.state === RELIABILITY_ANALYSIS_SUBJECTS.NOT_APPLICABLE) {
    return notApplicable(basis, { routes: 0, containers: 0, services: 0 });
  }
  if (subject.state === RELIABILITY_ANALYSIS_SUBJECTS.UNKNOWN) {
    return unknownDetection(subject.reason);
  }
  return null;
}

