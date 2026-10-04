/**
 * Code Guardian — API Analysis Rule Shared Helpers (Official Roadmap Phase 16)
 *
 * Small pure helpers the api-analysis rules share: the bounded-list helper so no rule can emit
 * unbounded output, the sanitizer that keeps a fingerprint key inside the Finding Engine's
 * character set, the two abstention shapes, and the applicability gate every rule runs first.
 * Nothing here decides a conclusion on its own.
 */

import { APPLICABILITY_COVERAGE } from "../../contracts.js";
import { createRuleDetection } from "../../evaluation.js";

import { API_ANALYSIS_LIMITS, API_ANALYSIS_STATES, API_ANALYSIS_SUBJECTS } from "../contracts.js";
import { apiSubject } from "../signals.js";

/** Sanitize a value into the bounded character set a finding `fingerprintKey` allows. */
export function keyFragment(value) {
  const text = typeof value === "string" ? value : String(value ?? "");
  return text.replace(/[^A-Za-z0-9._:-]/g, ".").slice(0, 120);
}

/** The first `limit` entries of a deterministic list, and whether the list was capped. */
export function capFindings(entries, limit = API_ANALYSIS_LIMITS.MAX_FINDINGS) {
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

/**
 * The clean `not_applicable` detection.
 *
 * No API subject exists, so a rule makes no claim and produces no finding. The `metadata.state`
 * records why, so a consumer can tell this from an established clean result.
 */
export function notApplicable(basis, extra = {}) {
  return {
    findings: [],
    evidence: [],
    metadata: { basis, state: API_ANALYSIS_STATES.NOT_APPLICABLE, ...extra },
  };
}

/**
 * Run the API-subject gate every rule shares.
 *
 * Returns `null` when the subject is `applicable` and the rule should proceed, or a detection
 * object to return directly when it should not (no API subject, or an API subject the model
 * could not establish).
 */
export function gateOnApiSubject(query, basis) {
  const subject = apiSubject(query);
  if (subject.state === API_ANALYSIS_SUBJECTS.NOT_APPLICABLE) {
    return notApplicable(basis, { routes: 0 });
  }
  if (subject.state === API_ANALYSIS_SUBJECTS.UNKNOWN) {
    return unknownDetection(subject.reason);
  }
  return null;
}

/** The union of the evidence ids the given entities cite, sorted. */
export function evidenceIdsFor(entities) {
  const ids = new Set();
  for (const entity of entities) {
    for (const id of entity.evidenceIds ?? []) ids.add(id);
  }
  return [...ids].sort();
}
