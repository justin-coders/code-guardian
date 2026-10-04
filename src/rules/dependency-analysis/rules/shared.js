/**
 * Code Guardian — Dependency Analysis Rule Shared Helpers (Official Roadmap Phase 15)
 *
 * Small pure helpers the dependency-analysis rules share: the bounded-list helper so no rule can
 * emit unbounded output, the sanitizer that keeps a fingerprint key inside the Finding Engine's
 * character set, the one shape an abstention takes, and the union of model evidence behind a set
 * of entities. Nothing here decides a conclusion on its own.
 */

import { APPLICABILITY_COVERAGE } from "../../contracts.js";
import { createRuleDetection } from "../../evaluation.js";

import { DEPENDENCY_ANALYSIS_LIMITS } from "../contracts.js";

/** Sanitize a value into the bounded character set a finding `fingerprintKey` allows. */
export function keyFragment(value) {
  const text = typeof value === "string" ? value : String(value ?? "");
  return text.replace(/[^A-Za-z0-9._:-]/g, ".").slice(0, 120);
}

/** The first `limit` entries of a deterministic list, and whether the list was capped. */
export function capFindings(entries, limit = DEPENDENCY_ANALYSIS_LIMITS.MAX_FINDINGS) {
  if (entries.length <= limit) return { entries, truncated: false };
  return { entries: entries.slice(0, limit), truncated: true };
}

/**
 * The Rule-Engine `unknown` detection carrying the reason.
 *
 * Used by every rule that cannot settle its answer from the evidence the model or the external
 * dataset establishes. `unknown` is never clean, and this is the only shape that says so.
 */
export function unknownDetection(reason) {
  return createRuleDetection({
    findings: [],
    coverage: APPLICABILITY_COVERAGE.UNKNOWN,
    reason,
  });
}

/** The union of the evidence ids the given entities cite, sorted. */
export function evidenceIdsFor(entities) {
  const ids = new Set();
  for (const entity of entities) {
    for (const id of entity.evidenceIds ?? []) ids.add(id);
  }
  return [...ids].sort();
}

/** A short label for an `(ecosystem, name)` pair. */
export function packageLabel(ecosystem, name) {
  return `${ecosystem}:${name}`;
}
