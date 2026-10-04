/**
 * Code Guardian — Architecture Analysis Rule Shared Helpers (Official Roadmap Phase 14)
 *
 * Small pure helpers the architecture rules share: the bounded-list helper so no rule can emit
 * unbounded output, the sanitizer that keeps a fingerprint key inside the Finding Engine's
 * character set, and the one shape an abstention takes. Nothing here decides a conclusion on its
 * own, and nothing reads outside the frozen model.
 */

import { APPLICABILITY_COVERAGE } from "../../contracts.js";
import { createRuleDetection } from "../../evaluation.js";

import { ARCHITECTURE_ANALYSIS_LIMITS } from "../contracts.js";

/**
 * Sanitize a value into the bounded character set a finding `fingerprintKey` allows.
 *
 * A repository-relative path contains `/`, which the key pattern refuses, so it is folded to
 * `.`; the result is a stable, readable discriminator that never depends on an index (an index
 * would shift every fingerprint when an unrelated entity is added).
 *
 * @param {unknown} value
 * @returns {string}
 */
export function keyFragment(value) {
  const text = typeof value === "string" ? value : String(value ?? "");
  return text.replace(/[^A-Za-z0-9._:-]/g, ".").slice(0, 120);
}

/**
 * The first `limit` entries of a deterministic list, and whether the list was capped.
 *
 * @param {object[]} entries
 * @param {number} limit
 * @returns {{entries: object[], truncated: boolean}}
 */
export function capFindings(entries, limit = ARCHITECTURE_ANALYSIS_LIMITS.MAX_FINDINGS) {
  if (entries.length <= limit) return { entries, truncated: false };
  return { entries: entries.slice(0, limit), truncated: true };
}

/**
 * The Rule-Engine `unknown` detection carrying the model's own reason.
 *
 * Reused by every rule that cannot settle its answer from the evidence the model establishes —
 * an unestablished import graph, or no repository-declared layer model. `unknown` is never
 * clean, and this is the only shape that says so.
 *
 * @param {string} reason Bounded explanation.
 * @returns {object}
 */
export function unknownDetection(reason) {
  return createRuleDetection({
    findings: [],
    coverage: APPLICABILITY_COVERAGE.UNKNOWN,
    reason,
  });
}

/** The union of the evidence ids a set of module-graph edges cites, sorted. */
export function edgeEvidenceIds(edges) {
  const ids = new Set();
  for (const edge of edges) {
    for (const id of edge.evidenceIds ?? []) ids.add(id);
  }
  return [...ids].sort();
}
