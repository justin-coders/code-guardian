/**
 * Code Guardian — Policy Preset Signals (Phase 23)
 *
 * The one place the `policy.preset.audit` rule asks the repository questions. Every read goes
 * through the Phase 11 query API over the frozen RepositoryModel: no filesystem, no `node:path`, no
 * source parsing, no preset registry, no process, no network, no clock. A rule that cannot answer a
 * question from the model abstains rather than going to look for itself — which is the point of
 * resolving the policy once, in the model.
 *
 * ### Nothing here re-derives a preset answer
 *
 * `activePreset`, `effectivePolicy` and `policyProvenance` hand back exactly what the query layer
 * published. The rule never re-reads the declared document, never re-merges a preset and never
 * computes an inherited key by diffing two documents: provenance is produced once, by the resolver,
 * and this layer only reads it.
 */

import { createRepositoryQuery } from "../../repository/model/index.js";

/**
 * Build the read-only query handle for an AnalysisContext.
 *
 * @param {object} context A validated AnalysisContext.
 * @returns {object} A frozen query handle.
 */
export function queryFor(context) {
  return createRepositoryQuery(context.repository);
}

/** The repository's policy area, as the query API hands it back, or `null`. */
export function policyArea(query) {
  return query.policy();
}

/** Which built-in preset governs the policy, or `null` when the model says nothing about policy. */
export function activePreset(query) {
  return query.policyPreset();
}

/** The effective policy the compliance report measures against, or `null`. */
export function effectivePolicy(query) {
  return query.effectivePolicy();
}

/** Where every effective policy value came from, or `null`. */
export function policyProvenance(query) {
  return query.policyProvenance();
}

/** Whether the query layer can answer anything at all about policy. */
export function hasPolicyArea(query) {
  return query.policy() !== null;
}

export { POLICY_DESCRIBED_STATES, POLICY_ABSTENTION_WORDING } from "./contracts.js";
