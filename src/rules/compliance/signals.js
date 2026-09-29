/**
 * Code Guardian — Compliance Repository Signals (Phase 22)
 *
 * The one place the `compliance.*` rules ask the repository questions. Every read goes through the
 * Phase 11 query API over the frozen RepositoryModel: no filesystem, no `node:path`, no source
 * parsing, no container runtime, no package manager, no process, no network, no clock. A rule that
 * cannot answer a question from the model abstains rather than going to look for itself — which is
 * the whole point of projecting the policy and the compliance report once, in the model.
 *
 * ### The report is read, never recomputed, and never re-derived
 *
 * `complianceSections` hands back the report's own sections with two additions per item: the
 * pack's own wording for the status and the policy key, and a `fingerprintKey`. The fingerprint key
 * exists because a finding's canonical fingerprint is derived from its rule, category and evidence
 * set, and two items about one subject frequently cite the same evidence — without a disambiguator
 * they would collapse into one finding and the run would fail as a duplicate. It is a stability
 * hash of the item's own id, never an index, which would shift every fingerprint when an unrelated
 * item is added.
 *
 * ### The policy behind an item is read from the model, never assumed
 *
 * `compliancePolicy` returns the policy area the query API hands back, so a rule can name the
 * policy state a domain was measured under, and `complianceAbsence` turns "this domain has no
 * measurement" into the sentence a rule abstains with. Neither ever constructs a requirement: the
 * only source of a requirement in this pack is an item the model already validated.
 */

import {
  COMPLIANCE_SECTIONS,
  COMPLIANCE_SECTION_TITLES,
  createRepositoryQuery,
  stabilityHash,
} from "../../repository/model/index.js";

import {
  COMPLIANCE_ABSTENTION_WORDING,
  COMPLIANCE_POLICY_STATE_WORDING,
  COMPLIANCE_SECTION_WORDING,
  COMPLIANCE_STATE_WORDING,
  COMPLIANCE_STATUS_WORDING,
} from "./contracts.js";

/**
 * Build the read-only query handle for an AnalysisContext.
 *
 * @param {object} context A validated AnalysisContext.
 * @returns {object} A frozen query handle.
 */
export function queryFor(context) {
  return createRepositoryQuery(context.repository);
}

/** One compliance item, as the pack reads it. */
function describeItem(item) {
  return {
    ...item,
    evidenceIds: [...item.evidenceIds],
    policyEvidenceIds: [...item.policyEvidenceIds],
    statusWording: COMPLIANCE_STATUS_WORDING[item.status] ?? null,
    fingerprintKey: `compliance:${item.domain}:${stabilityHash(item.id)}`,
  };
}

/** One section, as the pack reads it. */
function describeSection(section) {
  return {
    name: section.name,
    title: section.title,
    state: section.state,
    established: section.established === true,
    policyDeclared: section.policyDeclared === true,
    policyKeys: [...section.policyKeys],
    items: section.items.map(describeItem),
    counts: { ...section.counts },
    evidenceIds: [...section.evidenceIds],
    policyEvidenceIds: [...section.policyEvidenceIds],
    unknown: section.unknown.map((record) => ({
      reason: record.reason,
      detail: record.detail,
      count: record.count,
      wording: COMPLIANCE_ABSTENTION_WORDING[record.reason] ?? null,
    })),
    coverage: { ...section.coverage },
    stateWording: COMPLIANCE_STATE_WORDING[section.state] ?? null,
    domainWording: COMPLIANCE_SECTION_WORDING[section.name] ?? null,
  };
}

/**
 * Every section the compliance report carries, in the report's own declared order.
 *
 * @param {object} query
 * @returns {Array<object>} Frozen section rows.
 */
export function complianceSections(query) {
  const report = query.complianceReport();
  if (report === null) return [];
  return report.sections.map(describeSection);
}

/** One policy domain's section, or `null`. */
export function complianceSection(query, name) {
  const section = query.complianceSection(name);
  if (section === null) return null;
  return describeSection(section);
}

/** The report's own structured coverage statement, or `null`. */
export function complianceCoverage(query) {
  return query.complianceCoverage();
}

/** The repository's declared policy, as the query API hands it back, or `null`. */
export function compliancePolicy(query) {
  return query.policy();
}

/**
 * Whether one domain has a measurement to report at all.
 *
 * A domain answers only when the report established its section — and `established` is already
 * false for `unknown`, which is what "no policy for this domain", "the domain was not read" and
 * "nothing could be measured" all produce. The reasons are gathered from the section's own
 * abstentions, so the sentence a rule abstains with is the model's own explanation rather than a
 * second opinion about why the domain is empty.
 *
 * @param {object} query
 * @param {string} name
 * @returns {{established: boolean, reason: string|null, state: string|null}}
 */
export function complianceAbsence(query, name) {
  const section = query.complianceSection(name);
  if (section === null) {
    return Object.freeze({
      established: false,
      reason: "this model carries no compliance report",
      state: null,
    });
  }

  const reasons = [];
  if (section.established !== true) {
    for (const record of section.unknown) {
      const wording = COMPLIANCE_ABSTENTION_WORDING[record.reason];
      if (wording !== undefined) reasons.push(wording);
    }
    if (reasons.length === 0) {
      reasons.push("the report did not establish this domain");
    }
  } else if (section.coverage.truncated === true) {
    reasons.push("a bound stopped this domain before its item list was complete");
  }

  return Object.freeze({
    established: reasons.length === 0,
    reason: reasons.length === 0 ? null : reasons.join("; "),
    state: section.state,
  });
}

/**
 * Why a section that *did* establish a section still could not measure everything.
 *
 * `partial` is the one state where the section answered and something inside it did not: a
 * requirement whose reading was incomplete, a workflow whose name states no purpose, a Dockerfile
 * whose instructions were never established. A rule that treated that as a clean pass would report
 * silence over a requirement nobody measured, so it abstains with the model's own reasons.
 *
 * @param {object} section A described section.
 * @returns {string|null}
 */
export function complianceUnmeasuredReason(section) {
  if (section === null) return null;
  const reasons = section.unknown
    .map((record) => record.wording)
    .filter((wording) => typeof wording === "string");
  if (reasons.length === 0) return "the report did not measure every requirement in this domain";
  return reasons.join("; ");
}

/** The domain vocabulary this pack can describe, for tests. */
export const COMPLIANCE_DESCRIBED_SECTIONS = Object.freeze(
  Object.keys(COMPLIANCE_SECTION_WORDING),
);

/** The section-state vocabulary this pack can describe, for tests. */
export const COMPLIANCE_DESCRIBED_STATES = Object.freeze(
  Object.keys(COMPLIANCE_STATE_WORDING),
);

/** The item-status vocabulary this pack can describe, for tests. */
export const COMPLIANCE_DESCRIBED_STATUSES = Object.freeze(
  Object.keys(COMPLIANCE_STATUS_WORDING),
);

/** The abstention vocabulary this pack can describe, for tests. */
export const COMPLIANCE_DESCRIBED_ABSTENTIONS = Object.freeze(
  Object.keys(COMPLIANCE_ABSTENTION_WORDING),
);

/** The policy-state vocabulary this pack can describe, for tests. */
export const COMPLIANCE_DESCRIBED_POLICY_STATES = Object.freeze(
  Object.keys(COMPLIANCE_POLICY_STATE_WORDING),
);

export { COMPLIANCE_SECTIONS, COMPLIANCE_SECTION_TITLES };
