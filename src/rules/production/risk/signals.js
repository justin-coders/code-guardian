/**
 * Code Guardian — Production Risk Repository Signals (Phase 21)
 *
 * The one place the `production.risk.*` rules ask the repository questions. Every read goes
 * through the Phase 11 query API over the frozen RepositoryModel: no filesystem, no
 * `node:path`, no source parsing, no container runtime, no registry, no process, no network, no
 * clock. A rule that cannot answer a question from the model abstains rather than going to look
 * for itself — which is the whole point of projecting the report once, in the model.
 *
 * ### The report is read, never recomputed, and never re-derived
 *
 * `productionRiskSections` hands back the report's own sections with two additions per finding:
 * a `fingerprintKey` and the pack's own wording for its kind, severity and confidence. The
 * fingerprint key is necessary because a finding's canonical fingerprint is derived from its
 * rule, category and evidence set, and two findings about one file frequently cite the same
 * evidence — without a disambiguator they would collapse into one finding and the run would
 * fail as a duplicate. It is a stability hash of the finding's own id, never an index, which
 * would shift every fingerprint when an unrelated finding is added.
 */

import {
  PRODUCTION_RISK_SECTIONS,
  PRODUCTION_RISK_SECTION_TITLES,
  createRepositoryQuery,
  stabilityHash,
} from "../../../repository/model/index.js";

import {
  PRODUCTION_RISK_ABSTENTION_WORDING,
  PRODUCTION_RISK_CONFIDENCE_WORDING,
  PRODUCTION_RISK_FINDING_WORDING,
  PRODUCTION_RISK_SECTION_WORDING,
  PRODUCTION_RISK_SEVERITY_WORDING,
  PRODUCTION_RISK_STATE_WORDING,
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

/** One finding, as the pack reads it: the report's record plus its readability additions. */
function describeFinding(finding) {
  return {
    ...finding,
    evidenceIds: [...finding.evidenceIds],
    paths: Array.isArray(finding.paths) ? [...finding.paths] : [],
    kindWording: PRODUCTION_RISK_FINDING_WORDING[finding.kind] ?? null,
    severityWording: PRODUCTION_RISK_SEVERITY_WORDING[finding.severity] ?? null,
    confidenceWording: PRODUCTION_RISK_CONFIDENCE_WORDING[finding.confidence] ?? null,
    fingerprintKey: `production.risk:${finding.section}:${stabilityHash(finding.id)}`,
  };
}

/** One section, as the pack reads it. */
function describeSection(section) {
  return {
    name: section.name,
    title: section.title,
    state: section.state,
    established: section.established === true,
    counts: {
      ...section.counts,
      byKind: { ...section.counts.byKind },
      bySeverity: { ...section.counts.bySeverity },
    },
    unknown: section.unknown.map((record) => ({
      reason: record.reason,
      detail: record.detail,
      count: record.count,
      wording: PRODUCTION_RISK_ABSTENTION_WORDING[record.reason] ?? null,
    })),
    coverage: { ...section.coverage },
    findings: section.findings.map(describeFinding),
  };
}

/**
 * Every section the risk report carries, in the report's own declared order.
 *
 * @param {object} query
 * @returns {Array<object>} Frozen section rows.
 */
export function productionRiskSections(query) {
  const report = query.productionRiskReport();
  if (report === null) return [];
  return report.sections.map(describeSection);
}

/** One domain's section, or `null`. */
export function productionRiskSection(query, name) {
  const section = query.productionRiskSection(name);
  if (section === null) return null;
  return describeSection(section);
}

/** The report's own structured coverage statement, or `null`. */
export function productionRiskCoverage(query) {
  return query.productionRiskCoverage();
}

/**
 * Whether the report supports a statement about one domain at all.
 *
 * The same three-part reading the inventory pack uses, and for the same reason: a report must
 * exist, the section must have actually established an answer (neither `unknown` nor
 * `unsupported` is "nothing here" — both are "no answer", for two different reasons), and a
 * bound must not have cut the reading short. An established section with **no** findings is the
 * case that *is* an answer — "this repository's evidence shows no gap in this domain" — and the
 * section's own state is what says so.
 *
 * @param {object} query
 * @param {string} name
 * @returns {{established: boolean, reason: string|null, state: string|null}}
 */
export function productionRiskAbsence(query, name) {
  const section = query.productionRiskSection(name);
  if (section === null) {
    return Object.freeze({
      established: false,
      reason: "this model carries no production risk report",
      state: null,
    });
  }

  const reasons = [];
  if (section.established !== true) {
    for (const record of section.unknown) {
      if (record.reason === "risk-findings-truncated") continue;
      reasons.push(PRODUCTION_RISK_ABSTENTION_WORDING[record.reason] ?? record.reason);
    }
    if (reasons.length === 0) {
      reasons.push("the report did not establish this domain");
    }
  } else if (section.coverage.truncated === true) {
    reasons.push("a bound stopped this domain before its finding list was complete");
  }

  return Object.freeze({
    established: reasons.length === 0,
    reason: reasons.length === 0 ? null : reasons.join("; "),
    state: section.state,
  });
}

/** The section vocabulary this pack can describe, for tests. */
export const PRODUCTION_RISK_DESCRIBED_SECTIONS = Object.freeze(
  Object.keys(PRODUCTION_RISK_SECTION_WORDING),
);

/** The finding-kind vocabulary this pack can describe, for tests. */
export const PRODUCTION_RISK_DESCRIBED_KINDS = Object.freeze(
  Object.keys(PRODUCTION_RISK_FINDING_WORDING),
);

/** The severity vocabulary this pack can describe, for tests. */
export const PRODUCTION_RISK_DESCRIBED_SEVERITIES = Object.freeze(
  Object.keys(PRODUCTION_RISK_SEVERITY_WORDING),
);

/** The confidence vocabulary this pack can describe, for tests. */
export const PRODUCTION_RISK_DESCRIBED_CONFIDENCES = Object.freeze(
  Object.keys(PRODUCTION_RISK_CONFIDENCE_WORDING),
);

/** The abstention vocabulary this pack can describe, for tests. */
export const PRODUCTION_RISK_DESCRIBED_ABSTENTIONS = Object.freeze(
  Object.keys(PRODUCTION_RISK_ABSTENTION_WORDING),
);

/** The coverage-state vocabulary this pack can describe, for tests. */
export const PRODUCTION_RISK_DESCRIBED_STATES = Object.freeze(
  Object.keys(PRODUCTION_RISK_STATE_WORDING),
);

export { PRODUCTION_RISK_SECTIONS, PRODUCTION_RISK_SECTION_TITLES };
