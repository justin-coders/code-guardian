/**
 * Code Guardian — Production Repository Signals (Phase 20)
 *
 * The one place production rules ask the repository questions. Every read goes through the
 * Phase 11 query API over the frozen RepositoryModel: no filesystem, no `node:path`, no
 * source parsing, no container runtime, no registry, no process, no network, no clock. A
 * rule that cannot answer a question from the model reports `unknown` rather than going to
 * look for itself — which is the whole point of projecting the report once, in the model.
 *
 * ### The report is read, never recomputed
 *
 * `productionSections` hands back the report's own section objects with one addition
 * per observation: a `fingerprintKey`. A finding's canonical fingerprint is derived from
 * its rule, category and evidence set, and every observation from one file cites that
 * file's evidence, so without a disambiguator observations that share evidence would
 * collapse into one finding and the run would fail as a duplicate. The key is a stability
 * hash of the observation's own deterministic key — never an index, which would shift every
 * fingerprint when an unrelated observation is added.
 */

import {
  PRODUCTION_SECTIONS,
  PRODUCTION_SECTION_TITLES,
  createRepositoryQuery,
  stabilityHash,
} from "../../repository/model/index.js";

import {
  PRODUCTION_ABSTENTION_WORDING,
  PRODUCTION_OBSERVATION_WORDING,
  PRODUCTION_SECTION_WORDING,
  PRODUCTION_STATE_WORDING,
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

/**
 * Every section the report carries, in the report's own declared order, each with a
 * `fingerprintKey` on every observation.
 *
 * Sorted by section name through the report's order rather than by a Map's iteration order:
 * the report already declares the order, so this function preserves it and adds nothing.
 *
 * @param {object} query
 * @returns {Array<object>} Frozen section rows.
 */
export function productionSections(query) {
  const report = query.productionReport();
  if (report === null) return [];

  return report.sections.map((section) => ({
    name: section.name,
    title: section.title,
    state: section.state,
    established: section.established,
    counts: { ...section.counts },
    unknown: section.unknown.map((record) => ({ ...record })),
    coverage: { ...section.coverage },
    observations: section.observations.map((observation) => ({
      ...observation,
      evidenceIds: [...observation.evidenceIds],
      fingerprintKey: `production:${section.name}:${stabilityHash(`${observation.kind}:${observation.key}`)}`,
    })),
  }));
}

/**
 * One audit domain's section, or `null`.
 *
 * @param {object} query
 * @param {string} name
 * @returns {object|null}
 */
export function productionSection(query, name) {
  const section = query.productionSection(name);
  if (section === null) return null;
  return {
    name: section.name,
    title: section.title,
    state: section.state,
    established: section.established,
    counts: { ...section.counts },
    unknown: section.unknown.map((record) => ({ ...record })),
    coverage: { ...section.coverage },
    observations: section.observations.map((observation) => ({
      ...observation,
      evidenceIds: [...observation.evidenceIds],
      fingerprintKey: `production:${section.name}:${stabilityHash(`${observation.kind}:${observation.key}`)}`,
    })),
  };
}

/** The report's own structured coverage statement, or `null`. */
export function productionCoverage(query) {
  return query.productionCoverage();
}

/**
 * Whether the report supports a claim about one domain at all.
 *
 * Three separate things have to hold, and none of them is inferred from an empty
 * observation list: a report must exist, the section must have actually been established
 * (`unknown` is not "nothing here", it is "no answer"), and — when the reason is a bounded
 * list — the section must not have abstained in a way that leaves its answer open.
 *
 * @param {object} query
 * @param {string} name
 * @returns {{established: boolean, reason: string|null, state: string|null}}
 */
export function productionAbsence(query, name) {
  const section = query.productionSection(name);
  const reasons = [];

  if (section === null) {
    reasons.push("this model carries no production report");
    return Object.freeze({ established: false, reason: reasons.join("; "), state: null });
  }

  if (section.established !== true) {
    for (const record of section.unknown) {
      if (record.reason === "section-observations-truncated") continue;
      reasons.push(PRODUCTION_ABSTENTION_WORDING[record.reason] ?? record.reason);
    }
    if (reasons.length === 0) {
      reasons.push("the report did not establish this domain");
    }
  } else if (section.observations.length === 0) {
    // Established and empty: an answer, not a gap — but only when nothing in the section
    // says its reading was cut short.
    if (section.coverage.truncated === true) {
      reasons.push("a bound stopped this section before its answer was complete");
    }
  }

  return Object.freeze({
    established: reasons.length === 0,
    reason: reasons.length === 0 ? null : reasons.join("; "),
    state: section.state,
  });
}

/** The section vocabulary this pack can describe, for tests. */
export const PRODUCTION_DESCRIBED_SECTIONS = Object.freeze(Object.keys(PRODUCTION_SECTION_WORDING));

/** The observation-kind vocabulary this pack can describe, for tests. */
export const PRODUCTION_DESCRIBED_OBSERVATIONS = Object.freeze(
  Object.keys(PRODUCTION_OBSERVATION_WORDING),
);

/** The abstention vocabulary this pack can describe, for tests. */
export const PRODUCTION_DESCRIBED_ABSTENTIONS = Object.freeze(
  Object.keys(PRODUCTION_ABSTENTION_WORDING),
);

/** The coverage-state vocabulary this pack can describe, for tests. */
export const PRODUCTION_DESCRIBED_STATES = Object.freeze(Object.keys(PRODUCTION_STATE_WORDING));

export { PRODUCTION_SECTIONS, PRODUCTION_SECTION_TITLES };
