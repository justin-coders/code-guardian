/**
 * Code Guardian — External Dependency Intelligence (Official Roadmap Phase 15)
 *
 * The versioned, time-sensitive half of this phase. The roadmap says "external vulnerability
 * information should be treated as time-sensitive data and clearly versioned", so this module
 * accepts external intelligence as a **dataset with a revision**, normalizes it deterministically
 * and refuses anything it cannot fully understand.
 *
 * ### It is supplied, never fetched
 *
 * A rule never performs a network request. The dataset arrives on
 * `context.options.dependencyIntelligence` and this module turns it into a frozen, ordered,
 * bounded value. When it is absent the state is `absent`; when it is present but malformed or
 * over-large the state is `invalid` and the arrays are empty — fail-closed, so a broken dataset
 * makes the outdated and vulnerability domains `unknown` rather than silently clean.
 *
 * ### What each record must carry
 *
 *   source     `id` and `revision` — without a revision an advisory cannot be attributed to a
 *              point in time, which is the whole reason this phase versions its inputs.
 *   advisory   `id`, `sourceId`, `ecosystem`, `package`, `affectedRange`
 *   release    `sourceId`, `ecosystem`, `package`, `latest`, optional `versions`
 *
 * Nothing here is a judgment: no severity is inferred, no range is expanded, no "safe" is
 * computed. The rules do that, and they cite the source revision they used.
 */

import {
  DEPENDENCY_ANALYSIS_LIMITS,
  DEPENDENCY_INTELLIGENCE_STATES,
} from "./contracts.js";

const MAX_ID_LENGTH = 200;
const MAX_FIELD_LENGTH = 512;
const MAX_QUERY_LENGTH = 512;

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function boundedText(value, max = MAX_FIELD_LENGTH) {
  return typeof value === "string" && value.trim() !== "" && value.length <= max
    ? value.trim()
    : null;
}

function normalizedName(value) {
  const text = boundedText(value);
  return text === null ? null : text.toLowerCase();
}

function empty(state, reason = null) {
  return Object.freeze({
    state,
    reason,
    sources: Object.freeze([]),
    advisories: Object.freeze([]),
    releases: Object.freeze([]),
  });
}

/** Read the dataset from a context, normalized. Never throws. */
export function readDependencyIntelligence(context) {
  const raw = context?.options?.dependencyIntelligence;
  if (raw === undefined || raw === null) return empty(DEPENDENCY_INTELLIGENCE_STATES.ABSENT);
  return normalizeDependencyIntelligence(raw);
}

/**
 * Normalize and validate an external dataset.
 *
 * @param {unknown} raw
 * @returns {object} Frozen normalized dataset, or an `invalid`/`absent` statement.
 */
export function normalizeDependencyIntelligence(raw) {
  if (!isPlainObject(raw)) return empty(DEPENDENCY_INTELLIGENCE_STATES.INVALID, "dataset must be a plain object");

  const rawSources = Array.isArray(raw.sources) ? raw.sources : [];
  const rawAdvisories = Array.isArray(raw.advisories) ? raw.advisories : [];
  const rawReleases = Array.isArray(raw.releases) ? raw.releases : [];

  if (rawSources.length > DEPENDENCY_ANALYSIS_LIMITS.MAX_SOURCES) {
    return empty(DEPENDENCY_INTELLIGENCE_STATES.INVALID, "dataset declares too many sources");
  }
  if (rawAdvisories.length > DEPENDENCY_ANALYSIS_LIMITS.MAX_ADVISORIES) {
    return empty(DEPENDENCY_INTELLIGENCE_STATES.INVALID, "dataset declares too many advisories");
  }
  if (rawReleases.length > DEPENDENCY_ANALYSIS_LIMITS.MAX_RELEASES) {
    return empty(DEPENDENCY_INTELLIGENCE_STATES.INVALID, "dataset declares too many releases");
  }

  const sources = [];
  const sourceIds = new Set();
  for (const entry of rawSources) {
    if (!isPlainObject(entry)) return empty(DEPENDENCY_INTELLIGENCE_STATES.INVALID, "a source is not an object");
    const id = boundedText(entry.id, MAX_ID_LENGTH);
    const revision = boundedText(entry.revision, MAX_ID_LENGTH);
    if (id === null || revision === null) {
      return empty(DEPENDENCY_INTELLIGENCE_STATES.INVALID, "a source is missing an id or revision");
    }
    if (sourceIds.has(id)) continue;
    sourceIds.add(id);
    sources.push(
      Object.freeze({
        id,
        revision,
        kind: boundedText(entry.kind, MAX_ID_LENGTH),
        retrievedAt: boundedText(entry.retrievedAt, MAX_FIELD_LENGTH),
      }),
    );
  }
  sources.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  const advisories = [];
  for (const entry of rawAdvisories) {
    if (!isPlainObject(entry)) return empty(DEPENDENCY_INTELLIGENCE_STATES.INVALID, "an advisory is not an object");
    const id = boundedText(entry.id, MAX_ID_LENGTH);
    const sourceId = boundedText(entry.sourceId, MAX_ID_LENGTH);
    const ecosystem = boundedText(entry.ecosystem, MAX_ID_LENGTH);
    const name = normalizedName(entry.package);
    const affectedRange = boundedText(entry.affectedRange, MAX_QUERY_LENGTH);
    if (
      id === null ||
      sourceId === null ||
      ecosystem === null ||
      name === null ||
      affectedRange === null
    ) {
      return empty(DEPENDENCY_INTELLIGENCE_STATES.INVALID, "an advisory is missing a required field");
    }
    if (!sourceIds.has(sourceId)) {
      return empty(DEPENDENCY_INTELLIGENCE_STATES.INVALID, "an advisory names an unknown source");
    }
    advisories.push(
      Object.freeze({
        id,
        sourceId,
        ecosystem: ecosystem.toLowerCase(),
        package: name,
        affectedRange,
        severity: boundedText(entry.severity, MAX_ID_LENGTH),
        title: boundedText(entry.title, MAX_FIELD_LENGTH),
      }),
    );
  }
  advisories.sort((a, b) => {
    if (a.ecosystem !== b.ecosystem) return a.ecosystem < b.ecosystem ? -1 : 1;
    if (a.package !== b.package) return a.package < b.package ? -1 : 1;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });

  const releases = [];
  for (const entry of rawReleases) {
    if (!isPlainObject(entry)) return empty(DEPENDENCY_INTELLIGENCE_STATES.INVALID, "a release record is not an object");
    const sourceId = boundedText(entry.sourceId, MAX_ID_LENGTH);
    const ecosystem = boundedText(entry.ecosystem, MAX_ID_LENGTH);
    const name = normalizedName(entry.package);
    const latest = boundedText(entry.latest, MAX_QUERY_LENGTH);
    if (sourceId === null || ecosystem === null || name === null || latest === null) {
      return empty(DEPENDENCY_INTELLIGENCE_STATES.INVALID, "a release record is missing a required field");
    }
    if (!sourceIds.has(sourceId)) {
      return empty(DEPENDENCY_INTELLIGENCE_STATES.INVALID, "a release record names an unknown source");
    }
    const versions = [];
    if (Array.isArray(entry.versions)) {
      if (entry.versions.length > DEPENDENCY_ANALYSIS_LIMITS.MAX_VERSIONS_PER_PACKAGE) {
        return empty(DEPENDENCY_INTELLIGENCE_STATES.INVALID, "a release record declares too many versions");
      }
      for (const version of entry.versions) {
        const bounded = boundedText(version, MAX_QUERY_LENGTH);
        if (bounded === null) return empty(DEPENDENCY_INTELLIGENCE_STATES.INVALID, "a release version is malformed");
        versions.push(bounded);
      }
      versions.sort();
    }
    releases.push(
      Object.freeze({
        sourceId,
        ecosystem: ecosystem.toLowerCase(),
        package: name,
        latest,
        versions: Object.freeze(versions),
      }),
    );
  }
  releases.sort((a, b) => {
    if (a.ecosystem !== b.ecosystem) return a.ecosystem < b.ecosystem ? -1 : 1;
    if (a.package !== b.package) return a.package < b.package ? -1 : 1;
    return a.sourceId < b.sourceId ? -1 : a.sourceId > b.sourceId ? 1 : 0;
  });

  return Object.freeze({
    state: DEPENDENCY_INTELLIGENCE_STATES.VALID,
    reason: null,
    sources: Object.freeze(sources),
    advisories: Object.freeze(advisories),
    releases: Object.freeze(releases),
  });
}

/** Index advisories by `ecosystem:package`, in their normalized order. */
export function advisoriesByPackage(intelligence) {
  const index = new Map();
  for (const advisory of intelligence.advisories) {
    const key = `${advisory.ecosystem}:${advisory.package}`;
    const list = index.get(key);
    if (list === undefined) index.set(key, [advisory]);
    else list.push(advisory);
  }
  return index;
}

/** Index release records by `ecosystem:package`, in their normalized order. */
export function releasesByPackage(intelligence) {
  const index = new Map();
  for (const release of intelligence.releases) {
    const key = `${release.ecosystem}:${release.package}`;
    const list = index.get(key);
    if (list === undefined) index.set(key, [release]);
    else list.push(release);
  }
  return index;
}

/** The source record behind an id, or `null`. */
export function sourceById(intelligence, sourceId) {
  return intelligence.sources.find((source) => source.id === sourceId) ?? null;
}
