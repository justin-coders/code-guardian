/**
 * Code Guardian — Reliability Analysis Summary (Official Roadmap Phase 17)
 *
 * The analyzer's structured answer to "what does reliability analysis establish?". It is a pure
 * function of the frozen RepositoryModel, so two runs over the same model produce the same map —
 * no clock, no random source, no unordered iteration.
 *
 * Each of the ten official domains carries a `state` from the pack's vocabulary plus the measured
 * facts behind it, and the reliability subject's own state is reported separately so a consumer can
 * see that a domain is `unknown` because the *model* cannot establish it (not because the
 * repository is clean), and that a CLI repository's domains are `not_applicable` because there is
 * no reliability subject at all.
 *
 * `unknown` is never clean, and `not_applicable` is never used because evidence is missing. Nothing
 * here is a score: there is no reliability grade, resilience percentage or aggregate rating.
 */

import {
  RELIABILITY_ANALYSIS_DOMAINS,
  RELIABILITY_ANALYSIS_STATES,
  RELIABILITY_ANALYSIS_SUBJECTS,
} from "./contracts.js";
import {
  containerCoverageGap,
  containerDefinitions,
  containerFacts,
  containerHealthchecks,
  healthRoutes,
  observabilityDimensions,
  queryFor,
  reliabilityRoutes,
  reliabilitySubject,
  routeCoverageGap,
  symbolCoverageGap,
  usagesForDomain,
} from "./signals.js";

const STATES = RELIABILITY_ANALYSIS_STATES;
const SUBJECTS = RELIABILITY_ANALYSIS_SUBJECTS;

/** The domains whose absence is `unknown` (the mechanism may be configured inline/unread). */
const INLINE_ABSENCE_DOMAINS = new Set([
  "timeouts",
  "retry-behavior",
  "circuit-breaking",
  "graceful-shutdown",
  "failure-handling",
  "resource-cleanup",
]);

/** The domains that conclude `not_applicable` when no subject is established. */
const SUBJECT_ABSENCE_DOMAINS = new Set(["transaction-handling", "queue-behavior"]);

/** The state of a usage-based domain, from the same facts the rule reads. */
function usageState(query, domain) {
  const gap = symbolCoverageGap(query);
  if (gap !== null) return { state: STATES.UNKNOWN, reported: 0, reason: gap };

  const { usages } = usagesForDomain(query, domain);
  if (usages.length > 0) return { state: STATES.ESTABLISHED, reported: usages.length, reason: null };

  if (SUBJECT_ABSENCE_DOMAINS.has(domain)) {
    return { state: STATES.NOT_APPLICABLE, reported: 0, reason: null };
  }
  if (INLINE_ABSENCE_DOMAINS.has(domain)) {
    return {
      state: STATES.UNKNOWN,
      reported: 0,
      reason: `the repository establishes no ${domain} mechanism, and inline/framework configuration is not read by this build`,
    };
  }
  return { state: STATES.UNKNOWN, reported: 0, reason: `the repository establishes no ${domain} fact` };
}

/** The state of the structural health-checks domain. */
function healthChecksState(query) {
  const healthchecks = containerHealthchecks(query);
  const routes = healthRoutes(query);
  const packageUsages = usagesForDomain(query, "health-checks").usages;
  const reported = healthchecks.length + routes.length + packageUsages.length;
  if (reported > 0) return { state: STATES.ESTABLISHED, reported, reason: null };

  const routeGap = routeCoverageGap(query);
  if (routeGap !== null) return { state: STATES.UNKNOWN, reported: 0, reason: routeGap };
  const containerGap = containerCoverageGap(query);
  if (containerGap !== null) return { state: STATES.UNKNOWN, reported: 0, reason: containerGap };
  const symbolGap = symbolCoverageGap(query);
  if (symbolGap !== null) return { state: STATES.UNKNOWN, reported: 0, reason: symbolGap };

  const definitions = containerDefinitions(query);
  if (reliabilityRoutes(query).length === 0 && definitions.length === 0) {
    return {
      state: STATES.UNKNOWN,
      reported: 0,
      reason: "the repository declares no routes and no container definition, so there is no health surface over which to conclude",
    };
  }
  return { state: STATES.DETECTED, reported: 1, reason: null };
}

/** The state of the multi-dimensional observability domain. */
function observabilityState(query) {
  const gap = symbolCoverageGap(query);
  if (gap !== null) return { state: STATES.UNKNOWN, reported: 0, reason: gap };
  const dimensions = observabilityDimensions(query);
  const established = Object.values(dimensions).filter((entry) => entry.established).length;
  if (established > 0) return { state: STATES.ESTABLISHED, reported: established, reason: null };
  return {
    state: STATES.UNKNOWN,
    reported: 0,
    reason: "the repository establishes no observability dimension (logging, metrics, tracing or error reporting)",
  };
}

/** Build the reliability-analysis summary for an AnalysisContext. */
export function summarizeReliabilityAnalysis(context) {
  const query = queryFor(context);
  const subject = reliabilitySubject(query);
  const apiCoverage = query.apiCoverage();
  const symbolCoverage = query.symbolCoverage();
  const container = containerFacts(query);

  const coverageBasis = Object.freeze({
    apiGraphState: apiCoverage.state,
    apiRoutes: subject.routes,
    symbolGraphState: symbolCoverage.state,
    containerState: container.coverageState,
    containers: container.definitions,
    services: subject.services,
  });

  if (subject.state === SUBJECTS.NOT_APPLICABLE) {
    const domains = {};
    for (const { domain, ruleId } of RELIABILITY_ANALYSIS_DOMAINS) {
      domains[domain] = Object.freeze({ ruleId, state: STATES.NOT_APPLICABLE, reported: 0, reason: null });
    }
    return Object.freeze({
      subject: SUBJECTS.NOT_APPLICABLE,
      subjectReason: null,
      coverageBasis,
      domains: Object.freeze(domains),
    });
  }

  const subjectUnknown = subject.state === SUBJECTS.UNKNOWN;
  const domains = {};

  for (const { domain, ruleId } of RELIABILITY_ANALYSIS_DOMAINS) {
    let entry;
    if (subjectUnknown) {
      entry = { state: STATES.UNKNOWN, reported: 0, reason: subject.reason };
    } else if (domain === "health-checks") {
      entry = healthChecksState(query);
    } else if (domain === "observability") {
      entry = observabilityState(query);
    } else {
      entry = usageState(query, domain);
    }
    domains[domain] = Object.freeze({
      ruleId,
      state: entry.state,
      reported: entry.reported ?? 0,
      reason: entry.reason ?? null,
    });
  }

  return Object.freeze({
    subject: subject.state,
    subjectReason: subject.reason,
    coverageBasis,
    domains: Object.freeze(domains),
  });
}
