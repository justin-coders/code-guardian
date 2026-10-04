/**
 * Code Guardian — API Analysis Summary (Official Roadmap Phase 16)
 *
 * The analyzer's structured answer to "what does API analysis establish?". It is a pure function
 * of the frozen RepositoryModel, so two runs over the same model produce the same map — no
 * clock, no random source, no unordered iteration.
 *
 * Each of the thirteen official domains carries a `state` from the pack's vocabulary plus the
 * measured facts behind it, and the API subject's own state is reported separately so a consumer
 * can see that six domains are `unknown` because the *model* cannot establish them (not because
 * the repository is clean), and that a CLI repository's domains are `not_applicable` because
 * there is no API subject at all.
 *
 * `unknown` is never clean, and `not_applicable` is never used because evidence is missing.
 * Nothing here is a score: there is no API grade, readiness percentage or aggregate rating.
 */

import {
  COVERAGE_GUARANTEES,
  MIDDLEWARE_CLASSIFICATIONS,
} from "../../repository/model/index.js";

import {
  API_ANALYSIS_BODY_METHODS,
  API_ANALYSIS_DOMAIN_CLASSIFICATION,
  API_ANALYSIS_RULE_IDS,
  API_ANALYSIS_STATES,
  API_ANALYSIS_SUBJECTS,
} from "./contracts.js";
import {
  apiSubject,
  fileInventoryCoverage,
  middlewareCoverageGap,
  openapiArtifacts,
  queryFor,
  routeAbsenceReason,
  routeControls,
  routeCoverageGap,
} from "./signals.js";

const STATES = API_ANALYSIS_STATES;
const IDS = API_ANALYSIS_RULE_IDS;
const CLASSIFICATION = API_ANALYSIS_DOMAIN_CLASSIFICATION;
const CLASSIFICATIONS = MIDDLEWARE_CLASSIFICATIONS;

/** The state of a structural domain from the same facts the rules read. */
function structuralState(query, { classification, mode, scope }) {
  const routes = routeControls(query);

  if (mode === "positive") {
    let reported = 0;
    for (const route of routes) {
      reported += route.middleware.filter((entry) => entry.classification === classification).length;
    }
    return { state: STATES.ESTABLISHED, reported, reason: null };
  }

  const routeGap = routeCoverageGap(query);
  if (routeGap !== null) return { state: STATES.UNKNOWN, reported: 0, reason: routeGap };
  const mwGap = middlewareCoverageGap(query);
  if (mwGap !== null) return { state: STATES.UNKNOWN, reported: 0, reason: mwGap };

  let reported = 0;
  const reasons = [];
  for (const route of routes) {
    if (typeof scope === "function" && !scope(route)) continue;
    const absence = routeAbsenceReason(route);
    if (absence !== null) {
      reasons.push(absence);
      continue;
    }
    if (!route.middleware.some((entry) => entry.classification === classification)) reported += 1;
  }
  if (reported > 0) return { state: STATES.DETECTED, reported, reason: null };
  if (reasons.length > 0) return { state: STATES.UNKNOWN, reported: 0, reason: reasons.join("; ") };
  return { state: STATES.ESTABLISHED, reported: 0, reason: null };
}

/** The state of an artifact domain (OpenAPI). */
function artifactState(query) {
  const artifacts = openapiArtifacts(query);
  if (artifacts.length > 0) return { state: STATES.ESTABLISHED, reported: artifacts.length, reason: null };
  const inventory = fileInventoryCoverage(query);
  if (inventory.coverage !== COVERAGE_GUARANTEES.COMPLETE || inventory.truncated) {
    return {
      state: STATES.UNKNOWN,
      reported: 0,
      reason: "no OpenAPI artifact was observed, but the file inventory is not complete",
    };
  }
  return { state: STATES.ESTABLISHED, reported: 0, reason: null };
}

/** Build the api-analysis summary for an AnalysisContext. */
export function summarizeApiAnalysis(context) {
  const query = queryFor(context);
  const subject = apiSubject(query);
  const apiCoverage = query.apiCoverage();
  const middlewareCoverage = query.middlewareCoverage();

  const coverageBasis = Object.freeze({
    apiGraphState: subject.graph,
    apiRoutes: subject.routes,
    apiUnresolvedRoutes: apiCoverage.unresolved ?? 0,
    middlewareGraphState: middlewareCoverage.state,
    middlewareNodes: middlewareCoverage.middleware ?? 0,
    middlewareRouteViews: middlewareCoverage.routes ?? 0,
  });

  if (subject.state === API_ANALYSIS_SUBJECTS.NOT_APPLICABLE) {
    const domains = {};
    for (const [key, id] of Object.entries(IDS)) {
      domains[domainOf(id)] = Object.freeze({ ruleId: id, state: STATES.NOT_APPLICABLE, reported: 0, reason: null });
    }
    return Object.freeze({
      subject: API_ANALYSIS_SUBJECTS.NOT_APPLICABLE,
      subjectReason: null,
      coverageBasis,
      domains: Object.freeze(domains),
    });
  }

  const subjectUnknown = subject.state === API_ANALYSIS_SUBJECTS.UNKNOWN;

  const structural = {
    "input-validation": {
      classification: CLASSIFICATION["input-validation"],
      mode: "gap",
      scope: (route) => API_ANALYSIS_BODY_METHODS.includes(route.method),
    },
    authentication: { classification: CLASSIFICATION.authentication, mode: "gap" },
    authorization: {
      classification: CLASSIFICATION.authorization,
      mode: "gap",
      scope: (route) =>
        route.middleware.some((entry) => entry.classification === CLASSIFICATIONS.AUTHENTICATION),
    },
    "rate-limiting": { classification: CLASSIFICATION["rate-limiting"], mode: "positive" },
    cors: { classification: CLASSIFICATION.cors, mode: "positive" },
    logging: { classification: CLASSIFICATION.logging, mode: "gap" },
  };

  const unestablishedReason = (domain) => unestablishedReasonFor(domain, subject);

  const domains = {};
  domains["input-validation"] = frozen(
    IDS.INPUT_VALIDATION,
    subjectUnknown
      ? unknown(subject.reason)
      : structuralState(query, structural["input-validation"]),
  );
  domains["schema-validation"] = frozen(IDS.SCHEMA_VALIDATION, unknown(unestablishedReason("schema-validation")));
  domains.authentication = frozen(
    IDS.AUTHENTICATION,
    subjectUnknown ? unknown(subject.reason) : structuralState(query, structural.authentication),
  );
  domains.authorization = frozen(
    IDS.AUTHORIZATION,
    subjectUnknown ? unknown(subject.reason) : structuralState(query, structural.authorization),
  );
  domains["error-handling"] = frozen(IDS.ERROR_HANDLING, unknown(unestablishedReason("error-handling")));
  domains["status-codes"] = frozen(IDS.STATUS_CODES, unknown(unestablishedReason("status-codes")));
  domains.pagination = frozen(IDS.PAGINATION, unknown(unestablishedReason("pagination")));
  domains["rate-limiting"] = frozen(
    IDS.RATE_LIMITING,
    subjectUnknown ? unknown(subject.reason) : structuralState(query, structural["rate-limiting"]),
  );
  domains.cors = frozen(
    IDS.CORS,
    subjectUnknown ? unknown(subject.reason) : structuralState(query, structural.cors),
  );
  domains.openapi = frozen(
    IDS.OPENAPI,
    subjectUnknown ? unknown(subject.reason) : artifactState(query),
  );
  domains["request-limits"] = frozen(IDS.REQUEST_LIMITS, unknown(unestablishedReason("request-limits")));
  domains.logging = frozen(
    IDS.LOGGING,
    subjectUnknown ? unknown(subject.reason) : structuralState(query, structural.logging),
  );
  domains["correlation-ids"] = frozen(IDS.CORRELATION_IDS, unknown(unestablishedReason("correlation-ids")));

  return Object.freeze({
    subject: subject.state,
    subjectReason: subject.reason,
    coverageBasis,
    domains: Object.freeze(domains),
  });
}

/** The domain a rule id names (the segment after `api.`). */
function domainOf(ruleId) {
  return String(ruleId).replace(/^api\./, "");
}

/** A frozen domain entry with the rule id filled in. */
function frozen(ruleId, state) {
  return Object.freeze({
    ruleId,
    state: state.state,
    reported: state.reported ?? 0,
    reason: state.reason ?? null,
  });
}

function unknown(reason) {
  return { state: STATES.UNKNOWN, reported: 0, reason };
}

/** Why the model cannot establish an unestablished domain. */
function unestablishedReasonFor(domain, subject) {
  return `the repository model establishes no ${domain} fact (the API subject is ${subject.state})`;
}
