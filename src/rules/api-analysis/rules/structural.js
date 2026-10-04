/**
 * Code Guardian — API Analysis Structural Control Rules (Official Roadmap Phase 16)
 *
 * The shared engine behind the domains whose evidence is a middleware *classification*. Six of
 * the thirteen official domains read the same structural fact — a route's resolved middleware
 * chain — and ask the same shape of question about it, so the shape is written once here and
 * each domain supplies only its vocabulary:
 *
 *   gap       report a route that establishes none of the domain's middleware, over a chain the
 *             middleware graph fully established. An absence claim, so it abstains on every
 *             route whose chain is unresolved, unknown, truncated or not described.
 *   positive  report a route that establishes the domain's middleware. A presence claim, which
 *             needs no abstention: the middleware is right there in the established chain.
 *
 * ### What "established" means, and does not mean
 *
 * The classification is the middleware graph's own, derived **from the middleware's name alone**
 * (`requireAuth` is `authentication`; whether it authenticates is not the graph's business). So
 * a finding's wording says exactly that — the repository registers a middleware whose name
 * classifies into the domain — and its confidence is `NAME_DERIVED`, the weakest in the pack. It
 * never claims the middleware works, runs, or is configured correctly.
 *
 * ### The two halves of every finding
 *
 * A gap finding cites the route's own declaration and the middleware-source record of the file
 * that declares it, because "no middleware reaches this route" is a statement about both. A
 * positive finding cites the route's declaration and the middleware node's own observation.
 */

import { createRule } from "../../../core/index.js";

import { API_ANALYSIS_BASES, API_ANALYSIS_CONFIDENCE, API_ANALYSIS_STATES } from "../contracts.js";
import {
  middlewareCoverageGap,
  middlewareSourceEvidenceId,
  queryFor,
  routeAbsenceReason,
  routeControls,
  routeCoverageGap,
} from "../signals.js";

import { capFindings, gateOnApiSubject, keyFragment, unknownDetection } from "./shared.js";

const BASIS = API_ANALYSIS_BASES.MIDDLEWARE_GRAPH;

/** Whether a chain entry carries the domain's classification. */
function matches(entry, classification) {
  return entry.classification === classification;
}

/** A compact, deterministic view of a route's resolved chain, for finding metadata. */
function chainMetadata(route) {
  return route.middleware.map((entry) => ({
    name: entry.name,
    classification: entry.classification,
  }));
}

/** The evidence a gap finding cites: the route declaration and its file's registration record. */
function gapEvidence(query, route) {
  const source = route.sourcePaths
    .map((path) => middlewareSourceEvidenceId(query, path))
    .filter((id) => id !== null);
  return [...new Set([...route.evidenceIds, ...source])].sort();
}

/** One gap finding: the route establishes none of the domain's name-classified middleware. */
function gapFinding(query, route, spec) {
  return {
    confidence: API_ANALYSIS_CONFIDENCE.NAME_DERIVED,
    title: spec.gapTitle,
    description: spec.gapDescription(route),
    evidence: gapEvidence(query, route),
    metadata: {
      basis: BASIS,
      state: API_ANALYSIS_STATES.DETECTED,
      fingerprintKey: `${spec.domain}:route:${route.fingerprintKey}`,
      domain: spec.domain,
      route: route.id,
      method: route.method,
      path: route.path,
      frameworks: [...route.frameworks],
      sourcePaths: [...route.sourcePaths],
      protection: route.protection,
      protectionBasis: route.protectionBasis,
      classification: spec.classification,
      middleware: chainMetadata(route),
    },
  };
}

/** One positive finding: the route establishes the domain's name-classified middleware. */
function positiveFinding(route, entry, spec) {
  return {
    confidence: API_ANALYSIS_CONFIDENCE.NAME_DERIVED,
    title: spec.presentTitle,
    description: spec.presentDescription(route, entry),
    evidence: [...new Set([...route.evidenceIds, ...entry.evidenceIds])].sort(),
    metadata: {
      basis: BASIS,
      state: API_ANALYSIS_STATES.ESTABLISHED,
      fingerprintKey: `${spec.domain}:route:${route.fingerprintKey}:mw:${keyFragment(entry.id)}`,
      domain: spec.domain,
      route: route.id,
      method: route.method,
      path: route.path,
      frameworks: [...route.frameworks],
      sourcePaths: [...route.sourcePaths],
      protection: route.protection,
      protectionBasis: route.protectionBasis,
      classification: spec.classification,
      middleware: [{ name: entry.name, classification: entry.classification }],
    },
  };
}

/** The shared detection flow for a structural control rule. */
function detectStructural(context, spec) {
  const query = queryFor(context);

  const gated = gateOnApiSubject(query, BASIS);
  if (gated !== null) return gated;

  const routeGap = routeCoverageGap(query);
  if (routeGap !== null) return unknownDetection(routeGap);
  const mwGap = middlewareCoverageGap(query);
  if (mwGap !== null) return unknownDetection(mwGap);

  const routes = routeControls(query);

  if (spec.mode === "positive") {
    const candidates = [];
    for (const route of routes) {
      for (const entry of route.middleware) {
        if (matches(entry, spec.classification)) candidates.push(positiveFinding(route, entry, spec));
      }
    }
    const { entries, truncated } = capFindings(candidates);
    return {
      findings: entries,
      evidence: [],
      metadata: {
        basis: BASIS,
        state: API_ANALYSIS_STATES.ESTABLISHED,
        domain: spec.domain,
        classification: spec.classification,
        routes: routes.length,
        reported: entries.length,
        capped: truncated,
      },
    };
  }

  const findings = [];
  const unresolved = [];
  for (const route of routes) {
    if (typeof spec.scope === "function" && !spec.scope(route)) continue;
    const reason = routeAbsenceReason(route);
    if (reason !== null) {
      unresolved.push(reason);
      continue;
    }
    if (!route.middleware.some((entry) => matches(entry, spec.classification))) {
      findings.push(gapFinding(query, route, spec));
    }
  }

  const { entries, truncated } = capFindings(findings);

  if (entries.length > 0) {
    return {
      findings: entries,
      evidence: [],
      metadata: {
        basis: BASIS,
        state: API_ANALYSIS_STATES.DETECTED,
        domain: spec.domain,
        classification: spec.classification,
        routes: routes.length,
        reported: entries.length,
        capped: truncated,
        unresolved: unresolved.length,
      },
    };
  }

  if (unresolved.length > 0) {
    return unknownDetection(unresolved.join("; "));
  }

  return {
    findings: [],
    evidence: [],
    metadata: {
      basis: BASIS,
      state: API_ANALYSIS_STATES.ESTABLISHED,
      domain: spec.domain,
      classification: spec.classification,
      routes: routes.length,
      reported: 0,
      capped: false,
      unresolved: 0,
    },
  };
}

/**
 * Build a structural control rule from a domain specification.
 *
 * @param {object} spec
 * @param {string} spec.id Rule id (already namespaced).
 * @param {string} spec.domain The official domain name.
 * @param {string} spec.classification The middleware classification the domain reads.
 * @param {string} spec.mode `"gap"` or `"positive"`.
 * @param {string} spec.severity Finding severity.
 * @param {string} spec.ruleTitle Rule-level title.
 * @param {string} spec.ruleDescription Rule-level description.
 * @param {Function} [spec.scope] Which routes the rule considers (gap mode only).
 * @param {string} [spec.gapTitle] Finding title for a gap.
 * @param {Function} [spec.gapDescription] Finding description for a gap.
 * @param {string} [spec.presentTitle] Finding title for a presence.
 * @param {Function} [spec.presentDescription] Finding description for a presence.
 * @param {string[]} [spec.tags]
 * @param {string[]} [spec.falsePositives]
 * @returns {object} A Core rule descriptor.
 */
export function createStructuralRule(spec) {
  return createRule({
    id: spec.id,
    version: spec.version,
    category: spec.category,
    title: spec.ruleTitle,
    description: spec.ruleDescription,
    severity: spec.severity,
    applicability: {},
    detect: (context) => detectStructural(context, spec),
    remediation: {},
    metadata: {
      basis: BASIS,
      domain: spec.domain,
      classification: spec.classification,
      mode: spec.mode,
      tags: spec.tags ?? ["api", spec.domain],
      falsePositives: spec.falsePositives ?? [],
    },
  });
}
