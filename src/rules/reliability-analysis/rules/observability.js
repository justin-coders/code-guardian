/**
 * Code Guardian — Reliability Observability Rule (Official Roadmap Phase 17)
 *
 * The "observability" domain, kept **multi-dimensional** exactly as §54 requires: logging, metrics,
 * tracing and error reporting are distinct, so the rule reports each dimension's evidence
 * separately and never resolves observability to a boolean.
 *
 * The logging dimension reuses the middleware graph's existing `logging` classification (a
 * registration on the request path) *and* observed logging-package usage, and is deliberately kept
 * apart from the Phase 16 `api.logging` rule: this pack never re-reports that request-lifecycle
 * gap, only establishes which dimensions the repository evinces. A `logger.info(…)` call is not
 * read by this build, so the rule claims no more than a package/registration fact.
 */

import { createRule } from "../../../core/index.js";

import {
  RELIABILITY_ANALYSIS_BASES,
  RELIABILITY_ANALYSIS_CATEGORY,
  RELIABILITY_ANALYSIS_CONFIDENCE,
  RELIABILITY_ANALYSIS_RULE_IDS,
  RELIABILITY_ANALYSIS_RULE_VERSION,
  RELIABILITY_ANALYSIS_STATES,
} from "../contracts.js";
import { observabilityDimensions, queryFor, symbolCoverageGap } from "../signals.js";

import { capFindings, gateOnReliabilitySubject, unknownDetection } from "./shared.js";

const BASIS = RELIABILITY_ANALYSIS_BASES.MIDDLEWARE_GRAPH;

const DIMENSION_LABEL = Object.freeze({
  logging: "logging",
  metrics: "metrics",
  tracing: "tracing",
  "error-reporting": "error reporting",
});

function detect(context) {
  const query = queryFor(context);

  const gated = gateOnReliabilitySubject(query, BASIS);
  if (gated !== null) return gated;

  const gap = symbolCoverageGap(query);
  if (gap !== null) return unknownDetection(gap);

  const dimensions = observabilityDimensions(query);
  const candidates = [];

  for (const [dimension, evidence] of Object.entries(dimensions)) {
    for (const usage of evidence.usages) {
      candidates.push({
        confidence: usage.nameDerived
          ? RELIABILITY_ANALYSIS_CONFIDENCE.NAME_DERIVED
          : RELIABILITY_ANALYSIS_CONFIDENCE.PACKAGE_USAGE,
        title: `An observability ${DIMENSION_LABEL[dimension]} mechanism is used by the repository`,
        description: `\`${usage.path}\` imports \`${usage.name}\` from \`${usage.packageName}\` and the symbol graph observed the module using it. This establishes the ${DIMENSION_LABEL[dimension]} dimension only; whether it is configured, sampled or complete is not established.`,
        evidence: [...usage.evidenceIds],
        metadata: {
          basis: BASIS,
          state: RELIABILITY_ANALYSIS_STATES.ESTABLISHED,
          fingerprintKey: usage.fingerprintKey,
          domain: "observability",
          dimension,
          name: usage.name,
          packageName: usage.packageName,
          usage: usage.usage,
          sourcePath: usage.path,
        },
      });
    }

    if (evidence.middleware && evidence.evidenceIds.length > 0) {
      candidates.push({
        confidence: RELIABILITY_ANALYSIS_CONFIDENCE.NAME_DERIVED,
        title: "A logging-shaped middleware reaches a route",
        description:
          "A route is reached by a middleware the middleware graph classified `logging` — a registration on the request path. This establishes the logging dimension from a registration, derived from the middleware's name alone; it does not claim structured logging or that every request is logged, and it does not restate the Phase 16 request-logging gap.",
        evidence: [...evidence.evidenceIds],
        metadata: {
          basis: BASIS,
          state: RELIABILITY_ANALYSIS_STATES.ESTABLISHED,
          fingerprintKey: `reliability:observability:logging-middleware:${dimension}`,
          domain: "observability",
          dimension,
          evidenceClass: "middleware",
        },
      });
    }
  }

  const dimensionSummary = {};
  for (const [dimension, evidence] of Object.entries(dimensions)) {
    dimensionSummary[dimension] = evidence.established;
  }

  if (candidates.length > 0) {
    const { entries, truncated } = capFindings(candidates);
    return {
      findings: entries,
      evidence: [],
      metadata: {
        basis: BASIS,
        state: RELIABILITY_ANALYSIS_STATES.ESTABLISHED,
        domain: "observability",
        reported: entries.length,
        capped: truncated,
        dimensions: dimensionSummary,
      },
    };
  }

  return unknownDetection(
    "the repository establishes no observability dimension (logging, metrics, tracing or error reporting): no observability package usage and no logging-shaped middleware was observed, and inline logging calls are not read by this build",
  );
}

export const observabilityRules = Object.freeze([
  createRule({
    id: RELIABILITY_ANALYSIS_RULE_IDS.OBSERVABILITY,
    version: RELIABILITY_ANALYSIS_RULE_VERSION,
    category: RELIABILITY_ANALYSIS_CATEGORY,
    title: "The repository establishes observability dimensions",
    description:
      "Observability is reported per dimension — logging, metrics, tracing and error reporting — never collapsed into a boolean. Each dimension is established by an observed package usage, and the logging dimension additionally by the middleware graph's existing `logging` classification. The rule states which dimensions the repository evinces and makes no claim that logging is structured, that metrics are complete or that tracing propagates; it does not restate the Phase 16 request-logging gap, and when no dimension is established the domain is `unknown`.",
    severity: "info",
    applicability: {},
    detect,
    remediation: {},
    metadata: {
      basis: BASIS,
      domain: "observability",
      mode: "dimensional",
      tags: ["reliability", "observability"],
      falsePositives: [
        "a generic logger object (a variable) that the symbol graph does not establish as a callable",
        "a logging library imported for tests only",
        "a `logger.info(…)` call inside a handler, which this build does not read",
      ],
    },
  }),
]);
