/**
 * Code Guardian — Reliability Health Checks Rule (Official Roadmap Phase 17)
 *
 * The "health checks" domain, and the pack's one **structural** domain. It keeps three distinct
 * evidence classes apart, exactly as the roadmap insists:
 *
 *   container healthcheck   a Dockerfile whose own instructions declare `HEALTHCHECK` (observed
 *                           artifact — the existence is a fact; whether it succeeds at runtime is
 *                           not)
 *   health endpoint         a route whose path contains a health-shaped segment (`/health`,
 *                           `/readyz`, `/live`, …) — a structural indicator only
 *   health package          an observed usage of a health-check library
 *
 * A route named `/health` is a *structural indicator*: the rule never claims the check is correct,
 * that it verifies dependencies, or that the probe succeeds. Conversely an established health
 * check is not a gap.
 *
 * Absence is the one claim here that needs coverage, so it is gated: only over a complete route set
 * **and** a completely read container inventory, and only when the repository actually declares a
 * health surface (routes or a container). Even then the finding states what the repository
 * establishes, not that the service is unhealthy.
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
import {
  containerCoverageGap,
  containerDefinitions,
  containerHealthchecks,
  healthRoutes,
  queryFor,
  reliabilityRoutes,
  routeCoverageGap,
  symbolCoverageGap,
  usagesForDomain,
} from "../signals.js";

import { capFindings, gateOnReliabilitySubject, keyFragment, unknownDetection } from "./shared.js";

const BASIS = RELIABILITY_ANALYSIS_BASES.SERVICE_SIGNALS;

function detect(context) {
  const query = queryFor(context);

  const gated = gateOnReliabilitySubject(query, BASIS);
  if (gated !== null) return gated;

  const routes = reliabilityRoutes(query);
  const healthRouteList = healthRoutes(query);
  const healthchecks = containerHealthchecks(query);
  const definitions = containerDefinitions(query);
  const packageUsages = usagesForDomain(query, "health-checks").usages;

  const candidates = [];

  for (const check of healthchecks) {
    candidates.push({
      confidence: RELIABILITY_ANALYSIS_CONFIDENCE.OBSERVED_ARTIFACT,
      title: "A container healthcheck is declared in the repository",
      description: `The container definition \`${check.path}\` declares a healthcheck instruction. This states that the artifact declares one; what it checks, how often it runs and whether it succeeds at runtime are not established. It is not evidence of an application health endpoint.`,
      evidence: [...check.evidenceIds],
      metadata: {
        basis: BASIS,
        state: RELIABILITY_ANALYSIS_STATES.ESTABLISHED,
        fingerprintKey: `reliability:health-checks:container:${keyFragment(check.path)}`,
        domain: "health-checks",
        evidenceClass: "container-healthcheck",
        path: check.path,
      },
    });
  }

  for (const route of healthRouteList) {
    candidates.push({
      confidence: RELIABILITY_ANALYSIS_CONFIDENCE.ESTABLISHED_STRUCTURE,
      title: "A health-shaped endpoint is declared",
      description: `Route \`${route.method} ${route.path}\` has a health-shaped path segment. This is a structural indicator — the repository declares an endpoint under a health-shaped name — and it does not establish that the endpoint verifies dependencies, that it is used by an orchestrator, or that its check is correct. It is a different evidence class from a container healthcheck.`,
      evidence: [...route.evidenceIds],
      metadata: {
        basis: BASIS,
        state: RELIABILITY_ANALYSIS_STATES.ESTABLISHED,
        fingerprintKey: `${route.fingerprintKey}`,
        domain: "health-checks",
        evidenceClass: "health-endpoint",
        route: route.id,
        method: route.method,
        path: route.path,
      },
    });
  }

  for (const usage of packageUsages) {
    candidates.push({
      confidence: usage.nameDerived
        ? RELIABILITY_ANALYSIS_CONFIDENCE.NAME_DERIVED
        : RELIABILITY_ANALYSIS_CONFIDENCE.PACKAGE_USAGE,
      title: "A health-check mechanism is used by the repository",
      description:
        usage.packageName === null
          ? `\`${usage.path}\` declares and uses \`${usage.name}\`, whose name matches the closed health-check vocabulary. The match is derived from the symbol's name alone.`
          : `\`${usage.path}\` imports \`${usage.name}\` from \`${usage.packageName}\` and the symbol graph observed the module using it.`,
      evidence: [...usage.evidenceIds],
      metadata: {
        basis: BASIS,
        state: RELIABILITY_ANALYSIS_STATES.ESTABLISHED,
        fingerprintKey: usage.fingerprintKey,
        domain: "health-checks",
        evidenceClass: "health-package",
        name: usage.name,
        packageName: usage.packageName,
        usage: usage.usage,
        sourcePath: usage.path,
      },
    });
  }

  if (candidates.length > 0) {
    const { entries, truncated } = capFindings(candidates);
    return {
      findings: entries,
      evidence: [],
      metadata: {
        basis: BASIS,
        state: RELIABILITY_ANALYSIS_STATES.ESTABLISHED,
        domain: "health-checks",
        reported: entries.length,
        capped: truncated,
        routes: routes.length,
        healthRoutes: healthRouteList.length,
        containerHealthchecks: healthchecks.length,
      },
    };
  }

  // Absence. Gated on complete coverage, and only over a health surface the repository declares.
  const routeGap = routeCoverageGap(query);
  if (routeGap !== null) return unknownDetection(routeGap);
  const containerGap = containerCoverageGap(query);
  if (containerGap !== null) return unknownDetection(containerGap);
  const symbolGap = symbolCoverageGap(query);
  if (symbolGap !== null) return unknownDetection(symbolGap);

  if (routes.length === 0 && definitions.length === 0) {
    return unknownDetection(
      "the repository declares no routes and no container definition, so there is no health surface over which to conclude",
    );
  }

  return {
    findings: [
      {
        confidence: RELIABILITY_ANALYSIS_CONFIDENCE.ESTABLISHED_STRUCTURE,
        title: "The repository declares no health check",
        description: `Over a completely read route set (${routes.length} route(s)) and a completely read container inventory (${definitions.length} definition(s)), the repository declares no health-shaped endpoint, no container healthcheck and no health-check package usage. This states what the repository establishes — it does not establish that the service is unhealthy, that a check is required, or that an external orchestrator performs a check the repository does not declare.`,
        evidence: [
          ...new Set(
            [
              ...routes.flatMap((route) => route.evidenceIds ?? []),
              ...definitions.flatMap((definition) => definition.evidenceIds ?? []),
            ].filter((id) => typeof id === "string"),
          ),
        ].sort(),
        metadata: {
          basis: BASIS,
          state: RELIABILITY_ANALYSIS_STATES.DETECTED,
          fingerprintKey: "reliability:health-checks:service",
          domain: "health-checks",
          routes: routes.length,
          containers: definitions.length,
        },
      },
    ],
    evidence: [],
    metadata: {
      basis: BASIS,
      state: RELIABILITY_ANALYSIS_STATES.DETECTED,
      domain: "health-checks",
      reported: 1,
      capped: false,
      routes: routes.length,
      containerDefinitions: definitions.length,
    },
  };
}

export const healthChecksRules = Object.freeze([
  createRule({
    id: RELIABILITY_ANALYSIS_RULE_IDS.HEALTH_CHECKS,
    version: RELIABILITY_ANALYSIS_RULE_VERSION,
    category: RELIABILITY_ANALYSIS_CATEGORY,
    title: "The repository declares a health check, or establishes its absence",
    description:
      "Three distinct evidence classes are kept apart: a container healthcheck (an observed artifact), a health-shaped route (a structural indicator), and a health-check package usage. An established check is reported with the class it rests on. Absence is claimed only over a complete route set and a completely read container inventory, and only when the repository declares a health surface, and even then it states what the repository establishes rather than that the service is unhealthy.",
    severity: "low",
    applicability: {},
    detect,
    remediation: {},
    metadata: {
      basis: BASIS,
      domain: "health-checks",
      mode: "structural",
      tags: ["reliability", "health-checks"],
      falsePositives: [
        "a health check performed externally (an orchestrator probe) that the repository does not declare",
        "a `/status` or non-health-shaped path that serves the same purpose",
        "a health check on a route the API graph did not establish",
      ],
    },
  }),
]);
