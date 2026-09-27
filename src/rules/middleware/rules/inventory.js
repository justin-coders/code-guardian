/**
 * Code Guardian — Middleware Graph Inventory Rule (Phase 19)
 *
 * The integration proof for Phase 19's middleware graph, and deliberately an **inventory**
 * rule: it reports the middleware the repository registers, one finding per established
 * middleware, naming the classification derived from the middleware's own name, the scopes
 * and registration kinds it was registered with, the receivers and files it was registered
 * in, and the routes it structurally reaches.
 *
 * ### Why this is not an authentication, ordering, CORS or rate-limit rule
 *
 * "This file registers `requireAuth` on `router`" is a fact about the code. Whether
 * authentication should be required somewhere it is not, whether a middleware is strong
 * enough, whether its declared order is the correct one, whether an admin route is exposed,
 * whether CORS is configured safely and whether rate limiting is adequate all need a model
 * of what the application *should* require — and this architecture has no such model, so the
 * rule reports structure and stops. There is no severity above `info`, no authentication
 * verdict, no ordering verdict and no security-readiness statement anywhere in it.
 *
 * ### What it proves about the graph substrate
 *
 *   - it reads the graph **only** through the Phase 11 query API (`middlewareGraph`,
 *     `middlewareCoverage`, `unresolvedMiddleware`, `coverage`) — never the raw model area,
 *     never a file, never a parser, never a request pipeline;
 *   - every finding cites the declaring file's own middleware observation, so provenance
 *     survives fingerprinting;
 *   - it never claims execution, scheduling, request flow or behaviour: those relations do
 *     not exist in the graph;
 *   - a classification is reported as *name-shaped* (`authentication-shaped`), never as a
 *     behaviour claim;
 *   - middleware the repository could not establish is **not** a finding: it is reported in
 *     the detection metadata, and a route whose middleware could not be established makes
 *     the rule abstain rather than pass, so "no middleware here" is never claimed over a
 *     route the graph marked `unresolved`;
 *   - an empty middleware list is only reported as `pass` when the graph was actually
 *     established *and* complete *and* no route carries an unresolved observation, so
 *     "this repository registers no middleware" is never claimed over a repository whose
 *     scan was incomplete or whose sources could not be read;
 *   - output is deterministic: middleware are flattened and sorted by id.
 *
 * ### Boundedness
 *
 * A large application has one middleware per registration site. The rule stops at
 * `MAX_MIDDLEWARE_FINDINGS` and records that it did (`metadata.capped`), so a capped run is
 * never silently partial.
 */

import { createRule } from "../../../core/index.js";

import { APPLICABILITY_COVERAGE } from "../../contracts.js";
import { createRuleDetection } from "../../evaluation.js";

import {
  MAX_MIDDLEWARE_FINDINGS,
  MIDDLEWARE_BASIS,
  MIDDLEWARE_CATEGORY,
  MIDDLEWARE_CLASSIFICATION_WORDING,
  MIDDLEWARE_CONFIDENCE,
  MIDDLEWARE_RULE_IDS,
  MIDDLEWARE_RULE_VERSION,
} from "../contracts.js";
import {
  middlewareAbsence,
  middlewareCoverage,
  middlewareNodes,
  middlewareRouteViews,
  middlewareUnresolved,
  queryFor,
} from "../signals.js";

/** A parenthesised list, or an empty string. */
function listPhrase(values, empty = "") {
  if (values.length === 0) return empty;
  return values.map((value) => `\`${value}\``).join(", ");
}

/** How one middleware's classification reads. */
function classificationPhrase(classification) {
  return MIDDLEWARE_CLASSIFICATION_WORDING[classification] ?? classification;
}

/** A human-readable statement of one established middleware. */
function describe(node) {
  const classification = classificationPhrase(node.classification);
  const registrations = node.registrations.length === 0 ? "" : node.registrations.join("`, `");
  const receivers = listPhrase(node.receivers, "no receiver");
  const files = listPhrase(node.registeredOn);
  const where =
    node.registeredOn.length === 0
      ? `It is stated by a route declaration's own argument list, not by a receiver registration.`
      : `It is registered on ${receivers} in ${files} through \`${registrations}\`.`;
  const scopes = node.scopes.length === 0 ? "" : ` Its registration scope is ${listPhrase(node.scopes)}.`;
  const routes =
    node.routeProtection.length === 0
      ? " No route in this model is declared on a receiver it was registered on."
      : ` It structurally reaches ${node.routeProtection.length} route${node.routeProtection.length > 1 ? "s" : ""}: ${node.routeProtection
          .map((entry) => `\`${entry.method} ${entry.path}\``)
          .join(", ")}.`;
  return `The repository registers the middleware \`${node.name}\`, whose own name is ${classification}, in \`${node.path}\`. ${where}${scopes}${routes} This finding states a registration the repository declares; it says nothing about whether the middleware runs, whether it authenticates, authorizes, validates or rate-limits anything, whether its declared order is the correct one, or whether the protection is sufficient.`;
}

/** The bounded, reason-summarised view of the occurrences that produced no middleware. */
function unresolvedSummary(unresolved) {
  const byReason = {};
  for (const record of unresolved) {
    byReason[record.reason] = (byReason[record.reason] ?? 0) + record.count;
  }
  return {
    count: unresolved.reduce((total, record) => total + record.count, 0),
    byReason,
    records: unresolved.slice(0, 50).map((record) => ({
      path: record.path,
      reason: record.reason,
      kind: record.kind,
      receiver: record.receiver,
      scope: record.scope,
      route: record.route,
      name: record.name,
    })),
    truncated: unresolved.length > 50,
  };
}

/** How many routes carry each protection state. */
function protectionCounts(routes) {
  const counts = {};
  for (const route of routes) counts[route.protection] = (counts[route.protection] ?? 0) + 1;
  return counts;
}

/**
 * Detect the middleware the repository registers across the repository model.
 *
 * @param {object} context A validated AnalysisContext.
 * @returns {object} A detection object.
 */
function detectMiddlewareGraph(context) {
  const query = queryFor(context);
  const nodes = middlewareNodes(query);
  const routes = middlewareRouteViews(query);
  const coverage = middlewareCoverage(query);
  const unresolved = middlewareUnresolved(query);

  const findings = [];
  for (const node of nodes) {
    if (findings.length >= MAX_MIDDLEWARE_FINDINGS) break;
    findings.push({
      confidence: MIDDLEWARE_CONFIDENCE.OBSERVED_REGISTRATION,
      description: describe(node),
      evidence: [...node.evidenceIds],
      metadata: {
        middleware: node.id,
        name: node.name,
        path: node.path,
        classification: node.classification,
        scopes: [...node.scopes],
        registrations: [...node.registrations],
        receivers: [...node.receivers],
        frameworks: [...node.frameworks],
        hooks: [...node.hooks],
        registeredOn: [...node.registeredOn],
        registrationCount: node.registrationCount,
        routeCount: node.routeIds.length,
        routes: node.routeProtection.slice(0, 20),
        routesTruncated: node.routeProtection.length > 20,
        fingerprintKey: node.fingerprintKey,
        basis: MIDDLEWARE_BASIS,
      },
    });
  }

  const states = protectionCounts(routes);
  const metadata = {
    basis: MIDDLEWARE_BASIS,
    state: coverage.state,
    established: coverage.established === true,
    middleware: coverage.middleware,
    edges: coverage.edges,
    sources: coverage.sources,
    registrations: coverage.registrations,
    mounts: coverage.mounts,
    declaringModules: coverage.declaringModules,
    protectsEdges: coverage.protectsEdges,
    appliesToEdges: coverage.appliesToEdges,
    precedesEdges: coverage.precedesEdges,
    registeredOnEdges: coverage.registeredOnEdges,
    routes: routes.length,
    protectionStates: states,
    classifications: { ...(coverage.classifications ?? {}) },
    reported: findings.length,
    capped: findings.length < nodes.length,
    unresolved: unresolvedSummary(unresolved),
    unestablishedSources: (coverage.unestablishedSources ?? []).length,
    uninterpretedSources: coverage.uninterpretedSources ?? 0,
    uninterpretedExtensions: [...(coverage.uninterpretedExtensions ?? [])],
  };

  if (findings.length > 0) {
    return { findings, evidence: [], metadata };
  }

  const absence = middlewareAbsence(query);
  if (!absence.established) {
    return {
      ...createRuleDetection({
        findings: [],
        coverage: APPLICABILITY_COVERAGE.UNKNOWN,
        reason: `no middleware registration was observed, but ${absence.reason}`,
      }),
      metadata,
    };
  }

  // An established, complete graph with no middleware, but a route whose middleware could
  // not be established: "no middleware here" is a claim this rule refuses to make, because
  // the graph itself declined to make it.
  const unresolvedRoutes = states.unresolved ?? 0;
  if (unresolvedRoutes > 0) {
    return {
      ...createRuleDetection({
        findings: [],
        coverage: APPLICABILITY_COVERAGE.UNKNOWN,
        reason: `${unresolvedRoutes} route${unresolvedRoutes === 1 ? "" : "s"} carry a middleware-shaped occurrence that could not be established, so no middleware-free statement is supported`,
      }),
      metadata,
    };
  }

  return { findings, evidence: [], metadata };
}

export const middlewareRules = Object.freeze([
  createRule({
    id: MIDDLEWARE_RULE_IDS.GRAPH_INVENTORY,
    version: MIDDLEWARE_RULE_VERSION,
    category: MIDDLEWARE_CATEGORY,
    title: "Middleware registered by the repository",
    description:
      "A supported JavaScript or TypeScript source registers middleware on a framework receiver the module itself establishes — `app.use(...)`, `router.use(...)`, `fastify.addHook(...)`, `fastify.register(...)` — or states middleware in an Express/Fastify route declaration's own argument list, and the name resolves to exactly one module-scope binding the semantic layer established. The finding names the middleware, the classification derived from its own name, its scopes and registration kinds, the receivers and files it was registered in, and the routes it structurally reaches. It is an inventory statement: no authentication, authorization, ordering, CORS, rate-limit, insufficient-protection or runtime-execution claim is made, and an occurrence whose middleware could not be established is reported as metadata — and makes the rule abstain rather than pass — rather than as a registration.",
    severity: "info",
    applicability: {},
    detect: (context) => detectMiddlewareGraph(context),
    remediation: {},
    metadata: {
      basis: MIDDLEWARE_BASIS,
      tags: ["middleware", "authorization", "inventory"],
      falsePositives: [
        "a classification is derived from the middleware's own name, so a middleware named `auth` is `authentication-shaped` even if it authenticates nothing",
        "a middleware registered in a file whose route declarations live elsewhere reaches only the routes this model can connect by receiver and file",
        "a registration inside a conditional block, and a computed, spread or inline middleware, are observations rather than findings",
        "a middleware registered on a framework this build does not support is an observation, not a finding",
      ],
    },
  }),
]);
