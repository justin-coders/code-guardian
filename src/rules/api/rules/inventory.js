/**
 * Code Guardian — API Graph Inventory Rule (Phase 18)
 *
 * The integration proof for Phase 18's API graph, and deliberately an **inventory** rule:
 * it reports the HTTP endpoints the repository declares, one finding per endpoint, naming
 * the method, the path, the framework that declares it, the file that declares it, the
 * resolved handler and middleware symbols and the observation behind it.
 *
 * ### Why this is not an authentication, quality or missing-middleware rule
 *
 * "This file declares `GET /admin`" is a fact about the code. Whether that endpoint
 * *should* require authentication, whether it is versioned, whether its route naming is
 * consistent, whether middleware is missing and whether the API surface is healthy all
 * need a model of what the API is supposed to be — and this architecture has no such
 * model, so the rule reports structure and stops. There is no severity above `info`, no
 * authentication verdict, no REST-quality score and no readiness statement anywhere in it.
 *
 * ### What it proves about the graph substrate
 *
 *   - it reads the graph **only** through the Phase 11 query API (`apiGraph`,
 *     `apiCoverage`, `unresolvedRoutes`) — never the raw model area, never a file, never a
 *     parser, never a router;
 *   - every finding cites the declaring file's own observation, so provenance survives
 *     fingerprinting;
 *   - it never claims runtime reachability, execution order, authentication or request
 *     flow: those relations do not exist in the graph;
 *   - a route whose handler is a member access or an inline function carries that fact in
 *     the detection metadata rather than being reported as unhandled;
 *   - an empty route list is only reported as `pass` when the graph was actually
 *     established *and* complete, so "this repository exposes nothing" is never claimed
 *     over a repository whose scan was incomplete or whose sources could not be read;
 *   - route-shaped occurrences are **not** findings: they are reported in the detection
 *     metadata, because an occurrence whose receiver is not a framework registrar is not
 *     an endpoint a finding may claim;
 *   - output is deterministic: routes are flattened and sorted by id.
 *
 * ### Boundedness
 *
 * A large API has one route per endpoint. The rule stops at `MAX_API_FINDINGS` and records
 * that it did (`metadata.capped`), so a capped run is never silently partial.
 */

import { createRule } from "../../../core/index.js";

import { APPLICABILITY_COVERAGE } from "../../contracts.js";
import { createRuleDetection } from "../../evaluation.js";

import {
  MAX_API_FINDINGS,
  API_BASIS,
  API_CATEGORY,
  API_CONFIDENCE,
  API_RULE_IDS,
  API_RULE_VERSION,
} from "../contracts.js";
import { apiAbsence, apiCoverage, apiRoutes, apiUnresolved, queryFor } from "../signals.js";

/** A parenthesised list, or an empty string. */
function listPhrase(values, empty = "") {
  if (values.length === 0) return empty;
  return values.map((value) => `\`${value}\``).join(", ");
}

/** A human-readable statement of one established endpoint. */
function describe(route) {
  const frameworks = route.frameworks.length === 0 ? "" : ` (${route.frameworks.join(", ")})`;
  const files = listPhrase(route.sourcePaths);
  const handlers =
    route.handlerNames.length === 0
      ? " No handler is resolved for it: the call sites' final argument is an inline function, a member access, or a name this build does not establish as a module-scope binding."
      : ` Its resolved handler${route.handlerNames.length > 1 ? "s" : ""} ${route.handlerNames.length > 1 ? "are" : "is"} ${listPhrase(route.handlerNames)}.`;
  const middleware =
    route.middlewareNames.length === 0
      ? ""
      : ` The symbols it lists before the handler are ${listPhrase(route.middlewareNames)}.`;
  return `The repository declares the route \`${route.method} ${route.path}\`${frameworks}, registered on \`${route.receivers.join("`, `")}\` in ${files}.${handlers}${middleware} This finding states an endpoint the repository declares; it says nothing about whether the route is reachable at runtime, whether authentication applies, whether middleware runs, or whether the endpoint is correct.`;
}

/** The bounded, reason-summarised view of the occurrences that produced no route. */
function unresolvedSummary(unresolved) {
  const byReason = {};
  for (const record of unresolved) {
    byReason[record.reason] = (byReason[record.reason] ?? 0) + 1;
  }
  return {
    count: unresolved.length,
    byReason,
    records: unresolved.slice(0, 50).map((record) => ({
      path: record.path,
      reason: record.reason,
      receiver: record.receiver,
      method: record.method,
      route: record.route,
    })),
    truncated: unresolved.length > 50,
  };
}

/**
 * Detect established HTTP endpoints across the repository model.
 *
 * @param {object} context A validated AnalysisContext.
 * @returns {object} A detection object.
 */
function detectApi(context) {
  const query = queryFor(context);
  const routes = apiRoutes(query);
  const coverage = apiCoverage(query);
  const unresolved = apiUnresolved(query);

  const findings = [];
  for (const route of routes) {
    if (findings.length >= MAX_API_FINDINGS) break;
    findings.push({
      confidence: API_CONFIDENCE.OBSERVED_ENDPOINT,
      description: describe(route),
      evidence: [...route.evidenceIds],
      metadata: {
        route: route.id,
        method: route.method,
        path: route.path,
        frameworks: [...route.frameworks],
        receivers: [...route.receivers],
        receiverKinds: [...route.receiverKinds],
        sourcePaths: [...route.sourcePaths],
        handlerCount: route.handlerNames.length,
        middlewareCount: route.middlewareNames.length,
        fingerprintKey: route.fingerprintKey,
        basis: API_BASIS,
      },
    });
  }

  const metadata = {
    basis: API_BASIS,
    state: coverage.state,
    established: coverage.established === true,
    routes: coverage.routes,
    edges: coverage.edges,
    sources: coverage.sources,
    declaringModules: coverage.declaringModules,
    handlerEdges: coverage.handlerEdges,
    middlewareEdges: coverage.middlewareEdges,
    handlerModules: coverage.handlerModules,
    reported: findings.length,
    capped: findings.length < routes.length,
    unresolved: unresolvedSummary(unresolved),
    unestablishedSources: (coverage.unestablishedSources ?? []).length,
    uninterpretedSources: coverage.uninterpretedSources ?? 0,
    uninterpretedExtensions: [...(coverage.uninterpretedExtensions ?? [])],
  };

  if (findings.length > 0) {
    return { findings, evidence: [], metadata };
  }

  const absence = apiAbsence(query);
  if (!absence.established) {
    return {
      ...createRuleDetection({
        findings: [],
        coverage: APPLICABILITY_COVERAGE.UNKNOWN,
        reason: `no HTTP route was observed, but ${absence.reason}`,
      }),
      metadata,
    };
  }

  return { findings, evidence: [], metadata };
}

export const apiRules = Object.freeze([
  createRule({
    id: API_RULE_IDS.GRAPH_INVENTORY,
    version: API_RULE_VERSION,
    category: API_CATEGORY,
    title: "HTTP endpoint declared by the repository",
    description:
      "A supported JavaScript or TypeScript source declares an HTTP route on a framework registrar the module itself establishes: an Express or Fastify receiver bound to a framework factory, with a plain string-literal path. The finding names the method, path, framework, declaring file, the resolved handler and middleware symbols and the observation behind it. It is an inventory statement: no authentication, versioning, REST-quality, missing-middleware, runtime-reachability or execution-order claim is made, and an occurrence whose receiver is not a framework registrar is reported as metadata rather than as a finding.",
    severity: "info",
    applicability: {},
    detect: (context) => detectApi(context),
    remediation: {},
    metadata: {
      basis: API_BASIS,
      tags: ["api", "routes", "inventory"],
      falsePositives: [
        "a route whose handler is a member access (`controller.list`) has no resolved handler, and the finding says so rather than guessing",
        "a manipulation of the path at runtime is never a route: only a literal `/`-prefixed path is recorded",
        "a route declared on a framework this build does not support (Koa, Hapi, NestJS, …) is an observation, not a finding",
      ],
    },
  }),
]);
