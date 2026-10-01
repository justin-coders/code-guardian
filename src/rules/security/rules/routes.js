/**
 * Code Guardian — Route Exposure & Authorization Rules (official roadmap Phase 10)
 *
 * The pack's two rules about **declared addresses**, and the first rules it ships that
 * consume the API graph and the middleware & authorization graph rather than the file
 * inventory. They exist because the roadmap's Phase 10 rule families include
 * authorization configuration and debug endpoints, and because those two questions have
 * structural answers in this architecture that a string search would get wrong.
 *
 * ### Only the facts, and both halves of each fact
 *
 * The model collects facts; a rule makes the judgment (roadmap §30). So neither rule
 * decides anything about a handler's behaviour. What they read is:
 *
 *   - the **route declaration** — the API graph's route node, whose path, method,
 *     frameworks and declaring modules the repository states, cited through the evidence
 *     id of each declaring module's route scan;
 *   - the **registration record** — the middleware graph's per-route view, which states
 *     the route's structural protection (`protected` / `unresolved` / `none-observed` /
 *     `unknown`) and the middleware ids established for it, and the middleware node's
 *     `classification`, which the graph derived from the middleware's *name*.
 *
 * A finding cites both halves. "No middleware reaches this route" is not this pack's
 * inference: it is the middleware graph's `none-observed` state, which the graph only
 * reaches when the declaring file's registrations were established and not truncated, and
 * the observation cited beside it is that file's own middleware-source record.
 *
 * ### What a name can and cannot decide
 *
 * Both rules match a **path vocabulary** — whole words inside a path segment — and that is
 * the weakest evidence in the pack, so both say so: the confidence is
 * `NAME_DERIVED` (0.5), not the 0.9 an observed artifact earns, and neither rule's wording
 * claims the endpoint returns anything, is reachable, or is misconfigured. A path that
 * names `/admin/users` is a fact about the address a repository chose; that it is
 * *privileged* is the reader's judgment, which the finding supplies as the vocabulary it
 * matched rather than as a verdict.
 *
 * The authorization rule is the one exception in strength: once the address is privileged,
 * whether authorization reaches it is decided by the middleware graph and not by a name, so
 * its *finding* rests on a structural fact even though its *trigger* is a name.
 *
 * ### Abstention, not a pass
 *
 * A route whose middleware could not be established (`unresolved`), whose declaring file
 * has no registration record (`unknown`), whose chain was truncated, or that is reached by
 * a middleware the graph classified `unknown` is **never** reported as unprotected. The
 * rule records the reason and the evaluation becomes `unknown`, because "this middleware is
 * not known to authorize" states something else than "this route is unguarded" — and the
 * second is the one that would be a security conclusion drawn from missing information.
 * Likewise an unestablished API graph, an unresolved route-shaped occurrence or a truncated
 * graph make the *absence* of a privileged or diagnostic route unproven.
 *
 * Nothing here reads a file, a process, a clock, the environment or the network, and no
 * route is ever requested: the rules read the frozen model through the Phase 11 query API.
 */

import { createRule } from "../../../core/index.js";

import {
  MIDDLEWARE_CLASSIFICATIONS,
  MIDDLEWARE_PROTECTION_STATES,
  stabilityHash,
} from "../../../repository/model/index.js";

import { APPLICABILITY_COVERAGE } from "../../contracts.js";
import { createRuleDetection } from "../../evaluation.js";

import {
  AUTHORIZING_CLASSIFICATIONS,
  DIAGNOSTIC_ROUTE_SEGMENTS,
  FINDING_BASES,
  PRIVILEGED_ROUTE_SEGMENTS,
  SECURITY_CATEGORY,
  SECURITY_CONFIDENCE,
  SECURITY_RULE_IDS,
  SECURITY_RULE_VERSION,
} from "../contracts.js";
import { matchesRoutePath } from "../matching.js";
import {
  middlewareSourceEvidenceId,
  queryFor,
  routeInventory,
  routeProtections,
} from "../signals.js";

// The protection states and the classification vocabulary are the middleware graph's own, so
// they are read from it rather than re-declared: the rules layer may consume the model, and a
// second copy of a vocabulary it owns is exactly the architectural duplication this phase is
// meant to avoid.
const PROTECTION = MIDDLEWARE_PROTECTION_STATES;
const UNKNOWN_CLASSIFICATION = MIDDLEWARE_CLASSIFICATIONS.UNKNOWN;

/**
 * Why the repository's route set cannot be read as complete, or `null` when it can.
 *
 * A rule about to conclude "no privileged route exists" has to know that a route-shaped
 * occurrence was left unread, and this is the one place that reads the graph's coverage: an
 * unestablished graph, a truncated graph, or any unresolved route-shaped occurrence leaves
 * the answer unknown.
 */
function routeCoverageGap(inventory) {
  if (!inventory.established) {
    return `the API graph is ${inventory.state}, so the repository's routes are not established`;
  }
  if (inventory.truncated) {
    return "the API graph stopped at a limit before every route was established";
  }
  if (inventory.unresolvedRoutes.length > 0) {
    return `${inventory.unresolvedRoutes.length} route-shaped occurrence(s) were not established as routes`;
  }
  if (inventory.unresolvedLimited) {
    return "more route-shaped occurrences were left unresolved than the graph reports";
  }
  // The graph states its own completeness from the scan and its sources; a path that could
  // not be read is a module source it never saw, so the route set is only closed over if the
  // inventory it was read from is.
  if (!inventory.inventory.established) {
    return `the routes were read from an inventory that is not complete, because ${inventory.inventory.reason}`;
  }
  return null;
}

/** Why no route's registrations can be read as complete, or `null` when they can. */
function middlewareCoverageGap(protections) {
  if (!protections.established) {
    return `the middleware graph is ${protections.state}, so no route's registrations are established`;
  }
  if (protections.truncated) {
    return "the middleware graph stopped at a limit before every registration was established";
  }
  return null;
}

/** The audit basis recorded on a clean outcome. */
function cleanMetadata(extra) {
  return { basis: FINDING_BASES.ROUTE, ...extra };
}

/**
 * The analyzer-supplied fingerprint disambiguator for one route.
 *
 * A route's evidence is its declaring file's scan record, so two routes in the same file
 * would otherwise share a fingerprint and the analysis engine would refuse the result as a
 * duplicate. The key is the route's own graph identity, hashed through the model's own
 * `stabilityHash` so it is bounded, deterministic and never derived from a clock or a random
 * source.
 */
function routeFingerprintKey(routeId) {
  return `security:route:${stabilityHash(String(routeId))}`;
}

export const routeRules = Object.freeze([
  createRule({
    id: SECURITY_RULE_IDS.UNPROTECTED_PRIVILEGED_ROUTE,
    version: SECURITY_RULE_VERSION,
    category: SECURITY_CATEGORY,
    title: "A privileged route is reachable with no authorization middleware established",
    description:
      "A route whose declared path names a privileged surface — `admin`, `internal`, `manage`, `console`, `superuser` and the like — was observed, and the middleware the repository registers reaches it with no `authentication` or `authorization` middleware among them: either no middleware at all was established for it, or the only middleware that reaches it is classified as something else (logging, parsing, validation, rate limiting, CORS). The route declaration and the registration record for the file that declares it are both cited, so the claim is that the repository's own registrations do not reach this address with an authorization-shaped middleware — not that no authorization runs, and not that the handler is unsafe. Confirming it means adding the authentication or authorization middleware to the receiver the route is declared on, or moving the route behind one. Every case where a middleware could not be established, was classified `unknown`, or truncated the chain is abstained rather than reported.",
    severity: "high",
    // Universally applicable: a repository that declares no route at all is a meaningful
    // clean result. A selector here would skip the rule on exactly the repositories whose
    // frameworks look unusual, which is where a missed route hurts most.
    applicability: {},
    remediation: {},
    metadata: { basis: FINDING_BASES.ROUTE, tags: ["authorization", "route", "middleware"] },
    detect(context) {
      const query = queryFor(context);
      const inventory = routeInventory(query);

      const routeGap = routeCoverageGap(inventory);
      if (routeGap !== null) {
        return createRuleDetection({
          findings: [],
          coverage: APPLICABILITY_COVERAGE.UNKNOWN,
          reason: routeGap,
        });
      }

      const protections = routeProtections(query);
      const middlewareGap = middlewareCoverageGap(protections);
      if (middlewareGap !== null) {
        return createRuleDetection({
          findings: [],
          coverage: APPLICABILITY_COVERAGE.UNKNOWN,
          reason: middlewareGap,
        });
      }

      const privileged = inventory.routes.filter((route) =>
        matchesRoutePath(route.path, PRIVILEGED_ROUTE_SEGMENTS),
      );

      const viewByRouteId = new Map(protections.routes.map((view) => [view.route, view]));
      const middlewareById = new Map(protections.middleware.map((node) => [node.id, node]));

      const findings = [];
      const unresolved = [];

      for (const route of privileged) {
        const address = `${route.method} ${route.path}`;
        const view = viewByRouteId.get(route.id);

        if (view === undefined) {
          unresolved.push(`no registration record was established for ${address}`);
          continue;
        }
        if (view.chainTruncated === true) {
          unresolved.push(`the middleware chain established for ${address} was truncated`);
          continue;
        }
        if (view.protection === PROTECTION.UNRESOLVED || view.unresolvedCount > 0) {
          unresolved.push(
            `${view.unresolvedCount} middleware-shaped occurrence(s) on ${address} were not established as middleware`,
          );
          continue;
        }
        if (view.protection === PROTECTION.UNKNOWN) {
          unresolved.push(
            `the registrations of the file declaring ${address} are not established`,
          );
          continue;
        }

        const reaching = view.middleware
          .map((id) => middlewareById.get(id))
          .filter((node) => node !== undefined);

        // A middleware the graph names but this projection does not carry (a truncated node
        // list) is information the rule does not have, not an empty chain.
        if (reaching.length !== view.middleware.length) {
          unresolved.push(`not every middleware established for ${address} is described`);
          continue;
        }

        const classifications = reaching.map((node) => node.classification);

        if (classifications.some((value) => AUTHORIZING_CLASSIFICATIONS.includes(value))) {
          continue;
        }
        if (classifications.includes(UNKNOWN_CLASSIFICATION)) {
          unresolved.push(
            `a middleware reaching ${address} is classified unknown, so whether it authorizes is not established`,
          );
          continue;
        }
        if (
          view.protection !== PROTECTION.PROTECTED &&
          view.protection !== PROTECTION.NONE_OBSERVED
        ) {
          unresolved.push(`the protection of ${address} is ${view.protection}`);
          continue;
        }

        const sourceEvidence = route.sourcePaths
          .map((path) => middlewareSourceEvidenceId(query, path))
          .filter((id) => id !== null);

        findings.push({
          confidence: SECURITY_CONFIDENCE.NAME_DERIVED,
          // Both halves: the route's own declaration, and the registration record of the
          // file that declares it.
          evidence: [...new Set([...route.evidenceIds, ...sourceEvidence])].sort(),
          metadata: {
            fingerprintKey: routeFingerprintKey(route.id),
            path: route.path,
            method: route.method,
            sourcePaths: [...route.sourcePaths],
            frameworks: [...route.frameworks],
            protection: view.protection,
            protectionBasis: view.protectionBasis,
            matchedSegments: PRIVILEGED_ROUTE_SEGMENTS.filter((word) =>
              matchesRoutePath(route.path, [word]),
            ),
            middleware: reaching.map((node) => ({
              name: node.name,
              classification: node.classification,
            })),
            basis: FINDING_BASES.ROUTE,
          },
        });
      }

      if (findings.length > 0) {
        return {
          findings,
          evidence: [],
          metadata: cleanMetadata({
            privilegedRoutes: privileged.length,
            reported: findings.length,
            unresolved: unresolved.length,
          }),
        };
      }

      if (unresolved.length > 0) {
        return createRuleDetection({
          findings: [],
          coverage: APPLICABILITY_COVERAGE.UNKNOWN,
          reason: unresolved.join("; "),
        });
      }

      return {
        findings: [],
        evidence: [],
        metadata: cleanMetadata({ privilegedRoutes: privileged.length, unresolved: 0 }),
      };
    },
  }),

  createRule({
    id: SECURITY_RULE_IDS.DIAGNOSTIC_ENDPOINT,
    version: SECURITY_RULE_VERSION,
    category: SECURITY_CATEGORY,
    title: "A route whose path names a diagnostic surface was observed",
    description:
      "A route was observed whose declared path names a diagnostic surface — `debug`, `actuator`, `metrics`, `trace`, `heapdump`, `profiler`, `server-status` and the like. The finding is informational about a repository fact, not a verdict: it states that the address exists, cites the declaration that states it, and records the structural protection the middleware graph established beside it, so a reader can tell an endpoint no middleware reaches from one behind authentication. Diagnostic surfaces commonly expose process state, configuration or dependency versions, so a repository may want them removed from a production surface or placed behind authorization — but whether this one does any of that is not established by a path, which is why the confidence is `NAME_DERIVED`. The route set must be fully established for the opposite conclusion: an unread route-shaped occurrence, a truncated graph or an unestablished one abstains instead of passing.",
    severity: "medium",
    applicability: {},
    remediation: {},
    metadata: { basis: FINDING_BASES.ROUTE, tags: ["exposure", "route", "debug"] },
    detect(context) {
      const query = queryFor(context);
      const inventory = routeInventory(query);

      const gap = routeCoverageGap(inventory);
      if (gap !== null) {
        return createRuleDetection({
          findings: [],
          coverage: APPLICABILITY_COVERAGE.UNKNOWN,
          reason: gap,
        });
      }

      const diagnostic = inventory.routes.filter((route) =>
        matchesRoutePath(route.path, DIAGNOSTIC_ROUTE_SEGMENTS),
      );

      if (diagnostic.length === 0) {
        return {
          findings: [],
          evidence: [],
          metadata: cleanMetadata({ diagnosticRoutes: 0, routes: inventory.routes.length }),
        };
      }

      // Protection is recorded per finding, so a finding never has to be re-read against a
      // second query to know whether the endpoint is guarded. Read only when there is
      // something to say, and never allowed to turn a finding into an abstention.
      const protections = middlewareGraphViews(query);

      return {
        findings: diagnostic.map((route) => {
          const view = protections.get(route.id) ?? null;
          return {
            confidence: SECURITY_CONFIDENCE.NAME_DERIVED,
            evidence: [...route.evidenceIds],
            metadata: {
              fingerprintKey: routeFingerprintKey(route.id),
              path: route.path,
              method: route.method,
              sourcePaths: [...route.sourcePaths],
              frameworks: [...route.frameworks],
              matchedSegments: DIAGNOSTIC_ROUTE_SEGMENTS.filter((word) =>
                matchesRoutePath(route.path, [word]),
              ),
              protection: view === null ? null : view.protection,
              protectionBasis: view === null ? null : view.protectionBasis,
              basis: FINDING_BASES.ROUTE,
            },
          };
        }),
        evidence: [],
        metadata: cleanMetadata({
          diagnosticRoutes: diagnostic.length,
          routes: inventory.routes.length,
        }),
      };
    },
  }),
]);

/** The middleware graph's per-route views, keyed by route id, or an empty map. */
function middlewareGraphViews(query) {
  const protections = routeProtections(query);
  if (!protections.established) return new Map();
  return new Map(protections.routes.map((view) => [view.route, view]));
}
