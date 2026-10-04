/**
 * Code Guardian — API Authorization Rule (Official Roadmap Phase 16)
 *
 * The "authorization" domain, kept distinct from authentication. It reports a route that
 * establishes an `authentication`-classified middleware but no `authorization`-classified
 * middleware: the route proves *who* the caller is, not *what* they may do. That is a measured
 * relationship between two structural facts, but both facts are name-derived, so the finding
 * says so and never claims the endpoint is unprotected, that a role check is missing, or that
 * the handler does not enforce a policy itself.
 *
 * It is not the Security Analyzer's rule: this contract is about the API-level engineering gap
 * between "authenticated" and "authorized", over every route, and is not a security verdict.
 */

import { MIDDLEWARE_CLASSIFICATIONS } from "../../../repository/model/index.js";

import { API_ANALYSIS_CATEGORY, API_ANALYSIS_RULE_IDS, API_ANALYSIS_RULE_VERSION } from "../contracts.js";

import { createStructuralRule } from "./structural.js";

const IDS = API_ANALYSIS_RULE_IDS;

export const authorizationRules = Object.freeze([
  createStructuralRule({
    id: IDS.AUTHORIZATION,
    version: API_ANALYSIS_RULE_VERSION,
    category: API_ANALYSIS_CATEGORY,
    domain: "authorization",
    classification: MIDDLEWARE_CLASSIFICATIONS.AUTHORIZATION,
    mode: "gap",
    severity: "low",
    ruleTitle: "A route establishes authentication but no authorization-shaped middleware",
    ruleDescription:
      "A route whose established middleware chain contains an `authentication`-classified middleware contains no `authorization`-classified middleware. The finding states the measured relationship between two name-derived classifications: the repository authenticates the caller for this route but registers no authorization-shaped middleware beside it. It does not claim the endpoint is unprotected, that a role or permission check is absent, or that the handler does not enforce a policy itself — a route may legitimately authorize inside its handler. Every route whose chain is unresolved, unknown or truncated is abstained rather than reported.",
    scope: (route) =>
      route.middleware.some((entry) => entry.classification === MIDDLEWARE_CLASSIFICATIONS.AUTHENTICATION),
    gapTitle: "A route establishes authentication but no authorization-shaped middleware",
    gapDescription: (route) =>
      `Route \`${route.method} ${route.path}\` is reached by an authentication-classified middleware but by no authorization-classified middleware. The established chain is [${route.middleware.map((entry) => `\`${entry.name}\` (\`${entry.classification}\`)`).join(", ")}]. Both classifications come from middleware names alone: this states that the repository registers no authorization-shaped middleware beside the authenticating one — it does not claim the endpoint is unprotected, that no policy is enforced in the handler, or that authorization is absent at runtime.`,
    falsePositives: [
      "a route that enforces authorization inside its handler",
      "an authorization middleware registered through a form the model could not establish",
      "a route that is intentionally readable by any authenticated caller",
    ],
    tags: ["api", "authorization", "middleware"],
  }),
]);
