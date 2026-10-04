/**
 * Code Guardian — API Authentication Rule (Official Roadmap Phase 16)
 *
 * The "authentication" domain. It reports an API route whose established middleware chain
 * contains no middleware the middleware graph classifies as `authentication`. This is the
 * broader, all-route, name-derived API-engineering contract — every route, not only a
 * privileged one — and it is deliberately different from the Security Analyzer's
 * `security.authorization.unprotected-privileged-route`, which owns the privileged-path,
 * authorization-shaped security conclusion. This rule makes no security claim.
 *
 * A route whose chain is unresolved, unknown or truncated is never reported as unauthenticated:
 * the middleware graph's own abstention is carried into the rule's outcome, so missing
 * information is never read as absence of authentication.
 */

import { API_ANALYSIS_CATEGORY, API_ANALYSIS_RULE_IDS, API_ANALYSIS_RULE_VERSION } from "../contracts.js";

import { createStructuralRule } from "./structural.js";

const IDS = API_ANALYSIS_RULE_IDS;

export const authenticationRules = Object.freeze([
  createStructuralRule({
    id: IDS.AUTHENTICATION,
    version: API_ANALYSIS_RULE_VERSION,
    category: API_ANALYSIS_CATEGORY,
    domain: "authentication",
    classification: "authentication",
    mode: "gap",
    severity: "low",
    ruleTitle: "A route establishes no authentication-shaped middleware",
    ruleDescription:
      "An HTTP route is reached by middleware the middleware graph fully established, and none of it is classified `authentication`. The finding cites the route declaration and the registration record of the file that declares it, so the claim is exactly that the repository's own registrations reach this address without an authentication-shaped middleware. The classification is derived from a middleware's name alone, so the finding does not claim the route is reachable without authentication, that no authentication runs elsewhere in the stack, or that the endpoint should require it — a public endpoint is a legitimate reason for this condition. Every route whose chain is unresolved, unknown, truncated or classified `unknown` is abstained rather than reported.",
    gapTitle: "A route establishes no authentication-shaped middleware",
    gapDescription: (route) =>
      `Route \`${route.method} ${route.path}\` is reached by middleware the repository fully established, and none of it is classified \`authentication\`. The established chain is [${route.middleware.map((entry) => `\`${entry.name}\` (\`${entry.classification}\`)`).join(", ") || "empty"}]. The classification comes from a middleware's name alone: this states that the repository's registrations reach the route with no authentication-shaped middleware — it does not claim the route is unauthenticated at runtime, that the endpoint should require authentication, or that authentication is not enforced elsewhere.`,
    falsePositives: [
      "an intentionally public endpoint (health, status, documentation)",
      "authentication performed inside the handler rather than through middleware",
      "an authentication middleware registered through a form the model could not establish",
    ],
    tags: ["api", "authentication", "middleware"],
  }),
]);
