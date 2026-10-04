/**
 * Code Guardian — API Request Logging Rule (Official Roadmap Phase 16)
 *
 * The "logging" domain, scoped to the request lifecycle. A repository that contains a
 * general-purpose logger has not established that API requests are logged, and this build
 * cannot read a `logger.info("…")` call at all. What it *can* establish is whether the API's
 * routes are reached by a **middleware** the middleware graph classifies as `logging` — a
 * registration on the request path, by definition lifecycle-related — so that is exactly the
 * finding's claim, and nothing more.
 *
 * A route whose chain is unresolved, unknown or truncated is abstained: an unread registration
 * is not evidence that no request logging happens.
 */

import { API_ANALYSIS_CATEGORY, API_ANALYSIS_RULE_IDS, API_ANALYSIS_RULE_VERSION } from "../contracts.js";

import { createStructuralRule } from "./structural.js";

const IDS = API_ANALYSIS_RULE_IDS;

export const loggingRules = Object.freeze([
  createStructuralRule({
    id: IDS.LOGGING,
    version: API_ANALYSIS_RULE_VERSION,
    category: API_ANALYSIS_CATEGORY,
    domain: "logging",
    classification: "logging",
    mode: "gap",
    severity: "low",
    ruleTitle: "A route establishes no logging-shaped middleware",
    ruleDescription:
      "An HTTP route is reached by middleware the middleware graph fully established, and none of it is classified `logging`. Because the evidence is a *middleware registration on the request path*, this is a statement about the request lifecycle — it is not a statement about general application logging, and a `logger.info(…)` call inside a handler is invisible to this rule and to this model. The classification is derived from a middleware's name alone, so the finding states that the repository registers no logging-shaped middleware for the route, not that its requests are unlogged: a framework access logger configured elsewhere, or logging inside the handler, would look identical. Every route whose chain is unresolved, unknown or truncated is abstained rather than reported.",
    gapTitle: "A route establishes no logging-shaped middleware",
    gapDescription: (route) =>
      `Route \`${route.method} ${route.path}\` is reached by middleware the repository fully established, and none of it is classified \`logging\`. The established chain is [${route.middleware.map((entry) => `\`${entry.name}\` (\`${entry.classification}\`)`).join(", ") || "empty"}]. The classification comes from a middleware's name alone, and only middleware registrations are read: this states that the repository registers no request-lifecycle logging-shaped middleware for the route — it does not claim the route's requests are unlogged, and generic application logging is not evidence either way.`,
    falsePositives: [
      "logging performed inside the handler rather than through middleware",
      "a framework access logger configured through a form the model could not establish",
    ],
    tags: ["api", "logging", "middleware"],
  }),
]);
