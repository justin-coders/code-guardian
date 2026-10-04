/**
 * Code Guardian — API Rate Limiting Rule (Official Roadmap Phase 16)
 *
 * The "rate limiting" domain. The middleware graph already classifies middleware whose names
 * indicate rate limiting (`rateLimit`, `throttle`, `slowdown`, `limiter`, …), and a route whose
 * established chain contains one of them is a real, structural fact about the repository. This
 * rule reports that fact and only that fact: it is deliberately a **presence** rule, not a
 * gap rule, because the repository establishes no baseline for how much rate limiting an API
 * ought to have and a name is not proof that enforcement works.
 *
 * The finding's wording is therefore an inventory statement: the repository registers a
 * rate-limit-shaped middleware on this route. It does not claim the limit is enforced, correct,
 * or sufficient.
 */

import { API_ANALYSIS_CATEGORY, API_ANALYSIS_RULE_IDS, API_ANALYSIS_RULE_VERSION } from "../contracts.js";

import { createStructuralRule } from "./structural.js";

const IDS = API_ANALYSIS_RULE_IDS;

export const rateLimitingRules = Object.freeze([
  createStructuralRule({
    id: IDS.RATE_LIMITING,
    version: API_ANALYSIS_RULE_VERSION,
    category: API_ANALYSIS_CATEGORY,
    domain: "rate-limiting",
    classification: "rate-limit",
    mode: "positive",
    severity: "info",
    ruleTitle: "A route establishes rate-limit-shaped middleware",
    ruleDescription:
      "A route's established middleware chain contains a middleware the middleware graph classifies as `rate-limit`, from the middleware's name alone (`rateLimit`, `throttle`, `slowdown`, `limiter`, …). The finding is an inventory statement about a structural fact: the repository registers a rate-limit-shaped middleware on this route. It does not claim the limit is enforced, that its configuration is correct, or that it is sufficient — a name is not proof that rate limiting works, and this build reads no middleware body and runs nothing.",
    presentTitle: "A route establishes rate-limit-shaped middleware",
    presentDescription: (route, entry) =>
      `Route \`${route.method} ${route.path}\` is reached by \`${entry.name}\`, which the middleware graph classifies as \`rate-limit\` from its name alone. The full established chain is [${route.middleware.map((value) => `\`${value.name}\` (\`${value.classification}\`)`).join(", ")}]. This states that the repository registers a rate-limit-shaped middleware for the route; it does not claim the limit is enforced, correctly configured, or sufficient.`,
    falsePositives: [
      "a middleware whose name suggests rate limiting but which performs something else",
      "a rate limiter registered through a form the model could not establish (so it is simply absent from the chain, never mis-reported)",
    ],
    tags: ["api", "rate-limiting", "middleware"],
  }),
]);
