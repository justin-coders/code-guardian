/**
 * Code Guardian — API Input Validation Rule (Official Roadmap Phase 16)
 *
 * The "input validation" domain. The model establishes no request-body fact and no validator
 * relationship, so the only defensible structural anchor is the middleware the repository
 * registers whose *name* the middleware graph classifies as `validation`. The rule asks that
 * bounded question about the routes where input validation is conventionally expected — the
 * methods that carry a request body — and abstains everywhere the chain is not established.
 *
 * It is deliberately a **gap** finding, not a verdict: a middleware named `validate` is
 * validation-shaped; whether it validates anything, and whether a route even reads a body, are
 * facts this build does not have. The wording says so, and the confidence is `NAME_DERIVED`.
 */

import { API_ANALYSIS_BODY_METHODS, API_ANALYSIS_CATEGORY, API_ANALYSIS_RULE_IDS, API_ANALYSIS_RULE_VERSION } from "../contracts.js";

import { createStructuralRule } from "./structural.js";

const IDS = API_ANALYSIS_RULE_IDS;

export const inputValidationRules = Object.freeze([
  createStructuralRule({
    id: IDS.INPUT_VALIDATION,
    version: API_ANALYSIS_RULE_VERSION,
    category: API_ANALYSIS_CATEGORY,
    domain: "input-validation",
    classification: "validation",
    mode: "gap",
    severity: "low",
    ruleTitle: "A body-carrying route establishes no validation-shaped middleware",
    ruleDescription:
      "A route whose method conventionally carries a request body (POST, PUT or PATCH) is reached by no middleware the middleware graph classifies as `validation`. The finding names the route, its established middleware chain and the observation behind both. The classification is derived from the middleware's name alone, so the finding states that the repository registers no validation-shaped middleware for the route — it does not claim the handler fails to validate, that the route reads a body, or that a name is not a different framework's validator. Every route whose chain is unresolved, unknown or truncated is abstained rather than reported.",
    scope: (route) => API_ANALYSIS_BODY_METHODS.includes(route.method),
    gapTitle: "A body-carrying route establishes no validation-shaped middleware",
    gapDescription: (route) =>
      `Route \`${route.method} ${route.path}\` uses a method that conventionally carries a request body, and the middleware the repository establishes for it contains no \`validation\`-classified middleware. The established chain is [${route.middleware.map((entry) => `\`${entry.name}\` (\`${entry.classification}\`)`).join(", ") || "empty"}]. The classification comes from the middleware's name alone: this states that the repository registers no validation-shaped middleware for the route, not that its handler fails to validate input, and not that the route in fact reads a body.`,
    falsePositives: [
      "a route that validates its body inside the handler rather than through middleware",
      "a route whose body validation is registered on a receiver that was not established (a member-expression call such as `app.use(validator())`)",
      "a mutating route that reads no body at all",
    ],
    tags: ["api", "input-validation", "middleware"],
  }),
]);
