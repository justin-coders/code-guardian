/**
 * Code Guardian — API CORS Rule (Official Roadmap Phase 16)
 *
 * The "CORS" domain. The roadmap and this phase's rules both insist that "CORS exists" is not
 * "CORS is correct", and this build cannot read a CORS middleware's options at all: a route
 * reached by a middleware the middleware graph classifies `cors` is a **usage** fact, and the
 * rule reports exactly that, as a presence rule. It makes no claim about origins, credentials,
 * wildcards or method allow-lists, because the model establishes none of them.
 *
 * `app.use(cors())` is a member call the model records as an unresolved registration rather
 * than a middleware, so the common form is deliberately *not* reported here; only a middleware
 * the graph actually established (a named binding) is.
 */

import { API_ANALYSIS_CATEGORY, API_ANALYSIS_RULE_IDS, API_ANALYSIS_RULE_VERSION } from "../contracts.js";

import { createStructuralRule } from "./structural.js";

const IDS = API_ANALYSIS_RULE_IDS;

export const corsRules = Object.freeze([
  createStructuralRule({
    id: IDS.CORS,
    version: API_ANALYSIS_RULE_VERSION,
    category: API_ANALYSIS_CATEGORY,
    domain: "cors",
    classification: "cors",
    mode: "positive",
    severity: "info",
    ruleTitle: "A route establishes CORS-shaped middleware",
    ruleDescription:
      "A route's established middleware chain contains a middleware the middleware graph classifies as `cors`, from the middleware's name alone (`cors`, `crossOrigin`, …). The finding is a usage statement: the repository registers a CORS-shaped middleware on this route. It says nothing about the configuration — origins, credentials, allowed methods or headers — which the model does not establish, and it deliberately does not treat `app.use(cors())` (a member call the graph records as an unresolved registration) as an established middleware.",
    presentTitle: "A route establishes CORS-shaped middleware",
    presentDescription: (route, entry) =>
      `Route \`${route.method} ${route.path}\` is reached by \`${entry.name}\`, which the middleware graph classifies as \`cors\` from its name alone. This states that the repository registers a CORS-shaped middleware for the route; it does not claim the CORS configuration is correct, restricted or safe, because the model establishes none of those options.`,
    falsePositives: [
      "a middleware whose name suggests CORS but which does something else",
      "`app.use(cors())` is not reported here: the model records the member call as an unresolved registration, not an established middleware",
    ],
    tags: ["api", "cors", "middleware"],
  }),
]);
