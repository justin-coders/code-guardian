/**
 * Code Guardian — API Request Limits Rule (Official Roadmap Phase 16)
 *
 * The "request limits" domain. Request limits are not "a server exists" and not "a body parser
 * exists": they are body-size, header, parameter, upload and timeout controls, and the model
 * establishes none of them — the options live inside a body-parser call the model records as an
 * unresolved registration (a member expression), or in server configuration it does not read.
 * So the honest answer is `unknown` over an API subject and `not_applicable` when there is none.
 */

import { API_ANALYSIS_CATEGORY, API_ANALYSIS_RULE_IDS, API_ANALYSIS_RULE_VERSION } from "../contracts.js";

import { createUnestablishedRule } from "./unestablished.js";

const IDS = API_ANALYSIS_RULE_IDS;

export const requestLimitsRules = Object.freeze([
  createUnestablishedRule({
    id: IDS.REQUEST_LIMITS,
    version: API_ANALYSIS_RULE_VERSION,
    category: API_ANALYSIS_CATEGORY,
    domain: "request-limits",
    severity: "low",
    ruleTitle: "Request limits are not established by this model",
    ruleDescription:
      "This build reads route declarations and middleware names, not body-parser options, server configuration or upload limits, so it cannot establish whether the API bounds request bodies, headers, parameters, uploads or timeouts. A body-parser registration is not a limit: the model records `express.json()` as an unresolved member-call registration and reads no options from it. The rule abstains (`unknown`) over an API subject and reports `not_applicable` only when no API subject exists.",
    reason:
      "the repository model establishes no request-limit fact: this build does not read body-parser options, server configuration or upload limits, and a body-parser registration is not itself a limit",
    falsePositives: [
      "a limit set in server configuration the model does not read",
      "a limit set through a reverse proxy or platform rather than in the repository",
    ],
    tags: ["api", "request-limits"],
  }),
]);
