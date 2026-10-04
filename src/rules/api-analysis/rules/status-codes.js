/**
 * Code Guardian — API Status Codes Rule (Official Roadmap Phase 16)
 *
 * The "status codes" domain. A route existing is not a status code, and a method is not a
 * status: the model establishes neither `res.status(...)`, `res.sendStatus(...)`,
 * `reply.code(...)` nor any framework reply configuration, because it does not read handler
 * bodies. So the honest answer is `unknown` over an API subject and `not_applicable` when there
 * is none — never the assumption of `200`.
 */

import { API_ANALYSIS_CATEGORY, API_ANALYSIS_RULE_IDS, API_ANALYSIS_RULE_VERSION } from "../contracts.js";

import { createUnestablishedRule } from "./unestablished.js";

const IDS = API_ANALYSIS_RULE_IDS;

export const statusCodesRules = Object.freeze([
  createUnestablishedRule({
    id: IDS.STATUS_CODES,
    version: API_ANALYSIS_RULE_VERSION,
    category: API_ANALYSIS_CATEGORY,
    domain: "status-codes",
    severity: "low",
    ruleTitle: "Response status behaviour is not established by this model",
    ruleDescription:
      "This build does not read handler bodies or framework reply configuration, so it cannot establish which status codes a route returns. A route's existence is not a `200`, and its method does not imply one. The rule abstains (`unknown`) over an API subject and reports `not_applicable` only when no API subject exists, rather than inferring a status from a route declaration.",
    reason:
      "the repository model establishes no response-status fact: this build does not read handler bodies or framework reply configuration (`res.status`, `res.sendStatus`, `reply.code`), and a route's method does not imply a status",
    falsePositives: [
      "a status set through a helper or wrapper the model does not read",
      "a status returned dynamically by a framework the model does not interpret",
    ],
    tags: ["api", "status-codes"],
  }),
]);
