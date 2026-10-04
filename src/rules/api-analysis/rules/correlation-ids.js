/**
 * Code Guardian — API Correlation IDs Rule (Official Roadmap Phase 16)
 *
 * The "correlation IDs" domain. A correlation ID is a semantic property — an incoming request
 * identifier propagated through logging context and a response header — not the existence of a
 * `request.id` field. The model establishes no request-context propagation and no
 * correlation-ID semantics, and this build must not guess one from a name. So the honest answer
 * is `unknown` over an API subject and `not_applicable` when there is none.
 */

import { API_ANALYSIS_CATEGORY, API_ANALYSIS_RULE_IDS, API_ANALYSIS_RULE_VERSION } from "../contracts.js";

import { createUnestablishedRule } from "./unestablished.js";

const IDS = API_ANALYSIS_RULE_IDS;

export const correlationIdsRules = Object.freeze([
  createUnestablishedRule({
    id: IDS.CORRELATION_IDS,
    version: API_ANALYSIS_RULE_VERSION,
    category: API_ANALYSIS_CATEGORY,
    domain: "correlation-ids",
    severity: "low",
    ruleTitle: "Correlation-ID propagation is not established by this model",
    ruleDescription:
      "This build reads route declarations and middleware names, not request-context propagation or response-header semantics, so it cannot establish whether the API correlates requests. A random `request.id`, or a middleware whose name mentions tracing, is not correlation-ID infrastructure: the model records no propagation and no header relationship. The rule abstains (`unknown`) over an API subject and reports `not_applicable` only when no API subject exists.",
    reason:
      "the repository model establishes no correlation-ID fact: this build reads middleware registrations, not request-context propagation or response-header semantics, and a request identifier is not correlation-ID infrastructure",
    falsePositives: [
      "correlation handled by a framework plugin or platform layer the model does not read",
      "a middleware whose name mentions tracing but whose propagation is not established",
    ],
    tags: ["api", "correlation-ids"],
  }),
]);
