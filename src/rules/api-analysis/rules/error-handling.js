/**
 * Code Guardian — API Error Handling Rule (Official Roadmap Phase 16)
 *
 * The "error handling" domain. A repository-wide `try`/`catch` is not API error handling, and
 * the model establishes none of the forms that would be: it does not read handler bodies, does
 * not recognise a framework error-middleware signature (Express' four-argument handler, Fastify's
 * `setErrorHandler`), and does not read structured error responses. So the honest answer is
 * `unknown` over an API subject and `not_applicable` when there is none.
 */

import { API_ANALYSIS_CATEGORY, API_ANALYSIS_RULE_IDS, API_ANALYSIS_RULE_VERSION } from "../contracts.js";

import { createUnestablishedRule } from "./unestablished.js";

const IDS = API_ANALYSIS_RULE_IDS;

export const errorHandlingRules = Object.freeze([
  createUnestablishedRule({
    id: IDS.ERROR_HANDLING,
    version: API_ANALYSIS_RULE_VERSION,
    category: API_ANALYSIS_CATEGORY,
    domain: "error-handling",
    severity: "low",
    ruleTitle: "API error handling is not established by this model",
    ruleDescription:
      "This build does not read handler bodies and does not recognise framework error-handling signatures (an Express four-argument middleware, Fastify's error handler, a structured error response), so it cannot establish whether the API handles errors. A `try`/`catch` visible anywhere in a file would not be evidence of route-level error handling, and this model does not even read one. The rule abstains (`unknown`) over an API subject and reports `not_applicable` only when no API subject exists.",
    reason:
      "the repository model establishes no error-handler fact: this build does not read handler bodies or recognise framework error-middleware signatures such as Express' four-argument handler or Fastify's error handler",
    falsePositives: [
      "an error handler registered through a form the model does not read",
      "errors handled inside a handler rather than through middleware",
    ],
    tags: ["api", "error-handling"],
  }),
]);
