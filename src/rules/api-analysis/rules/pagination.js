/**
 * Code Guardian — API Pagination Rule (Official Roadmap Phase 16)
 *
 * The "pagination" domain, and the most inference-sensitive one. A collection endpoint does not
 * prove pagination exists, the literal word `page` proves nothing, and the model establishes
 * no query-parameter declaration, cursor/offset schema, framework pagination helper or OpenAPI
 * parameter. So the honest answer is `unknown` over an API subject and `not_applicable` when
 * there is none — this build does not pretend to score pagination, which the roadmap itself
 * flags as the domain most likely to be genuinely unknowable.
 */

import { API_ANALYSIS_CATEGORY, API_ANALYSIS_RULE_IDS, API_ANALYSIS_RULE_VERSION } from "../contracts.js";

import { createUnestablishedRule } from "./unestablished.js";

const IDS = API_ANALYSIS_RULE_IDS;

export const paginationRules = Object.freeze([
  createUnestablishedRule({
    id: IDS.PAGINATION,
    version: API_ANALYSIS_RULE_VERSION,
    category: API_ANALYSIS_CATEGORY,
    domain: "pagination",
    severity: "low",
    ruleTitle: "Pagination is not established by this model",
    ruleDescription:
      "This build reads route declarations and middleware names, not query parameters, cursor/offset schemas, pagination helpers or OpenAPI pagination parameters, so it cannot establish whether any route paginates. A collection route does not prove pagination, and the literal word `page` proves nothing; conversely, a route that paginates through a mechanism this build does not read would look identical to one that does not. The rule abstains (`unknown`) over an API subject and reports `not_applicable` only when no API subject exists.",
    reason:
      "the repository model establishes no pagination fact: this build reads route declarations and middleware names, not query-parameter declarations, cursor/offset schemas, framework pagination helpers or OpenAPI pagination parameters",
    falsePositives: [
      "pagination implemented through a mechanism the model does not read (a query parser, a repository helper, a cursor middleware)",
      "a route that returns a bounded collection without parameters",
    ],
    tags: ["api", "pagination"],
  }),
]);
