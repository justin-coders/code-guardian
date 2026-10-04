/**
 * Code Guardian — API Analysis Rule Set (Official Roadmap Phase 16)
 *
 * The thirteen official-roadmap domain rules, frozen and sorted by id. Ordering is stated here
 * (and again by the registry) so no consumer can inherit an ordering from module-evaluation
 * order: two runs over the same model must evaluate, report and fingerprint in the same
 * sequence.
 *
 * Six of the rules read a structural middleware classification, one is an artifact rule and six
 * are unestablished-domain rules that abstain (`unknown`) rather than invent a conclusion. All
 * thirteen are addressed, which is what the roadmap asks; none of them claims more than the
 * model establishes.
 */

import { authenticationRules } from "./authentication.js";
import { authorizationRules } from "./authorization.js";
import { correlationIdsRules } from "./correlation-ids.js";
import { corsRules } from "./cors.js";
import { errorHandlingRules } from "./error-handling.js";
import { inputValidationRules } from "./input-validation.js";
import { loggingRules } from "./logging.js";
import { openapiRules } from "./openapi.js";
import { paginationRules } from "./pagination.js";
import { rateLimitingRules } from "./rate-limiting.js";
import { requestLimitsRules } from "./request-limits.js";
import { schemaValidationRules } from "./schema-validation.js";
import { statusCodesRules } from "./status-codes.js";

function byId(a, b) {
  if (a.id === b.id) return 0;
  return a.id < b.id ? -1 : 1;
}

/** Every rule this pack ships, sorted by rule id. */
export const apiAnalysisRules = Object.freeze(
  [
    ...inputValidationRules,
    ...schemaValidationRules,
    ...authenticationRules,
    ...authorizationRules,
    ...errorHandlingRules,
    ...statusCodesRules,
    ...paginationRules,
    ...rateLimitingRules,
    ...corsRules,
    ...openapiRules,
    ...requestLimitsRules,
    ...loggingRules,
    ...correlationIdsRules,
  ].sort(byId),
);

export {
  authenticationRules,
  authorizationRules,
  correlationIdsRules,
  corsRules,
  errorHandlingRules,
  inputValidationRules,
  loggingRules,
  openapiRules,
  paginationRules,
  rateLimitingRules,
  requestLimitsRules,
  schemaValidationRules,
  statusCodesRules,
};
