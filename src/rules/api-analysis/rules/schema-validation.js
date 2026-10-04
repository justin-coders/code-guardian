/**
 * Code Guardian — API Schema Validation Rule (Official Roadmap Phase 16)
 *
 * The "schema validation" domain, kept distinct from input validation. A request schema is a
 * *runtime* contract: a framework route-schema option (`fastify.get(path, { schema }, handler)`),
 * a schema library binding (`zod`, `joi`, `celebrate`) or an OpenAPI parameter definition. The
 * model this build reads establishes none of those — it records a route's declaration and its
 * middleware's name, not the object literal a route passes as its second argument, and a
 * TypeScript type is not a runtime schema. So the honest answer is `unknown` whenever an API
 * subject exists, and `not_applicable` when none does.
 */

import { API_ANALYSIS_CATEGORY, API_ANALYSIS_RULE_IDS, API_ANALYSIS_RULE_VERSION } from "../contracts.js";

import { createUnestablishedRule } from "./unestablished.js";

const IDS = API_ANALYSIS_RULE_IDS;

export const schemaValidationRules = Object.freeze([
  createUnestablishedRule({
    id: IDS.SCHEMA_VALIDATION,
    version: API_ANALYSIS_RULE_VERSION,
    category: API_ANALYSIS_CATEGORY,
    domain: "schema-validation",
    severity: "low",
    ruleTitle: "Request/response schema validation is not established by this model",
    ruleDescription:
      "This build reads route declarations and middleware registrations, not framework route-schema options or schema-library bindings, so it cannot establish whether the API validates requests or responses against a schema. A TypeScript type is not a runtime schema and is not evidence here. The rule abstains (`unknown`) over an API subject and reports `not_applicable` only when no API subject exists, rather than inventing a schema gap.",
    reason:
      "the repository model establishes no request or response schema fact: this build reads route declarations and middleware names, not framework route-schema options or schema-library bindings, and a TypeScript type is not a runtime schema",
    falsePositives: [
      "a framework route-schema option the model does not read",
      "a schema library bound inside a handler or through an unestablished registration",
    ],
    tags: ["api", "schema-validation", "schema"],
  }),
]);
