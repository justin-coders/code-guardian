/**
 * Code Guardian — API Analysis Rule Pack Boundary (Official Roadmap Phase 16)
 *
 * The stable import surface for the api-analysis domain. Consumers import from here rather than
 * reaching into the individual rule modules.
 *
 * ### This pack is the official roadmap's Phase 16
 *
 * The official roadmap's Phase 16 is **"API Analyzer"**, and this pack plus `analyzer.js` is
 * that analyzer:
 *
 *   Repository → Scanner(facts) → RepositoryModel → APIAnalyzer → api-analysis rules
 *              → evidence → findings
 *
 * The existing `src/rules/api/` pack stays as the substrate (its `api.graph.inventory` rule
 * states facts) and `src/rules/middleware/` stays as the protection substrate. This pack adds
 * analysis over both and preserves the central distinction: what the repository establishes is
 * kept apart from what this build cannot know, which is reported `unknown` rather than clean.
 *
 * ### Dependency direction
 *
 *   core ← repository/model ← analysis ← rules ← rules/api-analysis
 *
 * The pack reads the frozen RepositoryModel through the query API and nothing else. It must never
 * import `node:fs`, `node:fs/promises`, `node:path`, `child_process`, `node:net`, `node:http`,
 * `node:https`, `node:dns`, `node:worker_threads`, `src/tools.js`, `tool-registry`, a transport
 * or an MCP/CLI module. It reads no source, starts no server, sends no request, resolves no
 * handler and consults no clock, random source or environment.
 *
 * ### The thirteen domains, and where each rests
 *
 *   structural (a middleware name classification the graph established)
 *     input validation · authentication · authorization · rate limiting · CORS · logging
 *   artifact (an observed file)
 *     OpenAPI
 *   unestablished (the model holds no fact; the rule abstains)
 *     schema validation · error handling · status codes · pagination · request limits ·
 *     correlation IDs
 *
 * ### Numbers, not judgments
 *
 * There is no API score, grade, readiness percentage or aggregate rating anywhere in the pack,
 * and no rule edits, reorders or fixes anything. Findings and measured facts are the whole
 * output.
 */

export {
  API_ANALYSIS_ANALYZER_ID,
  API_ANALYSIS_ANALYZER_NAME,
  API_ANALYSIS_ANALYZER_SCOPE,
  API_ANALYSIS_BASES,
  API_ANALYSIS_BODY_METHODS,
  API_ANALYSIS_CATEGORY,
  API_ANALYSIS_CONFIDENCE,
  API_ANALYSIS_DOMAIN_CLASSIFICATION,
  API_ANALYSIS_DOMAINS,
  API_ANALYSIS_LIMITS,
  API_ANALYSIS_OPENAPI_BASENAMES,
  API_ANALYSIS_RULE_ID_PREFIX,
  API_ANALYSIS_RULE_IDS,
  API_ANALYSIS_RULE_PACK_VERSION,
  API_ANALYSIS_RULE_VERSION,
  API_ANALYSIS_STATES,
  API_ANALYSIS_SUBJECTS,
} from "./contracts.js";

export {
  apiGraphCoverage,
  apiSubject,
  basenameOf,
  fileInventoryCoverage,
  middlewareCoverageGap,
  middlewareGraphCoverage,
  middlewareSourceEvidenceId,
  openapiArtifacts,
  queryFor,
  routeAbsenceReason,
  routeControls,
  routeCoverageGap,
} from "./signals.js";

export { summarizeApiAnalysis } from "./summary.js";

export {
  apiAnalysisRules,
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
} from "./rules/index.js";

export { apiAnalysisRuleSetIssues, createApiAnalysisRuleRegistry } from "./registry.js";

export { createApiAnalysisAnalyzer } from "./analyzer.js";
