/**
 * Code Guardian — Reliability Analysis Rule Pack Boundary (Official Roadmap Phase 17)
 *
 * The stable import surface for the reliability-analysis domain. Consumers import from here rather
 * than reaching into the individual rule modules.
 *
 * ### This pack is the official roadmap's Phase 17
 *
 * The official roadmap's Phase 17 is **"Reliability Analyzer"**, and this pack plus `analyzer.js`
 * is that analyzer:
 *
 *   Repository → Scanner(facts) → RepositoryModel → ReliabilityAnalyzer → reliability-analysis rules
 *              → evidence → findings
 *
 * ### Dependency direction
 *
 *   core ← repository/model ← analysis ← rules ← rules/reliability-analysis
 *
 * The pack reads the frozen RepositoryModel through the query API and nothing else. It must never
 * import `node:fs`, `node:fs/promises`, `node:path`, `child_process`, `node:net`, `node:http`,
 * `node:https`, `node:dns`, `node:worker_threads`, `src/tools.js`, `tool-registry`, a transport or
 * an MCP/CLI module. It reads no source, starts no server, sends no request, connects to no
 * database or queue, and consults no clock, random source or environment.
 *
 * ### The ten domains, and where each rests
 *
 *   usage        timeouts · retry behavior · circuit breaking · graceful shutdown · failure
 *                handling · resource cleanup · transaction handling · queue behavior
 *   structural   health checks (a route, a container healthcheck, a health package)
 *   dimensional  observability (logging · metrics · tracing · error reporting)
 *
 * ### Numbers, not judgments
 *
 * There is no reliability score, resilience percentage, uptime prediction, grade or aggregate
 * rating anywhere in the pack, and no rule edits, reorders or fixes anything.
 */

export {
  RELIABILITY_ANALYSIS_ANALYZER_ID,
  RELIABILITY_ANALYSIS_ANALYZER_NAME,
  RELIABILITY_ANALYSIS_ANALYZER_SCOPE,
  RELIABILITY_ANALYSIS_BASES,
  RELIABILITY_ANALYSIS_CATEGORY,
  RELIABILITY_ANALYSIS_CONFIDENCE,
  RELIABILITY_ANALYSIS_DOMAINS,
  RELIABILITY_ANALYSIS_LIMITS,
  RELIABILITY_ANALYSIS_RULE_ID_PREFIX,
  RELIABILITY_ANALYSIS_RULE_IDS,
  RELIABILITY_ANALYSIS_RULE_PACK_VERSION,
  RELIABILITY_ANALYSIS_RULE_VERSION,
  RELIABILITY_ANALYSIS_STATES,
  RELIABILITY_ANALYSIS_SUBJECTS,
  RELIABILITY_CONTAINER_SECTION,
  RELIABILITY_HEALTH_PATH_SEGMENTS,
  RELIABILITY_LOCAL_VOCABULARY,
  RELIABILITY_OBSERVABILITY_DIMENSIONS,
  RELIABILITY_PACKAGE_VOCABULARY,
  RELIABILITY_SERVICE_RUNTIME_PACKAGES,
} from "./contracts.js";

export {
  apiGraphCoverage,
  containerCoverageGap,
  containerDefinitions,
  containerFacts,
  containerHealthchecks,
  containerSection,
  hasLoggingMiddleware,
  healthRoutes,
  isHealthShapedPath,
  observabilityDimensions,
  queryFor,
  reliabilityRoutes,
  reliabilitySubject,
  routeCoverageGap,
  routeMiddleware,
  runtimeUsages,
  symbolCoverageGap,
  symbolGraphCoverage,
  symbolSourceEvidenceId,
  testFilePaths,
  usagesForDomain,
} from "./signals.js";

export { summarizeReliabilityAnalysis } from "./summary.js";

export {
  circuitBreakingRules,
  failureHandlingRules,
  gracefulShutdownRules,
  healthChecksRules,
  observabilityRules,
  queueBehaviorRules,
  reliabilityAnalysisRules,
  resourceCleanupRules,
  retryBehaviorRules,
  timeoutsRules,
  transactionHandlingRules,
} from "./rules/index.js";

export { createReliabilityAnalysisRuleRegistry, reliabilityAnalysisRuleSetIssues } from "./registry.js";

export { createReliabilityAnalysisAnalyzer } from "./analyzer.js";
