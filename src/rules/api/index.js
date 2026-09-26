/**
 * Code Guardian — API Rule Pack Boundary (Phase 18)
 *
 * The stable import surface for the API domain. Consumers — an MCP tool, the CLI, a CI
 * job, a future aggregate analyzer — should import from here rather than reaching into the
 * individual rule modules.
 *
 * Phase 18 adds one informational rule (`api.graph.inventory`) that inventories the HTTP
 * endpoints the repository declares and the handler and middleware symbols they connect
 * to. It consumes the Phase 18 API graph through the same query API, resolves nothing
 * itself, starts no server and makes no judgment about authentication, versioning,
 * REST quality, missing middleware or API health.
 *
 * Dependency direction, unchanged from Phase 10 and enforced by an architectural test in
 * `tests/api-graph.test.js`:
 *
 *   core ← repository/model (8D … 18) ← analysis (9) ← rules (10) ← rules/api (18)
 *
 * The pack reads the frozen RepositoryModel through the Phase 11 query API and nothing
 * else. It must never import `node:fs`, `node:path`, `child_process`, `node:net`,
 * `node:http`, `node:https`, `node:dns`, `node:worker_threads`, the Phase 8A filesystem
 * boundary, the Phase 8B execution boundary, `src/tools.js`, `tool-registry`, a transport,
 * an MCP/CLI module, or the scanner/acquisition layer that produced the route records. It
 * reads no source file, starts no server, sends no request, resolves no handler, runs no
 * process, contacts no network, and consults no clock, random source or environment: API
 * findings in this phase are deterministic, evidence-first, and scoped to what the
 * repository model can prove.
 */

export {
  API_ANALYZER_ID,
  API_ANALYZER_NAME,
  API_ANALYZER_SCOPE,
  API_BASIS,
  API_CATEGORY,
  API_CONFIDENCE,
  API_EDGE_TYPE_WORDING,
  API_RULE_ID_PREFIX,
  API_RULE_IDS,
  API_RULE_PACK_VERSION,
  API_RULE_VERSION,
  API_UNRESOLVED_REASON_WORDING,
  MAX_API_FINDINGS,
} from "./contracts.js";

export {
  API_DESCRIBED_EDGE_TYPES,
  API_DESCRIBED_UNRESOLVED_REASONS,
  API_GRAPH_STATES,
  apiAbsence,
  apiCoverage,
  apiRoutes,
  apiUnresolved,
  queryFor,
} from "./signals.js";

export { apiInventoryRules, apiRules } from "./rules/index.js";

export { apiRuleSetIssues, createApiRuleRegistry } from "./registry.js";

export { createApiAnalyzer } from "./analyzer.js";
