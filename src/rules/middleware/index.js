/**
 * Code Guardian — Middleware Rule Pack Boundary (Phase 19)
 *
 * The stable import surface for the middleware domain. Consumers — an MCP tool, the CLI, a
 * CI job, a future aggregate analyzer — should import from here rather than reaching into the
 * individual rule modules.
 *
 * Phase 19 adds one informational rule (`middleware.graph.inventory`) that inventories the
 * middleware the repository registers and the routes each registration structurally reaches.
 * It consumes the Phase 19 middleware graph through the same query API, resolves nothing
 * itself, starts no server and makes no judgment about missing authentication, weak
 * authentication, middleware ordering, exposed admin routes, CORS configuration or rate
 * limiting.
 *
 * Dependency direction, unchanged from Phase 10 and enforced by an architectural test in
 * `tests/middleware-graph.test.js`:
 *
 *   core ← repository/model (8D … 19) ← analysis (9) ← rules (10) ← rules/middleware (19)
 *
 * The pack reads the frozen RepositoryModel through the Phase 11 query API and nothing else.
 * It must never import `node:fs`, `node:path`, `child_process`, `node:net`, `node:http`,
 * `node:https`, `node:dns`, `node:worker_threads`, the Phase 8A filesystem boundary, the
 * Phase 8B execution boundary, `src/tools.js`, `tool-registry`, a transport, an MCP/CLI
 * module, or the scanner/acquisition layer that produced the registration records. It reads
 * no source file, starts no server, sends no request, resolves no symbol, runs no process,
 * contacts no network, and consults no clock, random source or environment: middleware
 * findings in this phase are deterministic, evidence-first, and scoped to what the repository
 * model can prove.
 */

export {
  MAX_MIDDLEWARE_FINDINGS,
  MIDDLEWARE_ANALYZER_ID,
  MIDDLEWARE_ANALYZER_NAME,
  MIDDLEWARE_ANALYZER_SCOPE,
  MIDDLEWARE_BASIS,
  MIDDLEWARE_CATEGORY,
  MIDDLEWARE_CLASSIFICATION_WORDING,
  MIDDLEWARE_CONFIDENCE,
  MIDDLEWARE_EDGE_TYPE_WORDING,
  MIDDLEWARE_PROTECTION_WORDING,
  MIDDLEWARE_RULE_ID_PREFIX,
  MIDDLEWARE_RULE_IDS,
  MIDDLEWARE_RULE_PACK_VERSION,
  MIDDLEWARE_RULE_VERSION,
  MIDDLEWARE_UNRESOLVED_REASON_WORDING,
} from "./contracts.js";

export {
  MIDDLEWARE_DESCRIBED_EDGE_TYPES,
  MIDDLEWARE_DESCRIBED_UNRESOLVED_REASONS,
  MIDDLEWARE_GRAPH_STATES,
  middlewareAbsence,
  middlewareCoverage,
  middlewareNodes,
  middlewareRouteViews,
  middlewareUnresolved,
  queryFor,
} from "./signals.js";

export { middlewareInventoryRules, middlewareRules } from "./rules/index.js";

export { createMiddlewareRuleRegistry, middlewareRuleSetIssues } from "./registry.js";

export { createMiddlewareAnalyzer } from "./analyzer.js";
