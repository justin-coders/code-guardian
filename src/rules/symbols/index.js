/**
 * Code Guardian — Symbol Rule Pack Boundary (Phase 17)
 *
 * The stable import surface for the semantic domain. Consumers — an MCP tool, the CLI,
 * a CI job, a future aggregate analyzer — should import from here rather than reaching
 * into the individual rule modules.
 *
 * Phase 17 adds one informational rule (`symbols.graph.inventory`) that inventories the
 * declarations, references, calls, exports and import bindings the repository
 * establishes. It consumes the Phase 17 symbol graph through the same query API,
 * resolves nothing itself, invents no symbol and makes no judgment about complexity,
 * coupling, reachability, dead code or call-graph health.
 *
 * Dependency direction, unchanged from Phase 10 and enforced by an architectural test
 * in `tests/symbol-graph.test.js`:
 *
 *   core ← repository/model (8D, 11, 13, 15, 16, 17) ← analysis (9) ← rules (10) ← rules/symbols (17)
 *
 * The pack reads the frozen RepositoryModel through the Phase 11 query API and nothing
 * else. It must never import `node:fs`, `node:path`, `child_process`, `node:net`,
 * `node:http`, `node:https`, `node:dns`, `node:worker_threads`, the Phase 8A filesystem
 * boundary, the Phase 8B execution boundary, `src/tools.js`, `tool-registry`, a
 * transport, an MCP/CLI module, or the scanner/acquisition layer that produced the
 * semantic records. It reads no source file, builds no AST, resolves no symbol, walks no
 * scope, runs no process, contacts no network, and consults no clock, random source or
 * environment: symbol findings in this phase are deterministic, evidence-first, and
 * scoped to what the repository model can prove.
 */

export {
  EDGE_TYPE_WORDING,
  MAX_SYMBOL_FINDINGS,
  SYMBOL_ANALYZER_ID,
  SYMBOL_ANALYZER_NAME,
  SYMBOL_ANALYZER_SCOPE,
  SYMBOL_BASIS,
  SYMBOL_CATEGORY,
  SYMBOL_CONFIDENCE,
  SYMBOL_KIND_WORDING,
  SYMBOL_RULE_ID_PREFIX,
  SYMBOL_RULE_IDS,
  SYMBOL_RULE_PACK_VERSION,
  SYMBOL_RULE_VERSION,
  UNRESOLVED_SYMBOL_REASON_WORDING,
} from "./contracts.js";

export {
  SYMBOL_DESCRIBED_EDGE_TYPES,
  SYMBOL_DESCRIBED_UNRESOLVED_REASONS,
  SYMBOL_GRAPH_STATES,
  queryFor,
  symbolCoverage,
  symbolRelationships,
  symbolUnresolved,
  symbolsAbsence,
} from "./signals.js";

export { symbolInventoryRules, symbolRules } from "./rules/index.js";

export { createSymbolRuleRegistry, symbolRuleSetIssues } from "./registry.js";

export { createSymbolAnalyzer } from "./analyzer.js";
