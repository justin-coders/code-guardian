/**
 * Code Guardian — Architecture Rule Pack Boundary (Phase 15)
 *
 * The stable import surface for the architecture domain. Consumers — an MCP tool, the
 * CLI, a CI job, a future aggregate analyzer — should import from here rather than
 * reaching into the individual rule modules.
 *
 * Phase 15 adds one informational rule (`architecture.graph.inventory`) that
 * inventories the architectural relationships the repository establishes. It consumes
 * the Phase 15 architecture graph through the same query API, invents no relationship
 * and makes no judgment about structure.
 *
 * Dependency direction, unchanged from Phase 10 and enforced by an architectural test
 * in `tests/architecture-graph.test.js`:
 *
 *   core ← repository/model (8D, 11, 13, 15) ← analysis (9) ← rules (10) ← rules/architecture (15)
 *
 * The pack reads the frozen RepositoryModel through the Phase 11 query API and nothing
 * else. It must never import `node:fs`, `node:path`, `child_process`, `node:net`,
 * `node:http`, `node:https`, `node:dns`, `node:worker_threads`, the Phase 8A
 * filesystem boundary, the Phase 8B execution boundary, `src/tools.js`,
 * `tool-registry`, a transport, an MCP/CLI module, or the scanner/parser layer that
 * acquired the inventory. It parses no source file, builds no AST, resolves no
 * import, runs no process, contacts no network, and consults no clock, random source
 * or environment: architecture findings in this phase are deterministic,
 * evidence-first, and scoped to what the repository model can prove.
 */

export {
  ARCHITECTURE_ANALYZER_ID,
  ARCHITECTURE_ANALYZER_NAME,
  ARCHITECTURE_ANALYZER_SCOPE,
  ARCHITECTURE_BASIS,
  ARCHITECTURE_CATEGORY,
  ARCHITECTURE_CONFIDENCE,
  ARCHITECTURE_RULE_ID_PREFIX,
  ARCHITECTURE_RULE_IDS,
  ARCHITECTURE_RULE_PACK_VERSION,
  ARCHITECTURE_RULE_VERSION,
  EDGE_WORDING,
  MAX_ARCHITECTURE_FINDINGS,
} from "./contracts.js";

export {
  ARCHITECTURE_DESCRIBED_EDGE_TYPES,
  architectureAbsence,
  architectureCoverage,
  architectureRelationships,
  queryFor,
} from "./signals.js";

export { architectureInventoryRules, architectureRules } from "./rules/index.js";

export { createArchitectureRuleRegistry, architectureRuleSetIssues } from "./registry.js";

export { createArchitectureAnalyzer } from "./analyzer.js";
