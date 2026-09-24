/**
 * Code Guardian — Import Rule Pack Boundary (Phase 16)
 *
 * The stable import surface for the import domain. Consumers — an MCP tool, the CLI, a
 * CI job, a future aggregate analyzer — should import from here rather than reaching
 * into the individual rule modules.
 *
 * Phase 16 adds one informational rule (`import.graph.inventory`) that inventories the
 * static module references the repository establishes. It consumes the Phase 16 import
 * graph through the same query API, resolves nothing itself, invents no reference and
 * makes no judgment about cycles, coupling, layering or dead code.
 *
 * Dependency direction, unchanged from Phase 10 and enforced by an architectural test
 * in `tests/import-graph.test.js`:
 *
 *   core ← repository/model (8D, 11, 13, 15, 16) ← analysis (9) ← rules (10) ← rules/imports (16)
 *
 * The pack reads the frozen RepositoryModel through the Phase 11 query API and nothing
 * else. It must never import `node:fs`, `node:path`, `child_process`, `node:net`,
 * `node:http`, `node:https`, `node:dns`, `node:worker_threads`, the Phase 8A
 * filesystem boundary, the Phase 8B execution boundary, `src/tools.js`,
 * `tool-registry`, a transport, an MCP/CLI module, or the scanner/parser layer that
 * acquired the inventory. It reads no source file, builds no AST, resolves no
 * specifier, runs no process, contacts no network, and consults no clock, random
 * source or environment: import findings in this phase are deterministic,
 * evidence-first, and scoped to what the repository model can prove.
 */

export {
  IMPORT_ANALYZER_ID,
  IMPORT_ANALYZER_NAME,
  IMPORT_ANALYZER_SCOPE,
  IMPORT_BASIS,
  IMPORT_CATEGORY,
  IMPORT_CONFIDENCE,
  IMPORT_RULE_ID_PREFIX,
  IMPORT_RULE_IDS,
  IMPORT_RULE_PACK_VERSION,
  IMPORT_RULE_VERSION,
  KIND_WORDING,
  MAX_IMPORT_FINDINGS,
  UNRESOLVED_REASON_WORDING,
} from "./contracts.js";

export {
  IMPORT_DESCRIBED_UNRESOLVED_REASONS,
  importCoverage,
  importsAbsence,
  importRelationships,
  importUnresolved,
  queryFor,
} from "./signals.js";

export { importInventoryRules, importRules } from "./rules/index.js";

export { createImportRuleRegistry, importRuleSetIssues } from "./registry.js";

export { createImportAnalyzer } from "./analyzer.js";
