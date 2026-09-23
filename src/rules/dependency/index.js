/**
 * Code Guardian — Dependency Rule Pack Boundary (Phase 13)
 *
 * The stable import surface for the dependency domain. Consumers — an MCP tool, the
 * CLI, a CI job, a future aggregate analyzer — should import from here rather than
 * reaching into the individual rule modules.
 *
 * Phase 14 extends the pack with one graph rule (`dependency.graph.inventory`) that
 * inventories the relationships a lockfile established. It consumes the Phase 14
 * dependency graph through the same query API, invents no edge and makes no judgment
 * about graph shape.
 *
 * Dependency direction, unchanged from Phase 10 and enforced by an architectural test
 * in `tests/dependency-intelligence.test.js`:
 *
 *   core ← repository/model (8D, 11, 13) ← analysis (9) ← rules (10) ← rules/dependency (13)
 *
 * The pack reads the frozen RepositoryModel through the Phase 11 query API and nothing
 * else. It must never import `node:fs`, `node:path`, `child_process`, `node:net`,
 * `node:http`, `node:https`, `node:dns`, `node:worker_threads`, the Phase 8A
 * filesystem boundary, the Phase 8B execution boundary, `src/tools.js`,
 * `tool-registry`, a transport, an MCP/CLI module, or the scanner/parser layer that
 * acquired the manifests. It parses no manifest, reads no file, runs no package
 * manager, contacts no registry, and consults no clock, random source or environment:
 * dependency findings in this phase are deterministic, evidence-first, and scoped to
 * what the repository model can prove.
 */

export {
  DEPENDENCY_ANALYZER_ID,
  DEPENDENCY_ANALYZER_NAME,
  DEPENDENCY_ANALYZER_SCOPE,
  DEPENDENCY_BASIS,
  DEPENDENCY_CATEGORY,
  DEPENDENCY_CONFIDENCE,
  DEPENDENCY_GRAPH_BASIS,
  DEPENDENCY_RULE_ID_PREFIX,
  DEPENDENCY_RULE_IDS,
  DEPENDENCY_RULE_PACK_VERSION,
  DEPENDENCY_RULE_VERSION,
  DEPENDENCY_SIGNALS,
  MAX_DECLARATION_FINDINGS,
  MAX_GRAPH_FINDINGS,
  compareDeclarations,
} from "./contracts.js";

export {
  dependencyAbsence,
  dependencyAcquisitionCoverage,
  dependencyDeclarations,
  dependencyGraphAbsence,
  dependencyGraphCoverage,
  dependencyGraphEdges,
  dependencyObservations,
  queryFor,
} from "./signals.js";

export { dependencyGraphRules, dependencyRules } from "./rules/index.js";

export { createDependencyRuleRegistry, dependencyRuleSetIssues } from "./registry.js";

export { createDependencyAnalyzer } from "./analyzer.js";
