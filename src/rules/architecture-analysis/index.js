/**
 * Code Guardian — Architecture Analysis Rule Pack Boundary (Official Roadmap Phase 14)
 *
 * The stable import surface for the architecture-analysis domain. Consumers import from here
 * rather than reaching into the individual rule modules.
 *
 * ### This pack is the official roadmap's Phase 14
 *
 * The official roadmap's Phase 14 is **"Architecture Analyzer"**, and this pack plus
 * `analyzer.js` is that analyzer:
 *
 *   Repository → Scanner(facts) → RepositoryModel → ArchitectureAnalyzer → architecture rules
 *              → evidence → findings
 *
 * It is distinct from the internal architecture *graph* integration analyzer
 * (`src/rules/architecture/`), which ships one inventory rule over the architecture graph. This
 * pack reuses that graph's substrate, the import graph and the symbol graph through the query
 * API, and adds the nine roadmap domains.
 *
 * ### Dependency direction
 *
 *   core ← repository/model ← analysis ← rules ← rules/architecture-analysis
 *
 * The pack reads the frozen RepositoryModel through the query API and nothing else. It must
 * never import `node:fs`, `node:fs/promises`, `node:path`, `child_process`, `node:net`,
 * `node:http`, `node:https`, `node:dns`, `node:worker_threads`, `src/tools.js`,
 * `tool-registry`, a transport or an MCP/CLI module. It reads no file contents of its own, runs
 * no command, and consults no clock, random source or environment.
 *
 * ### The nine domains, and where each rests
 *
 *   module boundaries        the import graph's module sources and the directories that hold them
 *   dependency direction     established import edges aggregated to the module level
 *   circular dependencies    strongly connected components of the module graph
 *   layer violations         directions the repository *declares* between its local packages
 *   coupling                 measured outgoing/incoming module counts
 *   cohesion indicators      a module whose members establish no internal import edge
 *   large modules            measured module-source and declaration counts against thresholds
 *   boundary leakage         an import past a module's published `index.<ext>` entry
 *   architecture patterns    multiple independent facts (a workspace monorepo)
 *
 * ### Limitations, stated rather than hidden
 *
 *   - **No layer model is assumed.** A layer violation is reported only where the repository
 *     declares a local-package direction; otherwise the domain is `unknown`.
 *   - **No architecture score.** The pack exposes observations, evidence, findings and coverage,
 *     never an aggregate grade or percentage.
 *   - **Indicators are indicators.** Large modules, coupling and cohesion report measured counts
 *     against documented, deterministic thresholds; they never call a module wrong.
 *   - **Module resolution is JavaScript/TypeScript.** The underlying import graph interprets JS
 *     and TS; a repository whose sources are another language yields `unknown`, never a false
 *     clean or a false finding.
 */

export {
  ARCHITECTURE_ANALYSIS_ANALYZER_ID,
  ARCHITECTURE_ANALYSIS_ANALYZER_NAME,
  ARCHITECTURE_ANALYSIS_ANALYZER_SCOPE,
  ARCHITECTURE_ANALYSIS_BASES,
  ARCHITECTURE_ANALYSIS_CATEGORY,
  ARCHITECTURE_ANALYSIS_CONFIDENCE,
  ARCHITECTURE_ANALYSIS_LIMITS,
  ARCHITECTURE_ANALYSIS_RULE_ID_PREFIX,
  ARCHITECTURE_ANALYSIS_RULE_IDS,
  ARCHITECTURE_ANALYSIS_RULE_PACK_VERSION,
  ARCHITECTURE_ANALYSIS_RULE_VERSION,
  ARCHITECTURE_ANALYSIS_STATES,
  ARCHITECTURE_PATTERNS,
  LOCAL_PACKAGE_SPEC_KINDS,
  ROOT_MODULE_PATH,
} from "./contracts.js";

export {
  buildModuleGraph,
  declaredLocalDirections,
  evidenceForPaths,
  isEstablishedImportState,
  isUnder,
  moduleLabelOf,
  modulePathOf,
  queryFor,
  workspacePatternFacts,
} from "./signals.js";

export { findModuleCycles, isEntryFile, stronglyConnectedComponents } from "./graph.js";

export { summarizeArchitecture } from "./summary.js";

export {
  architectureAnalysisRules,
  architectureCouplingRules,
  architectureDependencyRules,
  architectureLayerRules,
  architectureLeakageRules,
  architectureModuleRules,
  architecturePatternRules,
} from "./rules/index.js";

export { architectureAnalysisRuleSetIssues, createArchitectureAnalysisRuleRegistry } from "./registry.js";

export { createArchitectureAnalysisAnalyzer } from "./analyzer.js";
