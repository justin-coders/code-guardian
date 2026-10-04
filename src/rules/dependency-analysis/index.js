/**
 * Code Guardian — Dependency Analysis Rule Pack Boundary (Official Roadmap Phase 15)
 *
 * The stable import surface for the dependency-analysis domain. Consumers import from here rather
 * than reaching into the individual rule modules.
 *
 * ### This pack is the official roadmap's Phase 15
 *
 * The official roadmap's Phase 15 is **"Dependency Analyzer"**, and this pack plus `analyzer.js`
 * is that analyzer:
 *
 *   Repository → Scanner(facts) → RepositoryModel → DependencyAnalyzer → dependency rules
 *              → evidence → findings
 *
 * The existing `src/rules/dependency/` pack stays as the substrate (its two inventory rules state
 * facts). This pack adds analysis over that substrate and preserves the central distinction:
 * what the repository establishes is kept separate from what external, versioned dependency
 * intelligence establishes.
 *
 * ### Dependency direction
 *
 *   core ← repository/model ← analysis ← rules ← rules/dependency-analysis
 *
 * The pack reads the frozen RepositoryModel through the query API and nothing else. It must never
 * import `node:fs`, `node:fs/promises`, `node:path`, `child_process`, `node:net`, `node:http`,
 * `node:https`, `node:dns`, `node:worker_threads`, `src/tools.js`, `tool-registry`, a transport
 * or an MCP/CLI module, and it performs no network access.
 *
 * ### The eight domains, and where each rests
 *
 *   outdated              repository version instances × external release metadata
 *   known vulnerabilities repository version instances × external advisories (revisioned)
 *   unused                declared dependencies × import/script/CI/file usage evidence
 *   duplicate versions    lockfile resolution records that disagree
 *   concentration         in-degree in the recorded dependency graph
 *   lockfile integrity    manifest declarations × lockfile resolutions
 *   manager consistency   competing package-manager lockfiles per ecosystem
 *   supply-chain          out-of-registry dependency sources (git/url/alias)
 *
 * ### Limitations, stated rather than hidden
 *
 *   - **No vulnerability or release source is fetched.** External intelligence is supplied, never
 *     acquired here; absent it, those domains are `unknown`.
 *   - **Version semantics are ecosystem-aware.** Only ecosystems this build compares (`node`
 *     SemVer) produce a comparison; others are `unknown`.
 *   - **No score and no remediation.** No dependency grade and no automatic change anywhere.
 */

export {
  DEPENDENCY_ANALYSIS_ANALYZER_ID,
  DEPENDENCY_ANALYSIS_ANALYZER_NAME,
  DEPENDENCY_ANALYSIS_ANALYZER_SCOPE,
  DEPENDENCY_ANALYSIS_BASES,
  DEPENDENCY_ANALYSIS_CATEGORY,
  DEPENDENCY_ANALYSIS_CONFIDENCE,
  DEPENDENCY_ANALYSIS_LIMITS,
  DEPENDENCY_ANALYSIS_RULE_ID_PREFIX,
  DEPENDENCY_ANALYSIS_RULE_IDS,
  DEPENDENCY_ANALYSIS_RULE_PACK_VERSION,
  DEPENDENCY_ANALYSIS_RULE_VERSION,
  DEPENDENCY_ANALYSIS_STATES,
  DEPENDENCY_INTELLIGENCE_STATES,
  INTERPRETED_LOCKFILES,
  PACKAGE_MANAGER_BY_LOCKFILE,
  SEMVER_ECOSYSTEMS,
  UNUSUAL_SOURCE_SPEC_KINDS,
} from "./contracts.js";

export {
  advisoriesByPackage,
  normalizeDependencyIntelligence,
  readDependencyIntelligence,
  releasesByPackage,
  sourceById,
} from "./intelligence.js";

export {
  compareVersions,
  exactDeclaredVersion,
  isComparableEcosystem,
  parseVersion,
  satisfiesRange,
} from "./versions.js";

export {
  basenameOf,
  dependencyAcquisitionCoverage,
  dependencyCoverageEstablished,
  dependencyDeclarations,
  dependencyEntities,
  dependencyGraphCoverage,
  dependencyGraphEdges,
  dependencyGraphEstablished,
  dependencyResolutions,
  lockfileFacts,
  manifestEntities,
  queryFor,
} from "./signals.js";

export { isReferenced, packageRootOf, usageEvidence, wordTokens } from "./usage.js";

export { summarizeDependencyAnalysis } from "./summary.js";

export {
  dependencyAnalysisRules,
  dependencyConcentrationRules,
  dependencyDuplicateRules,
  dependencyLockfileRules,
  dependencyManagerRules,
  dependencyOutdatedRules,
  dependencySupplyChainRules,
  dependencyUnusedRules,
  dependencyVulnerabilityRules,
} from "./rules/index.js";

export { dependencyAnalysisRuleSetIssues, createDependencyAnalysisRuleRegistry } from "./registry.js";

export { createDependencyAnalysisAnalyzer } from "./analyzer.js";
