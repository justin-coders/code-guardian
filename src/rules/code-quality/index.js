/**
 * Code Guardian — Code Quality Rule Pack Boundary (Official Roadmap Phase 12)
 *
 * The stable import surface for the code-quality domain. Consumers import from here rather
 * than reaching into the individual rule modules.
 *
 * ### Phase numbering: this pack is the official roadmap's Phase 12
 *
 * The official roadmap's Phase 12 is **"Code Quality Analyzer"**, and this pack plus
 * `analyzer.js` is that analyzer:
 *
 *   Repository → RepositoryModel → CodeQualityAnalyzer → applicable rules → evidence → findings
 *
 * "Official Roadmap Phase 12" is the only numbering that says where the *product* is. A bare
 * `Phase 8C`/`Phase 10` in comments names the repository's *internal* implementation increment
 * for a consumed layer, not this milestone.
 *
 * ### Dependency direction
 *
 * Enforced by an architectural test in `tests/code-quality-analyzer.test.js`:
 *
 *   core ← repository/model ← analysis ← rules ← rules/code-quality
 *
 * The pack reads the frozen RepositoryModel through the query API and nothing else. It must
 * never import `node:fs`, `node:fs/promises`, `node:path`, `child_process`, `node:net`,
 * `node:http`, `node:https`, `node:dns`, `node:worker_threads`, the filesystem boundary, the
 * execution boundary, `src/tools.js`, `tool-registry`, a transport, or an MCP/CLI module. It
 * reads no file contents of its own, runs no command, and consults no clock, random source or
 * environment.
 *
 * ### The nine domains, and where each rests
 *
 *   linting / formatting / type checking   configuration entities, declared manifest scripts,
 *                                          declared dependencies, and CI workflow content
 *   dead code                              the import graph (orphan modules) and the symbol
 *                                          graph (exports with no established references)
 *   complexity                             module-scope declaration counts from the symbol
 *                                          graph — a module-size indicator, never a
 *                                          cyclomatic-complexity measurement
 *   duplication                            no measurement exists in this build: the domain is
 *                                          `unknown`, never clean
 *   unsafe patterns                        dynamic-scope constructs (`eval`/`with`) the
 *                                          semantic acquisition recorded per source
 *   maintainability                        the concrete tooling the repository does not show —
 *                                          never a score
 *   configuration consistency              configurations the model proves contradict or are
 *                                          disconnected from any execution path
 *   declared quality scripts               manifest-declared script names that name a tool, and
 *                                          the one place this phase can produce `failed` — a
 *                                          manifest whose parse failed cannot have its declared
 *                                          scripts read, which is an established failure rather
 *                                          than an absence
 *
 * ### Language modularity
 *
 * Language-specific knowledge — which dependency names and script words establish a tool for
 * which ecosystem — lives in `rules/languages/`, one module per ecosystem. The domain rules are
 * language-neutral and read the union, so adding a language is adding a module, never editing a
 * rule. No language-specific *rule* is shipped: the model exposes no content-level fact that
 * would justify a distinct, non-duplicative finding beyond the generic domain rules.
 *
 * ### Limitations, stated rather than hidden
 *
 *   - **No execution claim.** The analyzer runs no lint, format or type-check command.
 *     `verified` means "configured **and** observed invoked in CI", never "the run passed".
 *   - **`not_applicable` for `not_applicable` domains.** The three tooling domains are *open*:
 *     a tool can be invoked without a recognized marker, so an unmarked tooling domain with
 *     source is `unknown`, never `not_applicable`.
 *   - **Complexity is module size.** There is no AST, control-flow or line-count metric in this
 *     build; the complexity rule reports module-scope declaration counts and says so.
 *   - **Duplication is unmeasured.** The model exposes no normalized-source evidence, so the
 *     domain is always `unknown` when source exists.
 *   - **Dead code is an indicator.** An export with no established references and an orphan
 *     module are graph shapes, not verdicts.
 *   - **CI evidence is content-based.** A workflow's bytes are matched against a closed tool
 *     vocabulary; no YAML or shell parsing is performed.
 *   - **`failed` is one narrow fact.** The only failed operation this build can establish is a
 *     manifest that failed to parse; the tooling domains stay `unknown` in that case, because
 *     an open domain's absence is never proven by one blocked channel.
 */

export {
  CODE_QUALITY_ANALYZER_ID,
  CODE_QUALITY_ANALYZER_NAME,
  CODE_QUALITY_ANALYZER_SCOPE,
  CODE_QUALITY_BASES,
  CODE_QUALITY_CATEGORY,
  CODE_QUALITY_CONFIDENCE,
  CODE_QUALITY_LIMITS,
  CODE_QUALITY_RULE_ID_PREFIX,
  CODE_QUALITY_RULE_IDS,
  CODE_QUALITY_RULE_PACK_VERSION,
  CODE_QUALITY_RULE_VERSION,
  CODE_QUALITY_STATES,
  QUALITY_CONFIGURATION_SIGNALS,
  QUALITY_DEPENDENCY_NAMES,
  QUALITY_TOOL_DOMAINS,
  QUALITY_TOOL_IDS,
  TYPE_CHECK_CONFIG_BASENAMES,
} from "./contracts.js";

export {
  QUALITY_SIGNALS,
  basenameOf,
  ciInventory,
  ciQualityObservation,
  configurationBySignal,
  configurationInventory,
  declaredDependencyNames,
  declaredScriptNames,
  declaresDependency,
  dependenciesInEcosystem,
  fileEntities,
  fileEvidenceIds,
  hasSourceSubject,
  importGraphEvidence,
  languageEntities,
  languageIds,
  manifestFacts,
  queryFor,
  scriptNamesMatching,
  sourceAbsence,
  symbolGraphEvidence,
} from "./signals.js";

export { summarizeCodeQuality } from "./summary.js";

export { TOOLING_DOMAINS, toolingEvidence } from "./tooling.js";

export {
  QUALITY_LANGUAGE_IDS,
  QUALITY_LANGUAGE_PROFILES,
  QUALITY_TOOLING,
  QUALITY_TOOLING_DOMAINS,
} from "./rules/languages/index.js";

export { codeQualityRules } from "./rules/index.js";

export { codeQualityRuleSetIssues, createCodeQualityRuleRegistry } from "./registry.js";

export { createCodeQualityAnalyzer } from "./analyzer.js";
