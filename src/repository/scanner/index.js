/**
 * Code Guardian — Repository Scanner Boundary (Phase 8C)
 *
 * Stable import boundary for the repository inventory layer. Phase 8D
 * (RepositoryModel population) and later analyzers should import from here rather
 * than reaching into individual files.
 *
 * Dependency direction: this layer consumes the Core contracts/errors and the
 * accepted Phase 8A filesystem boundary. The Core must never import this layer,
 * and this layer must never import MCP, HTTP, stdio, `tools.js`,
 * `tool-registry.js`, the analyzers, or `child_process`. It reads the repository;
 * it never writes to it and never spawns a process.
 */

export {
  CONTAINER_UNPARSED_REASONS,
  CONTENT_INSPECTION_REASONS,
  DEPENDENCY_PROBLEM_REASONS,
  DEPENDENCY_SCOPES,
  DEPENDENCY_SOURCE_REASONS,
  DEPENDENCY_SOURCE_STATUSES,
  DEPENDENCY_SPEC_KINDS,
  MAX_EVIDENCE_PER_SIGNAL,
  SCAN_RESULT_VERSION,
  SCAN_SIGNALS,
  SYMLINK_TARGET_KINDS,
  SYMLINK_UNKNOWN_REASONS,
  capEvidence,
  compareEvidence,
  createScanResult,
  validateScanResult,
} from "./contracts.js";

export {
  MAX_SYMLINK_CHAIN,
  SYMLINK_UNKNOWN_REASONS as SYMLINK_POLICY_REASONS,
  isSymlinkUnknownReason,
  resolveSymlinkChain,
  resolveSymlinkTargets,
  uninspectedTarget,
} from "./policies/symlinks.js";

export {
  CONTENT_CANDIDATE_CLASSES,
  CONTENT_CANDIDATE_RULES,
  CONTENT_INSPECTION_LIMITS,
  CONTENT_PATTERN_IDS,
  CONTENT_PATTERNS,
  detectContentPatterns,
} from "./detectors/content.js";

export {
  COMPOSE_RULES,
  CONTAINER_DECLARATION_DETAILS,
  classifyBuildDeclaration,
  detectContainers,
  resolveBuildDeclaration,
} from "./detectors/containers.js";

export {
  COMPOSE_FILENAMES,
  COMPOSE_UNPARSED_REASONS,
  CONTAINER_DECLARATION_LIMITS,
  DEFAULT_DOCKERFILE_NAME,
  isComposeUnparsedReason,
  parseComposeBuildContexts,
} from "./policies/containers.js";

export {
  DEFAULT_IGNORED_DIRECTORIES,
  GITIGNORE_FILENAME,
  GITIGNORE_UNSUPPORTED_REASONS,
  IGNORE_POLICIES,
  buildIgnorePolicy,
  isIgnored,
  parseGitignore,
  segmentGlobToRegExp,
} from "./policies/ignore.js";

export { DEFAULT_SCANNER_LIMITS, resolveScanLimits } from "./policies/limits.js";

// Phase 13 — dependency acquisition: the pure parser/vocabulary policy and the
// detector that applies it to the manifest inventory.
export {
  DEPENDENCY_LIMITS,
  DEPENDENCY_SOURCE_TABLE,
  NODE_DEPENDENCY_SECTIONS,
  classifySpecKind,
  compareDeclarations,
  compareEdges,
  compareProblems,
  compareResolved,
  dependencySourceFor,
  isDependencyName,
  isDependencyProblemReason,
  isDependencySourceReason,
  isDependencySpec,
  isDependencyVersion,
  normalizeDependencyName,
  parseGoMod,
  parseNpmLockfile,
  parsePackageJson,
  parseRequirementsTxt,
  runDependencyParser,
} from "./policies/dependencies.js";

export { detectDependencies } from "./detectors/dependencies.js";

// Phase 16 — import acquisition: the deterministic tokenizer/module scanner and its
// closed vocabularies, plus the detector that applies it to the module sources in
// the inventory.
export {
  IMPORT_ACQUISITION_LIMITS,
  IMPORT_NON_STATIC_REASONS,
  IMPORT_PROBLEM_REASONS,
  IMPORT_SOURCE_REASONS,
  IMPORT_SOURCE_STATUSES,
  IMPORT_SPECIFIER_KINDS,
  MODULE_FILE_EXTENSIONS,
  PARSED_MODULE_EXTENSIONS,
  UNSUPPORTED_MODULE_EXTENSIONS,
  isModuleFileExtension,
  isParsedModuleExtension,
  isUsableSpecifier,
  moduleLanguageOf,
  parseModuleReferences,
  tokenizeModule,
} from "./policies/imports.js";

export { detectImports } from "./detectors/imports.js";

// Phase 17 — semantic acquisition: the structural scanner that records module-scope
// declarations, import bindings, exports, reference counts and call sites, with its
// closed vocabularies and bounds, plus the detector that applies it.
export {
  SEMANTIC_ACQUISITION_LIMITS,
  SEMANTIC_LEXICAL_PROBLEMS,
  SEMANTIC_MODULE_EXTENSIONS,
  SEMANTIC_PARSED_EXTENSIONS,
  SEMANTIC_PROBLEMS,
  SEMANTIC_SOURCE_REASONS,
  SEMANTIC_SOURCE_STATUSES,
  SEMANTIC_UNSUPPORTED_EXTENSIONS,
  SYMBOL_BINDING_KINDS,
  SYMBOL_EXPORT_FORMS,
  SYMBOL_KINDS,
  SYMBOL_OCCURRENCE_FORMS,
  isSemanticModuleExtension,
  isUsableSymbolName,
  scanModuleSemantics,
} from "./policies/semantics.js";

export { detectSemantics } from "./detectors/semantics.js";

export {
  API_ACQUISITION_LIMITS,
  API_FRAMEWORKS,
  API_HTTP_METHODS,
  API_PROBLEMS,
  API_RECEIVER_KINDS,
  API_ROUTE_METHODS,
  API_SHAPE_REASONS,
  API_SOURCE_REASONS,
  API_SOURCE_STATUSES,
  API_UNSUPPORTED_FRAMEWORKS,
  isUsableApiName,
  isUsableRoutePath,
  scanApiRoutes,
} from "./policies/api.js";

export { detectApi } from "./detectors/api.js";

export {
  SCAN_OPTION_KEYS,
  TRUNCATION_REASONS,
  scanRepository,
} from "./scanner.js";
