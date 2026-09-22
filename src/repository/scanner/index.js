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

export {
  SCAN_OPTION_KEYS,
  TRUNCATION_REASONS,
  scanRepository,
} from "./scanner.js";
