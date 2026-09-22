/**
 * Code Guardian — Repository Filesystem Infrastructure (Phase 8A)
 *
 * Stable import boundary for the reusable filesystem/path primitives that
 * Phase 8B (command boundary), 8C (repository scanner) and 8D (RepositoryModel
 * population) will consume. Consumers should import from here rather than
 * reaching into individual files.
 *
 * Dependency direction: this layer may depend on the Core (it uses Core errors
 * as its error boundary). The Core must never depend on this layer, and this
 * layer must never import MCP, HTTP, stdio, `tools.js`, `tool-registry.js`, or
 * `child_process`.
 */

export {
  FILESYSTEM_ERROR_KINDS,
  FILESYSTEM_ERROR_CODES,
  FilesystemError,
  classifyFilesystemError,
  filesystemErrorMessage,
  sanitizeFilesystemPath,
  toFilesystemError,
} from "./errors.js";

export {
  createPathTools,
  normalizeRoot,
  resolvePath,
  isContained,
  resolveWithin,
  joinWithin,
  toRepositoryRelative,
} from "./paths.js";

export {
  DIRECTORY_ENTRY_TYPES,
  LINK_TARGET_KINDS,
  LINK_UNKNOWN_REASONS,
  SYMLINK_POLICY,
  classifyLinkTarget,
  readFile,
  readLink,
  listDirectory,
} from "./operations.js";

export {
  DEFAULT_WALK_OPTIONS,
  walk,
} from "./walk.js";
