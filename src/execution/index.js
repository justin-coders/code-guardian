/**
 * Code Guardian — Command Execution Boundary (Phase 8B)
 *
 * Stable import boundary for the secure, transport-independent command
 * execution infrastructure. Phase 8C/8D and future analyzers should import from
 * here rather than reaching into individual files.
 *
 * Dependency direction: this layer consumes the Core contracts/errors and the
 * accepted Phase 8A filesystem layer. Core must never import this layer, and
 * this layer must never import MCP, HTTP, stdio, `tools.js`, `tool-registry.js`,
 * analyzers, or the RepositoryScanner.
 */

export {
  EXECUTION_ERROR_KINDS,
  EXECUTION_ERROR_CODES,
  CommandExecutionError,
  executionErrorMessage,
  sanitizeCommandIdentity,
} from "./errors.js";

export { commandIdentity, evaluateCommandPolicy } from "./policy.js";

export {
  canonicalizeExecutablePath,
  isPathLikeExecutable,
  isWithinExecutableRoots,
  resolveCommandExecutable,
  trustedExecutableRoots,
} from "./executable.js";

export {
  DEFAULT_TERMINATION_GRACE_MS,
  resolveExecutionLimits,
} from "./limits.js";

export {
  EXECUTION_CONTROL_ENVIRONMENT_VARIABLES,
  buildEnvironment,
  isExecutionControlVariable,
} from "./environment.js";

export { resolveExecutionCwd } from "./cwd.js";

export { EXECUTION_STATUS, runExecution } from "./runner.js";
