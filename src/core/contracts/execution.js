/**
 * Code Guardian Core — Execution Contracts
 *
 * These contracts *describe* command execution; they never execute anything.
 * There is deliberately no `child_process` import here: a Command Runner is a
 * later infrastructure layer that will consume these shapes.
 *
 * A non-zero exit code is normal execution data, not a Code Guardian error:
 * a failing command can still produce useful analysis evidence.
 *
 * This module defines the shape/constants/factories only.
 */

/** Derived outcome states of an ExecutionResult. */
export const EXECUTION_STATES = Object.freeze({
  COMPLETED: "completed",
  NON_ZERO_EXIT: "non-zero-exit",
  TIMED_OUT: "timed-out",
  KILLED: "killed",
  NOT_STARTED: "not-started",
});

/** Fields every ExecutionRequest must declare. */
export const EXECUTION_REQUEST_FIELDS = Object.freeze([
  "command",
  "args",
  "cwd",
  "environment",
  "timeout",
  "limits",
  "policy",
]);

/** Fields every ExecutionResult must declare. */
export const EXECUTION_RESULT_FIELDS = Object.freeze([
  "exitCode",
  "stdout",
  "stderr",
  "duration",
  "timedOut",
  "killed",
  "truncated",
]);

/** Default command duration limit, in milliseconds. */
export const DEFAULT_EXECUTION_TIMEOUT_MS = 30000;

/** Default captured-output limit, in bytes. */
export const DEFAULT_MAX_OUTPUT_BYTES = 1048576;

/** Default network posture for command execution. */
export const DEFAULT_NETWORK_POLICY = "disabled";

/** Default execution limits. */
export const DEFAULT_EXECUTION_LIMITS = Object.freeze({
  maxOutputBytes: DEFAULT_MAX_OUTPUT_BYTES,
  maxProcesses: 1,
});

/**
 * Build an execution limits descriptor.
 * @param {object} [input]
 * @returns {object}
 */
export function createExecutionLimits(input = {}) {
  return {
    maxOutputBytes: input.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES,
    maxProcesses: input.maxProcesses ?? 1,
  };
}

/**
 * Build an execution policy (the trust boundary for command execution).
 * @param {object} [input]
 * @returns {object}
 */
export function createExecutionPolicy(input = {}) {
  return {
    allowCommands: input.allowCommands ?? [],
    denyCommands: input.denyCommands ?? [],
    allowedRoots: input.allowedRoots ?? [],
    network: input.network ?? DEFAULT_NETWORK_POLICY,
    maxDurationMs: input.maxDurationMs ?? DEFAULT_EXECUTION_TIMEOUT_MS,
    maxOutputBytes: input.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES,
    maxProcesses: input.maxProcesses ?? 1,
  };
}

/**
 * Build an ExecutionRequest descriptor. Nothing is executed.
 * `command` and `cwd` are intentionally left un-defaulted so callers must
 * supply and validate them explicitly.
 * @param {object} [input]
 * @returns {object}
 */
export function createExecutionRequest(input = {}) {
  return {
    command: input.command,
    args: input.args ?? [],
    cwd: input.cwd,
    environment: input.environment ?? {},
    timeout: input.timeout ?? DEFAULT_EXECUTION_TIMEOUT_MS,
    limits: createExecutionLimits(input.limits ?? {}),
    policy: createExecutionPolicy(input.policy ?? {}),
  };
}

/**
 * Build an ExecutionResult descriptor from captured execution facts.
 * @param {object} [input]
 * @returns {object}
 */
export function createExecutionResult(input = {}) {
  return {
    exitCode: input.exitCode ?? null,
    stdout: input.stdout ?? "",
    stderr: input.stderr ?? "",
    duration: input.duration ?? 0,
    timedOut: input.timedOut ?? false,
    killed: input.killed ?? false,
    truncated: input.truncated ?? false,
  };
}

/**
 * Derive the outcome state of an ExecutionResult.
 *
 * Precedence: timeout > killed > not-started > non-zero exit > completed.
 * Non-zero exits are reported as `non-zero-exit` rather than an error state.
 *
 * @param {object} result ExecutionResult-shaped object.
 * @returns {string} One of the `EXECUTION_STATES` values.
 */
export function getExecutionState(result = {}) {
  if (result.timedOut === true) return EXECUTION_STATES.TIMED_OUT;
  if (result.killed === true) return EXECUTION_STATES.KILLED;
  if (result.exitCode === null || result.exitCode === undefined) {
    return EXECUTION_STATES.NOT_STARTED;
  }
  if (result.exitCode !== 0) return EXECUTION_STATES.NON_ZERO_EXIT;
  return EXECUTION_STATES.COMPLETED;
}
