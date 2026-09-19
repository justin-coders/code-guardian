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
 * Precedence used to combine request-level `limits` with policy-level ceilings.
 *
 * `limits` (on an ExecutionRequest) express *per-invocation resource limits*:
 * how much this single command may consume. `policy` expresses *security /
 * authorization constraints*: what the Core is willing to permit at all. Where
 * both name the same dimension (duration, output size, process count), the
 * **most restrictive** value wins — a request can never widen what the policy
 * authorizes, only narrow it. Resolving the effective values is the Command
 * Runner's job; this contract records the rule so behavior is never guessed.
 */
export const EXECUTION_LIMIT_PRECEDENCE = "most-restrictive";

/**
 * Precedence used to combine `allowCommands` and `denyCommands`.
 *
 * An explicit deny always overrides an allow. Empty lists are meaningful and
 * are *not* wildcards:
 *
 * - `denyCommands: []` denies nothing by name.
 * - `allowCommands: []` grants no command name and by itself authorizes
 *   nothing. It is an empty allowlist, never "allow everything". A mode that
 *   intends to permit arbitrary commands must express that separately rather
 *   than by leaving the allowlist empty.
 *
 * Enforcement is the Command Runner's job; this contract records the rule.
 */
export const EXECUTION_COMMAND_PRECEDENCE = "deny-overrides-allow";

/**
 * Build an execution limits descriptor (per-invocation resource limits).
 *
 * Limits describe *how much* one invocation may consume. They are distinct
 * from `createExecutionPolicy`, which describes what is authorized at all. See
 * `EXECUTION_LIMIT_PRECEDENCE` for how the two combine.
 *
 * @param {object} [input]
 * @returns {object} An ExecutionLimits-shaped draft; validate before use.
 */
export function createExecutionLimits(input = {}) {
  return {
    maxOutputBytes: input.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES,
    maxProcesses: input.maxProcesses ?? 1,
  };
}

/**
 * Build an execution policy (the trust boundary for command execution).
 *
 * A policy is about *security / authorization*: which commands may run, from
 * which roots, with what network posture, and the maximum resources the policy
 * is willing to authorize. It is not a substitute for per-invocation
 * `limits`; the duration/output/process values here are authorization ceilings.
 * See `EXECUTION_COMMAND_PRECEDENCE` and `EXECUTION_LIMIT_PRECEDENCE`.
 *
 * `allowedRoots` authorizes *working directories*. `allowedExecutableRoots`
 * authorizes *executable directories*: a name in `allowCommands` (`"node"`)
 * authorizes the executable the trusted environment resolves, and this list
 * additionally authorizes executables that live in a declared directory (for
 * example a repository-local toolchain). A bare allow name is never satisfied
 * by a file that merely shares the basename, and a relative command or entry
 * is resolved against the requested execution cwd, never against the Code
 * Guardian process cwd.
 *
 * @param {object} [input]
 * @returns {object} An ExecutionPolicy-shaped draft; validate before use.
 */
export function createExecutionPolicy(input = {}) {
  return {
    allowCommands: input.allowCommands ?? [],
    denyCommands: input.denyCommands ?? [],
    allowedRoots: input.allowedRoots ?? [],
    allowedExecutableRoots: input.allowedExecutableRoots ?? [],
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
