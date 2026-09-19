/**
 * Code Guardian — Command Runner (Phase 8B)
 *
 * Executes a single external command under explicit policy and resource limits
 * and returns a structured result. This is the security boundary: it never
 * interprets a shell command line, never inherits an unvalidated working
 * directory, and never accumulates unbounded output.
 *
 * Design rules:
 *   - `shell: false` always. `command` + `args[]` are passed verbatim to
 *     `spawn`, so shell metacharacters and `$(...)`/`;` are literal arguments.
 *   - The command is *resolved first*, then authorized, then spawned **by the
 *     resolved absolute path**. Resolution uses the trusted (inherited)
 *     environment, so a caller-supplied `PATH` cannot change which executable
 *     runs, and `allowCommands: ["node"]` cannot be satisfied by a file that
 *     merely shares the basename `node`. An unresolvable command is a
 *     rejection, never a spawn.
 *   - A **relative** command (`./tools/check`) and a relative `allowCommands`/
 *     `denyCommands` entry are resolved against the requested execution cwd —
 *     never against the Code Guardian process cwd — so both sides of the
 *     authorization check share one base. Without a valid execution cwd a
 *     relative command is unresolved rather than silently resolved elsewhere.
 *   - Policy is evaluated *before* spawning. A rejected command never runs and
 *     is reported as `rejected`, not as a failed process.
 *   - The working directory is resolved through the Phase 8A path layer and must
 *     sit inside an allowed root (with a realpath cross-check).
 *   - Output is capped per stream; exceeding a cap bounds memory and is
 *     reported via `stdoutTruncated`/`stderrTruncated` without killing the
 *     process (truncation and termination are separate concerns).
 *   - Cancellation registration re-checks `signal.aborted` immediately after
 *     subscribing, because an abort is never replayed to a late listener; the
 *     promise settles exactly once and every timer/listener is cleaned up.
 *
 * The public entry point is `runExecution(request, options)`. Invalid input
 * throws a Core `ValidationError`; runtime outcomes are returned as results so
 * that policy rejection, spawn failure and process results stay distinct.
 */

import { spawn } from "node:child_process";

import { EXECUTION_STATES, ValidationError } from "../core/index.js";

import { resolveExecutionCwd } from "./cwd.js";
import {
  buildEnvironment,
  isExecutionControlVariable,
} from "./environment.js";
import {
  resolveCommandExecutable,
  trustedExecutableRoots,
} from "./executable.js";
import { CommandExecutionError, EXECUTION_ERROR_KINDS } from "./errors.js";
import { resolveExecutionLimits } from "./limits.js";
import { evaluateCommandPolicy } from "./policy.js";

/**
 * Coarse outcome of a `runExecution` call.
 *
 * The four process outcomes reuse the accepted Phase 7 `EXECUTION_STATES`
 * values verbatim; the three pre-spawn outcomes extend them so a policy
 * rejection, a spawn failure and a cancellation are never confused with a
 * process that actually ran.
 */
export const EXECUTION_STATUS = Object.freeze({
  REJECTED: "rejected",
  SPAWN_FAILED: "spawn-failed",
  CANCELED: "canceled",
  COMPLETED: EXECUTION_STATES.COMPLETED,
  NON_ZERO_EXIT: EXECUTION_STATES.NON_ZERO_EXIT,
  TIMED_OUT: EXECUTION_STATES.TIMED_OUT,
  KILLED: EXECUTION_STATES.KILLED,
});

// ─── Validation ──────────────────────────────────────────────────────────────

const REQUEST_KEYS = [
  "command",
  "args",
  "cwd",
  "environment",
  "timeout",
  "limits",
  "policy",
];
const OPTION_KEYS = [
  "terminationGraceMs",
  "maxStdoutBytes",
  "maxStderrBytes",
  "inheritEnvironment",
  "signal",
  "shell",
];
const ENVIRONMENT_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isPositiveInteger(value) {
  return Number.isInteger(value) && value > 0;
}

function isNonNegativeInteger(value) {
  return Number.isInteger(value) && value >= 0;
}

function validateEnvironment(environment, issues) {
  if (environment === undefined) return;
  if (!isPlainObject(environment)) {
    issues.push("environment: must be a plain object of string overrides");
    return;
  }
  for (const [key, value] of Object.entries(environment)) {
    if (!ENVIRONMENT_NAME.test(key)) {
      issues.push(`environment.${key}: invalid environment variable name`);
    }
    if (isExecutionControlVariable(key)) {
      // Reserved so a caller cannot re-point executable resolution or inject
      // flags/loader hooks into an otherwise authorized command. The name is
      // echoed; the value never is.
      issues.push(
        `environment.${key}: overriding an execution-control variable is not allowed`,
      );
    }
    if (typeof value !== "string") {
      issues.push(
        `environment.${key}: must be a string (undefined/null removal is not supported)`,
      );
    }
  }
}

function validateLimits(limits, issues) {
  if (limits === undefined) return;
  if (!isPlainObject(limits)) {
    issues.push("limits: must be a plain object");
    return;
  }
  for (const field of ["maxOutputBytes", "maxProcesses"]) {
    if (limits[field] !== undefined && !isPositiveInteger(limits[field])) {
      issues.push(`limits.${field}: must be a positive integer`);
    }
  }
}

function validatePolicy(policy, issues) {
  if (policy === undefined) return;
  if (!isPlainObject(policy)) {
    issues.push("policy: must be a plain object");
    return;
  }
  for (const field of [
    "allowCommands",
    "denyCommands",
    "allowedRoots",
    "allowedExecutableRoots",
  ]) {
    if (policy[field] === undefined) continue;
    const list = policy[field];
    if (
      !Array.isArray(list) ||
      !list.every((entry) => typeof entry === "string" && entry.trim() !== "")
    ) {
      issues.push(`policy.${field}: must be an array of non-empty strings`);
    }
  }
  if (
    policy.network !== undefined &&
    (typeof policy.network !== "string" || policy.network.trim() === "")
  ) {
    issues.push("policy.network: must be a non-empty string");
  }
  for (const field of ["maxDurationMs", "maxOutputBytes", "maxProcesses"]) {
    if (policy[field] !== undefined && !isPositiveInteger(policy[field])) {
      issues.push(`policy.${field}: must be a positive integer`);
    }
  }
}

/** Throw a single structured `ValidationError` for any malformed input. */
function validateExecutionInput(request, options) {
  const issues = [];

  if (!isPlainObject(request)) {
    issues.push("request: must be a plain object");
  } else {
    for (const key of Object.keys(request)) {
      if (!REQUEST_KEYS.includes(key)) {
        issues.push(`request.${key}: unknown field`);
      }
    }
    if (typeof request.command !== "string" || request.command.trim() === "") {
      issues.push("command: must be a non-empty string");
    }
    if (
      request.args !== undefined &&
      (!Array.isArray(request.args) ||
        !request.args.every((arg) => typeof arg === "string"))
    ) {
      issues.push("args: must be an array of strings");
    }
    if (
      request.cwd !== undefined &&
      (typeof request.cwd !== "string" || request.cwd.trim() === "")
    ) {
      issues.push("cwd: must be a non-empty string");
    }
    validateEnvironment(request.environment, issues);
    if (request.timeout !== undefined && !isPositiveInteger(request.timeout)) {
      issues.push("timeout: must be a positive integer (milliseconds)");
    }
    validateLimits(request.limits, issues);
    validatePolicy(request.policy, issues);
  }

  if (!isPlainObject(options)) {
    issues.push("options: must be a plain object");
  } else {
    for (const key of Object.keys(options)) {
      if (!OPTION_KEYS.includes(key)) {
        issues.push(`options.${key}: unknown option`);
      }
    }
    for (const field of ["maxStdoutBytes", "maxStderrBytes"]) {
      if (options[field] !== undefined && !isPositiveInteger(options[field])) {
        issues.push(`options.${field}: must be a positive integer`);
      }
    }
    if (
      options.terminationGraceMs !== undefined &&
      !isNonNegativeInteger(options.terminationGraceMs)
    ) {
      issues.push(
        "options.terminationGraceMs: must be a non-negative integer (milliseconds)",
      );
    }
    if (
      options.inheritEnvironment !== undefined &&
      typeof options.inheritEnvironment !== "boolean"
    ) {
      issues.push("options.inheritEnvironment: must be a boolean");
    }
    if (options.signal !== undefined) {
      const signal = options.signal;
      const looksLikeSignal =
        signal !== null &&
        typeof signal === "object" &&
        typeof signal.aborted === "boolean" &&
        typeof signal.addEventListener === "function";
      if (!looksLikeSignal) {
        issues.push("options.signal: must be an AbortSignal");
      }
    }
    if (options.shell !== undefined && options.shell !== false) {
      issues.push("options.shell: shell execution is not supported");
    }
  }

  if (issues.length > 0) {
    throw new ValidationError("Invalid execution request", {
      details: { contract: "ExecutionRequest", issues },
    });
  }
}

// ─── Result construction ─────────────────────────────────────────────────────

function baseResult({ command, args, identity, limits, policy }) {
  return {
    status: null,
    command,
    args,
    identity,
    cwd: null,
    pid: null,
    exitCode: null,
    signal: null,
    stdout: "",
    stderr: "",
    duration: 0,
    timedOut: false,
    killed: false,
    canceled: false,
    stdoutTruncated: false,
    stderrTruncated: false,
    truncated: false,
    limits,
    policy,
    error: null,
  };
}

function rejectedResult(base, kind, cwd, startTime) {
  return {
    ...base,
    status: EXECUTION_STATUS.REJECTED,
    cwd: cwd ?? null,
    duration: Date.now() - startTime,
    error: new CommandExecutionError({
      kind,
      command: base.identity,
      cwd: cwd ?? null,
    }),
  };
}

function canceledResult(base, cwd, startTime) {
  return {
    ...base,
    status: EXECUTION_STATUS.CANCELED,
    cwd: cwd ?? null,
    canceled: true,
    duration: Date.now() - startTime,
  };
}

function spawnFailedResult(base, cwd, startTime, cause) {
  return {
    ...base,
    status: EXECUTION_STATUS.SPAWN_FAILED,
    cwd: cwd ?? null,
    duration: Date.now() - startTime,
    error: new CommandExecutionError({
      kind: EXECUTION_ERROR_KINDS.SPAWN_FAILED,
      command: base.identity,
      cwd: cwd ?? null,
      cause,
    }),
  };
}

// ─── Child lifecycle ─────────────────────────────────────────────────────────

/** Bounded collector: never grows past the stream's byte cap. */
function makeCollector(state) {
  return (chunk) => {
    if (state.truncated) return; // keep draining the pipe, discard the bytes
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    const remaining = state.limit - state.bytes;
    if (buffer.length > remaining) {
      if (remaining > 0) state.chunks.push(buffer.subarray(0, remaining));
      state.bytes = state.limit;
      state.truncated = true;
    } else {
      state.chunks.push(buffer);
      state.bytes += buffer.length;
    }
  };
}

function statusForClose({ timedOut, canceled, signal, code }) {
  if (timedOut) return EXECUTION_STATUS.TIMED_OUT;
  if (canceled) return EXECUTION_STATUS.CANCELED;
  if (signal !== null && signal !== undefined) return EXECUTION_STATUS.KILLED;
  return code === 0
    ? EXECUTION_STATUS.COMPLETED
    : EXECUTION_STATUS.NON_ZERO_EXIT;
}

function runChild({ child, base, cwdRelative, limits, signal, startTime }) {
  return new Promise((resolve) => {
    let settled = false;
    let timedOut = false;
    let canceled = false;
    let killed = false;
    let timeoutTimer = null;
    let graceTimer = null;

    const stdoutState = {
      chunks: [],
      bytes: 0,
      truncated: false,
      limit: limits.maxStdoutBytes,
    };
    const stderrState = {
      chunks: [],
      bytes: 0,
      truncated: false,
      limit: limits.maxStderrBytes,
    };

    const cleanup = () => {
      if (timeoutTimer) {
        clearTimeout(timeoutTimer);
        timeoutTimer = null;
      }
      if (graceTimer) {
        clearTimeout(graceTimer);
        graceTimer = null;
      }
      if (signal) signal.removeEventListener?.("abort", onAbort);
    };

    const finish = (status, { exitCode = null, signal: termSignal = null, error = null } = {}) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (termSignal !== null && termSignal !== undefined) killed = true;
      resolve({
        ...base,
        status,
        cwd: cwdRelative,
        pid: child.pid ?? null,
        exitCode,
        signal: termSignal,
        stdout: Buffer.concat(stdoutState.chunks, stdoutState.bytes).toString(
          "utf8",
        ),
        stderr: Buffer.concat(stderrState.chunks, stderrState.bytes).toString(
          "utf8",
        ),
        duration: Date.now() - startTime,
        timedOut,
        killed,
        canceled,
        stdoutTruncated: stdoutState.truncated,
        stderrTruncated: stderrState.truncated,
        truncated: stdoutState.truncated || stderrState.truncated,
        error,
      });
    };

    // Idempotent: timeout and cancellation can both request termination, and
    // a second call must not stage a second grace timer (which would orphan the
    // first) or re-signal an already-dead process.
    const requestTermination = () => {
      killed = true;
      try {
        child.kill("SIGTERM");
      } catch {
        // the process may already be gone
      }
      if (graceTimer) return;
      graceTimer = setTimeout(() => {
        try {
          child.kill("SIGKILL");
        } catch {
          // the process may already be gone
        }
      }, limits.terminationGraceMs);
      graceTimer.unref?.();
    };

    // Guarded so a synchronous re-check after registration cannot terminate
    // twice when the listener already fired.
    function onAbort() {
      if (settled || canceled) return;
      canceled = true;
      requestTermination();
    }

    child.stdout?.on("data", makeCollector(stdoutState));
    child.stderr?.on("data", makeCollector(stderrState));
    // A closed/aborted pipe must never surface as an unhandled 'error'.
    child.stdout?.on("error", () => {});
    child.stderr?.on("error", () => {});

    if (signal) {
      signal.addEventListener?.("abort", onAbort, { once: true });
      // Close the registration race: an abort that lands between the pre-spawn
      // check and this subscription is never replayed to a late listener, so
      // re-check immediately instead of relying on timing.
      if (signal.aborted) onAbort();
    }

    timeoutTimer = setTimeout(() => {
      if (settled) return;
      timedOut = true;
      requestTermination();
    }, limits.timeoutMs);

    // Spawn failures (e.g. ENOENT) surface as 'error'; 'close' may follow.
    child.once("error", (error) => {
      finish(EXECUTION_STATUS.SPAWN_FAILED, {
        error: new CommandExecutionError({
          kind: EXECUTION_ERROR_KINDS.SPAWN_FAILED,
          command: base.identity,
          cwd: cwdRelative,
          cause: error,
        }),
      });
    });

    child.once("close", (code, termSignal) => {
      finish(statusForClose({ timedOut, canceled, signal: termSignal, code }), {
        exitCode: code,
        signal: termSignal,
      });
    });
  });
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Execute a single command under explicit policy and resource limits.
 *
 * @param {object} request Core `ExecutionRequest`-shaped input.
 * @param {string} request.command Executable (no shell interpretation).
 * @param {string[]} [request.args] Arguments, passed verbatim.
 * @param {string} [request.cwd] Repository-relative or absolute cwd.
 * @param {object} [request.environment] String environment overrides.
 * @param {number} [request.timeout] Request duration cap, in ms.
 * @param {object} [request.limits] `{ maxOutputBytes, maxProcesses }`.
 * @param {object} [request.policy] Core `ExecutionPolicy`-shaped authorization,
 *   including `allowedExecutableRoots` for authorized executable directories.
 * @param {object} [options] Runner options.
 * @param {number} [options.terminationGraceMs] Delay before SIGKILL.
 * @param {number} [options.maxStdoutBytes] Per-stream stdout cap.
 * @param {number} [options.maxStderrBytes] Per-stream stderr cap.
 * @param {boolean} [options.inheritEnvironment] Inherit the parent env.
 * @param {AbortSignal} [options.signal] Cancellation signal.
 * @returns {Promise<object>} A structured execution result.
 * @throws {ValidationError} When the request or options are malformed.
 */
export async function runExecution(request, options = {}) {
  validateExecutionInput(request, options);
  const startTime = Date.now();

  const command = request.command;
  const args = [...(request.args ?? [])];
  const policy = request.policy ?? {};
  const limits = request.limits ?? {};
  const overrides = request.environment ?? {};
  const signal = options.signal;

  // Resolution and authorization both use the *trusted* environment (the
  // runner's own inherited environment) — never the caller's overrides — and
  // the executable that was authorized is the exact path that gets spawned.
  const trustedRoots = trustedExecutableRoots();

  // The working directory is resolved first: a relative executable is only
  // meaningful relative to the directory the command will actually run in, so
  // authorization must see the same base the process will be given. A cwd that
  // cannot be authorized yields no base, which leaves relative commands
  // unresolved instead of falling back to the runner's own process cwd.
  const cwdResolution = await resolveExecutionCwd(
    request.cwd,
    policy.allowedRoots ?? [],
  );
  const executionCwd = cwdResolution.ok ? cwdResolution.absolute : null;

  const resolution = resolveCommandExecutable(command, trustedRoots, {
    baseDir: executionCwd,
  });
  const commandPolicy = evaluateCommandPolicy(command, policy, {
    resolvedPath: resolution.resolvedPath,
    trustedRoots,
    cwd: executionCwd,
  });
  const { resolvedPath, ...policyDecision } = commandPolicy;

  const effectiveLimits = resolveExecutionLimits({
    policy,
    limits,
    timeout: request.timeout,
    options,
  });

  const base = baseResult({
    command,
    args,
    identity: policyDecision.identity,
    limits: effectiveLimits,
    policy: policyDecision,
  });

  if (signal?.aborted) return canceledResult(base, null, startTime);
  // Policy is evaluated before the cwd rejection so an explicit deny is always
  // visible; both are rejections and neither spawns anything.
  if (!commandPolicy.allowed || resolvedPath === null) {
    return rejectedResult(
      base,
      commandPolicy.kind ?? EXECUTION_ERROR_KINDS.COMMAND_NOT_RESOLVED,
      null,
      startTime,
    );
  }

  if (!cwdResolution.ok) {
    return rejectedResult(
      base,
      cwdResolution.kind,
      cwdResolution.cwd,
      startTime,
    );
  }

  if (signal?.aborted) {
    return canceledResult(base, cwdResolution.relative, startTime);
  }

  const environment = buildEnvironment(
    overrides,
    options.inheritEnvironment === false ? {} : process.env,
  );

  let child;
  try {
    child = spawn(resolvedPath, args, {
      cwd: cwdResolution.absolute,
      env: environment,
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (error) {
    return spawnFailedResult(base, cwdResolution.relative, startTime, error);
  }

  return runChild({
    child,
    base,
    cwdRelative: cwdResolution.relative,
    limits: effectiveLimits,
    signal,
    startTime,
  });
}
