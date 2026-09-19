/**
 * Code Guardian — Execution Limit Resolution (Phase 8B)
 *
 * Limits arrive from several layers and must be combined deterministically.
 * The accepted Phase 7 rule is `EXECUTION_LIMIT_PRECEDENCE =
 * "most-restrictive"`: wherever two layers name the same dimension, the smaller
 * value wins, so a request can only narrow what the policy authorizes — never
 * widen it.
 *
 * Layers, from broadest to narrowest:
 *
 *   policy.maxDurationMs / maxOutputBytes / maxProcesses   authorization ceilings
 *   request.timeout / limits.maxOutputBytes / maxProcesses per-invocation caps
 *   options.maxStdoutBytes / maxStderrBytes / terminationGraceMs  explicit tightening
 *
 * `maxOutputBytes` is interpreted as a cap applied to **each stream
 * independently** (stdout and stderr), matching the Phase 8B requirement for
 * independent output limits. `terminationGraceMs` is a runner knob with no
 * policy counterpart and is not subject to the most-restrictive rule.
 *
 * Nothing is enforced that Node cannot enforce cross-platform: `maxProcesses`
 * is recorded for compatibility, but 8B runs exactly one process per call.
 */

import {
  DEFAULT_EXECUTION_TIMEOUT_MS,
  DEFAULT_MAX_OUTPUT_BYTES,
} from "../core/index.js";

/** Default delay between requesting and forcing process termination. */
export const DEFAULT_TERMINATION_GRACE_MS = 5000;

function mostRestrictive(...values) {
  return values.reduce((smallest, value) =>
    value < smallest ? value : smallest,
  );
}

/**
 * Resolve the effective limits for one invocation.
 *
 * @param {object} [input]
 * @param {object} [input.policy] Core `ExecutionPolicy`-shaped ceilings.
 * @param {object} [input.limits] Core `ExecutionLimits`-shaped request caps.
 * @param {number} [input.timeout] Request-level duration cap, in ms.
 * @param {object} [input.options] Runner options (`maxStdoutBytes`, ...).
 * @returns {{ timeoutMs: number, terminationGraceMs: number, maxStdoutBytes: number, maxStderrBytes: number, maxProcesses: number }}
 */
export function resolveExecutionLimits({
  policy = {},
  limits = {},
  timeout,
  options = {},
} = {}) {
  const policyDuration = policy.maxDurationMs ?? DEFAULT_EXECUTION_TIMEOUT_MS;
  const requestDuration = timeout ?? policyDuration;
  const timeoutMs = mostRestrictive(policyDuration, requestDuration);

  const policyOutput = policy.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
  const requestOutput = limits.maxOutputBytes ?? policyOutput;
  const outputCeiling = mostRestrictive(policyOutput, requestOutput);

  const maxStdoutBytes =
    options.maxStdoutBytes === undefined
      ? outputCeiling
      : mostRestrictive(outputCeiling, options.maxStdoutBytes);
  const maxStderrBytes =
    options.maxStderrBytes === undefined
      ? outputCeiling
      : mostRestrictive(outputCeiling, options.maxStderrBytes);

  const policyProcesses = policy.maxProcesses ?? 1;
  const requestProcesses = limits.maxProcesses ?? policyProcesses;
  const maxProcesses = mostRestrictive(policyProcesses, requestProcesses);

  const terminationGraceMs =
    options.terminationGraceMs ?? DEFAULT_TERMINATION_GRACE_MS;

  return {
    timeoutMs,
    terminationGraceMs,
    maxStdoutBytes,
    maxStderrBytes,
    maxProcesses,
  };
}
