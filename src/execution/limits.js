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
 * Timer delays must stay *truthful*. `setTimeout` cannot represent a delay
 * above `MAX_TIMER_DELAY_MS`: Node clamps anything larger to **1 ms** and emits
 * a `TimeoutOverflowWarning`, so a declared long budget would silently become an
 * immediate kill while `limits.timeoutMs` still reported the declared value —
 * an unenforced limit recorded as if it were enforced. Resolving such a value
 * is therefore a structured `ValidationError` rather than a silent clamp.
 *
 * Only the *effective* delays are range-checked, never the declaring layers: a
 * policy ceiling that is large but always narrowed by the request (or the
 * default) still resolves to a usable value and keeps working.
 *
 * Nothing is enforced that Node cannot enforce cross-platform: `maxProcesses`
 * is recorded for compatibility, but 8B runs exactly one process per call.
 */

import {
  DEFAULT_EXECUTION_TIMEOUT_MS,
  DEFAULT_MAX_OUTPUT_BYTES,
  ValidationError,
} from "../core/index.js";

/** Default delay between requesting and forcing process termination. */
export const DEFAULT_TERMINATION_GRACE_MS = 5000;

/**
 * Largest delay `setTimeout` can represent (a signed 32-bit millisecond count).
 * Larger values are clamped to 1 ms by Node, so the runner refuses them instead
 * of recording a limit it cannot enforce.
 */
export const MAX_TIMER_DELAY_MS = 2147483647;

function mostRestrictive(...values) {
  return values.reduce((smallest, value) =>
    value < smallest ? value : smallest,
  );
}

/**
 * Reject an effective timer delay the platform cannot represent.
 *
 * @param {string} name Field name reported in the validation issue.
 * @param {number} value Resolved delay, in milliseconds.
 * @returns {number} The same value when it is representable.
 * @throws {ValidationError} When the delay would be clamped by `setTimeout`.
 */
function requireRepresentableDelay(name, value) {
  if (value > MAX_TIMER_DELAY_MS) {
    throw new ValidationError("Invalid execution limits", {
      details: {
        contract: "ExecutionLimits",
        issues: [
          `${name}: must not exceed ${MAX_TIMER_DELAY_MS} ms ` +
            "(maximum timer delay)",
        ],
      },
    });
  }
  return value;
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
    timeoutMs: requireRepresentableDelay("timeoutMs", timeoutMs),
    terminationGraceMs: requireRepresentableDelay(
      "terminationGraceMs",
      terminationGraceMs,
    ),
    maxStdoutBytes,
    maxStderrBytes,
    maxProcesses,
  };
}
