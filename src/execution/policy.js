/**
 * Code Guardian — Command Policy (Phase 8B)
 *
 * Pure, deterministic command authorization. No process is spawned here, which
 * makes the policy independently unit-testable.
 *
 * Semantics are fixed by the accepted Phase 7 contract
 * (`EXECUTION_COMMAND_PRECEDENCE = "deny-overrides-allow"`):
 *
 *   - An explicit deny always beats an allow.
 *   - `denyCommands: []` denies nothing by name.
 *   - `allowCommands: []` grants nothing — it is an empty allowlist, never
 *     "allow everything". A deny-only policy therefore authorizes nothing.
 *
 * Matching is against the *executable identity*, not the raw command string:
 * the basename of `command`, with a Windows executable extension stripped and
 * case-folded on Windows. Matching is exact (no prefix, no wildcard), so
 * `node-malicious` can never satisfy an allowlist entry of `node`.
 *
 * Executable *location* is intentionally not part of the policy: `node` may be
 * resolved anywhere on `PATH` (Phase 8B §12). Repository containment governs
 * the working directory (see `cwd.js`), not executable lookup.
 */

import nodePath from "node:path";

import { EXECUTION_ERROR_KINDS } from "./errors.js";

const WINDOWS = process.platform === "win32";
const WINDOWS_EXECUTABLE_EXTENSION = /\.(exe|cmd|bat|com)$/i;

/**
 * Normalize a command or allowlist entry to a comparable executable identity.
 * @param {string} command
 * @returns {string}
 */
export function commandIdentity(command) {
  const base = nodePath.basename(String(command));
  const stripped = WINDOWS
    ? base.replace(WINDOWS_EXECUTABLE_EXTENSION, "")
    : base;
  return WINDOWS ? stripped.toLowerCase() : stripped;
}

function normalizeList(entries) {
  return new Set((entries ?? []).map((entry) => commandIdentity(entry)));
}

/**
 * Evaluate whether a command is authorized by a policy.
 *
 * @param {string} command Executable to run.
 * @param {object} [policy] Execution policy (Core `ExecutionPolicy` shape).
 * @returns {{ allowed: boolean, identity: string, reason: string|null, kind: string|null }}
 */
export function evaluateCommandPolicy(command, policy = {}) {
  const identity = commandIdentity(command);
  const allow = normalizeList(policy.allowCommands);
  const deny = normalizeList(policy.denyCommands);

  if (deny.has(identity)) {
    return {
      allowed: false,
      identity,
      reason: "denied",
      kind: EXECUTION_ERROR_KINDS.COMMAND_DENIED,
    };
  }

  if (allow.size === 0 || !allow.has(identity)) {
    return {
      allowed: false,
      identity,
      reason: "not-allowed",
      kind: EXECUTION_ERROR_KINDS.COMMAND_NOT_ALLOWED,
    };
  }

  return { allowed: true, identity, reason: null, kind: null };
}
