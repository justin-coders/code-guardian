/**
 * Code Guardian — Command Policy (Phase 8B)
 *
 * Deterministic command authorization. No process is spawned here.
 *
 * Semantics fixed by the accepted Phase 7 contract
 * (`EXECUTION_COMMAND_PRECEDENCE = "deny-overrides-allow"`):
 *
 *   - An explicit deny always beats an allow.
 *   - `denyCommands: []` denies nothing by name.
 *   - `allowCommands: []` grants nothing — it is an empty allowlist, never
 *     "allow everything". A deny-only policy therefore authorizes nothing.
 *
 * Matching is against the *executable identity* (basename, Windows executable
 * extension stripped and case-folded on Windows), and is exact — no prefix, no
 * wildcard — so `node-malicious` can never satisfy an entry of `node`.
 *
 * Authorization is **name plus location**, because a name alone is not a
 * security boundary: `allowCommands: ["node"]` must not authorize
 * `/tmp/attacker/node`. An allow entry therefore resolves to one of two rules:
 *
 *   - bare entry (`node`)            → name rule; requires the resolved file to
 *                                      be trusted (on the trusted `PATH` roots,
 *                                      or under `policy.allowedExecutableRoots`)
 *   - path entry (`/usr/bin/node`)   → explicit location rule; authorizes that
 *                                      exact canonical file and nothing else
 *
 * `policy.allowedExecutableRoots` is an additive Phase 8B policy field (Core's
 * policy validation accepts it unchanged) for deliberately authorizing an
 * executable *directory* — e.g. a repository-local toolchain.
 *
 * A deny entry is deliberately location-agnostic when bare: `denyCommands:
 * ["node"]` denies every file named `node`, wherever it lives.
 *
 * Pure matching lives in `evaluateCommandPolicy`; the only filesystem access is
 * canonicalizing explicit paths (`realpath`), delegated to `executable.js`.
 */

import { EXECUTION_ERROR_KINDS } from "./errors.js";
import {
  canonicalizeExecutablePath,
  canonicalizeExecutableRoot,
  commandIdentity,
  executablePathKey,
  isPathLikeExecutable,
  isWithinExecutableRoots,
} from "./executable.js";

export { commandIdentity };

function compileRules(entries) {
  const names = new Set();
  const paths = new Set();
  for (const entry of entries ?? []) {
    if (isPathLikeExecutable(entry)) {
      const canonical = canonicalizeExecutablePath(entry);
      if (canonical !== null) paths.add(executablePathKey(canonical));
    } else {
      names.add(commandIdentity(entry));
    }
  }
  return { names, paths };
}

function decision(allowed, identity, resolvedPath, reason, kind) {
  return { allowed, identity, resolvedPath, reason, kind };
}

/**
 * Evaluate whether a command is authorized by a policy.
 *
 * @param {string} command Executable to run.
 * @param {object} [policy] `ExecutionPolicy`-shaped authorization.
 * @param {string[]} [policy.allowCommands] Allowed names and/or explicit paths.
 * @param {string[]} [policy.denyCommands] Denied names and/or explicit paths.
 * @param {string[]} [policy.allowedExecutableRoots] Authorized executable dirs.
 * @param {object} [context]
 * @param {string|null} [context.resolvedPath] Canonical executable location.
 * @param {string[]} [context.trustedRoots] Trusted executable directories.
 * @returns {{
 *   allowed: boolean,
 *   identity: string,
 *   resolvedPath: string|null,
 *   reason: string|null,
 *   kind: string|null,
 * }}
 */
export function evaluateCommandPolicy(command, policy = {}, context = {}) {
  const identity = commandIdentity(command);
  const resolvedPath = context.resolvedPath ?? null;
  const pathKey = resolvedPath === null ? null : executablePathKey(resolvedPath);
  const trustedRoots = context.trustedRoots ?? [];

  const allow = compileRules(policy.allowCommands);
  const deny = compileRules(policy.denyCommands);

  // Deny overrides allow. A bare deny entry matches by name only, so it denies
  // the command wherever it resolves; an explicit path entry denies that file.
  if (deny.names.has(identity) || (pathKey !== null && deny.paths.has(pathKey))) {
    return decision(
      false,
      identity,
      resolvedPath,
      "denied",
      EXECUTION_ERROR_KINDS.COMMAND_DENIED,
    );
  }

  const byName = allow.names.has(identity);
  const byExplicitPath = pathKey !== null && allow.paths.has(pathKey);

  if (!byName && !byExplicitPath) {
    return decision(
      false,
      identity,
      resolvedPath,
      "not-allowed",
      EXECUTION_ERROR_KINDS.COMMAND_NOT_ALLOWED,
    );
  }

  if (resolvedPath === null) {
    return decision(
      false,
      identity,
      null,
      "unresolved",
      EXECUTION_ERROR_KINDS.COMMAND_NOT_RESOLVED,
    );
  }

  // A name rule additionally requires a trusted location; an explicit path rule
  // has already named the location deliberately.
  if (!byExplicitPath) {
    const allowedRoots = (policy.allowedExecutableRoots ?? [])
      .map(canonicalizeExecutableRoot)
      .filter((root) => root !== null);
    if (
      !isWithinExecutableRoots(resolvedPath, trustedRoots) &&
      !isWithinExecutableRoots(resolvedPath, allowedRoots)
    ) {
      return decision(
        false,
        identity,
        resolvedPath,
        "untrusted-location",
        EXECUTION_ERROR_KINDS.COMMAND_UNTRUSTED_LOCATION,
      );
    }
  }

  return decision(true, identity, resolvedPath, null, null);
}
