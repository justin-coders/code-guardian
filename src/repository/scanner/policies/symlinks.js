/**
 * Code Guardian — Scanner Symlink Target Policy (Phase 12 correction)
 *
 * Phase 8A refuses to *follow* a symlink, so the inventory records a link without
 * ever resolving it. That is the right safety policy, but it left one question
 * unanswerable: does this link point out of the repository? "A symlink exists" and
 * "a symlink escapes" are different facts, and only the second one is a security
 * observation.
 *
 * This module answers it **without following anything**. For every symlink in the
 * inventory it performs one `readLink` (a `readlink(2)` on the link itself, no
 * `stat`, no open of the target) and classifies the target into the closed
 * vocabulary the filesystem layer defines:
 *
 *   inside   the target resolves inside the repository; the model records it as a
 *            repository-relative path, so a consumer can compare it with the
 *            inventory without ever seeing a host location
 *   outside  the target escapes the repository, or is an absolute path that does
 *            not point back into it. Its text is discarded — a host path is
 *            exactly what must not travel with the model
 *   unknown  the link could not be read at all
 *
 * ### Chains
 *
 * A `/outside` target is not the only way out. `a -> b`, `b -> /outside` escapes,
 * and `a -> b`, `b -> a` loops forever. Both are detected here from the recorded
 * *one-hop* facts, never by resolving: the chain walk is a bounded table lookup
 * (`MAX_SYMLINK_CHAIN` hops, visited-set cycle detection) over links the inventory
 * already contains, so the total work is linear in the number of links and no link
 * is ever opened twice. A hop that leaves the recorded link set ends the chain:
 * the target is a real file or directory, or it does not exist, and either way it
 * cannot escape — only a link can point outside.
 *
 * The result is a *pointwise* classification, so the model can state a fact about
 * one link rather than a repository-wide verdict. Absence of a target record
 * (`not-inspected`) is reported as `unknown`, never as `inside`: a scanner that
 * skipped the inspection must not read as "this link is safe".
 */

import {
  LINK_TARGET_KINDS,
  LINK_UNKNOWN_REASONS,
  readLink,
} from "../../filesystem/index.js";

/** Maximum link hops followed while resolving a chain of recorded targets. */
export const MAX_SYMLINK_CHAIN = 8;

/** Every reason a symlink target can be `unknown`. */
export const SYMLINK_UNKNOWN_REASONS = Object.freeze({
  NOT_INSPECTED: LINK_UNKNOWN_REASONS.NOT_INSPECTED,
  UNREADABLE: LINK_UNKNOWN_REASONS.UNREADABLE,
  CYCLE: LINK_UNKNOWN_REASONS.CYCLE,
  DEPTH_EXCEEDED: LINK_UNKNOWN_REASONS.DEPTH_EXCEEDED,
});

const REASON_VALUES = Object.freeze(Object.values(SYMLINK_UNKNOWN_REASONS));

/** Whether a value is a reason this policy can produce. */
export function isSymlinkUnknownReason(value) {
  return typeof value === "string" && REASON_VALUES.includes(value);
}

function inside(path) {
  return { kind: LINK_TARGET_KINDS.INSIDE, path, reason: null };
}

function outside() {
  return { kind: LINK_TARGET_KINDS.OUTSIDE, path: null, reason: null };
}

function unknown(reason) {
  return { kind: LINK_TARGET_KINDS.UNKNOWN, path: null, reason };
}

/**
 * Resolve a chain of *recorded* link targets, without touching the filesystem.
 *
 * Exported so the chain rules can be tested directly on Windows, where creating a
 * real symlink may require privileges the test runner does not have.
 *
 * @param {string} startPath Repository-relative path of the link being resolved.
 * @param {Map<string, object>} oneHopByPath One-hop classifications by link path.
 * @param {number} [maxChain] Maximum hops.
 * @returns {{kind: string, path: string|null, reason: string|null}}
 */
export function resolveSymlinkChain(startPath, oneHopByPath, maxChain = MAX_SYMLINK_CHAIN) {
  const visited = new Set([startPath]);
  let current = oneHopByPath.get(startPath);
  if (current === undefined) return unknown(SYMLINK_UNKNOWN_REASONS.NOT_INSPECTED);
  if (current.kind !== LINK_TARGET_KINDS.INSIDE) {
    return current.kind === LINK_TARGET_KINDS.OUTSIDE ? outside() : current;
  }

  let hops = 0;
  while (hops < maxChain) {
    const nextPath = current.path;
    // The target is the repository root itself, or a path outside the recorded link
    // set: either way the chain ends inside and cannot escape.
    if (nextPath === null) return inside(null);
    const next = oneHopByPath.get(nextPath);
    if (next === undefined) return inside(nextPath);

    if (next.kind === LINK_TARGET_KINDS.OUTSIDE) return outside();
    if (next.kind === LINK_TARGET_KINDS.UNKNOWN) return next;
    if (visited.has(nextPath)) return unknown(SYMLINK_UNKNOWN_REASONS.CYCLE);

    visited.add(nextPath);
    hops += 1;
    current = next;
  }

  return unknown(SYMLINK_UNKNOWN_REASONS.DEPTH_EXCEEDED);
}

/**
 * Classify every symlink in the inventory.
 *
 * @param {string} root Absolute repository root.
 * @param {Array<{relative: string}>} symlinks Walked symlink entries.
 * @returns {Promise<Map<string, {kind: string, path: string|null, reason: string|null}>>}
 *   One classification per symlink path, in the inventory's order.
 */
export async function resolveSymlinkTargets(root, symlinks) {
  const oneHop = new Map();

  for (const entry of symlinks) {
    const result = await readLink(root, entry.relative);
    if (!result.ok) {
      // The link could not be read (permissions, or it stopped being a link
      // between the walk and this read). The target is not established, and the
      // model must say so rather than assume the link is harmless.
      oneHop.set(entry.relative, unknown(SYMLINK_UNKNOWN_REASONS.UNREADABLE));
      continue;
    }
    oneHop.set(entry.relative, result.target);
  }

  const targets = new Map();
  for (const entry of symlinks) {
    targets.set(entry.relative, resolveSymlinkChain(entry.relative, oneHop));
  }
  return targets;
}

/** A `not-inspected` target, for a symlink the scanner never classified. */
export function uninspectedTarget() {
  return unknown(SYMLINK_UNKNOWN_REASONS.NOT_INSPECTED);
}
