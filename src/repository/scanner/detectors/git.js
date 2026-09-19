/**
 * Code Guardian — Git Signal Detection (Phase 8C)
 *
 * Git metadata is read **without executing anything**. `.git/HEAD` is a plain
 * text file, so the current branch (or detached commit) is a deterministic file
 * read through the accepted Phase 8A boundary — no `git` process, no command
 * policy, no dependency on Git being installed. Scanning therefore never fails
 * because Git is unavailable.
 *
 * Deliberate omissions, each for a reason:
 *
 *   - `.git/config` is NOT read: remote URLs can embed credentials.
 *   - Refs other than `HEAD` are NOT read: enumerating refs is git's job, and
 *     doing it by hand would not be deterministic across packed/unpacked state.
 *   - Commit history, status and diff are NOT inspected: those need a command
 *     runner and belong to a later phase with an explicit command policy.
 *
 * The `.git` directory is excluded from the file *inventory* by the ignore
 * policy, which is exactly why this detector asks the filesystem boundary about
 * `.git` directly: repository metadata is the point of this section.
 *
 * Untrusted content is never echoed. A branch name is recorded only when it is a
 * well-formed `refs/...` name with no traversal segments, so a hostile
 * `.git/HEAD` cannot smuggle arbitrary text — or an absolute host path — into
 * the scan result.
 */

import { compareEvidence, SCAN_SIGNALS } from "../contracts.js";

/** Path of the repository metadata directory. */
export const GIT_DIRECTORY = ".git";

/** Largest prefix of `.git/HEAD` the detector inspects (bytes). */
export const MAX_HEAD_BYTES = 4096;

const REF_PATTERN = /^[A-Za-z0-9._/-]{1,200}$/;
const COMMIT_PATTERN = /^[0-9a-f]{7,64}$/;
const BRANCH_REF_PREFIX = "refs/heads/";
const REF_PREFIX = "refs/";

/**
 * Whether a ref from `.git/HEAD` may be recorded at all.
 *
 * A HEAD file is repository content and therefore hostile input. Only a
 * well-formed `refs/...` name with no parent traversal is echoed into the scan
 * result; anything else (absolute paths, `../`, arbitrary text) is reported as
 * `kind: "unknown"` with the content discarded. A hostile HEAD can influence
 * *whether* a ref is reported, never *what text* the result carries.
 *
 * @param {string} ref
 * @returns {boolean}
 */
function isReportableRef(ref) {
  if (!REF_PATTERN.test(ref)) return false;
  if (ref.startsWith("/") || !ref.startsWith(REF_PREFIX)) return false;
  return !ref.split("/").includes("..");
}

/** Head kinds the detector can report. */
export const GIT_HEAD_KINDS = Object.freeze({
  BRANCH: "branch",
  DETACHED: "detached",
  GITFILE: "gitfile",
  UNKNOWN: "unknown",
});

/**
 * Parse `.git/HEAD` content into a bounded, validated descriptor.
 *
 * @param {string} content
 * @returns {{ kind: string, branch?: string, ref?: string, commit?: string }}
 */
export function parseGitHead(content) {
  const window = String(content).slice(0, MAX_HEAD_BYTES);
  const line = window.split(/\r?\n/).find((entry) => entry.trim() !== "");
  if (line === undefined) return { kind: GIT_HEAD_KINDS.UNKNOWN };

  const trimmed = line.trim();
  if (trimmed.startsWith("ref: ")) {
    const ref = trimmed.slice("ref: ".length).trim();
    if (!isReportableRef(ref)) return { kind: GIT_HEAD_KINDS.UNKNOWN };
    if (ref.startsWith(BRANCH_REF_PREFIX)) {
      const branch = ref.slice(BRANCH_REF_PREFIX.length);
      if (branch === "") return { kind: GIT_HEAD_KINDS.UNKNOWN };
      return { kind: GIT_HEAD_KINDS.BRANCH, branch, ref };
    }
    // A symbolic HEAD that does not name a local branch (e.g. a remote ref) is
    // reported as unknown rather than guessed at.
    return { kind: GIT_HEAD_KINDS.UNKNOWN, ref };
  }

  if (COMMIT_PATTERN.test(trimmed)) {
    return { kind: GIT_HEAD_KINDS.DETACHED, commit: trimmed };
  }

  return { kind: GIT_HEAD_KINDS.UNKNOWN };
}

/**
 * Detect git presence and, when deterministically readable, the checked-out ref.
 *
 * @param {object} view Repository view.
 * @returns {Promise<{ detected: boolean, head: object|null, evidence: object[] }>}
 */
export async function detectGit(view) {
  const evidence = [];
  let head = null;

  const directory = await view.list(GIT_DIRECTORY);
  if (directory.ok) {
    evidence.push({ path: GIT_DIRECTORY, signal: SCAN_SIGNALS.GIT_DIRECTORY });

    const headRead = await view.read(`${GIT_DIRECTORY}/HEAD`);
    if (headRead.ok) {
      evidence.push({
        path: `${GIT_DIRECTORY}/HEAD`,
        signal: SCAN_SIGNALS.GIT_HEAD,
      });
      head = parseGitHead(headRead.content);
    } else {
      head = { kind: GIT_HEAD_KINDS.UNKNOWN };
    }
  } else {
    // Worktrees and submodules store `.git` as a file holding `gitdir: ...`.
    const fileRead = await view.read(GIT_DIRECTORY);
    if (fileRead.ok) {
      evidence.push({ path: GIT_DIRECTORY, signal: SCAN_SIGNALS.GIT_FILE });
      head = { kind: GIT_HEAD_KINDS.GITFILE };
    }
  }

  return {
    detected: evidence.length > 0,
    head,
    evidence: evidence.sort(compareEvidence),
  };
}
