/**
 * Code Guardian — Repository Policy Detector (Phase 22)
 *
 * Reads the one document this architecture treats as a repository-owned contract:
 * `.codeguardian/policy.json`. It records exactly what the file established — and, when it
 * established nothing, why — so the model can decide whether a policy exists before any
 * compliance question is asked.
 *
 * Four answers, and none of them is "assume the best":
 *
 *   - `absent`      neither the contracted path nor a policy-shaped path in another format was
 *                   observed. What the repository declares is therefore "no policy", and the
 *                   model may say so — subject to its own coverage statement.
 *   - `parsed`      the file was read, parsed as JSON and satisfied the closed schema. The
 *                   document it carries is the *rebuilt* canonical one, never the parsed value.
 *   - `failed`      the file was observed but could not be interpreted: unreadable, too large,
 *                   not text, not JSON, not an object, an unknown domain, an unknown key, a
 *                   value of the wrong type or a value out of range. A malformed policy is a
 *                   refusal, never a partly-applied contract.
 *   - `unsupported` a `.codeguardian/policy.yaml` (or `.yml`) exists and no JSON document does.
 *                   This build does not read YAML, so it says so rather than reporting the
 *                   repository as having no policy at all.
 *
 * The read is bounded (`POLICY_LIMITS.maxFileBytes`), goes through `view.read` — the Phase 8A
 * boundary, so containment and the symlink policy apply — and nothing is ever written. The
 * contracted path decides: when it exists, an alternative-format file is not consulted at all.
 */

import {
  POLICY_DOCUMENT_PATH,
  POLICY_FAILURE_REASONS,
  POLICY_LIMITS,
  POLICY_SOURCE_STATUSES,
  POLICY_UNREAD_FORMATS,
  POLICY_UNSUPPORTED_REASONS,
  boundedPolicyToken,
  parsePolicyDocument,
} from "../policies/policy.js";

/**
 * Read the repository's policy document.
 *
 * @param {object} view Repository view built by the scanner.
 * @returns {Promise<object>} One record: what was observed, what was established, and why not.
 */
export async function detectPolicy(view) {
  const observed = new Set(view.files.map((entry) => entry.path));

  if (observed.has(POLICY_DOCUMENT_PATH)) {
    const result = await view.read(POLICY_DOCUMENT_PATH, {
      maxBytes: POLICY_LIMITS.maxFileBytes,
    });

    if (!result.ok) {
      return {
        path: POLICY_DOCUMENT_PATH,
        detected: true,
        inspected: false,
        status: POLICY_SOURCE_STATUSES.FAILED,
        // The classified error kind is a bounded token, never a platform message.
        reason: POLICY_FAILURE_REASONS.READ_FAILED,
        detail: boundedPolicyToken(result.error?.kind),
        document: null,
      };
    }

    if (result.truncated === true) {
      return {
        path: POLICY_DOCUMENT_PATH,
        detected: true,
        inspected: false,
        status: POLICY_SOURCE_STATUSES.FAILED,
        reason: POLICY_FAILURE_REASONS.TOO_LARGE,
        detail: null,
        document: null,
      };
    }

    const parsed = parsePolicyDocument(result.content);
    if (!parsed.ok) {
      return {
        path: POLICY_DOCUMENT_PATH,
        detected: true,
        inspected: true,
        status: POLICY_SOURCE_STATUSES.FAILED,
        reason: parsed.reason,
        detail: parsed.detail,
        document: null,
      };
    }

    return {
      path: POLICY_DOCUMENT_PATH,
      detected: true,
      inspected: true,
      status: POLICY_SOURCE_STATUSES.PARSED,
      reason: null,
      detail: null,
      document: parsed.document,
    };
  }

  // The contracted path is absent. A policy document in a format this build does not read is
  // recorded as exactly that, so the model can say `unsupported` rather than "no policy".
  const unread = POLICY_UNREAD_FORMATS.find((entry) => observed.has(entry.path)) ?? null;
  if (unread !== null) {
    return {
      path: POLICY_DOCUMENT_PATH,
      detected: false,
      inspected: false,
      status: POLICY_SOURCE_STATUSES.UNSUPPORTED,
      reason: POLICY_UNSUPPORTED_REASONS.FORMAT_NOT_INTERPRETED,
      detail: unread.format,
      document: null,
    };
  }

  return {
    path: POLICY_DOCUMENT_PATH,
    detected: false,
    inspected: false,
    status: POLICY_SOURCE_STATUSES.ABSENT,
    reason: null,
    detail: null,
    document: null,
  };
}
