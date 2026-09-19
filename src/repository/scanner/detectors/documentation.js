/**
 * Code Guardian — Documentation Signal Detection (Phase 8C)
 *
 * Records the presence of human-facing documentation artifacts. It does not
 * evaluate quality, completeness or currency: an empty `README.md` and a
 * thorough one are the same fact to a scanner.
 *
 * Matching is case-insensitive for these entry points (`README.md`, `readme.md`
 * and `Readme.md` are the same artifact to a developer, and the difference is
 * only meaningful on case-sensitive filesystems).
 */

import { capEvidence, compareEvidence, SCAN_SIGNALS } from "../contracts.js";
import { matchEntries } from "./match.js";

/** Ordered documentation rules (most specific first). */
export const DOCUMENTATION_RULES = Object.freeze([
  { basenamePattern: "CHANGELOG*", caseInsensitive: true, signal: SCAN_SIGNALS.CHANGELOG },
  { basenamePattern: "CHANGES*", caseInsensitive: true, signal: SCAN_SIGNALS.CHANGELOG },
  { basenamePattern: "CONTRIBUTING*", caseInsensitive: true, signal: SCAN_SIGNALS.CONTRIBUTING },
  { basenamePattern: "CODE_OF_CONDUCT*", caseInsensitive: true, signal: SCAN_SIGNALS.CODE_OF_CONDUCT },
  { basenamePattern: "README*", caseInsensitive: true, signal: SCAN_SIGNALS.README },
  {
    directoryName: ["docs", "doc", "documentation"],
    caseInsensitive: true,
    signal: SCAN_SIGNALS.DOCUMENTATION_DIRECTORY,
  },
]);

/**
 * Detect documentation signals.
 *
 * @param {object} view Repository view.
 * @returns {{ detected: boolean, evidence: object[], evidenceTruncated: boolean }}
 */
export function detectDocumentation(view) {
  const entries = view.directories.concat(view.files);
  const matches = matchEntries(DOCUMENTATION_RULES, entries);

  const evidence = matches.map(({ rule, entry }) => ({
    path: entry.path,
    signal: rule.signal,
    isDirectory: entry.isDirectory,
  }));

  const ordered = evidence.sort(compareEvidence);
  const capped = capEvidence(ordered);

  return {
    detected: ordered.length > 0,
    evidence: capped.evidence,
    evidenceTruncated: capped.evidenceTruncated,
  };
}
