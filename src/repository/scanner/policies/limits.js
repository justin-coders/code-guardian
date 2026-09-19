/**
 * Code Guardian — Scanner Limit Policy (Phase 8C)
 *
 * A repository scan must be bounded. The maxima come from the accepted Phase 7
 * `DEFAULT_SCAN_LIMITS` baseline so the scanner, the filesystem `walk` and the
 * future RepositoryModel agree on what "bounded" means.
 *
 * Limits are *declared*, never guessed: whatever the scanner actually used is
 * recorded on the result (`result.scan.limits`), so a truncated scan can be
 * recognised as truncated instead of being mistaken for a complete inventory.
 *
 * Invalid limits throw a Core `ValidationError` (matching `walk`) rather than
 * being silently replaced by defaults.
 */

import { DEFAULT_SCAN_LIMITS, ValidationError } from "../../../core/index.js";

/** Limits a scan uses when the caller declares none. */
export const DEFAULT_SCANNER_LIMITS = Object.freeze({
  maxFiles: DEFAULT_SCAN_LIMITS.maxFiles,
  maxDepth: DEFAULT_SCAN_LIMITS.maxDepth,
});

function isPositiveInteger(value) {
  return Number.isInteger(value) && value > 0;
}

/**
 * Validate and normalize scan limits.
 *
 * @param {object} [input] `{ maxFiles?, maxDepth? }`.
 * @returns {{ maxFiles: number, maxDepth: number }} The effective limits.
 * @throws {ValidationError} When a limit is not a positive integer.
 */
export function resolveScanLimits(input = {}) {
  const issues = [];
  const maxFiles = input.maxFiles ?? DEFAULT_SCANNER_LIMITS.maxFiles;
  const maxDepth = input.maxDepth ?? DEFAULT_SCANNER_LIMITS.maxDepth;

  if (!isPositiveInteger(maxFiles)) {
    issues.push("options.maxFiles: must be a positive integer");
  }
  if (!isPositiveInteger(maxDepth)) {
    issues.push("options.maxDepth: must be a positive integer");
  }

  if (issues.length > 0) {
    throw new ValidationError("Invalid scan limits", {
      details: { contract: "ScanLimits", issues },
    });
  }

  return { maxFiles, maxDepth };
}
