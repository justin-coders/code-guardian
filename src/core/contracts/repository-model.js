/**
 * Code Guardian Core — RepositoryModel Contract
 *
 * The RepositoryModel represents *observed repository facts*, never judgments.
 *
 * Correct:   configuration.envFiles = [{ path: ".env" }]
 * Incorrect: configuration.security = "bad"
 *
 * A scanner collects facts; analyzers decide whether a fact is a problem.
 *
 * The model also explicitly represents incomplete scanning so that
 * "not inspected" can never silently become "not found".
 *
 * This module defines the shape/constants/factory only. It does not scan,
 * import transports, or execute commands.
 */

/** Version of the RepositoryModel contract. */
export const REPOSITORY_MODEL_VERSION = "1";

/**
 * Required top-level areas of a RepositoryModel.
 * Each area must be present (it may be empty) so that consumers can rely on
 * the shape, but the contract requires no analysis judgments.
 */
export const REPOSITORY_MODEL_AREAS = Object.freeze([
  "identity",
  "files",
  "languages",
  "frameworks",
  "manifests",
  "dependencies",
  "scripts",
  "configuration",
  "git",
  "tests",
  "ci",
  "architecture",
  "scan",
  "metadata",
]);

/** Fields every `scan` state must declare (Phase 7 Blueprint §6). */
export const SCAN_REQUIRED_FIELDS = Object.freeze([
  "complete",
  "truncated",
  "limits",
  "errors",
]);

/**
 * Default scanner limits. These are the maxima a scanner is expected to
 * declare; they are recorded in `scan.limits` so truncation is observable.
 */
export const DEFAULT_SCAN_LIMITS = Object.freeze({
  maxFiles: 10000,
  maxDepth: 20,
});

/**
 * Areas that must never be required as judgments. Exported for documentation
 * and regression tests: the fact model deliberately omits verdicts.
 */
export const REPOSITORY_MODEL_JUDGMENT_AREAS = Object.freeze([
  "security",
  "risk",
  "score",
  "grade",
  "verdict",
  "quality",
]);

/**
 * Build a complete RepositoryModel skeleton.
 *
 * Facts are passed in; nothing is inferred or judged. `scan.complete` defaults
 * to `false` so an unfinished scan is never reported as complete.
 *
 * @param {object} [overrides] Partial model. Unknown keys are ignored so the
 *   factory always returns the contracted shape.
 * @returns {object} A RepositoryModel-shaped object.
 */
export function createRepositoryModel(overrides = {}) {
  const scan = overrides.scan ?? {};
  const files = overrides.files ?? {};
  return {
    version: overrides.version ?? REPOSITORY_MODEL_VERSION,
    identity: overrides.identity ?? {},
    files: {
      entries: files.entries ?? [],
      count: files.count ?? 0,
      truncated: files.truncated ?? false,
    },
    languages: overrides.languages ?? [],
    frameworks: overrides.frameworks ?? [],
    manifests: overrides.manifests ?? {},
    dependencies: overrides.dependencies ?? {},
    scripts: overrides.scripts ?? {},
    configuration: overrides.configuration ?? {},
    git: overrides.git ?? {},
    tests: overrides.tests ?? {},
    ci: overrides.ci ?? {},
    architecture: overrides.architecture ?? {},
    scan: {
      complete: scan.complete ?? false,
      truncated: scan.truncated ?? false,
      limits: scan.limits ?? {},
      errors: scan.errors ?? [],
    },
    metadata: overrides.metadata ?? {},
  };
}
