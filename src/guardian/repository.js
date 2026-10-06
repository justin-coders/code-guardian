/**
 * Code Guardian — Repository Input Resolution (Official Roadmap Phase 19)
 *
 * Pipeline stage 2 is "build RepositoryModel". This module turns whatever the
 * caller handed `audit()` into exactly one validated `RepositoryModel`, using the
 * accepted pipeline and no other:
 *
 *   string root        → scanRepository(root, scanOptions) → buildRepositoryModel
 *   ScanResult         → buildRepositoryModel
 *   RepositoryModel    → used as-is
 *
 * It deliberately does **not** implement a scanner, a filesystem walk, manifest
 * detection, dependency acquisition or graph construction. Those already exist in
 * the Phase 8C/8D layers, and a second implementation would let the model
 * contradict the scan it claims to describe. The model layer never touches the
 * filesystem; only a path input reaches the scanner.
 */

import { validateRepositoryModel } from "../core/index.js";
import { buildRepositoryModel } from "../repository/model/index.js";
import { scanRepository, validateScanResult } from "../repository/scanner/index.js";

import { GUARDIAN_FAILURE_CODES, GuardianConfigurationError } from "./errors.js";

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Whether a value is shaped like a built `RepositoryModel`.
 *
 * The discriminator is `identity`, which a `ScanResult` never carries and a model
 * always does. Shape alone never makes a value valid — the Core validator below is
 * still the authority.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isRepositoryModel(value) {
  return isPlainObject(value) && isPlainObject(value.identity) && isPlainObject(value.scan);
}

/**
 * Whether a value is shaped like a `ScanResult`.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isScanResult(value) {
  return (
    isPlainObject(value) &&
    !isRepositoryModel(value) &&
    Array.isArray(value.files) &&
    isPlainObject(value.scan)
  );
}

function invalid(message, details) {
  return new GuardianConfigurationError(message, {
    code: GUARDIAN_FAILURE_CODES.invalidRepository,
    details,
  });
}

/**
 * Resolve the `audit()` repository input to a validated RepositoryModel.
 *
 * @param {string|object} repository A repository root path, a `ScanResult`, or a
 *   built `RepositoryModel`.
 * @param {object} [scanOptions] Scanner options (`maxFiles`, `maxDepth`), used
 *   only when `repository` is a path.
 * @returns {Promise<object>} A validated, frozen RepositoryModel.
 * @throws {GuardianConfigurationError} When the input is none of the accepted forms.
 */
export async function resolveRepositoryModel(repository, scanOptions = {}) {
  if (typeof repository === "string") {
    if (repository.trim() === "") {
      throw invalid("repository: a root path must be a non-empty string", {
        field: "repository",
      });
    }
    const scan = await scanRepository(repository, scanOptions);
    return buildRepositoryModel(scan);
  }

  if (isRepositoryModel(repository)) {
    return validateRepositoryModel(repository);
  }

  if (isScanResult(repository)) {
    return buildRepositoryModel(validateScanResult(repository));
  }

  throw invalid(
    "repository: must be a repository root path, a ScanResult, or a built RepositoryModel",
    { field: "repository", received: repository === null ? "null" : typeof repository },
  );
}
