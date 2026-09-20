/**
 * Code Guardian — Analyzer Applicability (Phase 9)
 *
 * Applicability answers one question only: *should this analyzer run against this
 * repository?* It is deliberately separate from analysis, so that
 *
 *   - a Python analyzer on a Go repository is `not-applicable` rather than a
 *     "clean" result that silently claims coverage it never had, and
 *   - applicability can be evaluated (and reported) without executing anything.
 *
 * "Not applicable" is **not** a failure: it is the correct, expected outcome for
 * most analyzers on most repositories, and the framework never records it as an
 * error.
 *
 * The Core `AnalyzerApplicability` contract is the authority on the shape
 * (`{ applicable: boolean, reason?: string }`). A `canAnalyze()` that returns a
 * bare boolean, `null`, or anything else is a contract violation and is reported
 * as such — the framework does not guess what the analyzer meant, because
 * guessing would make applicability harder to trust than the analysis it gates.
 */

import { createApplicability, validateAnalyzerApplicability } from "../core/index.js";

import { ANALYZER_FAILURE_KINDS } from "./contracts.js";
import { AnalyzerFrameworkError, sanitizeMessage } from "./errors.js";

/**
 * Evaluate and validate one analyzer's applicability.
 *
 * `canAnalyze` may be synchronous or asynchronous; both are awaited.
 *
 * @param {object} analyzer A registered analyzer.
 * @param {object} context A validated AnalysisContext.
 * @returns {Promise<object>} A validated `{ applicable, reason? }`.
 * @throws {AnalyzerFrameworkError} kind `invalid-applicability` when the
 *   analyzer returns something that is not the contracted shape.
 */
export async function evaluateApplicability(analyzer, context) {
  const raw = await analyzer.canAnalyze(context);

  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new AnalyzerFrameworkError(
      ANALYZER_FAILURE_KINDS.INVALID_APPLICABILITY,
      "canAnalyze() must return an applicability object ({ applicable: boolean })",
      { analyzerId: analyzer.id, returned: describeValue(raw) },
    );
  }

  try {
    return validateAnalyzerApplicability(createApplicability(raw));
  } catch (error) {
    throw new AnalyzerFrameworkError(
      ANALYZER_FAILURE_KINDS.INVALID_APPLICABILITY,
      sanitizeMessage(error?.message ?? "invalid applicability result"),
      {
        analyzerId: analyzer.id,
        issues: error?.details?.issues ?? [],
      },
    );
  }
}

/**
 * A bounded description of a value's type, for diagnostics.
 * Never includes the value itself: it may be anything, including a secret.
 */
export function describeValue(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return `${typeof value}`;
}
