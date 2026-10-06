/**
 * Code Guardian — Risk Aggregation (Official Roadmap Phase 19)
 *
 * Pipeline stage 8 is "calculate risk". This is the **first** place in the system
 * permitted to produce a Guardian-level risk interpretation, and it is the place
 * the phase most needs an explicit, documented decision rather than an invented
 * formula. The decision is this:
 *
 * ### Risk is a profile, not a number
 *
 * The architecture specification (§22) requires risk to consider severity,
 * confidence, impact, scope, exploitability and evidence completeness, and to
 * "avoid pretending that these can always be reduced to a single mathematically
 * objective number", with the underlying dimensions remaining visible. The Core
 * therefore reports a **profile**:
 *
 *   highestSeverity   the highest severity present among the canonical findings, or
 *                     `null` when there are none. This is a *fact about the finding
 *                     set* — literally `max(severity)` — not a verdict, not a
 *                     percentage and not a score.
 *   counts            how many canonical findings sit at each severity.
 *   complete          whether the run covered enough of the repository, with no
 *                     analyzer failing or being skipped, for any statement to be
 *                     treated as a bounded conclusion.
 *   coverage          the repository and analysis coverage facts the `complete`
 *                     judgement rests on, so a consumer can see exactly why.
 *   limitations       the deterministic reasons the run is not complete.
 *
 * ### Severity and confidence stay independent
 *
 * Severity is "how bad if true"; confidence is "how certain the analysis is that
 * it is true". They are never multiplied, weighted or collapsed. `highestSeverity`
 * reads only severity; every finding keeps its own `confidence` on the canonical
 * result. A consumer that wants to combine them does so explicitly, on data the
 * Core did not pre-combine — because a Core that combined them would have made a
 * policy decision the architecture says is not objective.
 *
 * ### An incomplete analysis is never clean
 *
 * `complete` is false when the repository scan was not complete, when it was
 * truncated, or when any analyzer failed or was skipped. `highestSeverity` may
 * still name a severity — the findings that *were* observed remain facts — but a
 * consumer reading `complete: false` and a non-empty `limitations` list cannot
 * mistake the profile for a clean bill of health. An analyzer that declined
 * (not-applicable) is a normal, expected outcome and does **not** make the run
 * incomplete; absence of evidence is not turned into a risk conclusion.
 *
 * ### Determinism and versioning
 *
 * The profile is a pure function of the canonical findings and the run's coverage
 * facts. Counts iterate the closed severity vocabulary, and `limitations` is
 * sorted and de-duplicated, so the profile does not depend on finding order,
 * analyzer scheduling or object key order. `RISK_CONTRACT_VERSION` is recorded on
 * the profile so a consumer baselining risk can detect a semantic change.
 *
 * This module performs no I/O and reads no clock.
 */

import { deepFreeze } from "../analysis/index.js";
import { FINDING_SEVERITIES } from "../core/index.js";

import {
  MAX_LIMITATION_LENGTH,
  RISK_CONTRACT_VERSION,
  RISK_LIMITATION_KINDS,
  RISK_SEVERITIES,
} from "./contracts.js";

/** Bound one limitation string. */
function bounded(value) {
  const text = String(value);
  return text.length > MAX_LIMITATION_LENGTH ? text.slice(0, MAX_LIMITATION_LENGTH) : text;
}

/** Findings for one analyzer status, by id, sorted. */
function idsWithStatus(analysisRun, status) {
  return analysisRun.analyzers
    .filter((result) => result.status === status)
    .map((result) => result.analyzer.id)
    .sort();
}

/**
 * Calculate the deterministic risk profile for one analysis run.
 *
 * @param {object} input
 * @param {object} input.repository The validated RepositoryModel.
 * @param {object} input.analysisRun The accepted AnalysisRunResult.
 * @returns {object} A deeply frozen risk profile.
 */
export function calculateRisk({ repository, analysisRun }) {
  const counts = { total: 0 };
  for (const severity of RISK_SEVERITIES) counts[severity] = 0;

  for (const finding of analysisRun.findings) {
    // Findings are canonical, so their severity is guaranteed to be a member of the
    // Core vocabulary; an unexpected value is counted under `total` only rather than
    // inventing a bucket.
    if (RISK_SEVERITIES.includes(finding.severity)) counts[finding.severity] += 1;
    counts.total += 1;
  }

  let highestSeverity = null;
  for (const severity of RISK_SEVERITIES) {
    if (counts[severity] > 0) highestSeverity = severity;
  }

  const scan = repository.scan;
  const guarantee = scan.coverage?.guarantee ?? "partial";
  const repositoryComplete = scan.complete === true && scan.truncated !== true;

  const failed = idsWithStatus(analysisRun, "failed");
  const skipped = idsWithStatus(analysisRun, "skipped");

  const limitations = [];
  if (!repositoryComplete) limitations.push(RISK_LIMITATION_KINDS.REPOSITORY_INCOMPLETE);
  if (scan.truncated === true) limitations.push(RISK_LIMITATION_KINDS.REPOSITORY_TRUNCATED);
  for (const id of failed) {
    limitations.push(bounded(`${RISK_LIMITATION_KINDS.ANALYZER_FAILED}:${id}`));
  }
  for (const id of skipped) {
    limitations.push(bounded(`${RISK_LIMITATION_KINDS.ANALYZER_SKIPPED}:${id}`));
  }

  const complete = repositoryComplete && failed.length === 0 && skipped.length === 0;

  return deepFreeze({
    version: RISK_CONTRACT_VERSION,
    highestSeverity,
    counts: deepFreeze({ ...counts }),
    complete,
    coverage: deepFreeze({
      repository: {
        complete: repositoryComplete,
        truncated: scan.truncated === true,
        guarantee,
      },
      analysis: {
        selected: analysisRun.analyzers.length,
        completed: analysisRun.analyzers.filter((result) => result.status === "completed").length,
        notApplicable: analysisRun.analyzers.filter(
          (result) => result.status === "not-applicable",
        ).length,
        failed: failed.length,
        skipped: skipped.length,
      },
    }),
    limitations: deepFreeze([...new Set(limitations)].sort()),
  });
}

/** Re-exported so a consumer can order severities without importing Core. */
export { FINDING_SEVERITIES };
