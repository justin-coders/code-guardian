/**
 * Code Guardian — Exposure Security Rules (Phase 12 correction)
 *
 * One rule, and it is the pack's only finding that is *about a link*:
 *
 *   a symlink whose target resolves outside the repository was observed
 *
 * The claim is deliberately narrow. It does not say the target is readable, that
 * anything was read through the link, or that the link is malicious. It says the
 * model classified the link's target as leaving the repository — which is a fact
 * about where the link points, established by reading the link itself and never
 * following it (Phase 8A's `not-followed` policy is preserved end to end).
 *
 * Why it matters: a repository-relative path that resolves outside the repository
 * breaks the assumption every other rule rests on. A `.env`-shaped link, a
 * `config/secrets.json` link or a linked directory can make content that lives
 * outside the checkout look like part of it — to a build, a container copy, a
 * packaging step or a tool that trusts the path.
 *
 * The rule declines to conclude in two ways, and neither is a `pass`:
 *
 *   - a link the scanner could not classify (`unknown`) — the answer depends on a
 *     link whose target was never established;
 *   - an unresolved *inventory*: when the scan did not cover the repository
 *     completely or a path could not be read, "no escaping link exists" is not
 *     established. Findings still win: an escaping link that *was* observed is
 *     reported whatever the coverage was.
 */

import { createRule } from "../../../core/index.js";

import { APPLICABILITY_COVERAGE } from "../../contracts.js";
import { createRuleDetection } from "../../evaluation.js";

import {
  FINDING_BASES,
  SECURITY_CATEGORY,
  SECURITY_CONFIDENCE,
  SECURITY_RULE_IDS,
  SECURITY_RULE_VERSION,
} from "../contracts.js";
import { inventoryAbsence, queryFor, symlinkTargets } from "../signals.js";

/** A bounded, human-readable list of reasons, for an `unknown` explanation. */
function describeReasons(reasons) {
  if (reasons.length === 0) return "the reason was not recorded";
  return reasons.join(", ");
}

export const exposureRules = Object.freeze([
  createRule({
    id: SECURITY_RULE_IDS.SYMLINK_ESCAPE,
    version: SECURITY_RULE_VERSION,
    category: SECURITY_CATEGORY,
    title: "Symlink target resolves outside the repository",
    description:
      "A symlink was observed whose target resolves outside the repository. The link itself was inspected (the phase-8A policy never follows a symlink), so this finding reports where the link points: a path inside the repository is not a symlink escape, and a link that resolves to a location outside it is. No target content was read, and nothing was resolved through the link.",
    severity: "medium",
    // Universally applicable: a repository that contains no symlink at all is a
    // meaningful clean result, so a selector here would only skip the check.
    applicability: {},
    remediation: {},
    metadata: { basis: FINDING_BASES.LINK, tags: ["exposure", "symlink"] },
    detect(context) {
      const query = queryFor(context);
      const targets = symlinkTargets(query);

      if (targets.escaping.length > 0) {
        return {
          findings: targets.escaping.map((symlink) => ({
            confidence: SECURITY_CONFIDENCE.OBSERVED_LINK,
            // The observation the model already recorded for this link — its
            // inventory record, which carries the classified target.
            evidence: [...symlink.evidenceIds],
            metadata: {
              path: symlink.path,
              targetKind: symlink.target?.kind ?? "unknown",
              basis: FINDING_BASES.LINK,
            },
          })),
          evidence: [],
          // Recorded, not hidden: links the scanner could not classify exist
          // alongside the ones it could.
          metadata: {
            basis: FINDING_BASES.LINK,
            symlinks: targets.total,
            unresolved: targets.unresolved.length,
            unresolvedReasons: [...targets.reasons],
          },
        };
      }

      if (targets.unresolved.length > 0) {
        return createRuleDetection({
          findings: [],
          coverage: APPLICABILITY_COVERAGE.UNKNOWN,
          reason: `${targets.unresolved.length} symlink(s) could not be classified (${describeReasons(
            targets.reasons,
          )}), so whether a link escapes the repository is not established`,
        });
      }

      // No symlink was observed at all: that is an absence claim like any other.
      if (targets.total === 0) {
        const absence = inventoryAbsence(query);
        if (!absence.established) {
          return createRuleDetection({
            findings: [],
            coverage: APPLICABILITY_COVERAGE.UNKNOWN,
            reason: `no symlink was observed, but ${absence.reason}`,
          });
        }
        return {
          findings: [],
          evidence: [],
          metadata: {
            basis: FINDING_BASES.LINK,
            symlinks: 0,
            observedFiles: absence.observedFiles,
            ignoredPaths: absence.ignoredPaths,
          },
        };
      }

      return {
        findings: [],
        evidence: [],
        metadata: {
          basis: FINDING_BASES.LINK,
          symlinks: targets.total,
          inside: targets.inside.length,
        },
      };
    },
  }),
]);
