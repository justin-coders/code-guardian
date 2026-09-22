/**
 * Code Guardian — Configuration Security Rules (Phase 12)
 *
 * One rule, and it is the pack's only *derived* check: it compares two observations
 * instead of naming a single artifact.
 *
 *   a Dockerfile was observed, and no `.dockerignore` was observed in the same
 *   directory → `docker build .` may copy secrets, local configuration and VCS
 *   metadata into the image
 *
 * Both halves are things the model actually recorded: the Phase 8C configuration
 * detector reports a `dockerfile` signal and a separate `container-ignore` signal,
 * and the Phase 8D model keeps each entity's `directoryId`, so "beside the
 * Dockerfile" is a comparison of observed facts rather than a guess about paths.
 *
 * The rule is honest about the two ways it can decline to conclude:
 *
 *   - nothing to compare: no Dockerfile was observed. With complete coverage that is
 *     a `pass`; with incomplete coverage a Dockerfile might simply not have been
 *     reached, so it is `unknown`.
 *   - the absence half: a Dockerfile was observed without a `.dockerignore` beside
 *     it, which is only meaningful if the scan supports an absence claim. When it
 *     does not, the outcome is `unknown` — a `.dockerignore` that was never walked
 *     past is not evidence that the build is unprotected.
 */

import { createRule } from "../../../core/index.js";

import { APPLICABILITY_COVERAGE } from "../../contracts.js";
import { createRuleDetection } from "../../evaluation.js";

import {
  CONFIGURATION_SIGNALS,
  FINDING_BASIS,
  SECURITY_CATEGORY,
  SECURITY_CONFIDENCE,
  SECURITY_RULE_IDS,
  SECURITY_RULE_VERSION,
} from "../contracts.js";
import { configurationEntities, inventoryAbsence, queryFor } from "../signals.js";

/** The audit basis recorded on a clean outcome. */
function cleanMetadata(extra) {
  return { basis: FINDING_BASIS, ...extra };
}

export const configurationRules = Object.freeze([
  createRule({
    id: SECURITY_RULE_IDS.CONTAINER_IGNORE,
    version: SECURITY_RULE_VERSION,
    category: SECURITY_CATEGORY,
    title: "Container build context is not restricted by a .dockerignore file",
    description:
      "A Dockerfile was observed with no `.dockerignore` in its directory. Without an ignore file the build context sent to the daemon includes everything alongside the Dockerfile — local environment files, credentials, `.git` and build output — so content that is not meant to ship can be copied into an image layer. Only the presence of the two files was observed: neither was read.",
    severity: "medium",
    applicability: {},
    remediation: {},
    metadata: { basis: FINDING_BASIS, tags: ["containers", "build-context"] },
    detect(context) {
      const query = queryFor(context);
      const dockerfiles = configurationEntities(query, CONFIGURATION_SIGNALS.DOCKERFILE);

      // Nothing to compare. The claim "no container build is configured" is an
      // absence claim like any other, so it needs the same coverage support.
      if (dockerfiles.length === 0) {
        const absence = inventoryAbsence(query);
        if (!absence.established) {
          return createRuleDetection({
            findings: [],
            coverage: APPLICABILITY_COVERAGE.UNKNOWN,
            reason: `no Dockerfile was observed, but ${absence.reason}`,
          });
        }
        return { findings: [], evidence: [], metadata: cleanMetadata({ dockerfiles: 0 }) };
      }

      const ignoreDirectories = new Set(
        configurationEntities(query, CONFIGURATION_SIGNALS.CONTAINER_IGNORE).map(
          (entity) => entity.directoryId,
        ),
      );
      const unprotected = dockerfiles.filter(
        (dockerfile) => !ignoreDirectories.has(dockerfile.directoryId),
      );

      if (unprotected.length === 0) {
        return {
          findings: [],
          evidence: [],
          metadata: cleanMetadata({
            dockerfiles: dockerfiles.length,
            dockerignores: ignoreDirectories.size,
          }),
        };
      }

      const absence = inventoryAbsence(query);
      if (!absence.established) {
        return createRuleDetection({
          findings: [],
          coverage: APPLICABILITY_COVERAGE.UNKNOWN,
          reason: `a Dockerfile was observed without a .dockerignore beside it, but ${absence.reason}`,
        });
      }

      return {
        findings: unprotected.map((dockerfile) => ({
          confidence: SECURITY_CONFIDENCE.DERIVED_CONDITION,
          evidence: [...dockerfile.evidenceIds],
          metadata: {
            path: dockerfile.path,
            directory: dockerfile.directoryId,
            basis: FINDING_BASIS,
          },
        })),
        evidence: [],
      };
    },
  }),
]);
