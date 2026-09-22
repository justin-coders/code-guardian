/**
 * Code Guardian — Configuration Security Rules (Phase 12, corrected)
 *
 * One rule, and it is the pack's only *derived* check: it compares observed paths
 * rather than naming one artifact.
 *
 *   a Dockerfile was observed, its build context root is established, and no
 *   `.dockerignore` was observed at that root → `docker build` may copy secrets, local
 *   configuration and VCS metadata into the image
 *
 * ### Why the context must be established, not guessed
 *
 * Docker applies exactly one `.dockerignore`, and it is the file at the **build
 * context root**. The rule cannot see the build command, so a context it cannot
 * establish makes both "protected" and "unprotected" unsupported. Earlier revisions
 * tried to work around that by inference — first "a `.dockerignore` must sit beside
 * the Dockerfile", then "a root `.dockerignore` may apply to a nested Dockerfile" —
 * and both turned a possibility into a security conclusion: the first reported
 * protected builds as unprotected, the second reported possibly-unprotected builds as
 * protected.
 *
 * So the rule only concludes when the repository states the context:
 *
 *   **declared**      a Compose `build` configuration names this Dockerfile and its
 *                     context root (Phase 12 acquisition records that as an
 *                     observation on the Dockerfile). The applicable `.dockerignore` is
 *                     the one at that root, and no other.
 *   **root default**  the Dockerfile itself sits at the repository root, so the root
 *                     is the context its own directory implies — the one case where
 *                     the Dockerfile's location and the context root coincide without
 *                     any further evidence.
 *   **otherwise**     `unknown`. Nothing in the model ties this Dockerfile to a
 *                     context, so neither conclusion is available.
 *
 * A Compose file whose build declarations could not be interpreted makes every
 * undeclared Dockerfile `unknown` too, because such a file *could* have declared a
 * context for it. Absence of a declaration is only as trustworthy as the parse.
 *
 * ### Other ways the rule declines
 *
 *   - no Dockerfile was observed at all: an absence claim like any other, so it needs
 *     the coverage support every rule uses for one;
 *   - more than one declaration for the same Dockerfile with **different** context
 *     roots: the repository contradicts itself, which is `unknown`, not a coin flip;
 *   - a build context that is not fully covered by the scan, which is where the
 *     violation claim's other half (no `.dockerignore` there) cannot be established.
 */

import { createRule } from "../../../core/index.js";

import { APPLICABILITY_COVERAGE } from "../../contracts.js";
import { createRuleDetection } from "../../evaluation.js";

import {
  CONFIGURATION_SIGNALS,
  FINDING_BASES,
  SECURITY_CATEGORY,
  SECURITY_CONFIDENCE,
  SECURITY_RULE_IDS,
  SECURITY_RULE_VERSION,
} from "../contracts.js";
import {
  configurationEntities,
  declaredBuildContexts,
  inventoryAbsence,
  queryFor,
  uninterpretableComposeFiles,
} from "../signals.js";

/** The one ignore filename Docker understands. */
const DOCKERIGNORE = ".dockerignore";

/** The repository root, as a bounded container-directory token. */
const ROOT_DIRECTORY = ".";

/** The audit basis recorded on a clean outcome. */
function cleanMetadata(extra) {
  return { basis: FINDING_BASES.BUILD_CONTEXT, ...extra };
}

/** The directory holding a repository-relative path (`.` at the root). */
function directoryOf(path) {
  const index = path.lastIndexOf("/");
  return index === -1 ? ROOT_DIRECTORY : path.slice(0, index);
}

/** Whether a `.dockerignore` was observed at a container directory. */
function ignoreFilesByDirectory(ignores) {
  const directories = new Set();
  for (const ignore of ignores) directories.add(directoryOf(ignore.path));
  return directories;
}

export const configurationRules = Object.freeze([
  createRule({
    id: SECURITY_RULE_IDS.CONTAINER_IGNORE,
    version: SECURITY_RULE_VERSION,
    category: SECURITY_CATEGORY,
    title: "Container build context is not restricted by a .dockerignore file",
    description:
      "A Dockerfile was observed whose build context root is established by the repository — from a Compose `build` declaration, or from the Dockerfile sitting at the repository root — and no `.dockerignore` was observed at that root. Without an ignore file the build context sent to the daemon includes everything beneath the context root — local environment files, credentials, `.git` and build output — so content that is not meant to ship can be copied into an image layer. Only the presence and location of the files was observed: neither was read.",
    severity: "medium",
    applicability: {},
    remediation: {},
    metadata: { basis: FINDING_BASES.BUILD_CONTEXT, tags: ["containers", "build-context"] },
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

      const ignoreDirectories = ignoreFilesByDirectory(
        configurationEntities(query, CONFIGURATION_SIGNALS.CONTAINER_IGNORE),
      );
      const uninterpretable = uninterpretableComposeFiles(query);

      const unprotected = [];
      const unresolved = [];
      let protectedCount = 0;

      for (const dockerfile of dockerfiles) {
        const declaration = declaredBuildContexts(query, dockerfile);

        if (declaration.contexts.length > 1) {
          unresolved.push(
            `the build context of ${dockerfile.path} is declared twice with different roots (${declaration.contexts.join(
              ", ",
            )})`,
          );
          continue;
        }

        // An undeclared Dockerfile is only as trustworthy as the parse that found no
        // declaration for it: a Compose file whose build configuration could not be
        // interpreted could have declared this exact context, so nothing is concluded
        // — not even from the Dockerfile's own location at the repository root, which
        // such a declaration would have overridden.
        if (declaration.contexts.length === 0 && uninterpretable.length > 0) {
          unresolved.push(`the build context of ${dockerfile.path} is not established, and ${uninterpretable.length} Compose file(s) could not be interpreted (${uninterpretable
            .map((entry) => `${entry.path}: ${entry.reason}`)
            .join(", ")})`);
          continue;
        }

        const contextRoot = declaration.contexts[0] ?? defaultContextRoot(dockerfile.path);
        if (contextRoot === null) {
          unresolved.push(
            `the build context of ${dockerfile.path} is not established by the repository model`,
          );
          continue;
        }

        if (ignoreDirectories.has(contextRoot)) {
          protectedCount += 1;
          continue;
        }

        unprotected.push({
          entity: dockerfile,
          contextRoot,
          declared: declaration.contexts.length === 1,
          declarationEvidenceIds: declaration.evidenceIds,
        });
      }

      if (unprotected.length > 0) {
        // A missing ignore file is still an absence claim: the scan has to have seen
        // enough of the repository for "there is none at that root" to hold.
        const absence = inventoryAbsence(query);
        if (!absence.established) {
          return createRuleDetection({
            findings: [],
            coverage: APPLICABILITY_COVERAGE.UNKNOWN,
            reason: `a Dockerfile was observed with no .dockerignore at its build context root, but ${absence.reason}`,
          });
        }

        return {
          findings: unprotected.map((entry) => ({
            confidence: SECURITY_CONFIDENCE.DERIVED_CONDITION,
            // The Dockerfile's own observation, plus the declaration that established
            // the context when there is one.
            evidence: [
              ...new Set([...entry.entity.evidenceIds, ...entry.declarationEvidenceIds]),
            ].sort(),
            metadata: {
              path: entry.entity.path,
              contextRoot: entry.contextRoot,
              contextSource: entry.declared ? "compose" : "dockerfile-location",
              basis: FINDING_BASES.BUILD_CONTEXT,
            },
          })),
          evidence: [],
          metadata: {
            basis: FINDING_BASES.BUILD_CONTEXT,
            dockerfiles: dockerfiles.length,
            protected: protectedCount,
            unresolved: unresolved.length,
          },
        };
      }

      if (unresolved.length > 0) {
        return createRuleDetection({
          findings: [],
          coverage: APPLICABILITY_COVERAGE.UNKNOWN,
          reason: unresolved.join("; "),
        });
      }

      return {
        findings: [],
        evidence: [],
        metadata: cleanMetadata({
          dockerfiles: dockerfiles.length,
          dockerignores: ignoreDirectories.size,
        }),
      };
    },
  }),
]);

/**
 * The context root a Dockerfile's own location establishes, or `null`.
 *
 * Only a Dockerfile at the repository root qualifies: its own directory *is* the
 * repository root, so the file's location and the context root coincide without any
 * further evidence. A nested Dockerfile's directory proves nothing about the context
 * (`docker build -f docker/Dockerfile .` is equally ordinary), which is exactly the
 * inference this rule no longer makes.
 */
function defaultContextRoot(dockerfilePath) {
  return directoryOf(dockerfilePath) === ROOT_DIRECTORY ? ROOT_DIRECTORY : null;
}

