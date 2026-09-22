/**
 * Code Guardian — Configuration Security Rules (Phase 12, corrected)
 *
 * One rule, and it is the pack's only *derived* check: it compares observed paths
 * rather than naming one artifact.
 *
 *   a Dockerfile was observed, and no `.dockerignore` was observed at any build
 *   context root that could apply to it → `docker build` may copy secrets, local
 *   configuration and VCS metadata into the image
 *
 * ### Why the original version was wrong
 *
 * It required a `.dockerignore` in the Dockerfile's own directory. That assumption is
 * false for a nested Dockerfile: `docker build -f docker/Dockerfile .` builds with
 * the repository root as context, and Docker applies exactly one ignore file — the
 * one at the *context root*. A nested Dockerfile protected by a root `.dockerignore`
 * was therefore reported unprotected, which is a false positive, and the fix cannot
 * simply be the reverse (accepting any ignore file anywhere) because that would
 * silently clear a genuinely unprotected build. So the rule models the contexts
 * instead.
 *
 * ### The context model
 *
 * Docker's ignore file lives at the context root, and the model knows two roots that
 * can plausibly be the context for an observed Dockerfile:
 *
 *   1. **the Dockerfile's own directory** — the default for `cd <dir> && docker
 *      build .`, and what `docker build .` from inside a project directory does;
 *   2. **the repository root** — for `docker build -f <dir>/Dockerfile .`. This is
 *      only considered when a root `.dockerignore` actually exists, because that file
 *      is the observable evidence that a root-context build is configured.
 *
 * With those two candidates the rule is a small lattice, and each branch states a
 * different thing:
 *
 *   every candidate root has an ignore file   → `pass`: protected under either build
 *   no candidate root has an ignore file      → violation: no ignore file exists that
 *                                               any plausible build could apply
 *   some do, some do not                      → `unknown`: which one applies depends
 *                                               on a build command the model does not
 *                                               record, so neither answer is honest
 *
 * A Dockerfile at the repository root has a single candidate (the root), so it keeps
 * the simple behaviour — protected with a `.dockerignore`, unprotected without one.
 *
 * ### What is still not modelled
 *
 * A `build:` block in a compose file or a build script can declare any context, and
 * the scanner does not parse either. That is the one input that would turn the
 * `unknown` branch into a definite answer, so it is recorded here as the intended
 * acquisition-side improvement rather than guessed at.
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
import { configurationEntities, inventoryAbsence, queryFor } from "../signals.js";

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

/**
 * The plausible build-context roots for one Dockerfile.
 *
 * @param {string} dockerfilePath
 * @param {Set<string>} ignorePaths Paths of observed `.dockerignore` files.
 * @returns {string[]} Container directories, most specific first.
 */
function contextCandidates(dockerfilePath, ignorePaths) {
  const directory = directoryOf(dockerfilePath);
  if (directory === ROOT_DIRECTORY) return [ROOT_DIRECTORY];
  if (!ignorePaths.has(DOCKERIGNORE)) return [directory];
  return [directory, ROOT_DIRECTORY];
}

/** Whether an ignore file was observed in a container directory. */
function isProtected(directory, ignoreDirectories) {
  if (directory === ROOT_DIRECTORY) return ignoreDirectories.root;
  return ignoreDirectories.local.has(directory);
}

/**
 * Index observed `.dockerignore` files by the container directory they sit in.
 *
 * A root-level ignore file is tracked separately from directory-local ones, because
 * the two mean different things to the context model above.
 */
function indexIgnoreFiles(ignores) {
  const local = new Set();
  let root = false;
  for (const ignore of ignores) {
    const directory = directoryOf(ignore.path);
    if (directory === ROOT_DIRECTORY) root = true;
    else local.add(directory);
  }
  return { root, local };
}

export const configurationRules = Object.freeze([
  createRule({
    id: SECURITY_RULE_IDS.CONTAINER_IGNORE,
    version: SECURITY_RULE_VERSION,
    category: SECURITY_CATEGORY,
    title: "Container build context is not restricted by a .dockerignore file",
    description:
      "A Dockerfile was observed and no `.dockerignore` was observed at any build context root that could apply to it. Without an ignore file the build context sent to the daemon includes everything beneath the context root — local environment files, credentials, `.git` and build output — so content that is not meant to ship can be copied into an image layer. Only the presence and location of the files was observed: neither was read.",
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

      const ignorePaths = new Set(
        configurationEntities(query, CONFIGURATION_SIGNALS.CONTAINER_IGNORE).map(
          (entity) => entity.path,
        ),
      );
      const ignoreDirectories = indexIgnoreFiles(
        configurationEntities(query, CONFIGURATION_SIGNALS.CONTAINER_IGNORE),
      );

      const unprotected = [];
      const ambiguous = [];
      let protectedCount = 0;

      for (const dockerfile of dockerfiles) {
        const candidates = contextCandidates(dockerfile.path, ignorePaths);
        const covered = candidates.filter((directory) =>
          isProtected(directory, ignoreDirectories),
        );

        if (covered.length === candidates.length) {
          protectedCount += 1;
          continue;
        }

        const record = {
          entity: dockerfile,
          path: dockerfile.path,
          directory: directoryOf(dockerfile.path),
          contexts: candidates,
          protectedContexts: covered,
        };
        if (covered.length > 0) ambiguous.push(record);
        else unprotected.push(record);
      }

      if (unprotected.length > 0) {
        // An unprotected build is still only a violation if the scan supports the
        // absence half of the comparison.
        const absence = inventoryAbsence(query);
        if (!absence.established) {
          return createRuleDetection({
            findings: [],
            coverage: APPLICABILITY_COVERAGE.UNKNOWN,
            reason: `a Dockerfile was observed with no .dockerignore at a build context root, but ${absence.reason}`,
          });
        }

        return {
          findings: unprotected.map((entry) => ({
            confidence: SECURITY_CONFIDENCE.DERIVED_CONDITION,
            // The observation the model already recorded for this Dockerfile.
            evidence: [...entry.entity.evidenceIds],
            metadata: {
              path: entry.path,
              contextRoot: entry.directory,
              contexts: entry.contexts,
              basis: FINDING_BASES.BUILD_CONTEXT,
            },
          })),
          evidence: [],
          metadata: {
            basis: FINDING_BASES.BUILD_CONTEXT,
            dockerfiles: dockerfiles.length,
            protected: protectedCount,
            ambiguous: ambiguous.length,
          },
        };
      }

      if (ambiguous.length > 0) {
        // A `.dockerignore` exists that may or may not be the applicable one. Which
        // depends on the build command, which the model does not record, so neither
        // "protected" nor "unprotected" is a claim the evidence supports.
        const contexts = ambiguous
          .flatMap((entry) => entry.protectedContexts.map((directory) => `${directory}/${DOCKERIGNORE}`))
          .sort();
        return createRuleDetection({
          findings: [],
          coverage: APPLICABILITY_COVERAGE.UNKNOWN,
          reason: `a Dockerfile was observed outside the repository root with a .dockerignore that applies to one plausible build context but not another (${contexts.join(
            ", ",
          )}); the build context is not recorded in the repository model`,
        });
      }

      return {
        findings: [],
        evidence: [],
        metadata: cleanMetadata({
          dockerfiles: dockerfiles.length,
          dockerignores: ignorePaths.size,
        }),
      };
    },
  }),
]);
