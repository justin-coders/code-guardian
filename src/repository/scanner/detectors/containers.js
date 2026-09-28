/**
 * Code Guardian — Container Build-Context Detector (Phase 12 correction)
 *
 * Reads the repository's Compose files (already inventoried as `compose-file`
 * configuration signals) under the Phase 8A boundary and records the build
 * declarations they state: which Dockerfile each service builds, and from which
 * context root. That is the evidence the container security rule needs in order to
 * stop inferring a context it cannot know.
 *
 * The detector records *facts about the file*, never a verdict: a declaration whose
 * context escapes the repository, or whose Dockerfile is not an observed file, is
 * dropped rather than reinterpreted (there is no observed artifact for it to be about,
 * and the affected Dockerfile simply stays unestablished). A Compose file the parser
 * cannot interpret is recorded as unparsed *with its reason*, so the rule can say
 * "unknown" instead of treating the file as if it declared nothing.
 *
 * Reads are bounded by `CONTAINER_DECLARATION_LIMITS`, go through `view.read` (the
 * Phase 8A boundary, so containment and symlink policy apply), and nothing is ever
 * written.
 */

import { resolveWithin, toRepositoryRelative } from "../../filesystem/index.js";
import {
  COMPOSE_FILENAMES,
  COMPOSE_UNPARSED_REASONS,
  CONTAINER_DECLARATION_LIMITS,
  DEFAULT_DOCKERFILE_NAME,
  isAbsoluteContainerReference,
  parseComposeBuildContexts,
} from "../policies/containers.js";
// Phase 20 — the container definition's own declared structure. Read through the same
// detector because a Dockerfile and the Compose file that builds it are one subject:
// "what does this repository's container configuration establish".
import {
  DOCKERFILE_DETAILS,
  DOCKERFILE_INSPECTION_LIMITS,
  DOCKERFILE_RULES,
  DOCKERFILE_UNPARSED_REASONS,
  parseDockerfileStructure,
  unestablishedDockerfileStructure,
} from "../policies/dockerfile.js";
import { matchEntries } from "./match.js";

/** Which inventory files are Compose files. Shared basenames, so no drift. */
export const COMPOSE_RULES = Object.freeze([
  { basename: [...COMPOSE_FILENAMES], signal: "compose-file" },
]);

/**
 * Read the declared structure of every Dockerfile the inventory observed.
 *
 * One record per Dockerfile, always — including for a file whose structure could not
 * be established. That is what lets a consumer distinguish "this Dockerfile declares
 * one stage and no healthcheck" from "this Dockerfile was not read", which is the
 * distinction the production report's container section refuses to collapse.
 *
 * Bounded by `DOCKERFILE_INSPECTION_LIMITS` on every axis, deterministic (records are
 * sorted by path and stage names by name), and read-only: the file is opened through
 * the Phase 8A boundary and never written.
 *
 * @param {object} view Repository view built by the scanner.
 * @returns {Promise<object[]>} Structure records, sorted by path.
 */
async function detectDockerfileStructures(view) {
  const matches = matchEntries(DOCKERFILE_RULES, view.files);
  const records = [];
  let inspected = 0;

  for (const { entry } of matches) {
    if (inspected >= DOCKERFILE_INSPECTION_LIMITS.maxFiles) {
      records.push({
        path: entry.path,
        ...unestablishedDockerfileStructure(
          DOCKERFILE_UNPARSED_REASONS.BUDGET_EXHAUSTED,
          null,
        ),
      });
      continue;
    }

    const result = await view.read(entry.path, {
      maxBytes: DOCKERFILE_INSPECTION_LIMITS.maxFileBytes,
    });

    if (!result.ok) {
      records.push({
        path: entry.path,
        // The classified reason is a bounded token, never a raw Node message: the
        // field carries *why* the file is unread, not what the platform said.
        ...unestablishedDockerfileStructure(
          DOCKERFILE_UNPARSED_REASONS.READ_FAILED,
          DOCKERFILE_DETAILS.UNREADABLE,
        ),
      });
      continue;
    }

    inspected += 1;

    if (result.truncated === true) {
      // The read budget cut the file short, so the instructions after the cut were
      // never seen: the structure is not established, and the *reason* says why.
      records.push({
        path: entry.path,
        ...unestablishedDockerfileStructure(
          DOCKERFILE_UNPARSED_REASONS.TOO_LARGE,
          DOCKERFILE_DETAILS.TRUNCATED_READ,
        ),
      });
      continue;
    }

    const text = typeof result.content === "string" ? result.content : "";
    const parsed = parseDockerfileStructure(text);

    records.push(
      parsed.ok
        ? {
            path: entry.path,
            parsed: true,
            reason: null,
            detail: null,
            truncated: false,
            stages: parsed.stages,
            multiStage: parsed.multiStage,
            stageNames: [...parsed.stageNames],
            healthcheck: parsed.healthcheck,
            healthcheckDisabled: parsed.healthcheckDisabled,
            instructions: parsed.instructions,
          }
        : {
            path: entry.path,
            ...unestablishedDockerfileStructure(parsed.reason, parsed.detail),
          },
    );
  }

  records.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  return { records, inspected };
}

/** The directory holding a repository-relative path (`.` at the root). */
function parentDirectoryOf(path) {
  const index = path.lastIndexOf("/");
  return index === -1 ? "." : path.slice(0, index);
}

/**
 * Why a single declaration could not be resolved to repository-relative paths.
 *
 * Bounded identifiers, never the offending text: the value that failed is exactly the
 * value that might be a host path, so it is classified and then dropped.
 *
 *   context-outside-repository   the context is absolute, or resolves outside the root
 *   dockerfile-outside-repository the Dockerfile name is absolute, or resolves outside
 *   dockerfile-outside-context   the Dockerfile escapes its own context, which Docker
 *                                rejects (`the Dockerfile must be within the build
 *                                context`) — such a build cannot run, so it establishes
 *                                no context at all
 *   dockerfile-not-observed      the declaration resolved inside the repository, but to
 *                                a file the inventory never saw; it is about a
 *                                different artifact, not an uninterpretable one
 */
export const CONTAINER_DECLARATION_DETAILS = Object.freeze({
  CONTEXT_OUTSIDE: "context-outside-repository",
  DOCKERFILE_OUTSIDE: "dockerfile-outside-repository",
  DOCKERFILE_OUTSIDE_CONTEXT: "dockerfile-outside-context",
  DOCKERFILE_NOT_OBSERVED: "dockerfile-not-observed",
});

/**
 * Classify one declaration as resolved evidence, or as a bounded reason it is not.
 *
 * A relative `context` is resolved against the Compose file's own directory (Compose's
 * default project directory) and the Dockerfile against that context. Compose permits
 * an absolute `context`, but an absolute path names a host location the model knows
 * nothing about: it cannot be checked for containment, so it is reported as
 * unresolvable rather than silently ignored. Silently dropping it would leave the
 * Dockerfile looking undeclared, and an undeclared rooted Dockerfile is reported as
 * unprotected — a security conclusion drawn from a declaration that actually exists.
 *
 * `dockerfile-not-observed` is the one classification that is *not* an interpretation
 * failure: the declaration was understood perfectly, it simply names an artifact this
 * scan did not inventory.
 *
 * @returns {{ok: true, declaration: {source: string, service: string, context: string|null,
 *   dockerfile: string}} | {ok: false, detail: string}}
 */
export function classifyBuildDeclaration(root, source, declaration) {
  const { service, context, dockerfile } = declaration;
  const fileName = dockerfile ?? DEFAULT_DOCKERFILE_NAME;
  if (isAbsoluteContainerReference(context)) {
    return { ok: false, detail: CONTAINER_DECLARATION_DETAILS.CONTEXT_OUTSIDE };
  }
  if (isAbsoluteContainerReference(fileName)) {
    return { ok: false, detail: CONTAINER_DECLARATION_DETAILS.DOCKERFILE_OUTSIDE };
  }

  const directory = parentDirectoryOf(source);
  const contextReference = directory === "." ? context : `${directory}/${context}`;

  let contextDirectory;
  let dockerfileRelative;
  try {
    contextDirectory = toRepositoryRelative(root, resolveWithin(root, contextReference));
  } catch {
    return { ok: false, detail: CONTAINER_DECLARATION_DETAILS.CONTEXT_OUTSIDE };
  }
  try {
    dockerfileRelative = toRepositoryRelative(
      root,
      resolveWithin(root, `${contextDirectory}/${fileName}`),
    );
  } catch {
    return { ok: false, detail: CONTAINER_DECLARATION_DETAILS.DOCKERFILE_OUTSIDE };
  }

  // Docker requires the Dockerfile to live *inside* its own build context, so a
  // declaration whose `dockerfile` climbs back out (`context: ./sub` with
  // `dockerfile: ../Dockerfile`) describes a build the daemon refuses. Treating it as
  // evidence would be reasoning from an impossible configuration.
  if (!isWithinDirectory(contextDirectory, dockerfileRelative)) {
    return { ok: false, detail: CONTAINER_DECLARATION_DETAILS.DOCKERFILE_OUTSIDE_CONTEXT };
  }

  return {
    ok: true,
    declaration: {
      source,
      service,
      // The repository root has no repository-relative form, so it is recorded as
      // `null` — the same convention a symlink target uses for the root. The Dockerfile
      // path is always concrete.
      context: contextDirectory === "." ? null : contextDirectory,
      dockerfile: dockerfileRelative,
    },
  };
}

/**
 * Resolve one declaration to repository-relative paths, or `null` when it cannot be.
 *
 * @returns {{source: string, service: string, context: string|null, dockerfile: string}|null}
 */
export function resolveBuildDeclaration(root, source, declaration) {
  const result = classifyBuildDeclaration(root, source, declaration);
  return result.ok ? result.declaration : null;
}

/**
 * Whether a repository-relative path sits at or beneath a repository-relative
 * directory (`.` being the repository root).
 *
 * @param {string} directory
 * @param {string} path
 * @returns {boolean}
 */
function isWithinDirectory(directory, path) {
  if (directory === ".") return true;
  return path === directory || path.startsWith(`${directory}/`);
}

/**
 * Detect container build declarations and Dockerfile structure.
 *
 * Two independent observations about one subject. The Compose declarations say which
 * Dockerfile a service builds and from where; the structure records say what the
 * Dockerfile's own instructions declare. Neither is inferred from the other, and a
 * Dockerfile no Compose file mentions is still read, because "this repository has a
 * container definition" does not depend on anything declaring that it is used.
 *
 * @param {object} view Repository view built by the scanner.
 * @returns {Promise<object>} The scan result's `containers` section.
 */
export async function detectContainers(view) {
  const matches = matchEntries(COMPOSE_RULES, view.files);
  const observedFiles = new Set(view.files.map((file) => file.path));

  const declarations = [];
  const unparsed = [];
  let inspected = 0;

  for (const { entry } of matches) {
    if (
      inspected >= CONTAINER_DECLARATION_LIMITS.maxFiles ||
      declarations.length >= CONTAINER_DECLARATION_LIMITS.maxDeclarations
    ) {
      unparsed.push({
        source: entry.path,
        reason: COMPOSE_UNPARSED_REASONS.BUDGET_EXHAUSTED,
        detail: null,
      });
      continue;
    }

    const result = await view.read(entry.path, {
      maxBytes: CONTAINER_DECLARATION_LIMITS.maxFileBytes,
    });

    if (!result.ok) {
      unparsed.push({
        source: entry.path,
        reason: COMPOSE_UNPARSED_REASONS.READ_FAILED,
        // The classified filesystem kind, never a raw Node message.
        detail: typeof result.error?.kind === "string" ? result.error.kind : null,
      });
      continue;
    }

    inspected += 1;

    if (result.truncated === true) {
      unparsed.push({
        source: entry.path,
        reason: COMPOSE_UNPARSED_REASONS.TOO_LARGE,
        detail: null,
      });
      continue;
    }

    const text = typeof result.content === "string" ? result.content : "";
    const parsed = parseComposeBuildContexts(text);

    if (!parsed.ok) {
      unparsed.push({ source: entry.path, reason: parsed.reason, detail: parsed.detail ?? null });
      continue;
    }

    // A declaration that cannot be resolved leaves the file's build configuration only
    // partly read, and an uninterpreted declaration could have named *any* Dockerfile in
    // the repository. Recording the source file as unparsed is what makes the rule answer
    // `unknown` for a Dockerfile the file never named, instead of treating the file as if
    // it had declared nothing. The detail is the bounded classification, never the text
    // that failed to resolve.
    let unresolvedDetail = null;

    for (const declaration of parsed.declarations) {
      const result = classifyBuildDeclaration(view.root, entry.path, declaration);
      if (!result.ok) {
        if (result.detail !== CONTAINER_DECLARATION_DETAILS.DOCKERFILE_NOT_OBSERVED) {
          unresolvedDetail ??= result.detail;
        }
        continue;
      }
      // A declaration about a Dockerfile the inventory never observed describes a file
      // this model cannot make a claim about.
      if (!observedFiles.has(result.declaration.dockerfile)) continue;
      declarations.push(result.declaration);
    }

    if (unresolvedDetail !== null) {
      unparsed.push({
        source: entry.path,
        reason: COMPOSE_UNPARSED_REASONS.AMBIGUOUS,
        detail: unresolvedDetail,
      });
    }
  }

  // The same key the ScanResult contract validates against, so a declaration can never
  // be emitted in an order the contract rejects. `context` is normalized to `""` for the
  // repository root (`null`), which is what the contract compares — sorting on the
  // literal string `"null"` would place the root *after* every nested context.
  const declarationKey = (entry) =>
    `${entry.dockerfile}\u0000${entry.context ?? ""}\u0000${entry.service}\u0000${entry.source}`;
  declarations.sort((a, b) => {
    const left = declarationKey(a);
    const right = declarationKey(b);
    return left === right ? 0 : left < right ? -1 : 1;
  });
  unparsed.sort((a, b) => (a.source < b.source ? -1 : a.source > b.source ? 1 : 0));

  const dockerfiles = await detectDockerfileStructures(view);

  return {
    inspected: inspected > 0 || dockerfiles.inspected > 0,
    declarations,
    unparsed,
    dockerfiles: dockerfiles.records,
    limits: { ...CONTAINER_DECLARATION_LIMITS },
  };
}
