/**
 * Code Guardian — RepositoryModel Identity (Phase 8D)
 *
 * Every entity in the model carries a **stable, derivation-only identifier**:
 *
 *   directory:src
 *   file:src/app.ts
 *   manifest:package.json
 *   language:typescript
 *   framework:jest
 *   ecosystem:node
 *   test:src/app.test.js
 *   cicd:.github/workflows/ci.yml
 *   documentation:README.md
 *   configuration:tsconfig.json
 *   symlink:vendor-link
 *   git
 *
 * The identifier is `kind:key`, where the key is the canonical
 * repository-relative path (for path-shaped entities) or the normalized name (for
 * value-shaped entities). Nothing else takes part: no UUIDs, no timestamps, no
 * process ids, no memory addresses, no absolute host paths. Scanning the same
 * repository state twice therefore yields byte-identical ids.
 *
 * ### Identity is not a fingerprint
 *
 * A path-based id answers "which entity is this?", not "is this content
 * unchanged?". Content fingerprints are the deferred Finding/Evidence engine's
 * job (Phase 7 §Fingerprints), and this module deliberately produces none: the
 * scanner does not read file content for most files, and fabricating a hash over
 * data that was never read would be a lie encoded as a string.
 *
 * ### The repository id
 *
 * The repository itself has no relative path, and using the absolute scan root
 * would make identity machine-specific (and would leak a host path into every
 * consumer). `repositoryId` is therefore derived from the *observed inventory
 * shape*: the model version plus the sorted relative paths of every file,
 * directory and symlink, the sorted manifest paths and the sorted language ids.
 *
 * Two consequences are deliberate and documented rather than hidden:
 *
 *   - The same repository state always produces the same id (required).
 *   - Two *different* repositories with an identical inventory produce the same
 *     id, and a repository whose inventory changed produces a different one. The
 *     id identifies a scan's repository *shape*, not a location and not a
 *     commit — it is a stability id, not a security fingerprint.
 *
 * Every input to the hash is public inventory data, so the id cannot be used to
 * recover a host path.
 */

import { REPOSITORY_MODEL_VERSION } from "../../core/index.js";

/** Entity kinds, and the id prefix each uses. */
export const ENTITY_KINDS = Object.freeze({
  DIRECTORY: "directory",
  FILE: "file",
  SYMLINK: "symlink",
  LANGUAGE: "language",
  FRAMEWORK: "framework",
  ECOSYSTEM: "ecosystem",
  MANIFEST: "manifest",
  TEST: "test",
  CICD: "cicd",
  DOCUMENTATION: "documentation",
  CONFIGURATION: "configuration",
  GIT: "git",
});

/** The single id of the git entity (there is one repository). */
export const GIT_ENTITY_ID = "git";

/** Prefix of the repository node that relationships are rooted at. */
export const REPOSITORY_ID_PREFIX = "repository";

/**
 * FNV-1a (32-bit) over UTF-16 code units, rendered as eight lower-case hex digits.
 *
 * Chosen because it is tiny, dependency-free and fully deterministic. It is a
 * *stability* hash: collisions are acceptable here (an id that is stable and
 * collision-prone is still a valid identity key), and it must never be treated as
 * a content fingerprint or as a security boundary.
 *
 * @param {string} input
 * @returns {string}
 */
export function stabilityHash(input) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}

/**
 * Build an entity id from a kind and a key.
 * @param {string} kind One of `ENTITY_KINDS`.
 * @param {string} key Canonical relative path or normalized name.
 * @returns {string}
 */
export function entityId(kind, key) {
  return `${kind}:${key}`;
}

/**
 * Build an evidence id. Evidence ids live in their own namespace (`evidence:`) so
 * they can never collide with entity ids.
 * @param {string} subject Evidence subject (see `evidence.js`).
 * @param {string} key Subject-local unique key.
 * @returns {string}
 */
export function evidenceId(subject, key) {
  return `evidence:${subject}:${key}`;
}

/**
 * Derive the repository id from an observed inventory.
 *
 * @param {object} input
 * @param {string[]} input.paths Sorted inventory paths (files, directories, symlinks).
 * @param {string[]} input.manifestPaths Sorted manifest paths.
 * @param {string[]} input.languageIds Sorted language ids.
 * @returns {string}
 */
export function repositoryId({ paths, manifestPaths, languageIds }) {
  const material = [
    `model:${REPOSITORY_MODEL_VERSION}`,
    ...paths.map((path) => `p:${path}`),
    ...manifestPaths.map((path) => `m:${path}`),
    ...languageIds.map((id) => `l:${id}`),
  ].join("\n");
  return `${REPOSITORY_ID_PREFIX}:${stabilityHash(material)}`;
}
