/**
 * Code Guardian — RepositoryModel Entities (Phase 8D)
 *
 * Turns the sections of a validated `ScanResult` into typed model entities. This
 * is a pure transformation: the ScanResult is the only input, nothing is read from
 * the filesystem, no clock is consulted, and nothing is fabricated. Where the
 * scanner did not observe something, the model says so (`null`, `[]` or an
 * explicit `detected: false`) instead of guessing.
 *
 * Design rules applied uniformly:
 *
 *   - **Every entity has a stable id** (`kind:key`) and at least one evidence id,
 *     except the git entity, which may legitimately be absent (no `.git`).
 *   - **Untrusted text is projected, never echoed raw.** `parse`, `head` and
 *     disposition fields are copied through a closed vocabulary: a value outside
 *     that vocabulary makes the ScanResult malformed and is rejected, so hostile
 *     text cannot become a model identity.
 *   - **Derived values are derived.** `depth` is recomputed from the path and the
 *     directory id from the parent path, so a ScanResult cannot claim a depth or
 *     parent that contradicts the path it carries.
 *   - **No absolute host paths.** Every entity path is guarded by
 *     `requireRepositoryRelativePath`; the only absolute path in the whole model is
 *     `identity.root`.
 */

import { ValidationError } from "../../core/index.js";

import {
  CONTENT_STATUSES,
  CONTENT_UNINSPECTED_REASONS,
  EVIDENCE_SUBJECTS,
  INVENTORY_KINDS,
  createContentInspectionObservation,
  createContentPatternObservation,
  createInventoryObservation,
  createSignalObservation,
} from "./evidence.js";
import { ENTITY_KINDS, GIT_ENTITY_ID, entityId } from "./identity.js";
import {
  basenameOfPath,
  depthOfPath,
  parentPathOf,
  requireRepositoryRelativePath,
} from "./paths.js";

/** Test evidence kinds the scanner can report. */
export const TEST_KINDS = Object.freeze({
  DIRECTORY: "directory",
  FILE: "file",
  CONFIGURATION: "configuration",
});

/** Manifest parse statuses the scanner can report. */
export const MANIFEST_PARSE_STATUSES = Object.freeze([
  "parsed",
  "failed",
  "not-parsed",
]);

/** Git head kinds the scanner can report. */
export const GIT_HEAD_KINDS = Object.freeze({
  BRANCH: "branch",
  DETACHED: "detached",
  GITFILE: "gitfile",
  UNKNOWN: "unknown",
});

/**
 * Where a symlink target resolves. Re-declared here rather than imported from the
 * scanner, because the model layer must not depend on the acquisition layer; a test
 * pins the two vocabularies together.
 */
export const SYMLINK_TARGET_KINDS = Object.freeze({
  INSIDE: "inside",
  OUTSIDE: "outside",
  UNKNOWN: "unknown",
});

/** Why a symlink target is `unknown`. Closed vocabulary, re-declared like the kinds. */
export const SYMLINK_TARGET_REASONS = Object.freeze({
  NOT_INSPECTED: "not-inspected",
  UNREADABLE: "unreadable",
  CYCLE: "cycle",
  DEPTH_EXCEEDED: "depth-exceeded",
});

/** The target recorded for a symlink the scan did not classify. */
export const UNINSPECTED_SYMLINK_TARGET = Object.freeze({
  kind: SYMLINK_TARGET_KINDS.UNKNOWN,
  path: null,
  reason: SYMLINK_TARGET_REASONS.NOT_INSPECTED,
});

/** Maximum content candidates a scan result may carry. */
const MAX_CONTENT_CANDIDATES = 512;

/** Bounded identifier text: letters, digits, `.`, `-`, `_`, `/` only. */
const IDENTIFIER_PATTERN = /^[A-Za-z0-9._/-]{1,120}$/;
const COMMIT_PATTERN = /^[0-9a-f]{7,64}$/;
const MAX_SCRIPT_KEYS = 100;
const MAX_DEPENDENCY_SECTIONS = 8;
const MAX_LANGUAGES_PER_MANIFEST = 16;
const MAX_EXTENSIONS_PER_LANGUAGE = 64;

class ScanResultShapeError extends ValidationError {
  constructor(issues) {
    super("Malformed scan result", {
      details: { contract: "ScanResult", issues },
    });
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function fail(issues, path, message) {
  issues.push(`${path}: ${message}`);
  return null;
}

/** Bounded identifier text, or `null` when it is not safely representable. */
function identifier(value) {
  return typeof value === "string" && IDENTIFIER_PATTERN.test(value) ? value : null;
}

function sortById(entities) {
  return [...entities].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

function sortEvidenceIds(ids) {
  return [...new Set(ids)].sort();
}

/** Project a bounded array of strings. */
function identifierArray(value, limit) {
  if (!Array.isArray(value)) return [];
  const out = [];
  for (const entry of value) {
    if (out.length >= limit) break;
    const projected = identifier(entry);
    if (projected !== null) out.push(projected);
  }
  return out;
}

/**
 * Project the shallow `package.json` metadata the scanner recorded.
 *
 * Keys are copied explicitly; unknown keys are dropped, and every string passes
 * the bounded identifier projection. No dependency graph is built here — the
 * scanner only counted dependency *names* per section, and those counts are what
 * the model keeps.
 */
function projectManifestMetadata(value, issues, path) {
  if (!isPlainObject(value)) {
    if (value !== undefined && value !== null) {
      fail(issues, `${path}.metadata`, "must be a plain object");
    }
    return null;
  }

  const dependencySections = [];
  if (Array.isArray(value.dependencySections)) {
    for (const entry of value.dependencySections) {
      if (dependencySections.length >= MAX_DEPENDENCY_SECTIONS) break;
      if (!isPlainObject(entry)) {
        fail(issues, `${path}.metadata.dependencySections`, "entries must be plain objects");
        continue;
      }
      const section = identifier(entry.section);
      if (section === null || !Number.isInteger(entry.count) || entry.count < 0) {
        fail(
          issues,
          `${path}.metadata.dependencySections`,
          "entries must carry a bounded section name and a non-negative integer count",
        );
        continue;
      }
      dependencySections.push({ section, count: entry.count });
    }
  }

  const name = value.name === undefined || value.name === null ? null : identifier(value.name);
  const version =
    value.version === undefined || value.version === null ? null : identifier(value.version);
  const type = value.type === undefined || value.type === null ? null : identifier(value.type);

  return {
    name,
    version,
    type,
    private: typeof value.private === "boolean" ? value.private : null,
    workspaces: value.workspaces === true,
    scripts: identifierArray(value.scripts, MAX_SCRIPT_KEYS),
    scriptsTruncated: value.scriptsTruncated === true,
    dependencySections,
  };
}

/**
 * Project a manifest parse outcome into a closed, bounded shape.
 * @returns {object}
 */
function projectManifestParse(parse, issues, path) {
  if (!isPlainObject(parse)) {
    fail(issues, `${path}.parse`, "must be a plain object");
    return { status: "not-parsed", format: "unknown", reason: null };
  }

  const status = identifier(parse.status);
  if (status === null || !MANIFEST_PARSE_STATUSES.includes(status)) {
    fail(issues, `${path}.parse.status`, "must be a documented parse status");
  }
  const format = identifier(parse.format);
  if (format === null) {
    fail(issues, `${path}.parse.format`, "must be a bounded format name");
  }

  const projected = {
    status: status ?? "not-parsed",
    format: format ?? "unknown",
  };

  const reason = parse.reason === undefined ? null : identifier(parse.reason);
  if (parse.reason !== undefined && reason === null) {
    fail(issues, `${path}.parse.reason`, "must be a bounded reason identifier");
  }
  projected.reason = reason;

  if (parse.bytes !== undefined) {
    if (!Number.isInteger(parse.bytes) || parse.bytes < 0) {
      fail(issues, `${path}.parse.bytes`, "must be a non-negative integer");
    } else {
      projected.bytes = parse.bytes;
    }
  }

  if (parse.errorKind !== undefined) {
    const errorKind = identifier(parse.errorKind);
    if (errorKind === null) {
      fail(issues, `${path}.parse.errorKind`, "must be a bounded error kind");
    } else {
      projected.errorKind = errorKind;
    }
  }

  if (parse.metadata !== undefined) {
    projected.metadata = projectManifestMetadata(parse.metadata, issues, `${path}.parse`);
  }

  return projected;
}

function requireContentReason(value, issues, path) {
  const reasons = Object.values(CONTENT_UNINSPECTED_REASONS);
  if (!reasons.includes(value)) {
    fail(issues, path, `must be one of: ${reasons.join(", ")}`);
    return null;
  }
  return value;
}

/**
 * Project the scan's bounded content inspection into observations.
 *
 * Nothing is inferred from a filename here: the observations state only what the
 * inspection did (`status`, `reason`, bytes examined) and which *pattern shapes*
 * matched. A candidate that was not inspected keeps its reason, so the model keeps
 * two very different situations apart — content that was examined and matched
 * nothing, versus content that was never examined at all — a distinction a security
 * rule must not lose.
 *
 * The projection fails closed on an incoherent section (a candidate that is not an
 * observed file, an unknown status, an unbounded pattern id) rather than dropping
 * the record, because a silently dropped content observation is a silently missing
 * security fact.
 *
 * @param {object|undefined} section The scan result's `content` section.
 * @param {Set<string>} observedFilePaths Paths the inventory actually observed.
 * @param {string[]} issues Issue collector.
 * @param {Function} record Records one observation and returns its id.
 * @returns {void}
 */
function projectContentSection(section, observedFilePaths, issues, record) {
  if (section === undefined || section === null) return;
  if (!isPlainObject(section)) {
    fail(issues, "scanResult.content", "must be a plain object");
    return;
  }
  if (!Array.isArray(section.candidates)) {
    fail(issues, "scanResult.content.candidates", "must be an array");
    return;
  }
  if (section.candidates.length > MAX_CONTENT_CANDIDATES) {
    fail(issues, "scanResult.content.candidates", "carries more candidates than a scan can report");
    return;
  }

  for (const candidate of section.candidates) {
    if (!isPlainObject(candidate)) {
      fail(issues, "scanResult.content.candidates[]", "must be a plain object");
      continue;
    }
    const path = requireRepositoryRelativePath(
      candidate.path,
      "scanResult.content.candidates[].path",
    );
    const candidateClass = identifier(candidate.candidate);
    if (candidateClass === null) {
      fail(issues, `scanResult.content.candidates[${path}].candidate`, "must be a bounded class id");
      continue;
    }
    if (!observedFilePaths.has(path)) {
      fail(
        issues,
        `scanResult.content.candidates[${path}]`,
        "a content candidate must be a file the inventory observed",
      );
      continue;
    }

    const inspected = candidate.inspected === true;
    const truncated = candidate.truncated === true;
    const bytesInspected =
      Number.isInteger(candidate.bytesInspected) && candidate.bytesInspected >= 0
        ? candidate.bytesInspected
        : 0;

    let status;
    let reason;
    if (inspected) {
      status = truncated ? CONTENT_STATUSES.PARTIAL : CONTENT_STATUSES.INSPECTED;
      reason = null;
    } else {
      status = CONTENT_STATUSES.UNINSPECTED;
      reason = requireContentReason(
        candidate.reason,
        issues,
        `scanResult.content.candidates[${path}].reason`,
      );
      // An uninspected candidate with no recorded reason cannot be modelled: the
      // record's entire meaning is *why* the content is unknown.
      if (reason === null) continue;
    }

    record(
      createContentInspectionObservation({ path, status, reason, bytesInspected }),
    );

    if (!inspected) continue;
    for (const patternId of Array.isArray(candidate.patterns) ? candidate.patterns : []) {
      const pattern = identifier(patternId);
      if (pattern === null) {
        fail(
          issues,
          `scanResult.content.candidates[${path}].patterns`,
          "must be bounded pattern ids",
        );
        continue;
      }
      record(createContentPatternObservation({ path, patternId: pattern }));
    }
  }
}

/**
 * Project a symlink's recorded target into the model's closed vocabulary.
 *
 * The three kinds are exhaustive and a location is only ever recorded for `inside`
 * — and then only as a repository-relative path. That is what makes the field safe
 * to serialize: an escaping target keeps no text at all, so an absolute host path
 * cannot be carried (or leaked) by the model, and `unknown` is a first-class value
 * rather than a missing field.
 *
 * @param {unknown} target
 * @param {string[]} issues
 * @param {string} path
 * @returns {{kind: string, path: string|null, reason: string|null}}
 */
export function projectSymlinkTarget(target, issues, path) {
  if (target === undefined || target === null) return { ...UNINSPECTED_SYMLINK_TARGET };
  if (!isPlainObject(target)) {
    fail(issues, path, "must be a plain object when present");
    return { ...UNINSPECTED_SYMLINK_TARGET };
  }

  const kinds = Object.values(SYMLINK_TARGET_KINDS);
  if (!kinds.includes(target.kind)) {
    fail(issues, `${path}.kind`, `must be one of: ${kinds.join(", ")}`);
    return { ...UNINSPECTED_SYMLINK_TARGET };
  }

  if (target.kind === SYMLINK_TARGET_KINDS.INSIDE) {
    if (target.path === null) return { kind: target.kind, path: null, reason: null };
    let relative;
    try {
      relative = requireRepositoryRelativePath(target.path, `${path}.path`);
    } catch (error) {
      for (const issue of error?.details?.issues ?? [`${path}.path: invalid`]) {
        issues.push(issue);
      }
      return { ...UNINSPECTED_SYMLINK_TARGET };
    }
    return { kind: target.kind, path: relative, reason: null };
  }

  if (target.path !== null && target.path !== undefined) {
    fail(issues, `${path}.path`, `must be null for a ${target.kind} target`);
  }

  if (target.kind === SYMLINK_TARGET_KINDS.OUTSIDE) {
    if (target.reason !== null && target.reason !== undefined) {
      fail(issues, `${path}.reason`, "must be null for an outside target");
    }
    return { kind: target.kind, path: null, reason: null };
  }

  const reasons = Object.values(SYMLINK_TARGET_REASONS);
  if (!reasons.includes(target.reason)) {
    fail(issues, `${path}.reason`, `must be one of: ${reasons.join(", ")}`);
    return { ...UNINSPECTED_SYMLINK_TARGET };
  }
  return { kind: SYMLINK_TARGET_KINDS.UNKNOWN, path: null, reason: target.reason };
}

/** Flattened target fields for a symlink's inventory observation. */
function symlinkTargetData(target) {
  return {
    targetKind: target.kind,
    targetPath: target.path,
    targetReason: target.reason,
  };
}

/**
 * Project `.git/HEAD` into the model's closed head vocabulary.
 *
 * A hostile or corrupt HEAD must not be able to smear arbitrary text (or a host
 * path) into the model, so anything that is not a well-formed ref or commit is
 * degraded to `{ kind: "unknown" }` — the same bounded outcome the scanner itself
 * uses. Only these four keys are ever copied.
 *
 * @param {unknown} head
 * @returns {{ kind: string, branch?: string, ref?: string, commit?: string }}
 */
export function projectGitHead(head) {
  if (!isPlainObject(head)) return { kind: GIT_HEAD_KINDS.UNKNOWN };

  const kind = Object.values(GIT_HEAD_KINDS).includes(head.kind)
    ? head.kind
    : GIT_HEAD_KINDS.UNKNOWN;

  if (kind === GIT_HEAD_KINDS.BRANCH) {
    const branch = identifier(head.branch);
    if (branch === null || branch.startsWith("/") || branch.split("/").includes("..")) {
      return { kind: GIT_HEAD_KINDS.UNKNOWN };
    }
    const ref = identifier(head.ref);
    const refValid =
      ref !== null && ref.startsWith("refs/") && !ref.split("/").includes("..");
    return refValid ? { kind, branch, ref } : { kind, branch };
  }

  if (kind === GIT_HEAD_KINDS.DETACHED) {
    return COMMIT_PATTERN.test(head.commit)
      ? { kind, commit: head.commit }
      : { kind: GIT_HEAD_KINDS.UNKNOWN };
  }

  return { kind };
}

/**
 * Build every entity collection, plus the observation records they reference.
 *
 * @param {object} scanResult A validated ScanResult.
 * @param {string} repositoryIdValue Repository node id (from `identity.js`).
 * @returns {object} Entity collections, the git entity and the observations.
 * @throws {ValidationError} When the ScanResult contradicts itself (an unsafe
 *   path, an unsupported disposition, a missing parent directory, or an entity
 *   with no supporting observation). Failing closed is deliberate: a partially
 *   trustworthy model is worse than an explicit rejection.
 */
export function buildEntities(scanResult, repositoryIdValue) {
  const issues = [];
  const evidence = [];
  const observationsByPath = new Map();

  const record = (observation) => {
    evidence.push(observation);
    const path = observation.location.path;
    const bucket = observationsByPath.get(path);
    if (bucket === undefined) observationsByPath.set(path, [observation.id]);
    else bucket.push(observation.id);
    return observation.id;
  };


  // ── Filesystem entities ────────────────────────────────────────────────────

  const directories = [];
  const directoryIds = new Set();
  /** Resolve the containing directory id for a path (the repository itself at the root). */
  const directoryIdFor = (path) => {
    const parent = parentPathOf(path);
    return parent === null ? repositoryIdValue : entityId(ENTITY_KINDS.DIRECTORY, parent);
  };

  for (const entry of scanResult.directories) {
    const path = requireRepositoryRelativePath(entry.path, "scanResult.directories[].path");
    const id = entityId(ENTITY_KINDS.DIRECTORY, path);
    if (directoryIds.has(id)) {
      fail(issues, `scanResult.directories`, `duplicate directory path`);
      continue;
    }
    directoryIds.add(id);
    const parent = parentPathOf(path);
    directories.push({
      id,
      kind: ENTITY_KINDS.DIRECTORY,
      path,
      name: basenameOfPath(path),
      depth: depthOfPath(path),
      parentId: parent === null ? null : entityId(ENTITY_KINDS.DIRECTORY, parent),
      evidenceIds: [],
    });
  }

  const files = scanResult.files.map((entry) => {
    const path = requireRepositoryRelativePath(entry.path, "scanResult.files[].path");
    return {
      id: entityId(ENTITY_KINDS.FILE, path),
      kind: ENTITY_KINDS.FILE,
      path,
      name: basenameOfPath(path),
      extension: typeof entry.extension === "string" ? entry.extension.toLowerCase() : "",
      depth: depthOfPath(path),
      languageId: null,
      directoryId: directoryIdFor(path),
      evidenceIds: [],
    };
  });

  const symlinks = scanResult.symlinks.map((entry) => {
    const path = requireRepositoryRelativePath(entry.path, "scanResult.symlinks[].path");
    return {
      id: entityId(ENTITY_KINDS.SYMLINK, path),
      kind: ENTITY_KINDS.SYMLINK,
      path,
      name: basenameOfPath(path),
      depth: depthOfPath(path),
      // The Phase 8A policy refuses to traverse symlinks, so every symlink the
      // scanner reports was recorded without being followed.
      followed: false,
      // Where the link points, in the closed three-way vocabulary. A scan that did
      // not classify the link yields `unknown`, never `inside`: "we did not look"
      // must not read as "this link is harmless".
      target: projectSymlinkTarget(
        entry.target,
        issues,
        `scanResult.symlinks[${path}].target`,
      ),
      directoryId: directoryIdFor(path),
      evidenceIds: [],
    };
  });

  for (const entity of directories) {
    record(createInventoryObservation({ path: entity.path, kind: INVENTORY_KINDS.DIRECTORY }));
  }
  for (const entity of [...files, ...symlinks]) {
    record(
      createInventoryObservation({
        path: entity.path,
        kind: entity.kind === ENTITY_KINDS.FILE ? INVENTORY_KINDS.FILE : INVENTORY_KINDS.SYMLINK,
        data:
          entity.kind === ENTITY_KINDS.FILE
            ? { extension: entity.extension }
            : symlinkTargetData(entity.target),
      }),
    );
  }

  // ── Content observations (bounded file inspection) ───────────────────────────

  const observedFilePaths = new Set(files.map((file) => file.path));
  projectContentSection(scanResult.content, observedFilePaths, issues, record);

  // ── Languages ─────────────────────────────────────────────────────────────

  const languages = [];
  const extensionToLanguage = new Map();

  for (const entry of scanResult.languages) {
    const languageId = identifier(entry.id);
    if (languageId === null) {
      fail(issues, "scanResult.languages[].id", "must be a bounded language id");
      continue;
    }
    if (!Array.isArray(entry.evidence) || entry.evidence.length === 0) {
      fail(issues, "scanResult.languages[].evidence", "a language must carry evidence");
      continue;
    }

    const evidenceIds = [];
    for (const observation of entry.evidence) {
      const path = requireRepositoryRelativePath(
        observation.path,
        "scanResult.languages[].evidence[].path",
      );
      const signal = identifier(observation.signal);
      if (signal === null) {
        fail(issues, "scanResult.languages[].evidence[].signal", "must be a bounded signal id");
        continue;
      }
      evidenceIds.push(
        record(
          createSignalObservation({
            subject: EVIDENCE_SUBJECTS.LANGUAGE,
            path,
            signal,
            // Two languages can share a path only through a manifest that declares
            // both, so the language is part of the observation key.
            keyPrefix: `${languageId}:`,
            data: { languageId },
          }),
        ),
      );
    }

    const extensions = [];
    for (const extension of Array.isArray(entry.extensions) ? entry.extensions : []) {
      if (extensions.length >= MAX_EXTENSIONS_PER_LANGUAGE) break;
      if (typeof extension !== "string" || !/^\.[A-Za-z0-9._-]{1,20}$/.test(extension)) {
        fail(issues, "scanResult.languages[].extensions", "must be file extensions");
        continue;
      }
      const normalized = extension.toLowerCase();
      extensions.push(normalized);
      // First language wins on a shared extension, in sorted id order, so the
      // mapping is deterministic even for a hand-crafted ScanResult.
      if (!extensionToLanguage.has(normalized)) extensionToLanguage.set(normalized, languageId);
    }

    languages.push({
      id: entityId(ENTITY_KINDS.LANGUAGE, languageId),
      kind: ENTITY_KINDS.LANGUAGE,
      path: null,
      languageId,
      fileCount: Number.isInteger(entry.fileCount) && entry.fileCount >= 0 ? entry.fileCount : 0,
      extensions,
      // Preserved from the scan: the scanner caps evidence per signal, so a
      // bounded observation list is never mistaken for a complete one.
      evidenceTruncated: entry.evidenceTruncated === true,
      evidenceIds: sortEvidenceIds(evidenceIds),
    });
  }

  for (const file of files) {
    const languageId = extensionToLanguage.get(file.extension);
    if (languageId !== undefined) file.languageId = entityId(ENTITY_KINDS.LANGUAGE, languageId);
  }

  // ── Manifests and ecosystems ──────────────────────────────────────────────

  const manifests = [];
  const ecosystemIds = new Set();

  for (const entry of scanResult.manifests) {
    const path = requireRepositoryRelativePath(entry.path, "scanResult.manifests[].path");
    const ecosystem = identifier(entry.ecosystem);
    if (ecosystem === null) {
      fail(issues, "scanResult.manifests[].ecosystem", "must be a bounded ecosystem id");
      continue;
    }
    const manifestKind = identifier(entry.kind);
    if (manifestKind === null) {
      fail(issues, "scanResult.manifests[].kind", "must be a bounded manifest kind");
      continue;
    }

    const declaredLanguages = [];
    for (const languageId of Array.isArray(entry.languages) ? entry.languages : []) {
      if (declaredLanguages.length >= MAX_LANGUAGES_PER_MANIFEST) break;
      const validated = identifier(languageId);
      if (validated === null) {
        fail(issues, "scanResult.manifests[].languages", "must be bounded language ids");
        continue;
      }
      declaredLanguages.push(entityId(ENTITY_KINDS.LANGUAGE, validated));
    }

    record(
      createSignalObservation({
        subject: EVIDENCE_SUBJECTS.MANIFEST,
        path,
        signal: `manifest-${manifestKind}`,
        data: { ecosystem, manifestKind },
      }),
    );

    const ecosystemId = entityId(ENTITY_KINDS.ECOSYSTEM, ecosystem);
    ecosystemIds.add(ecosystemId);

    manifests.push({
      id: entityId(ENTITY_KINDS.MANIFEST, path),
      kind: ENTITY_KINDS.MANIFEST,
      path,
      name: basenameOfPath(path),
      depth: depthOfPath(path),
      directoryId: directoryIdFor(path),
      ecosystemId,
      manifestKind,
      languages: sortEvidenceIds(declaredLanguages),
      parse: projectManifestParse(entry.parse, issues, `scanResult.manifests[${path}]`),
      evidenceIds: [],
    });
  }

  const ecosystems = [...ecosystemIds].sort().map((id) => ({
    id,
    kind: ENTITY_KINDS.ECOSYSTEM,
    path: null,
    name: id.slice(`${ENTITY_KINDS.ECOSYSTEM}:`.length),
    // Filled from its manifests once their provenance is attached.
    evidenceIds: [],
  }));

  // ── Testing, frameworks, CI/CD, documentation, configuration ──────────────

  const tests = [];
  const frameworkIds = new Set();

  for (const entry of scanResult.tests.evidence) {
    const path = requireRepositoryRelativePath(entry.path, "scanResult.tests.evidence[].path");
    const signal = identifier(entry.signal);
    if (signal === null) {
      fail(issues, "scanResult.tests.evidence[].signal", "must be a bounded signal id");
      continue;
    }
    const resolvedKind = typeof entry.kind === "string" ? entry.kind : null;
    if (resolvedKind === null || !Object.values(TEST_KINDS).includes(resolvedKind)) {
      fail(issues, "scanResult.tests.evidence[].kind", "must be a documented test kind");
      continue;
    }

    const frameworkName =
      entry.framework === null || entry.framework === undefined ? null : identifier(entry.framework);
    if (entry.framework !== null && entry.framework !== undefined && frameworkName === null) {
      fail(issues, "scanResult.tests.evidence[].framework", "must be a bounded framework name");
      continue;
    }
    if (frameworkName !== null) frameworkIds.add(frameworkName);

    record(
      createSignalObservation({
        subject: EVIDENCE_SUBJECTS.TEST,
        path,
        signal,
        data: { testKind: resolvedKind, framework: frameworkName },
      }),
    );

    tests.push({
      id: entityId(ENTITY_KINDS.TEST, path),
      kind: ENTITY_KINDS.TEST,
      path,
      depth: depthOfPath(path),
      directoryId: directoryIdFor(path),
      signal,
      testKind: resolvedKind,
      frameworkId:
        frameworkName === null ? null : entityId(ENTITY_KINDS.FRAMEWORK, frameworkName),
      evidenceIds: [],
    });
  }

  const frameworks = [...frameworkIds].sort().map((name) => ({
    id: entityId(ENTITY_KINDS.FRAMEWORK, name),
    kind: ENTITY_KINDS.FRAMEWORK,
    path: null,
    name,
    category: "test",
    // Filled from its test evidence once that provenance is attached.
    evidenceIds: [],
  }));

  /**
   * Build the three homogeneous signal-entity sections (CI/CD, documentation,
   * configuration). Each entry projects its extra fields through the same bounded
   * vocabulary as everything else; a projection that cannot be represented
   * safely fails the whole build instead of yielding a half-described entity.
   */
  const buildSignalEntities = (entries, subject, kind, project) => {
    const out = [];
    for (const entry of entries) {
      const path = requireRepositoryRelativePath(
        entry.path,
        `scanResult.${subject}.evidence[].path`,
      );
      const signal = identifier(entry.signal);
      if (signal === null) {
        fail(issues, `scanResult.${subject}.evidence[].signal`, "must be a bounded signal id");
        continue;
      }
      const extra = project(entry, path, signal, issues);
      if (extra === null) continue;
      record(createSignalObservation({ subject, path, signal, data: extra.data }));

      out.push({
        id: entityId(kind, path),
        kind,
        path,
        depth: depthOfPath(path),
        directoryId: directoryIdFor(path),
        // The scanner signal that produced this entity, kept verbatim so a
        // consumer can tell a test *directory* from a test *file* from a *config*.
        signal,
        ...extra.fields,
        evidenceIds: [],
      });
    }
    return out;
  };

  const cicd = buildSignalEntities(
    scanResult.cicd.evidence,
    EVIDENCE_SUBJECTS.CICD,
    ENTITY_KINDS.CICD,
    (entry, path, signal, issuesList) => {
      const provider = identifier(entry.provider);
      if (provider === null) {
        fail(
          issuesList,
          `scanResult.cicd.evidence[${path}].provider`,
          "must be a bounded provider id",
        );
        return null;
      }
      return { data: { provider }, fields: { provider } };
    },
  );

  const documentation = buildSignalEntities(
    scanResult.documentation.evidence,
    EVIDENCE_SUBJECTS.DOCUMENTATION,
    ENTITY_KINDS.DOCUMENTATION,
    (entry) => ({
      data: { isDirectory: entry.isDirectory === true },
      fields: { isDirectory: entry.isDirectory === true },
    }),
  );

  const configuration = buildSignalEntities(
    scanResult.configuration.evidence,
    EVIDENCE_SUBJECTS.CONFIGURATION,
    ENTITY_KINDS.CONFIGURATION,
    () => ({ data: {}, fields: {} }),
  );

  // ── Git ───────────────────────────────────────────────────────────────────

  const gitEvidenceIds = [];
  for (const entry of scanResult.git.evidence) {
    const path = requireRepositoryRelativePath(entry.path, "scanResult.git.evidence[].path");
    const signal = identifier(entry.signal);
    if (signal === null) {
      fail(issues, "scanResult.git.evidence[].signal", "must be a bounded signal id");
      continue;
    }
    gitEvidenceIds.push(
      record(createSignalObservation({ subject: EVIDENCE_SUBJECTS.GIT, path, signal })),
    );
  }

  const git = {
    id: GIT_ENTITY_ID,
    kind: ENTITY_KINDS.GIT,
    path: null,
    detected: scanResult.git.detected === true,
    head: projectGitHead(scanResult.git.head),
    evidenceIds: sortEvidenceIds(gitEvidenceIds),
  };

  // ── Cross-checks that fail closed ─────────────────────────────────────────

  if (scanResult.git.detected === true && git.evidenceIds.length === 0) {
    fail(issues, "scanResult.git", "detected git must carry at least one observation");
  }
  for (const file of files) {
    if (
      file.directoryId !== repositoryIdValue &&
      !directoryIds.has(file.directoryId)
    ) {
      fail(
        issues,
        `scanResult.files[${file.path}]`,
        "a file's parent directory was not observed",
      );
    }
  }
  for (const entity of [...manifests, ...tests, ...cicd, ...documentation, ...configuration]) {
    if (entity.directoryId !== repositoryIdValue && !directoryIds.has(entity.directoryId)) {
      fail(
        issues,
        `scanResult[${entity.path}]`,
        "a path-bearing entity's parent directory was not observed",
      );
    }
  }
  for (const manifest of manifests) {
    for (const languageId of manifest.languages) {
      if (!languages.some((language) => language.id === languageId)) {
        fail(
          issues,
          `scanResult.manifests[${manifest.path}].languages`,
          "a declared language was not observed",
        );
      }
    }
  }

  // ── Provenance assignment ─────────────────────────────────────────────────
  //
  // Evidence is attached *after* every section has recorded its observations, so a
  // path observed by several detectors (a test file is both inventory and test
  // evidence) carries all of its provenance even though the entities are built in
  // passes. Every path-based entity references exactly the observations recorded
  // at its path — nothing is inferred, and a shared observation legitimately
  // supports more than one entity.
  const pathBasedEntities = [
    ...files,
    ...directories,
    ...symlinks,
    ...manifests,
    ...tests,
    ...cicd,
    ...documentation,
    ...configuration,
  ];
  for (const entity of pathBasedEntities) {
    entity.evidenceIds = sortEvidenceIds(observationsByPath.get(entity.path) ?? []);
    if (entity.evidenceIds.length === 0) {
      fail(issues, `scanResult[${entity.path}]`, "a path-bearing entity has no observation");
    }
  }

  // Derivative entities (a framework, an ecosystem) inherit the provenance of the
  // observations that produced them; they never carry evidence of their own.
  for (const framework of frameworks) {
    framework.evidenceIds = sortEvidenceIds(
      tests
        .filter((test) => test.frameworkId === framework.id)
        .flatMap((test) => test.evidenceIds),
    );
    if (framework.evidenceIds.length === 0) {
      fail(issues, `scanResult.tests.frameworks[${framework.name}]`, "framework has no evidence");
    }
  }
  for (const ecosystem of ecosystems) {
    ecosystem.evidenceIds = sortEvidenceIds(
      manifests
        .filter((manifest) => manifest.ecosystemId === ecosystem.id)
        .flatMap((manifest) => manifest.evidenceIds),
    );
    if (ecosystem.evidenceIds.length === 0) {
      fail(issues, `scanResult.manifests[${ecosystem.name}]`, "ecosystem has no evidence");
    }
  }

  // Identity is `kind:path`, so a duplicated path within one section is an
  // inconsistent inventory rather than a modelling choice.
  const seenIds = new Set();
  for (const entity of [...pathBasedEntities, ...languages, ...frameworks, ...ecosystems, git]) {
    if (seenIds.has(entity.id)) {
      fail(issues, `scanResult[${entity.id}]`, "duplicate entity identity in the scan result");
    }
    seenIds.add(entity.id);
  }

  if (issues.length > 0) throw new ScanResultShapeError(issues);

  return {
    files: sortById(files),
    directories: sortById(directories),
    symlinks: sortById(symlinks),
    languages: sortById(languages),
    frameworks: sortById(frameworks),
    ecosystems: sortById(ecosystems),
    manifests: sortById(manifests),
    tests: sortById(tests),
    cicd: sortById(cicd),
    documentation: sortById(documentation),
    configuration: sortById(configuration),
    git,
    evidence: [...evidence].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
  };
}
