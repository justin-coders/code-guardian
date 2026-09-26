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
  CONTAINER_SIGNALS,
  CONTENT_STATUSES,
  CONTENT_UNINSPECTED_REASONS,
  DEPENDENCY_SIGNALS,
  EVIDENCE_SUBJECTS,
  EVIDENCE_TYPE_BY_SUBJECT,
  INVENTORY_KINDS,
  createBuildContextObservation,
  createContentInspectionObservation,
  createContentPatternObservation,
  createDependencyDeclarationObservation,
  createDependencyResolutionObservation,
  createDependencySourceObservation,
  createApiSourceObservation,
  createImportSourceObservation,
  createInventoryObservation,
  createSymbolSourceObservation,
  createObservation,
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

/**
 * Dependency vocabularies and bounds.
 *
 * Re-declared here rather than imported from the acquisition layer, exactly like
 * `SYMLINK_TARGET_KINDS` above: the model must not depend on the scanner. A test in
 * `tests/dependency-intelligence.test.js` pins the two vocabularies together, so a
 * rename on either side fails the suite instead of silently retiring a value.
 *
 * What the model *does* re-derive is the safety property, not the ecosystem rules:
 * a dependency name is projected only when it is bounded, free of control
 * characters and free of path traversal. Which names an ecosystem permits is the
 * acquisition contract's question; whether a name may become a model identity is
 * this layer's, and a malformed ScanResult that smuggled `../evil` past the scan
 * contract is rejected here.
 */
export const DEPENDENCY_SOURCE_STATUSES = Object.freeze([
  "parsed",
  "unsupported",
  "failed",
]);

export const DEPENDENCY_SOURCE_REASONS = Object.freeze([
  "format-not-interpreted",
  "invalid-json",
  "json-value-is-not-an-object",
  "not-text",
  "manifest-could-not-be-read",
  "exceeds-max-manifest-bytes",
  "budget-exhausted",
]);

export const DEPENDENCY_SCOPES = Object.freeze([
  "runtime",
  "development",
  "optional",
  "peer",
  "unknown",
]);

export const DEPENDENCY_SPEC_KINDS = Object.freeze([
  "registry",
  "workspace",
  "local",
  "url",
  "git",
  "alias",
  "unknown",
]);

export const DEPENDENCY_PROBLEM_REASONS = Object.freeze([
  "invalid-name",
  "invalid-spec",
  "invalid-version",
  "invalid-entry-key",
  "duplicate-declaration",
  "depth-limit",
  "entry-limit",
  "edge-limit",
  "include-directive",
  "editable-requirement",
  "line-continuation-unsupported",
  "replace-directive",
  "exclude-directive",
]);

/** Maximum dependency sources (manifest records) a scan result may carry. */
const MAX_DEPENDENCY_SOURCES = 512;

/** Maximum dependency entities a scan result may describe. */
const MAX_DEPENDENCY_ENTITIES = 8000;

/** Maximum dependency edges a scan result may state. */
const MAX_DEPENDENCY_EDGES = 12000;

/** Bounded dependency name text. Wider than `IDENTIFIER_PATTERN` by `@`, for npm. */
const DEPENDENCY_NAME_PATTERN = /^[A-Za-z0-9@][A-Za-z0-9@._/+-]*$/;
const MAX_DEPENDENCY_NAME_LENGTH = 214;
const MAX_DEPENDENCY_SPEC_LENGTH = 200;

/** Maximum content candidates a scan result may carry. */
const MAX_CONTENT_CANDIDATES = 512;

/** Maximum container build declarations a scan result may carry. */
const MAX_CONTAINER_DECLARATIONS = 512;

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
 * Project the scan's container build declarations into observations.
 *
 * A declaration is recorded *at the Dockerfile it is about*, so the rule that owns
 * container security finds it through the Dockerfile's own evidence. An unparsed
 * Compose file is recorded at the Compose file, because that is the artifact whose
 * declarations could not be established — which is what turns "no declaration" into
 * the honest `unknown` rather than an absence of protection.
 *
 * Projection fails closed on an incoherent section (a declaration about an unobserved
 * Dockerfile, an unparsed entry for a path the inventory never saw, an unbounded
 * reason), because a dropped build declaration would silently weaken a security
 * conclusion.
 *
 * @param {object|undefined} section The scan result's `containers` section.
 * @param {Set<string>} observedFilePaths Paths the inventory actually observed.
 * @param {string[]} issues Issue collector.
 * @param {Function} record Records one observation and returns its id.
 * @returns {void}
 */
function projectContainerSection(section, observedFilePaths, issues, record) {
  if (section === undefined || section === null) return;
  if (!isPlainObject(section)) {
    fail(issues, "scanResult.containers", "must be a plain object");
    return;
  }

  if (!Array.isArray(section.declarations) || !Array.isArray(section.unparsed)) {
    fail(issues, "scanResult.containers", "must carry declarations and unparsed arrays");
    return;
  }
  if (section.declarations.length > MAX_CONTAINER_DECLARATIONS) {
    fail(issues, "scanResult.containers.declarations", "carries more declarations than a scan can report");
    return;
  }

  for (const declaration of section.declarations) {
    if (!isPlainObject(declaration)) {
      fail(issues, "scanResult.containers.declarations[]", "must be a plain object");
      continue;
    }
    const source = requireRepositoryRelativePath(
      declaration.source,
      "scanResult.containers.declarations[].source",
    );
    const service = identifier(declaration.service);
    if (service === null) {
      fail(issues, `scanResult.containers.declarations[${source}].service`, "must be a bounded service name");
      continue;
    }
    const dockerfilePath = requireRepositoryRelativePath(
      declaration.dockerfile,
      "scanResult.containers.declarations[].dockerfile",
    );
    // `null` means the repository root: it has no repository-relative form, and the
    // declaration still establishes it unambiguously.
    const contextPath =
      declaration.context === null || declaration.context === undefined
        ? null
        : requireRepositoryRelativePath(
            declaration.context,
            "scanResult.containers.declarations[].context",
          );
    if (!observedFilePaths.has(dockerfilePath)) {
      fail(
        issues,
        `scanResult.containers.declarations[${dockerfilePath}]`,
        "a declaration must name a Dockerfile the inventory observed",
      );
      continue;
    }
    record(
      createBuildContextObservation({
        path: dockerfilePath,
        source,
        service,
        contextPath,
      }),
    );
  }

  for (const entry of section.unparsed) {
    if (!isPlainObject(entry)) {
      fail(issues, "scanResult.containers.unparsed[]", "must be a plain object");
      continue;
    }
    const path = requireRepositoryRelativePath(
      entry.source,
      "scanResult.containers.unparsed[].source",
    );
    const reason = identifier(entry.reason);
    if (reason === null) {
      fail(issues, `scanResult.containers.unparsed[${path}].reason`, "must be a bounded reason");
      continue;
    }
    const detail = entry.detail === null || entry.detail === undefined ? null : identifier(entry.detail);
    if (entry.detail !== null && entry.detail !== undefined && detail === null) {
      fail(issues, `scanResult.containers.unparsed[${path}].detail`, "must be a bounded identifier");
      continue;
    }
    if (!observedFilePaths.has(path)) {
      fail(
        issues,
        `scanResult.containers.unparsed[${path}]`,
        "an unparsed entry must name a file the inventory observed",
      );
      continue;
    }
    record(
      createObservation({
        subject: EVIDENCE_SUBJECTS.CONFIGURATION,
        key: `${CONTAINER_SIGNALS.UNPARSED}:${path}`,
        type: EVIDENCE_TYPE_BY_SUBJECT[EVIDENCE_SUBJECTS.CONFIGURATION],
        path,
        data: { signal: CONTAINER_SIGNALS.UNPARSED, reason, detail },
      }),
    );
  }
}

/**
 * Project a dependency name that is about to become a model identity.
 *
 * Bounded, printable, path-free text only: `..`, a leading `/` or a leading `.`,
 * a control character or an out-of-vocabulary character is rejected, because the
 * name is part of an entity id and of evidence ids. The message never echoes the
 * rejected value — hostile text must not travel into an error a caller serializes.
 *
 * @param {unknown} value
 * @returns {string|null} The name, or `null` when it cannot be an identity.
 */
export function projectDependencyName(value) {
  if (typeof value !== "string") return null;
  if (value.length === 0 || value.length > MAX_DEPENDENCY_NAME_LENGTH) return null;
  if (value.includes("..") || value.startsWith("/") || value.startsWith(".")) return null;
  if (!DEPENDENCY_NAME_PATTERN.test(value)) return null;
  return value;
}

/**
 * Whether a declared spec is safe to record.
 *
 * The scan contract already bounded specs; this re-checks the property the model
 * depends on (bounded, control-character free) so a malformed ScanResult cannot
 * put a newline or a NUL into a model field.
 */
function projectDependencySpec(value) {
  if (value === null || value === undefined) return { ok: true, spec: null };
  if (typeof value !== "string") return { ok: false };
  if (value.length > MAX_DEPENDENCY_SPEC_LENGTH) return { ok: false };
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(value)) return { ok: false };
  return { ok: true, spec: value };
}

function compareByKeys(keys) {
  return (a, b) => {
    for (const key of keys) {
      if (a[key] === b[key]) continue;
      return a[key] < b[key] ? -1 : 1;
    }
    return 0;
  };
}

/**
 * Project the scan's dependency acquisition into dependency entities.
 *
 * This is where "what the manifests said" becomes a graph the query layer and the
 * rules can consume. Four properties are load-bearing:
 *
 *   1. **One entity per `(ecosystem, name)`.** A dependency is the same dependency
 *      whichever manifest declares it, so multi-manifest repositories get one node
 *      per package with a *declaration record per manifest*. Contradictory
 *      declarations in independent manifests are therefore both preserved, never
 *      reconciled or overwritten.
 *   2. **Provenance is per source.** Every declaration cites the manifest's own
 *      declaration observation; every resolution and edge cites the lockfile's
 *      resolution observation. A source that could not be interpreted cites its
 *      own source observation, which is what makes an `unknown` conclusion
 *      expressible in the model instead of invisible.
 *   3. **Nothing is invented.** A dependency exists because a manifest declared it,
 *      a lockfile resolved it, or a lockfile edge named it — never because a name
 *      looked like a package. `direct` is only ever set from a declaration the
 *      format itself marked direct, and `resolved` only from a lockfile entry.
 *   4. **Everything is bounded and fail-closed.** An incoherent section (an
 *      unobserved source path, an unknown status or scope, an unsafe name, more
 *      edges than a scan may state) fails the build rather than producing a model
 *      whose dependency facts are quietly partial.
 *
 * @param {object|undefined} section The scan result's `dependencies` section.
 * @param {object[]} manifests Built manifest entities (with ids).
 * @param {Set<string>} observedFilePaths Paths the inventory actually observed.
 * @param {string[]} issues Issue collector.
 * @param {Function} record Records one observation and returns its id.
 * @returns {{entries: object[], sources: object[],
 *   edges: Array<{from: string, to: string, evidenceIds: string[], manifestPaths: string[]}>,
 *   coverage: object}}
 */
function projectDependenciesSection(section, manifests, observedFilePaths, issues, record) {
  const empty = {
    entries: [],
    sources: [],
    edges: [],
    coverage: {
      inspected: false,
      complete: false,
      truncated: false,
      declarations: 0,
      resolved: 0,
      edges: 0,
    },
  };

  if (section === undefined || section === null) return empty;
  if (!isPlainObject(section)) {
    fail(issues, "scanResult.dependencies", "must be a plain object");
    return empty;
  }
  if (!Array.isArray(section.manifests)) {
    fail(issues, "scanResult.dependencies.manifests", "must be an array");
    return empty;
  }
  if (section.manifests.length > MAX_DEPENDENCY_SOURCES) {
    fail(
      issues,
      "scanResult.dependencies.manifests",
      "carries more dependency sources than a scan can report",
    );
    return empty;
  }

  const manifestByPath = new Map(manifests.map((manifest) => [manifest.path, manifest]));
  const entitiesById = new Map();
  const evidenceByEntity = new Map();
  const referencedByEntity = new Map();
  const declaredScopes = new Map();
  const sources = [];
  const edgeKeys = new Map();
  let declarationCount = 0;
  let resolvedCount = 0;

  const addEvidence = (entityIdValue, evidenceIdValue) => {
    let bucket = evidenceByEntity.get(entityIdValue);
    if (bucket === undefined) {
      bucket = new Set();
      evidenceByEntity.set(entityIdValue, bucket);
    }
    bucket.add(evidenceIdValue);
  };

  const ensureEntity = (ecosystem, name) => {
    const id = entityId(ENTITY_KINDS.DEPENDENCY, `${ecosystem}:${name}`);
    let entity = entitiesById.get(id);
    if (entity === undefined) {
      entity = {
        id,
        kind: ENTITY_KINDS.DEPENDENCY,
        // Value-shaped, like a language or an ecosystem: a dependency is identified
        // by `(ecosystem, name)`, not by a path in this repository.
        path: null,
        ecosystem,
        ecosystemId: entityId(ENTITY_KINDS.ECOSYSTEM, ecosystem),
        name,
        declared: false,
        direct: false,
        resolved: false,
        declarations: [],
        resolutions: [],
        referencedBy: [],
        scopes: [],
        evidenceIds: [],
      };
      entitiesById.set(id, entity);
      return { entity, created: true };
    }
    return { entity, created: false };
  };

  for (const source of section.manifests) {
    if (!isPlainObject(source)) {
      fail(issues, "scanResult.dependencies.manifests[]", "must be a plain object");
      continue;
    }
    const path = requireRepositoryRelativePath(
      source.path,
      "scanResult.dependencies.manifests[].path",
    );
    const ecosystem = identifier(source.ecosystem);
    if (ecosystem === null) {
      fail(
        issues,
        `scanResult.dependencies.manifests[${path}].ecosystem`,
        "must be a bounded ecosystem id",
      );
      continue;
    }
    if (!observedFilePaths.has(path)) {
      fail(
        issues,
        `scanResult.dependencies.manifests[${path}]`,
        "a dependency source must be a file the inventory observed",
      );
      continue;
    }
    const manifest = manifestByPath.get(path);
    if (manifest === undefined) {
      fail(
        issues,
        `scanResult.dependencies.manifests[${path}]`,
        "a dependency source must be a manifest the scan observed",
      );
      continue;
    }

    const status = source.status;
    if (!DEPENDENCY_SOURCE_STATUSES.includes(status)) {
      fail(
        issues,
        `scanResult.dependencies.manifests[${path}].status`,
        "must be a documented dependency source status",
      );
      continue;
    }
    const reason =
      source.reason === null || source.reason === undefined ? null : identifier(source.reason);
    if (reason === null && status !== "parsed") {
      fail(
        issues,
        `scanResult.dependencies.manifests[${path}].reason`,
        "must record why the source could not be parsed",
      );
      continue;
    }
    if (reason !== null && !DEPENDENCY_SOURCE_REASONS.includes(reason)) {
      fail(
        issues,
        `scanResult.dependencies.manifests[${path}].reason`,
        "must be a documented source reason",
      );
      continue;
    }
    const detail =
      source.detail === null || source.detail === undefined ? null : identifier(source.detail);
    if (source.detail !== null && source.detail !== undefined && detail === null) {
      fail(
        issues,
        `scanResult.dependencies.manifests[${path}].detail`,
        "must be a bounded detail identifier",
      );
      continue;
    }

    const problems = [];
    for (const problemEntry of Array.isArray(source.problems) ? source.problems : []) {
      if (!isPlainObject(problemEntry)) {
        fail(
          issues,
          `scanResult.dependencies.manifests[${path}].problems`,
          "entries must be plain objects",
        );
        continue;
      }
      const problemReason = identifier(problemEntry.reason);
      if (problemReason === null || !DEPENDENCY_PROBLEM_REASONS.includes(problemReason)) {
        fail(
          issues,
          `scanResult.dependencies.manifests[${path}].problems`,
          "must carry documented problem reasons",
        );
        continue;
      }
      problems.push(problemReason);
    }
    problems.sort();

    const sourceEvidenceId = record(
      createDependencySourceObservation({
        path,
        ecosystem,
        status,
        reason,
        detail,
        problems,
      }),
    );
    sources.push({
      path,
      ecosystem,
      status,
      reason,
      detail,
      // Whether this source's facts were cut short by a limit. Kept on the record so a
      // consumer can tell a lockfile that resolved 5000 packages apart because it had
      // exactly that many, and one whose 5000 is the cap.
      truncated: source.truncated === true,
      problems,
      evidenceId: sourceEvidenceId,
    });

    // ── Declarations ────────────────────────────────────────────────────────
    for (const declaration of Array.isArray(source.dependencies) ? source.dependencies : []) {
      if (!isPlainObject(declaration)) {
        fail(
          issues,
          `scanResult.dependencies.manifests[${path}].dependencies[]`,
          "must be a plain object",
        );
        continue;
      }
      const name = projectDependencyName(declaration.name);
      if (name === null) {
        fail(
          issues,
          `scanResult.dependencies.manifests[${path}].dependencies[].name`,
          "must be a bounded, path-free dependency name",
        );
        continue;
      }
      const scope = declaration.scope;
      if (!DEPENDENCY_SCOPES.includes(scope)) {
        fail(
          issues,
          `scanResult.dependencies.manifests[${path}].dependencies[].scope`,
          "must be a documented dependency scope",
        );
        continue;
      }
      const specKind = declaration.specKind;
      if (!DEPENDENCY_SPEC_KINDS.includes(specKind)) {
        fail(
          issues,
          `scanResult.dependencies.manifests[${path}].dependencies[].specKind`,
          "must be a documented spec kind",
        );
        continue;
      }
      const projectedSpec = projectDependencySpec(declaration.spec);
      if (!projectedSpec.ok) {
        fail(
          issues,
          `scanResult.dependencies.manifests[${path}].dependencies[].spec`,
          "must be a bounded spec string or null",
        );
        continue;
      }
      if (declaration.direct !== true && declaration.direct !== false) {
        fail(
          issues,
          `scanResult.dependencies.manifests[${path}].dependencies[].direct`,
          "must be a boolean",
        );
        continue;
      }

      const { entity } = ensureEntity(ecosystem, name);
      const declarationEvidenceId = record(
        createDependencyDeclarationObservation({
          path,
          name,
          scope,
          spec: projectedSpec.spec,
          specKind,
          direct: declaration.direct,
        }),
      );
      addEvidence(entity.id, declarationEvidenceId);

      entity.declarations.push({
        manifestId: manifest.id,
        manifestPath: path,
        scope,
        spec: projectedSpec.spec,
        specKind,
        direct: declaration.direct,
        conditional: declaration.conditional === true,
        evidenceIds: [declarationEvidenceId],
      });
      entity.declared = true;
      if (declaration.direct === true) entity.direct = true;
      declarationCount += 1;

      let scopes = declaredScopes.get(entity.id);
      if (scopes === undefined) {
        scopes = new Set();
        declaredScopes.set(entity.id, scopes);
      }
      scopes.add(scope);
    }

    // ── Resolutions (lockfiles only) ────────────────────────────────────────
    const resolvedEntries = [];
    for (const resolved of Array.isArray(source.resolved) ? source.resolved : []) {
      if (!isPlainObject(resolved)) {
        fail(
          issues,
          `scanResult.dependencies.manifests[${path}].resolved[]`,
          "must be a plain object",
        );
        continue;
      }
      const name = projectDependencyName(resolved.name);
      if (name === null || !identifier(resolved.version)) {
        fail(
          issues,
          `scanResult.dependencies.manifests[${path}].resolved[]`,
          "must carry a bounded name and version",
        );
        continue;
      }
      resolvedEntries.push({ name, version: resolved.version });
    }

    const edgeEntries = [];
    for (const edge of Array.isArray(source.edges) ? source.edges : []) {
      if (!isPlainObject(edge)) {
        fail(
          issues,
          `scanResult.dependencies.manifests[${path}].edges[]`,
          "must be a plain object",
        );
        continue;
      }
      const from = projectDependencyName(edge.from);
      const to = projectDependencyName(edge.to);
      if (from === null || to === null) {
        fail(
          issues,
          `scanResult.dependencies.manifests[${path}].edges[]`,
          "must name two bounded, path-free dependencies",
        );
        continue;
      }
      edgeEntries.push({ from, to });
    }

    if (resolvedEntries.length > 0 || edgeEntries.length > 0) {
      // One file-level observation per lockfile: the resolved pair list is carried by
      // the entities (bounded per package), while the counts here state what the
      // file established. Recorded before the per-package records below so every
      // one of them can cite it.
      const resolutionEvidenceId = record(
        createDependencyResolutionObservation({
          path,
          ecosystem,
          resolved: resolvedEntries.length,
          edges: edgeEntries.length,
        }),
      );

      for (const resolved of resolvedEntries) {
        const { entity } = ensureEntity(ecosystem, resolved.name);
        entity.resolved = true;
        entity.resolutions.push({
          manifestId: manifest.id,
          manifestPath: path,
          version: resolved.version,
          evidenceIds: [resolutionEvidenceId],
        });
        addEvidence(entity.id, resolutionEvidenceId);
        resolvedCount += 1;
      }

      for (const edge of edgeEntries) {
        const fromEntity = ensureEntity(ecosystem, edge.from).entity;
        const toEntity = ensureEntity(ecosystem, edge.to).entity;
        addEvidence(fromEntity.id, resolutionEvidenceId);
        addEvidence(toEntity.id, resolutionEvidenceId);
        for (const entity of [fromEntity, toEntity]) {
          let paths = referencedByEntity.get(entity.id);
          if (paths === undefined) {
            paths = new Set();
            referencedByEntity.set(entity.id, paths);
          }
          paths.add(path);
        }
        // The edge itself carries its own provenance: which lockfile observations
        // established it and which lockfile paths stated it. Phase 14's dependency
        // graph is traceable because of this, so an edge can never be cited without
        // the observation that supports it. Two lockfiles stating the same
        // relationship produce one edge citing both.
        const key = `${fromEntity.id}\u0000${toEntity.id}`;
        let record = edgeKeys.get(key);
        if (record === undefined) {
          record = {
            from: fromEntity.id,
            to: toEntity.id,
            evidenceIds: new Set(),
            manifestPaths: new Set(),
          };
          edgeKeys.set(key, record);
        }
        record.evidenceIds.add(resolutionEvidenceId);
        record.manifestPaths.add(path);
      }
    }
  }

  const edges = [...edgeKeys.values()]
    .map((record) => ({
      from: record.from,
      to: record.to,
      evidenceIds: [...record.evidenceIds].sort(),
      manifestPaths: [...record.manifestPaths].sort(),
    }))
    .sort((a, b) =>
      a.from === b.from ? (a.to < b.to ? -1 : a.to > b.to ? 1 : 0) : a.from < b.from ? -1 : 1,
    );
  if (edges.length > MAX_DEPENDENCY_EDGES) {
    fail(issues, "scanResult.dependencies", "states more dependency edges than a scan can report");
    return empty;
  }

  const entries = [];
  for (const entity of entitiesById.values()) {
    entity.declarations.sort(compareByKeys(["manifestPath", "scope"]));
    entity.resolutions.sort(compareByKeys(["manifestPath", "version"]));
    const referencedBy = referencedByEntity.get(entity.id);
    entity.referencedBy = referencedBy === undefined ? [] : [...referencedBy].sort();
    const scopes = declaredScopes.get(entity.id);
    entity.scopes = scopes === undefined ? [] : [...scopes].sort();
    entity.evidenceIds = sortEvidenceIds([...(evidenceByEntity.get(entity.id) ?? [])]);

    if (
      entity.declarations.length === 0 &&
      entity.resolutions.length === 0 &&
      entity.referencedBy.length === 0
    ) {
      fail(
        issues,
        `scanResult.dependencies[${entity.name}]`,
        "a dependency must be declared, resolved or named by an edge",
      );
      continue;
    }
    if (entity.evidenceIds.length === 0) {
      fail(
        issues,
        `scanResult.dependencies[${entity.name}]`,
        "a dependency must reference at least one observation",
      );
      continue;
    }
    entries.push(entity);
  }
  entries.sort(compareByKeys(["id"]));

  if (entries.length > MAX_DEPENDENCY_ENTITIES) {
    fail(issues, "scanResult.dependencies", "describes more dependencies than a scan can report");
    return empty;
  }

  return {
    entries,
    sources: sources.sort(compareByKeys(["path"])),
    edges,
    coverage: {
      inspected: section.inspected === true,
      complete: section.complete === true,
      truncated: section.truncated === true,
      declarations: declarationCount,
      resolved: resolvedCount,
      edges: edges.length,
    },
  };
}

/**
 * Import vocabularies and bounds.
 *
 * Re-declared here rather than imported from the acquisition layer, exactly like
 * the dependency vocabularies above: the model must not depend on the scanner, and
 * a test in `tests/import-graph.test.js` pins every one of these lists against the
 * scanner's own, so a rename on either side fails the suite instead of silently
 * retiring a value.
 *
 * What the model re-derives is the safety property, not the acquisition rules: a
 * specifier is projected only when it is bounded, printable, non-empty text, because
 * a specifier is about to become a path the resolver looks up and a string a
 * consumer reads. Whether a bundler would resolve `./x?raw` is the acquisition
 * layer's question; whether it may enter the model as a path candidate is this
 * layer's.
 */
export const IMPORT_SOURCE_STATUSES = Object.freeze([
  "parsed",
  "unsupported",
  "failed",
  "not-inspected",
]);

export const IMPORT_SOURCE_REASONS = Object.freeze([
  "format-not-interpreted",
  "module-could-not-be-read",
  "not-text",
  "budget-exhausted",
]);

export const IMPORT_SPECIFIER_KINDS = Object.freeze([
  "static-import",
  "export-from",
  "require",
  "dynamic-import",
]);

export const IMPORT_PROBLEM_REASONS = Object.freeze([
  "unterminated-import-declaration",
  "unterminated-string",
  "unterminated-template",
  "unterminated-comment",
  "unterminated-regex",
  "unlexable-character",
  "token-limit",
  "reference-limit",
  "non-static-specifier",
]);

/** Extensions that make a file a module source for the import graph. */
export const IMPORT_MODULE_EXTENSIONS = Object.freeze([
  ".js",
  ".mjs",
  ".cjs",
  ".ts",
  ".mts",
  ".cts",
  ".jsx",
  ".tsx",
]);

/** Maximum import source records a scan result may carry. */
const MAX_IMPORT_SOURCES = 20000;

/** Maximum module references one source record may carry. */
const MAX_IMPORT_REFERENCES = 512;

/** Longest specifier text the model will keep. */
const MAX_SPECIFIER_LENGTH = 512;

/**
 * Project a module specifier that is about to become a resolvable path.
 *
 * Bounded, printable, non-empty text only. Unlike a dependency name, a specifier is
 * not an identity — it is looked up against the observed inventory — so `./x` and
 * `../x` are legitimate here, and it is the *resolver* that refuses a path leaving
 * the repository. A control character or an over-long string is refused because it
 * cannot be a path and must not reach a consumer or an error message.
 *
 * @param {unknown} value
 * @returns {string|null} The specifier, or `null` when it cannot be kept.
 */
export function projectModuleSpecifier(value) {
  if (typeof value !== "string") return null;
  if (value.length === 0 || value.length > MAX_SPECIFIER_LENGTH) return null;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(value)) return null;
  return value;
}

/**
 * Project the scan's import acquisition into per-source import records.
 *
 * One record per module source, never per reference: the record is what makes the
 * file's own coverage answerable (was it read, was it truncated, were there
 * module-shaped expressions that could not be established), and its own observation
 * is the provenance every import edge from that file cites.
 *
 * Four properties are load-bearing:
 *
 *   1. **A module source must be a file the inventory observed.** A record about an
 *      unobserved path would let a malformed ScanResult invent an import edge into a
 *      file that does not exist.
 *   2. **A reference's kind and a problem's reason come from closed vocabularies,**
 *      and a specifier must be bounded, printable text. Hostile text therefore
 *      cannot enter the import graph at all.
 *   3. **Resolution is not attempted here.** The record keeps the specifier as
 *      written; what it points at is decided by `import-graph.js` against the file
 *      entities, so this layer never guesses a target.
 *   4. **Everything is bounded and fail-closed.** An incoherent section (an
 *      unobserved path, an unknown status or kind, an unbounded problem, more
 *      sources or references than a scan may state) fails the build rather than
 *      producing a model whose import facts are quietly partial.
 *
 * @param {object|undefined} section The scan result's `imports` section.
 * @param {Set<string>} observedFilePaths Paths the inventory actually observed.
 * @param {Function} record Records one observation and returns its id.
 * @returns {{sources: object[], coverage: object}}
 */
function projectImportsSection(section, observedFilePaths, issues, record) {
  const empty = {
    sources: [],
    coverage: {
      inspected: false,
      complete: false,
      truncated: false,
      sources: 0,
      references: 0,
      unresolved: 0,
      nonStatic: 0,
    },
  };

  if (section === undefined || section === null) return empty;
  if (!isPlainObject(section)) {
    fail(issues, "scanResult.imports", "must be a plain object");
    return empty;
  }
  if (!Array.isArray(section.files)) {
    fail(issues, "scanResult.imports.files", "must be an array");
    return empty;
  }
  if (section.files.length > MAX_IMPORT_SOURCES) {
    fail(issues, "scanResult.imports.files", "carries more module sources than a scan can report");
    return empty;
  }

  const sources = [];
  let referenceCount = 0;
  let nonStaticCount = 0;

  for (const source of section.files) {
    if (!isPlainObject(source)) {
      fail(issues, "scanResult.imports.files[]", "must be a plain object");
      continue;
    }
    const path = requireRepositoryRelativePath(source.path, "scanResult.imports.files[].path");
    if (!observedFilePaths.has(path)) {
      fail(
        issues,
        `scanResult.imports.files[${path}]`,
        "a module source must be a file the inventory observed",
      );
      continue;
    }

    const extension = identifier(source.extension);
    if (extension === null || !IMPORT_MODULE_EXTENSIONS.includes(extension)) {
      fail(
        issues,
        `scanResult.imports.files[${path}].extension`,
        "must be a module source extension this graph covers",
      );
      continue;
    }
    const language = identifier(source.language);
    if (language === null) {
      fail(issues, `scanResult.imports.files[${path}].language`, "must be a bounded language id");
      continue;
    }

    const status = source.status;
    if (!IMPORT_SOURCE_STATUSES.includes(status)) {
      fail(
        issues,
        `scanResult.imports.files[${path}].status`,
        "must be a documented module source status",
      );
      continue;
    }

    const reason =
      source.reason === null || source.reason === undefined
        ? null
        : identifier(source.reason);
    if (reason !== null && !IMPORT_SOURCE_REASONS.includes(reason)) {
      fail(
        issues,
        `scanResult.imports.files[${path}].reason`,
        "must be a documented acquisition reason",
      );
      continue;
    }
    // `parsed` and a reason are mutually exclusive, and every other status requires
    // one: an unread module must never be indistinguishable from one that imports
    // nothing.
    if (status === "parsed" && reason !== null) {
      fail(issues, `scanResult.imports.files[${path}].reason`, "must be null for a parsed source");
      continue;
    }
    if (status !== "parsed" && reason === null) {
      fail(
        issues,
        `scanResult.imports.files[${path}].reason`,
        "must record why the module source was not parsed",
      );
      continue;
    }

    const detail =
      source.detail === null || source.detail === undefined ? null : identifier(source.detail);
    if (source.detail !== null && source.detail !== undefined && detail === null) {
      fail(issues, `scanResult.imports.files[${path}].detail`, "must be a bounded identifier");
      continue;
    }

    const bytesInspected =
      Number.isInteger(source.bytesInspected) && source.bytesInspected >= 0
        ? source.bytesInspected
        : 0;

    const problems = [];
    for (const problem of Array.isArray(source.problems) ? source.problems : []) {
      const problemReason = identifier(problem);
      if (problemReason === null || !IMPORT_PROBLEM_REASONS.includes(problemReason)) {
        fail(
          issues,
          `scanResult.imports.files[${path}].problems`,
          "must carry documented import problem reasons",
        );
        continue;
      }
      problems.push(problemReason);
    }
    problems.sort();

    const references = [];
    const rawReferences = Array.isArray(source.references) ? source.references : [];
    if (rawReferences.length > MAX_IMPORT_REFERENCES) {
      fail(
        issues,
        `scanResult.imports.files[${path}].references`,
        "carries more references than a module source may state",
      );
      continue;
    }
    for (const reference of rawReferences) {
      if (!isPlainObject(reference)) {
        fail(
          issues,
          `scanResult.imports.files[${path}].references[]`,
          "must be a plain object",
        );
        continue;
      }
      if (!IMPORT_SPECIFIER_KINDS.includes(reference.kind)) {
        fail(
          issues,
          `scanResult.imports.files[${path}].references[].kind`,
          "must be a documented module reference kind",
        );
        continue;
      }
      const specifier = projectModuleSpecifier(reference.specifier);
      if (specifier === null) {
        fail(
          issues,
          `scanResult.imports.files[${path}].references[].specifier`,
          "must be bounded, printable specifier text",
        );
        continue;
      }
      references.push({ kind: reference.kind, specifier });
    }

    if (status !== "parsed" && references.length > 0) {
      fail(
        issues,
        `scanResult.imports.files[${path}].references`,
        "a module source that was not parsed states no reference",
      );
      continue;
    }

    const nonStatic =
      Number.isInteger(source.nonStatic) && source.nonStatic >= 0 ? source.nonStatic : 0;

    const evidenceId = record(
      createImportSourceObservation({
        path,
        language,
        status,
        reason,
        detail,
        references: references.length,
        nonStatic,
        problems,
        truncated: source.truncated === true,
      }),
    );

    referenceCount += references.length;
    nonStaticCount += nonStatic;

    sources.push({
      path,
      extension,
      languageId: entityId(ENTITY_KINDS.LANGUAGE, language),
      status,
      reason,
      detail,
      bytesInspected,
      // Whether the source was cut short by a byte or token budget, or never read
      // because the file budget was spent. Kept on the record so a consumer can tell
      // a file that states six thousand references apart because it had exactly that
      // many from one whose six thousand is the cap.
      truncated: source.truncated === true || status === "not-inspected",
      nonStatic,
      problems,
      references,
      evidenceId,
    });
  }

  return {
    sources: sources.sort(compareByKeys(["path"])),
    coverage: {
      inspected: section.inspected === true,
      complete: section.complete === true,
      truncated: section.truncated === true,
      sources: sources.length,
      references: referenceCount,
      // Filled by the graph projection, which is where resolution happens; the
      // section itself can only count what it acquired.
      unresolved: 0,
      nonStatic: nonStaticCount,
    },
  };
}

/**
 * Semantic vocabularies and bounds (Phase 17).
 *
 * Re-declared here rather than imported from the acquisition layer, exactly like the
 * import and dependency vocabularies above: the model must not depend on the scanner,
 * and a test in `tests/symbol-graph.test.js` pins every one of these lists against the
 * scanner's own, so a rename on either side fails the suite instead of silently
 * retiring a value.
 *
 * What the model re-derives is the safety property, not the acquisition rules: a
 * symbol name is projected only when it is bounded, printable identifier text that
 * cannot corrupt a symbol identity, and a reference count is projected only when it
 * is a positive integer. Which names a language permits is the acquisition
 * contract's question; whether a name may become a model identity is this layer's.
 */
export const SEMANTIC_SOURCE_STATUSES = Object.freeze([
  "parsed",
  "unsupported",
  "failed",
  "not-inspected",
]);

export const SEMANTIC_SOURCE_REASONS = Object.freeze([
  "format-not-interpreted",
  "module-could-not-be-read",
  "not-text",
  "budget-exhausted",
]);

export const SEMANTIC_PROBLEM_REASONS = Object.freeze([
  "unterminated-string",
  "unterminated-template",
  "unterminated-comment",
  "unterminated-regex",
  "unlexable-character",
  "token-limit",
  "unbalanced-groups",
  "declaration-limit",
  "reference-limit",
  "export-limit",
  "dynamic-scope-construct",
  "anonymous-default-export",
  "unsupported-export-form",
  "unsupported-declarator",
  "unterminated-export-clause",
  "commonjs-module-form",
]);

/** The declaration kinds a module-scope binding can be observed as. */
export const SYMBOL_KINDS = Object.freeze([
  "function",
  "class",
  "variable",
  "interface",
  "type-alias",
  "enum",
  "namespace",
  "imported-binding",
]);

/** How an imported binding was declared. */
export const SYMBOL_BINDING_KINDS = Object.freeze(["default", "named", "namespace", "require"]);

/** How a file exposes a name. */
export const SYMBOL_EXPORT_FORMS = Object.freeze(["named", "default", "star", "reexport"]);

/** The syntactic form of one recorded occurrence. */
export const SYMBOL_OCCURRENCE_FORMS = Object.freeze(["reference", "call", "construct"]);

/** Extensions that make a file a semantic source. The same set the import graph reads. */
export const SEMANTIC_MODULE_EXTENSIONS = Object.freeze([
  ".js",
  ".mjs",
  ".cjs",
  ".ts",
  ".mts",
  ".cts",
  ".jsx",
  ".tsx",
]);

/** Maximum semantic source records a scan result may carry. */
const MAX_SEMANTIC_SOURCES = 20000;

/** Maximum declarations one source record may carry. */
const MAX_SEMANTIC_DECLARATIONS = 512;

/** Maximum exports one source record may carry. */
const MAX_SEMANTIC_EXPORTS = 512;

/** Maximum distinct referenced names one source record may carry. */
const MAX_SEMANTIC_REFERENCES = 2048;

/** Longest binding name the model will keep. */
const MAX_SYMBOL_NAME_LENGTH = 256;

/**
 * API route vocabularies and bounds (Phase 18).
 *
 * Re-declared here rather than imported from the acquisition layer, exactly like the
 * import, dependency and semantic vocabularies above: the model must not depend on the
 * scanner, and a test in `tests/api-graph.test.js` pins every one of these lists
 * against the scanner's own, so a rename on either side fails the suite instead of
 * silently retiring a value.
 */
export const API_SOURCE_STATUSES = Object.freeze([
  "parsed",
  "unsupported",
  "failed",
  "not-inspected",
]);

export const API_SOURCE_REASONS = Object.freeze([
  "format-not-interpreted",
  "unreadable",
  "not-text",
  "budget-exhausted",
]);

export const API_PROBLEM_REASONS = Object.freeze([
  "lexical-failure",
  "token-limit",
  "unbalanced-groups",
  "route-limit",
  "receiver-limit",
  "shape-limit",
]);

/** Supported route-registrar frameworks. */
export const API_FRAMEWORKS = Object.freeze(["express", "fastify"]);

/** Recognised-but-unsupported framework ids a file may import. */
export const API_UNSUPPORTED_FRAMEWORKS = Object.freeze([
  "koa",
  "hapi",
  "nestjs",
  "next",
  "remix",
  "trpc",
  "graphql",
  "apollo",
  "socket.io",
  "ws",
  "restify",
  "polka",
  "feathers",
  "adonisjs",
  "hono",
]);

/** The recorded HTTP methods a route may state. */
export const API_ROUTE_METHODS = Object.freeze([
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "HEAD",
  "OPTIONS",
  "ALL",
]);

/** What kind of route registrar a receiver is. */
export const API_RECEIVER_KINDS = Object.freeze(["app", "router"]);

/** The callable forms a handler or middleware reference can take. */
export const API_CALLABLE_FORMS = Object.freeze(["reference", "inline"]);

/** Why a route-shaped occurrence produced no route. */
export const API_SHAPE_REASONS = Object.freeze([
  "receiver-not-established",
  "framework-unsupported",
  "path-not-established",
  "path-computed",
  "path-concatenated",
  "shorthand-not-established",
  "method-not-established",
]);

/** Maximum API source records a scan result may carry. */
const MAX_API_SOURCES = 20000;

/** Maximum routes one source record may carry. */
const MAX_API_ROUTES = 1024;

/** Maximum route-shaped observations one source record may carry. */
const MAX_API_SHAPES = 1024;

/** Maximum receiver bindings one source record may carry. */
const MAX_API_RECEIVERS = 256;

/** Longest receiver/handler name the model will keep. */
const MAX_API_NAME_LENGTH = 256;

/** Longest route path the model will keep. */
const MAX_API_PATH_LENGTH = 2048;

/**
 * Project a name that is about to become part of a route identity or an edge endpoint.
 *
 * Same discipline as `projectSymbolName`: bounded, printable, non-empty text with no
 * whitespace and no separator characters, so a hostile name cannot corrupt an id.
 *
 * @param {unknown} value
 * @returns {string|null}
 */
export function projectApiName(value) {
  if (typeof value !== "string") return null;
  if (value.length === 0 || value.length > MAX_API_NAME_LENGTH) return null;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x20 || code === 0x7f) return null;
    if (value[index] === "#" || value[index] === "/" || value[index] === "\\") return null;
  }
  return value;
}

/**
 * Project a route path.
 *
 * A path is a location, not an identity, so it may contain `/` — but never a control
 * character, and it must begin with `/` so it can never be mistaken for a module path.
 *
 * @param {unknown} value
 * @returns {string|null}
 */
export function projectRoutePath(value) {
  if (typeof value !== "string") return null;
  if (value.length === 0 || value.length > MAX_API_PATH_LENGTH) return null;
  if (!value.startsWith("/")) return null;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x20 || code === 0x7f) return null;
  }
  return value;
}

/** Project one callable reference (`handler`/`middleware`), or `null` when absent. */
function projectApiCallable(value, issues, path) {
  if (value === null || value === undefined) return null;
  if (!isPlainObject(value)) {
    fail(issues, path, "must be a plain object or null");
    return null;
  }
  const form = value.form;
  if (!API_CALLABLE_FORMS.includes(form)) {
    fail(issues, path + ".form", "must be a documented callable form");
    return null;
  }
  if (form === "inline") {
    return { form, name: null, member: null };
  }
  const name = projectApiName(value.name);
  if (name === null) {
    fail(issues, path + ".name", "must be a bounded identifier");
    return null;
  }
  const member =
    value.member === null || value.member === undefined ? null : projectApiName(value.member);
  if (value.member !== null && value.member !== undefined && member === null) {
    fail(issues, path + ".member", "must be a bounded identifier or null");
    return null;
  }
  return { form, name, member };
}

/**
 * Project a name that is about to become a symbol identity.
 *
 * Bounded, printable, non-empty text with no whitespace and no `#`, because a symbol
 * id is built from the file path and this name: a name that could contain the
 * separator would make two different symbols share an id. Unlike a specifier, a name
 * is an identity rather than a path, so anything path-shaped is refused.
 *
 * @param {unknown} value
 * @returns {string|null}
 */
export function projectSymbolName(value) {
  if (typeof value !== "string") return null;
  if (value.length === 0 || value.length > MAX_SYMBOL_NAME_LENGTH) return null;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x20 || code === 0x7f) return null;
    if (value[index] === "#" || value[index] === "/" || value[index] === "\\") return null;
  }
  return value;
}

/** A tri-state value: `true`, `false` or "not established". */
function projectTriState(value, issues, path) {
  if (value === true || value === false || value === null || value === undefined) {
    return value === true ? true : value === false ? false : null;
  }
  fail(issues, path, "must be true, false or null");
  return null;
}

/**
 * Project the scan's semantic acquisition into per-source symbol records.
 *
 * One record per module source, and it carries everything the projection needs to
 * decide what a name means: the declarations with their value shapes and their
 * shadow/reassignment flags, the export statements, the reference counts, and the
 * three establishment answers the scanner made. The model re-checks every one of them
 * because a malformed ScanResult must fail here rather than become a fabricated
 * symbol, and it never re-derives resolution — that is `symbol-graph.js`.
 *
 * @param {object|undefined} section The scan result's `semantics` section.
 * @param {Set<string>} observedFilePaths Paths the inventory actually observed.
 * @param {string[]} issues
 * @param {Function} record Records one observation and returns its id.
 * @returns {{sources: object[], coverage: object}}
 */
function projectSemanticsSection(section, observedFilePaths, issues, record) {
  const empty = {
    sources: [],
    coverage: {
      inspected: false,
      complete: false,
      truncated: false,
      sources: 0,
      declarations: 0,
      exports: 0,
      references: 0,
      calls: 0,
      unresolved: 0,
      unestablished: 0,
    },
  };

  if (section === undefined || section === null) return empty;
  if (!isPlainObject(section)) {
    fail(issues, "scanResult.semantics", "must be a plain object");
    return empty;
  }
  if (!Array.isArray(section.files)) {
    fail(issues, "scanResult.semantics.files", "must be an array");
    return empty;
  }
  if (section.files.length > MAX_SEMANTIC_SOURCES) {
    fail(issues, "scanResult.semantics.files", "carries more semantic sources than a scan can report");
    return empty;
  }

  const sources = [];
  let declarationCount = 0;
  let exportCount = 0;
  let referenceCount = 0;
  let callCount = 0;
  let unestablishedCount = 0;

  for (const source of section.files) {
    if (!isPlainObject(source)) {
      fail(issues, "scanResult.semantics.files[]", "must be a plain object");
      continue;
    }
    const path = requireRepositoryRelativePath(source.path, "scanResult.semantics.files[].path");
    if (!observedFilePaths.has(path)) {
      fail(
        issues,
        `scanResult.semantics.files[${path}]`,
        "a semantic source must be a file the inventory observed",
      );
      continue;
    }

    const extension = identifier(source.extension);
    if (extension === null || !SEMANTIC_MODULE_EXTENSIONS.includes(extension)) {
      fail(
        issues,
        `scanResult.semantics.files[${path}].extension`,
        "must be a module source extension this build covers",
      );
      continue;
    }
    const language = identifier(source.language);
    if (language === null) {
      fail(issues, `scanResult.semantics.files[${path}].language`, "must be a bounded language id");
      continue;
    }

    const status = source.status;
    if (!SEMANTIC_SOURCE_STATUSES.includes(status)) {
      fail(
        issues,
        `scanResult.semantics.files[${path}].status`,
        "must be a documented semantic source status",
      );
      continue;
    }

    const reason =
      source.reason === null || source.reason === undefined ? null : identifier(source.reason);
    if (reason !== null && !SEMANTIC_SOURCE_REASONS.includes(reason)) {
      fail(
        issues,
        `scanResult.semantics.files[${path}].reason`,
        "must be a documented acquisition reason",
      );
      continue;
    }
    if (status === "parsed" && reason !== null) {
      fail(issues, `scanResult.semantics.files[${path}].reason`, "must be null for a scanned source");
      continue;
    }
    if (status !== "parsed" && reason === null) {
      fail(
        issues,
        `scanResult.semantics.files[${path}].reason`,
        "must record why the source was not scanned",
      );
      continue;
    }

    const detail =
      source.detail === null || source.detail === undefined ? null : identifier(source.detail);

    const established = isPlainObject(source.established) ? source.established : {};
    const declarationsEstablished = established.declarations === true;
    const resolutionEstablished = established.resolution === true;
    const exportsEstablished = established.exports === true;
    if (resolutionEstablished && !declarationsEstablished) {
      fail(
        issues,
        `scanResult.semantics.files[${path}].established.resolution`,
        "cannot be established while the declaration set is not",
      );
      continue;
    }
    if (status !== "parsed" && (declarationsEstablished || resolutionEstablished || exportsEstablished)) {
      fail(
        issues,
        `scanResult.semantics.files[${path}].established`,
        "a source that was not scanned establishes nothing",
      );
      continue;
    }

    const problemReasons = [];
    let problemsValid = true;
    for (const problem of Array.isArray(source.problems) ? source.problems : []) {
      const problemReason = identifier(problem);
      if (problemReason === null || !SEMANTIC_PROBLEM_REASONS.includes(problemReason)) {
        fail(
          issues,
          `scanResult.semantics.files[${path}].problems`,
          "must carry documented semantic problem reasons",
        );
        problemsValid = false;
        break;
      }
      problemReasons.push(problemReason);
    }
    if (!problemsValid) continue;
    problemReasons.sort();

    // ── Declarations ─────────────────────────────────────────────────────────
    const declarations = [];
    let declarationsValid = true;
    const rawDeclarations = Array.isArray(source.declarations) ? source.declarations : [];
    if (rawDeclarations.length > MAX_SEMANTIC_DECLARATIONS) {
      fail(
        issues,
        `scanResult.semantics.files[${path}].declarations`,
        "carries more declarations than a source may state",
      );
      continue;
    }
    for (const declaration of rawDeclarations) {
      if (!isPlainObject(declaration)) {
        fail(
          issues,
          `scanResult.semantics.files[${path}].declarations[]`,
          "must be a plain object",
        );
        declarationsValid = false;
        break;
      }
      const name = projectSymbolName(declaration.name);
      if (name === null) {
        fail(
          issues,
          `scanResult.semantics.files[${path}].declarations[].name`,
          "must be bounded identifier text",
        );
        declarationsValid = false;
        break;
      }
      const kinds = [];
      for (const kind of Array.isArray(declaration.kinds) ? declaration.kinds : []) {
        if (!SYMBOL_KINDS.includes(kind)) {
          fail(
            issues,
            `scanResult.semantics.files[${path}].declarations[${name}].kinds`,
            "must be documented symbol kinds",
          );
          declarationsValid = false;
          break;
        }
        if (!kinds.includes(kind)) kinds.push(kind);
      }
      if (!declarationsValid) break;
      if (kinds.length === 0) {
        fail(
          issues,
          `scanResult.semantics.files[${path}].declarations[${name}].kinds`,
          "must state at least one kind",
        );
        declarationsValid = false;
        break;
      }
      kinds.sort();

      const exportNames = [];
      for (const exportName of Array.isArray(declaration.exportNames) ? declaration.exportNames : []) {
        const projected = projectSymbolName(exportName);
        if (projected === null) {
          fail(
            issues,
            `scanResult.semantics.files[${path}].declarations[${name}].exportNames`,
            "must be bounded identifier text",
          );
          declarationsValid = false;
          break;
        }
        if (!exportNames.includes(projected)) exportNames.push(projected);
      }
      if (!declarationsValid) break;
      exportNames.sort();

      let binding = null;
      if (declaration.binding !== null && declaration.binding !== undefined) {
        if (!isPlainObject(declaration.binding)) {
          fail(
            issues,
            `scanResult.semantics.files[${path}].declarations[${name}].binding`,
            "must be a plain object or null",
          );
          declarationsValid = false;
          break;
        }
        if (!SYMBOL_BINDING_KINDS.includes(declaration.binding.bindingKind)) {
          fail(
            issues,
            `scanResult.semantics.files[${path}].declarations[${name}].binding.kindingKind`,
            "must be a documented binding kind",
          );
          declarationsValid = false;
          break;
        }
        const importedName =
          declaration.binding.importedName === null || declaration.binding.importedName === undefined
            ? null
            : projectSymbolName(declaration.binding.importedName);
        const specifier =
          declaration.binding.specifier === null || declaration.binding.specifier === undefined
            ? null
            : projectModuleSpecifier(declaration.binding.specifier);
        if (declaration.binding.specifier != null && specifier === null) {
          fail(
            issues,
            `scanResult.semantics.files[${path}].declarations[${name}].binding.specifier`,
            "must be bounded, printable specifier text",
          );
          declarationsValid = false;
          break;
        }
        binding = {
          bindingKind: declaration.binding.bindingKind,
          importedName,
          specifier,
          typeOnly: declaration.binding.typeOnly === true,
        };
      }
      if (!declarationsValid) break;

      declarations.push({
        name,
        kinds,
        exported: declaration.exported === true || exportNames.length > 0,
        exportNames,
        callable: projectTriState(
          declaration.callable,
          issues,
          `scanResult.semantics.files[${path}].declarations[${name}].callable`,
        ),
        constructable: projectTriState(
          declaration.constructable,
          issues,
          `scanResult.semantics.files[${path}].declarations[${name}].constructable`,
        ),
        shadowed: declaration.shadowed === true,
        reassigned: declaration.reassigned === true,
        binding,
      });
    }
    if (!declarationsValid) continue;

    // ── Exports ──────────────────────────────────────────────────────────────
    const exports = [];
    let exportsValid = true;
    const rawExports = Array.isArray(source.exports) ? source.exports : [];
    if (rawExports.length > MAX_SEMANTIC_EXPORTS) {
      fail(
        issues,
        `scanResult.semantics.files[${path}].exports`,
        "carries more exports than a source may state",
      );
      continue;
    }
    for (const entry of rawExports) {
      if (!isPlainObject(entry)) {
        fail(issues, `scanResult.semantics.files[${path}].exports[]`, "must be a plain object");
        exportsValid = false;
        break;
      }
      const name =
        entry.name === null || entry.name === undefined ? null : projectSymbolName(entry.name);
      const localName =
        entry.localName === null || entry.localName === undefined
          ? null
          : projectSymbolName(entry.localName);
      if ((entry.name != null && name === null) || (entry.localName != null && localName === null)) {
        fail(
          issues,
          `scanResult.semantics.files[${path}].exports[].name`,
          "must be bounded identifier text or null",
        );
        exportsValid = false;
        break;
      }
      if (!SYMBOL_EXPORT_FORMS.includes(entry.form)) {
        fail(
          issues,
          `scanResult.semantics.files[${path}].exports[].form`,
          "must be a documented export form",
        );
        exportsValid = false;
        break;
      }
      const specifier =
        entry.specifier === null || entry.specifier === undefined
          ? null
          : projectModuleSpecifier(entry.specifier);
      if (entry.specifier != null && specifier === null) {
        fail(
          issues,
          `scanResult.semantics.files[${path}].exports[].specifier`,
          "must be bounded, printable specifier text",
        );
        exportsValid = false;
        break;
      }
      exports.push({
        name,
        localName,
        form: entry.form,
        specifier,
        typeOnly: entry.typeOnly === true,
      });
    }
    if (!exportsValid) continue;
    exports.sort(compareByKeys(["name", "form", "localName"]));

    // ── Star exports, references ─────────────────────────────────────────────
    const starExports = [];
    let starValid = true;
    for (const specifier of Array.isArray(source.starExports) ? source.starExports : []) {
      const projected = projectModuleSpecifier(specifier);
      if (projected === null) {
        fail(
          issues,
          `scanResult.semantics.files[${path}].starExports`,
          "must be bounded, printable specifier text",
        );
        starValid = false;
        break;
      }
      if (!starExports.includes(projected)) starExports.push(projected);
    }
    if (!starValid) continue;
    starExports.sort();

    const references = [];
    let referencesValid = true;
    const rawReferences = Array.isArray(source.references) ? source.references : [];
    if (rawReferences.length > MAX_SEMANTIC_REFERENCES) {
      fail(
        issues,
        `scanResult.semantics.files[${path}].references`,
        "carries more referenced names than a source may state",
      );
      continue;
    }
    for (const reference of rawReferences) {
      if (!isPlainObject(reference)) {
        fail(issues, `scanResult.semantics.files[${path}].references[]`, "must be a plain object");
        referencesValid = false;
        break;
      }
      const name = projectSymbolName(reference.name);
      if (name === null || !SYMBOL_OCCURRENCE_FORMS.includes(reference.form)) {
        fail(
          issues,
          `scanResult.semantics.files[${path}].references[]`,
          "must carry a bounded name and a documented occurrence form",
        );
        referencesValid = false;
        break;
      }
      const count = Number.isInteger(reference.count) && reference.count > 0 ? reference.count : null;
      if (count === null) {
        fail(
          issues,
          `scanResult.semantics.files[${path}].references[].count`,
          "must be a positive integer",
        );
        referencesValid = false;
        break;
      }
      references.push({ name, form: reference.form, count });
    }
    if (!referencesValid) continue;
    references.sort(compareByKeys(["name", "form"]));

    if (
      status !== "parsed" &&
      (declarations.length > 0 || exports.length > 0 || references.length > 0 || starExports.length > 0)
    ) {
      fail(
        issues,
        `scanResult.semantics.files[${path}]`,
        "a source that was not scanned states no declaration, export or reference",
      );
      continue;
    }

    const counts = isPlainObject(source.counts) ? source.counts : {};
    const countOf = (field) => (Number.isInteger(counts[field]) && counts[field] >= 0 ? counts[field] : 0);
    const callSites = countOf("calls") + countOf("constructs");

    const evidenceId = record(
      createSymbolSourceObservation({
        path,
        language,
        status,
        reason,
        detail,
        declarations: declarations.length,
        exports: exports.length,
        references: countOf("references") + callSites,
        calls: callSites,
        problems: problemReasons,
        declarationsEstablished,
        resolutionEstablished,
        exportsEstablished,
        truncated: source.truncated === true,
      }),
    );

    declarationCount += declarations.length;
    exportCount += exports.length;
    referenceCount += countOf("references");
    callCount += callSites;
    if (!declarationsEstablished || !resolutionEstablished) unestablishedCount += 1;

    sources.push({
      path,
      extension,
      languageId: entityId(ENTITY_KINDS.LANGUAGE, language),
      status,
      reason,
      detail,
      bytesInspected:
        Number.isInteger(source.bytesInspected) && source.bytesInspected >= 0
          ? source.bytesInspected
          : 0,
      truncated: source.truncated === true || status === "not-inspected",
      established: { declarationsEstablished, resolutionEstablished, exportsEstablished },
      declarations,
      exports,
      starExports,
      references,
      problems: problemReasons,
      counts: {
        declarations: declarations.length,
        exports: exports.length,
        names: references.length,
        references: countOf("references"),
        calls: countOf("calls"),
        constructs: countOf("constructs"),
        tokens: countOf("tokens"),
      },
      evidenceId,
    });
  }

  return {
    sources: sources.sort(compareByKeys(["path"])),
    coverage: {
      inspected: section.inspected === true,
      complete: section.complete === true,
      truncated: section.truncated === true,
      sources: sources.length,
      declarations: declarationCount,
      exports: exportCount,
      references: referenceCount,
      calls: callCount,
      // Filled by the graph projection, which is where resolution happens; the
      // section itself can only count what it acquired.
      unresolved: 0,
      unestablished: unestablishedCount,
    },
  };
}

/**
 * Project the scan's API route acquisition into per-source records.
 *
 * One record per module source, carrying the framework bindings the file established,
 * the route declarations, the route-shaped observations that produced no route, and the
 * counts. The model re-checks every closed vocabulary because a malformed ScanResult
 * must fail here rather than become a fabricated route, and it never resolves a handler
 * — that is `api-graph.js`, against the symbol graph, which is where identity lives.
 *
 * @param {object|undefined} section The scan result's `api` section.
 * @param {Set<string>} observedFilePaths Paths the inventory actually observed.
 * @param {string[]} issues
 * @param {Function} record Records one observation and returns its id.
 * @returns {{sources: object[], coverage: object}}
 */
function projectApiSection(section, observedFilePaths, issues, record) {
  const empty = {
    sources: [],
    coverage: {
      inspected: false,
      complete: false,
      truncated: false,
      sources: 0,
      routes: 0,
      shapes: 0,
      receivers: 0,
      established: 0,
      frameworks: [],
      unsupportedFrameworks: [],
    },
  };

  if (section === undefined || section === null) return empty;
  if (!isPlainObject(section)) {
    fail(issues, "scanResult.api", "must be a plain object");
    return empty;
  }
  if (!Array.isArray(section.files)) {
    fail(issues, "scanResult.api.files", "must be an array");
    return empty;
  }
  if (section.files.length > MAX_API_SOURCES) {
    fail(issues, "scanResult.api.files", "carries more API sources than a scan can report");
    return empty;
  }

  const sources = [];
  const frameworkSet = new Set();
  const unsupportedSet = new Set();
  let routeCount = 0;
  let shapeCount = 0;
  let receiverCount = 0;
  let establishedCount = 0;

  for (const source of section.files) {
    if (!isPlainObject(source)) {
      fail(issues, "scanResult.api.files[]", "must be a plain object");
      continue;
    }
    const path = requireRepositoryRelativePath(source.path, "scanResult.api.files[].path");
    if (!observedFilePaths.has(path)) {
      fail(issues, `scanResult.api.files[${path}]`, "names a path the inventory did not observe");
      continue;
    }
    const extension = source.extension;
    if (!SEMANTIC_MODULE_EXTENSIONS.includes(extension)) {
      fail(issues, `scanResult.api.files[${path}].extension`, "must be a module source extension");
      continue;
    }
    const language = identifier(source.language);
    if (language === null) {
      fail(issues, `scanResult.api.files[${path}].language`, "must be a bounded language id");
      continue;
    }
    const status = source.status;
    if (!API_SOURCE_STATUSES.includes(status)) {
      fail(issues, `scanResult.api.files[${path}].status`, "must be a documented API source status");
      continue;
    }
    let reason = source.reason ?? null;
    if (reason !== null && !API_SOURCE_REASONS.includes(reason)) {
      fail(issues, `scanResult.api.files[${path}].reason`, "must be a documented reason");
      continue;
    }
    if (status === "parsed" && reason !== null) {
      fail(issues, `scanResult.api.files[${path}].reason`, "must be null for a scanned source");
      continue;
    }
    if (status !== "parsed" && reason === null) {
      fail(issues, `scanResult.api.files[${path}].reason`, "must record why the source was not scanned");
      continue;
    }
    const detail =
      source.detail === null || source.detail === undefined ? null : identifier(source.detail);
    if (source.detail !== null && source.detail !== undefined && detail === null) {
      fail(issues, `scanResult.api.files[${path}].detail`, "must be a bounded token or null");
      continue;
    }

    const frameworks = [];
    if (!Array.isArray(source.frameworks)) {
      fail(issues, `scanResult.api.files[${path}].frameworks`, "must be an array");
      continue;
    }
    let bad = false;
    for (const framework of source.frameworks) {
      if (!API_FRAMEWORKS.includes(framework)) {
        fail(issues, `scanResult.api.files[${path}].frameworks`, "must name a supported framework");
        bad = true;
        break;
      }
      if (!frameworks.includes(framework)) frameworks.push(framework);
    }
    if (bad) continue;
    frameworks.sort();

    const unsupportedFrameworks = [];
    if (!Array.isArray(source.unsupportedFrameworks)) {
      fail(issues, `scanResult.api.files[${path}].unsupportedFrameworks`, "must be an array");
      continue;
    }
    for (const framework of source.unsupportedFrameworks) {
      if (!API_UNSUPPORTED_FRAMEWORKS.includes(framework)) {
        fail(
          issues,
          `scanResult.api.files[${path}].unsupportedFrameworks`,
          "must name a recognised framework",
        );
        bad = true;
        break;
      }
      if (!unsupportedFrameworks.includes(framework)) unsupportedFrameworks.push(framework);
    }
    if (bad) continue;
    unsupportedFrameworks.sort();

    // ── Receivers ─────────────────────────────────────────────────────────
    const receivers = [];
    if (!Array.isArray(source.receivers)) {
      fail(issues, `scanResult.api.files[${path}].receivers`, "must be an array");
      continue;
    }
    if (source.receivers.length > MAX_API_RECEIVERS) {
      fail(issues, `scanResult.api.files[${path}].receivers`, "carries more receivers than allowed");
      continue;
    }
    for (const receiver of source.receivers) {
      const name = projectApiName(receiver?.name);
      if (name === null) {
        fail(issues, `scanResult.api.files[${path}].receivers[].name`, "must be a bounded name");
        bad = true;
        break;
      }
      const framework = receiver.framework;
      const supported = receiver.supported === true;
      const known =
        (supported && API_FRAMEWORKS.includes(framework)) ||
        (!supported && API_UNSUPPORTED_FRAMEWORKS.includes(framework));
      if (!known) {
        fail(issues, `scanResult.api.files[${path}].receivers[].framework`, "must name a framework");
        bad = true;
        break;
      }
      if (!API_RECEIVER_KINDS.includes(receiver.kind)) {
        fail(issues, `scanResult.api.files[${path}].receivers[].kind`, "must be app or router");
        bad = true;
        break;
      }
      receivers.push({ name, framework, supported, kind: receiver.kind });
    }
    if (bad) continue;
    receivers.sort(compareByKeys(["name"]));

    // ── Routes ──────────────────────────────────────────────────────────
    const routes = [];
    if (!Array.isArray(source.routes)) {
      fail(issues, `scanResult.api.files[${path}].routes`, "must be an array");
      continue;
    }
    if (source.routes.length > MAX_API_ROUTES) {
      fail(issues, `scanResult.api.files[${path}].routes`, "carries more routes than allowed");
      continue;
    }
    for (const route of source.routes) {
      if (!API_ROUTE_METHODS.includes(route?.method)) {
        fail(issues, `scanResult.api.files[${path}].routes[].method`, "must be a recorded method");
        bad = true;
        break;
      }
      const routePath = projectRoutePath(route.path);
      if (routePath === null) {
        fail(issues, `scanResult.api.files[${path}].routes[].path`, "must be a route path");
        bad = true;
        break;
      }
      const receiverName = projectApiName(route.receiver);
      if (receiverName === null) {
        fail(issues, `scanResult.api.files[${path}].routes[].receiver`, "must be a bounded name");
        bad = true;
        break;
      }
      if (!API_FRAMEWORKS.includes(route.framework)) {
        fail(issues, `scanResult.api.files[${path}].routes[].framework`, "must be supported");
        bad = true;
        break;
      }
      if (!API_RECEIVER_KINDS.includes(route.receiverKind)) {
        fail(issues, `scanResult.api.files[${path}].routes[].receiverKind`, "must be app or router");
        bad = true;
        break;
      }
      if (route.form !== "direct" && route.form !== "chain") {
        fail(issues, `scanResult.api.files[${path}].routes[].form`, "must be direct or chain");
        bad = true;
        break;
      }
      const handler = projectApiCallable(
        route.handler,
        issues,
        `scanResult.api.files[${path}].routes[].handler`,
      );
      if (route.handler !== null && route.handler !== undefined && handler === null) {
        bad = true;
        break;
      }
      const middleware = [];
      if (!Array.isArray(route.middleware)) {
        fail(issues, `scanResult.api.files[${path}].routes[].middleware`, "must be an array");
        bad = true;
        break;
      }
      for (const entry of route.middleware) {
        const callable = projectApiCallable(
          entry,
          issues,
          `scanResult.api.files[${path}].routes[].middleware[]`,
        );
        if (callable === null) {
          bad = true;
          break;
        }
        middleware.push(callable);
      }
      if (bad) break;
      routes.push({
        method: route.method,
        path: routePath,
        receiver: receiverName,
        framework: route.framework,
        receiverKind: route.receiverKind,
        form: route.form,
        handler,
        middleware,
      });
    }
    if (bad) continue;
    routes.sort(compareByKeys(["method", "path", "receiver"]));

    // ── Route-shaped observations ────────────────────────────────────────
    const shapes = [];
    if (!Array.isArray(source.shapes)) {
      fail(issues, `scanResult.api.files[${path}].shapes`, "must be an array");
      continue;
    }
    if (source.shapes.length > MAX_API_SHAPES) {
      fail(issues, `scanResult.api.files[${path}].shapes`, "carries more shapes than allowed");
      continue;
    }
    for (const shape of source.shapes) {
      if (!API_SHAPE_REASONS.includes(shape?.reason)) {
        fail(issues, `scanResult.api.files[${path}].shapes[].reason`, "must be a documented reason");
        bad = true;
        break;
      }
      const receiverName = projectApiName(shape.receiver);
      if (receiverName === null) {
        fail(issues, `scanResult.api.files[${path}].shapes[].receiver`, "must be a bounded name");
        bad = true;
        break;
      }
      const shapePath =
        shape.path === null || shape.path === undefined ? null : projectRoutePath(shape.path);
      if (shape.path !== null && shape.path !== undefined && shapePath === null) {
        fail(issues, `scanResult.api.files[${path}].shapes[].path`, "must be a route path or null");
        bad = true;
        break;
      }
      const method = shape.method === null || shape.method === undefined ? null : shape.method;
      if (method !== null && !API_ROUTE_METHODS.includes(method)) {
        fail(issues, `scanResult.api.files[${path}].shapes[].method`, "must be null or a method");
        bad = true;
        break;
      }
      const framework =
        shape.framework === null || shape.framework === undefined ? null : shape.framework;
      if (
        framework !== null &&
        !API_FRAMEWORKS.includes(framework) &&
        !API_UNSUPPORTED_FRAMEWORKS.includes(framework)
      ) {
        fail(issues, `scanResult.api.files[${path}].shapes[].framework`, "must name a framework");
        bad = true;
        break;
      }
      shapes.push({
        receiver: receiverName,
        framework,
        supported: shape.supported === true,
        method,
        path: shapePath,
        reason: shape.reason,
      });
    }
    if (bad) continue;
    shapes.sort(compareByKeys(["reason", "receiver", "path"]));

    // ── Problems and counters ───────────────────────────────────────────
    const problemReasons = [];
    if (!Array.isArray(source.problems)) {
      fail(issues, `scanResult.api.files[${path}].problems`, "must be an array");
      continue;
    }
    for (const problem of source.problems) {
      if (!API_PROBLEM_REASONS.includes(problem)) {
        fail(issues, `scanResult.api.files[${path}].problems[]`, "must be a documented problem");
        bad = true;
        break;
      }
      if (!problemReasons.includes(problem)) problemReasons.push(problem);
    }
    if (bad) continue;
    problemReasons.sort();

    if (
      status !== "parsed" &&
      (routes.length > 0 || shapes.length > 0 || receivers.length > 0)
    ) {
      fail(
        issues,
        `scanResult.api.files[${path}]`,
        "a source that was not scanned states no route, shape or receiver",
      );
      continue;
    }

    const established = source.established === true && status === "parsed";
    const bytesInspected =
      Number.isInteger(source.bytesInspected) && source.bytesInspected >= 0
        ? source.bytesInspected
        : 0;
    const truncated = source.truncated === true || status === "not-inspected";

    const evidenceId = record(
      createApiSourceObservation({
        path,
        language,
        status,
        reason,
        detail,
        frameworks,
        unsupportedFrameworks,
        routes: routes.length,
        shapes: shapes.length,
        problems: problemReasons,
        established,
        truncated,
      }),
    );

    for (const framework of frameworks) frameworkSet.add(framework);
    for (const framework of unsupportedFrameworks) unsupportedSet.add(framework);
    routeCount += routes.length;
    shapeCount += shapes.length;
    receiverCount += receivers.length;
    if (established) establishedCount += 1;

    sources.push({
      path,
      extension,
      languageId: entityId(ENTITY_KINDS.LANGUAGE, language),
      status,
      reason,
      detail,
      bytesInspected,
      truncated,
      established,
      frameworks,
      unsupportedFrameworks,
      receivers,
      routes,
      shapes,
      problems: problemReasons,
      counts: {
        tokens: isPlainObject(source.counts) && Number.isInteger(source.counts.tokens)
          ? Math.max(0, source.counts.tokens)
          : 0,
        routes: routes.length,
        shapes: shapes.length,
        receivers: receivers.length,
      },
      evidenceId,
    });
  }

  return {
    sources: sources.sort(compareByKeys(["path"])),
    coverage: {
      inspected: section.inspected === true,
      complete: section.complete === true,
      truncated: section.truncated === true,
      sources: sources.length,
      routes: routeCount,
      shapes: shapeCount,
      receivers: receiverCount,
      established: establishedCount,
      frameworks: [...frameworkSet].sort(),
      unsupportedFrameworks: [...unsupportedSet].sort(),
    },
  };
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
  projectContainerSection(scanResult.containers, observedFilePaths, issues, record);

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

  // ── Dependencies ──────────────────────────────────────────────────────────
  //
  // Built after the manifests, because every dependency fact is *about* a
  // manifest: a declaration cites the manifest that made it, a resolution cites the
  // lockfile that stated it. A dependency therefore cannot exist without an
  // observed manifest behind it.

  const dependencySection = projectDependenciesSection(
    scanResult.dependencies,
    manifests,
    observedFilePaths,
    issues,
    record,
  );

  // Phase 16 — module acquisition. Built after the files, because a module source
  // *is* a file: a record about a path the inventory never observed fails the build
  // rather than inventing an import edge into a file that does not exist. Resolution
  // is deliberately not attempted here — the specifier is kept as written and the
  // graph projection decides what it points at, against the file entities.

  const importSection = projectImportsSection(
    scanResult.imports,
    observedFilePaths,
    issues,
    record,
  );

  // Phase 17 — the semantic section, projected by the same rules: a record about an
  // unobserved path fails the build, every vocabulary is re-checked here, and the
  // records are kept exactly as the scanner established them. Resolution is still not
  // attempted: whether a name resolves is decided by `symbol-graph.js` against the
  // file entities and the export tables, never here.
  const semanticsSection = projectSemanticsSection(
    scanResult.semantics,
    observedFilePaths,
    issues,
    record,
  );

  // Phase 18 — the API route section, projected by the same rules: a record about an
  // unobserved path fails the build, every vocabulary is re-checked here, and the
  // framework bindings and routes are kept exactly as the scanner established them.
  // Handler resolution is still not attempted: whether a handler name denotes a symbol
  // is decided by `api-graph.js` against the symbol graph, never here.
  const apiSection = projectApiSection(
    scanResult.api,
    observedFilePaths,
    issues,
    record,
  );

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
  for (const entity of [
    ...manifests,
    ...tests,
    ...cicd,
    ...documentation,
    ...configuration,
  ]) {
    if (entity.directoryId !== repositoryIdValue && !directoryIds.has(entity.directoryId)) {
      fail(
        issues,
        `scanResult[${entity.path}]`,
        "a path-bearing entity's parent directory was not observed",
      );
    }
  }
  {
    const manifestIds = new Set(manifests.map((manifest) => manifest.id));
    for (const dependency of dependencySection.entries) {
      for (const declaration of dependency.declarations) {
        if (!manifestIds.has(declaration.manifestId)) {
          fail(
            issues,
            `scanResult.dependencies[${dependency.name}]`,
            "a declaration must cite a manifest the scan observed",
          );
        }
      }
      for (const resolution of dependency.resolutions) {
        if (!manifestIds.has(resolution.manifestId)) {
          fail(
            issues,
            `scanResult.dependencies[${dependency.name}]`,
            "a resolution must cite a manifest the scan observed",
          );
        }
      }
    }
    const sourcePaths = new Set(dependencySection.sources.map((source) => source.path));
    if (sourcePaths.size !== dependencySection.sources.length) {
      fail(issues, "scanResult.dependencies.manifests", "must describe each source once");
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
  {
    const languageIds = new Set(languages.map((language) => language.id));
    for (const source of importSection.sources) {
      if (!languageIds.has(source.languageId)) {
        fail(
          issues,
          `scanResult.imports.files[${source.path}].language`,
          "a module source's language was not observed",
        );
      }
    }
    const sourcePaths = new Set(importSection.sources.map((source) => source.path));
    if (sourcePaths.size !== importSection.sources.length) {
      fail(issues, "scanResult.imports.files", "must describe each module source once");
    }
  }
  {
    const languageIds = new Set(languages.map((language) => language.id));
    for (const source of apiSection.sources) {
      if (!languageIds.has(source.languageId)) {
        fail(
          issues,
          `scanResult.api.files[${source.path}].language`,
          "an API source's language was not observed",
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
  for (const entity of [
    ...pathBasedEntities,
    ...languages,
    ...frameworks,
    ...ecosystems,
    ...dependencySection.entries,
    git,
  ]) {
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
    dependencies: dependencySection.entries,
    dependencySources: dependencySection.sources,
    dependencyEdges: dependencySection.edges,
    dependencyCoverage: dependencySection.coverage,
    importSources: importSection.sources,
    importCoverage: importSection.coverage,
    semanticsSources: semanticsSection.sources,
    semanticsCoverage: semanticsSection.coverage,
    apiSources: apiSection.sources,
    apiCoverage: apiSection.coverage,
    git,
    evidence: [...evidence].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
  };
}
