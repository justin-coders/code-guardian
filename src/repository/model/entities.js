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
  createImportSourceObservation,
  createInventoryObservation,
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
    git,
    evidence: [...evidence].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
  };
}
