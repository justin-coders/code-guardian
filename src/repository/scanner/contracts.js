/**
 * Code Guardian — Scanner Result Contract (Phase 8C)
 *
 * The scanner produces a *structured repository inventory*: what exists, where it
 * was observed, and whether the observation was complete. It never produces
 * judgments — no scores, severities, verdicts or recommendations. Those belong to
 * the analyzer layers (Phase 8D and later).
 *
 * The contract follows the Core conventions deliberately:
 *
 *   - `createScanResult()` is a **shape/draft factory** (see Core
 *     `CONTRACT_FACTORY_SEMANTICS`), not a guaranteed-valid constructor. It fills
 *     the contracted shape, defaults `scan.complete` to `false`, and never
 *     fabricates an observation.
 *   - `validateScanResult()` is the authority on validity and throws a Core
 *     `ValidationError` listing every issue it found.
 *
 * Two invariants matter enough to be enforced by the validator rather than
 * merely documented:
 *
 *   1. **A truncated scan is never complete.** `scan.truncated === true` together
 *      with `scan.complete === true` is invalid, mirroring the Core
 *      `RepositoryModel.scan` rule, so "not inspected" can never silently read as
 *      "not found".
 *   2. **Collections are deterministically ordered.** Files, directories,
 *      symlinks, manifests and language entries must be sorted by their identity,
 *      and evidence must be sorted by `(path, signal)`. A scan of an unchanged
 *      repository therefore serializes identically.
 *
 * `root` and `scannedAt` are scan metadata only. Neither takes part in
 * classification or ordering, so two scans of the same repository state produce
 * structurally equal results apart from `scannedAt`.
 *
 * Two sections added after the original Phase 8C contract follow the same rules:
 *
 *   - `symlinks[].target` records where a link points, in the closed vocabulary
 *     `inside` / `outside` / `unknown` (Phase 12 correction 1). An `inside` target
 *     is a repository-relative path; `outside` and `unknown` carry no location at
 *     all, so an absolute host path can never reach this contract. A symlink entry
 *     with no `target` is accepted and means `unknown`: a scanner that did not
 *     inspect the link must not look like one that found it harmless.
 *   - `content` records what the bounded content inspection observed (Phase 12
 *     correction 2): one entry per inspected candidate, each carrying the pattern
 *     ids that matched — never a matched value, line or byte.
 */

import { ValidationError } from "../../core/index.js";

import {
  DEPENDENCY_PROBLEM_REASON_VALUES,
  DEPENDENCY_SCOPE_VALUES,
  DEPENDENCY_SOURCE_REASONS,
  DEPENDENCY_SOURCE_STATUS_VALUES,
  DEPENDENCY_SOURCE_STATUSES,
  DEPENDENCY_SPEC_KIND_VALUES,
} from "./policies/dependencies.js";
import {
  IMPORT_NON_STATIC_REASON_VALUES,
  IMPORT_PROBLEM_REASON_VALUES,
  IMPORT_SOURCE_REASON_VALUES,
  IMPORT_SOURCE_STATUSES,
  IMPORT_SOURCE_STATUS_VALUES,
  IMPORT_SPECIFIER_KIND_VALUES,
  isUsableSpecifier,
} from "./policies/imports.js";

/** Version of the scan result contract. */
export const SCAN_RESULT_VERSION = "1";

/** Limit on evidence paths retained per detected signal. */
export const MAX_EVIDENCE_PER_SIGNAL = 10;

/** Where a symlink target resolves, relative to the repository root. */
export const SYMLINK_TARGET_KINDS = Object.freeze({
  INSIDE: "inside",
  OUTSIDE: "outside",
  UNKNOWN: "unknown",
});

/**
 * Why a symlink target is `unknown`. Closed vocabulary: a reason is never free
 * text, so a hostile path can never be smuggled through this field.
 */
export const SYMLINK_UNKNOWN_REASONS = Object.freeze({
  NOT_INSPECTED: "not-inspected",
  UNREADABLE: "unreadable",
  CYCLE: "cycle",
  DEPTH_EXCEEDED: "depth-exceeded",
});

/** Why a candidate's content was not inspected. Closed vocabulary. */
export const CONTENT_INSPECTION_REASONS = Object.freeze({
  BUDGET_EXHAUSTED: "budget-exhausted",
  UNREADABLE: "unreadable",
  NOT_TEXT: "not-text",
});

/**
 * Why a Compose file's build declarations are not established. Closed vocabulary.
 *
 * `detail` on an unparsed entry carries the structural cause as a bounded identifier.
 */
export const CONTAINER_UNPARSED_REASONS = Object.freeze({
  READ_FAILED: "read-failed",
  NOT_TEXT: "not-text",
  TOO_LARGE: "too-large",
  BUDGET_EXHAUSTED: "budget-exhausted",
  AMBIGUOUS: "ambiguous",
});

/**
 * Dependency source statuses, re-exported for consumers of the scan contract.
 *
 * The vocabulary lives in the acquisition policy (one place defines it) and is
 * re-exported here because the contract is what a consumer validates against.
 */
export {
  DEPENDENCY_PROBLEM_REASONS,
  DEPENDENCY_SCOPES,
  DEPENDENCY_SOURCE_REASONS,
  DEPENDENCY_SOURCE_STATUSES,
  DEPENDENCY_SPEC_KINDS,
} from "./policies/dependencies.js";

/**
 * Import acquisition vocabulary and bounds, re-exported for the same reason.
 *
 * The tokenizer, its closed vocabularies and its limits live in the acquisition
 * policy; the contract re-exports them so a consumer validates against one source.
 */
export {
  IMPORT_ACQUISITION_LIMITS,
  IMPORT_NON_STATIC_REASONS,
  IMPORT_PROBLEM_REASONS,
  IMPORT_SOURCE_REASONS,
  IMPORT_SOURCE_STATUSES,
  IMPORT_SPECIFIER_KINDS,
  MODULE_FILE_EXTENSIONS,
  PARSED_MODULE_EXTENSIONS,
  UNSUPPORTED_MODULE_EXTENSIONS,
  moduleLanguageOf,
} from "./policies/imports.js";

/** Stable signal ids used across detectors. */
export const SCAN_SIGNALS = Object.freeze({
  SOURCE_EXTENSION: "source-extension",
  MANIFEST: "manifest",
  LOCKFILE: "lockfile",
  TEST_DIRECTORY: "test-directory",
  TEST_FILE: "test-file",
  TEST_CONFIGURATION: "test-configuration",
  CI_CONFIGURATION: "ci-configuration",
  README: "readme",
  DOCUMENTATION_DIRECTORY: "documentation-directory",
  CHANGELOG: "changelog",
  CONTRIBUTING: "contributing",
  CODE_OF_CONDUCT: "code-of-conduct",
  DOCKERFILE: "dockerfile",
  CONTAINER_IGNORE: "container-ignore",
  COMPOSE_FILE: "compose-file",
  ENVIRONMENT_EXAMPLE: "environment-example",
  LINT_CONFIGURATION: "lint-configuration",
  FORMAT_CONFIGURATION: "format-configuration",
  BUILD_CONFIGURATION: "build-configuration",
  VERSION_PINNING: "version-pinning",
  LICENSE: "license",
  VCS_CONFIGURATION: "vcs-configuration",
  GIT_DIRECTORY: "git-directory",
  GIT_FILE: "git-file",
  GIT_HEAD: "git-head",
});

const ARRAY_SECTIONS = Object.freeze([
  "files",
  "directories",
  "symlinks",
  "ignored",
  "languages",
  "manifests",
]);

const DETECTION_SECTIONS = Object.freeze([
  "tests",
  "cicd",
  "documentation",
  "configuration",
]);

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim() !== "";
}

function isNonNegativeInteger(value) {
  return Number.isInteger(value) && value >= 0;
}

/** Absolute in POSIX, drive-letter or UNC terms — never a repository path. */
function isAbsolutePath(value) {
  return (
    value.startsWith("/") || /^[a-zA-Z]:[\\/]/.test(value) || value.startsWith("\\\\")
  );
}

function sortByPath(entries) {
  return [...entries].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

function emptyDetection() {
  return { detected: false, evidence: [] };
}

/**
 * Cap an evidence list at the contract limit, reporting the truncation.
 *
 * Evidence is never silently dropped: the caller records `evidenceTruncated` so
 * a bounded list cannot be mistaken for the complete set of observations.
 *
 * @param {object[]} entries Evidence drafts, deterministic order assumed.
 * @param {number} [limit]
 * @returns {{ evidence: object[], evidenceTruncated: boolean }}
 */
export function capEvidence(entries, limit = MAX_EVIDENCE_PER_SIGNAL) {
  if (entries.length <= limit) return { evidence: entries, evidenceTruncated: false };
  return { evidence: entries.slice(0, limit), evidenceTruncated: true };
}

/** Deterministic comparator for evidence entries: path, then signal. */
export function compareEvidence(a, b) {
  if (a.path !== b.path) return a.path < b.path ? -1 : 1;
  if (a.signal === b.signal) return 0;
  return a.signal < b.signal ? -1 : 1;
}

/**
 * Build a scan-result draft.
 *
 * @param {object} [overrides] Partial result. Unknown keys are ignored so the
 *   factory always returns the contracted shape.
 * @returns {object} A ScanResult-shaped draft; run `validateScanResult` first.
 */
export function createScanResult(overrides = {}) {
  const scan = overrides.scan ?? {};
  const statistics = overrides.statistics ?? {};
  const ignore = overrides.ignore ?? {};
  const tests = overrides.tests ?? {};
  const cicd = overrides.cicd ?? {};
  const documentation = overrides.documentation ?? {};
  const configuration = overrides.configuration ?? {};
  const git = overrides.git ?? {};
  const content = overrides.content ?? {};
  const containers = overrides.containers ?? {};
  const dependencies = overrides.dependencies ?? {};
  const imports = overrides.imports ?? {};

  return {
    version: overrides.version ?? SCAN_RESULT_VERSION,
    root: overrides.root ?? null,
    scannedAt: overrides.scannedAt ?? null,
    files: overrides.files ?? [],
    directories: overrides.directories ?? [],
    symlinks: overrides.symlinks ?? [],
    ignored: overrides.ignored ?? [],
    languages: overrides.languages ?? [],
    manifests: overrides.manifests ?? [],
    tests: {
      ...emptyDetection(),
      ...tests,
      evidence: tests.evidence ?? [],
      frameworks: tests.frameworks ?? [],
    },
    cicd: {
      ...emptyDetection(),
      ...cicd,
      evidence: cicd.evidence ?? [],
      providers: cicd.providers ?? [],
    },
    documentation: {
      ...emptyDetection(),
      ...documentation,
      evidence: documentation.evidence ?? [],
    },
    configuration: {
      ...emptyDetection(),
      ...configuration,
      evidence: configuration.evidence ?? [],
    },
    git: {
      detected: git.detected ?? false,
      head: git.head ?? null,
      evidence: git.evidence ?? [],
    },
    // `complete` defaults to `false`, exactly like `scan.complete`: a draft that
    // declares no content inspection must not read as "content was inspected and
    // nothing was found".
    content: {
      inspected: content.inspected ?? false,
      complete: content.complete ?? false,
      truncated: content.truncated ?? false,
      candidates: content.candidates ?? [],
      limits: content.limits ?? {},
    },
    // Empty and `inspected: false` by default: a draft that declares nothing about
    // container build contexts must not look like one whose Compose files were read
    // and found to establish nothing.
    containers: {
      inspected: containers.inspected ?? false,
      declarations: containers.declarations ?? [],
      unparsed: containers.unparsed ?? [],
      limits: containers.limits ?? {},
    },
    // `inspected` and `complete` default to `false`: a draft that declares nothing
    // about dependencies must not look like one whose manifests were read and found
    // to declare nothing.
    dependencies: {
      inspected: dependencies.inspected ?? false,
      complete: dependencies.complete ?? false,
      truncated: dependencies.truncated ?? false,
      manifests: dependencies.manifests ?? [],
      limits: dependencies.limits ?? {},
    },
    // Same three-state discipline for imports: a draft that declares nothing about
    // module sources must not look like one whose sources were read and found to
    // import nothing.
    imports: {
      inspected: imports.inspected ?? false,
      complete: imports.complete ?? false,
      truncated: imports.truncated ?? false,
      files: imports.files ?? [],
      limits: imports.limits ?? {},
    },
    statistics: {
      filesScanned: statistics.filesScanned ?? 0,
      directoriesScanned: statistics.directoriesScanned ?? 0,
      symlinksScanned: statistics.symlinksScanned ?? 0,
      ignored: statistics.ignored ?? 0,
      unreadable: statistics.unreadable ?? 0,
      truncatedBy: statistics.truncatedBy ?? [],
    },
    ignore: {
      sources: ignore.sources ?? [],
      defaultIgnoredDirectories: ignore.defaultIgnoredDirectories ?? [],
      unsupported: ignore.unsupported ?? [],
    },
    scan: {
      complete: scan.complete ?? false,
      truncated: scan.truncated ?? false,
      limits: scan.limits ?? {},
      errors: scan.errors ?? [],
    },
  };
}

function assertSortedByPath(entries, ctx, label) {
  for (let index = 1; index < entries.length; index += 1) {
    if (entries[index - 1].path > entries[index].path) {
      ctx.fail(`${label}[${index}].path`, "must be sorted ascending by path");
      return;
    }
  }
}

function collectEvidenceIssues(evidence, ctx, path) {
  if (!Array.isArray(evidence)) {
    ctx.fail(path, "must be an array");
    return;
  }
  evidence.forEach((entry, index) => {
    if (!isPlainObject(entry)) {
      ctx.fail(`${path}[${index}]`, "must be a plain object");
      return;
    }
    if (!isNonEmptyString(entry.path)) {
      ctx.fail(`${path}[${index}].path`, "must be a non-empty string");
    }
    if (!isNonEmptyString(entry.signal)) {
      ctx.fail(`${path}[${index}].signal`, "must be a non-empty string");
    }
  });
  for (let index = 1; index < evidence.length; index += 1) {
    const previous = `${evidence[index - 1].path}\u0000${evidence[index - 1].signal}`;
    const current = `${evidence[index].path}\u0000${evidence[index].signal}`;
    if (previous > current) {
      ctx.fail(`${path}[${index}]`, "evidence must be sorted by path then signal");
      return;
    }
  }
}

/**
 * Validate an optional symlink target record.
 *
 * Absent is valid and means `unknown`. Present must be the closed vocabulary:
 * `inside` carries a repository-relative path (or `null` for the repository root
 * itself), while `outside` and `unknown` must carry no location and no reason
 * respectively — a location on an escaping target would be a host path, which is
 * precisely what this field exists to prevent.
 */
function collectSymlinkTargetIssues(target, ctx, path) {
  if (target === undefined || target === null) return;
  if (!isPlainObject(target)) {
    ctx.fail(path, "must be a plain object when present");
    return;
  }

  const kinds = Object.values(SYMLINK_TARGET_KINDS);
  if (!kinds.includes(target.kind)) {
    ctx.fail(`${path}.kind`, `must be one of: ${kinds.join(", ")}`);
    return;
  }

  if (target.kind === SYMLINK_TARGET_KINDS.INSIDE) {
    if (target.path !== null && !isNonEmptyString(target.path)) {
      ctx.fail(`${path}.path`, "must be a repository-relative path or null");
    } else if (typeof target.path === "string" && isAbsolutePath(target.path)) {
      ctx.fail(`${path}.path`, "must not be an absolute path");
    }
  } else if (target.path !== null) {
    ctx.fail(`${path}.path`, `must be null for a ${target.kind} target`);
  }

  if (target.kind === SYMLINK_TARGET_KINDS.UNKNOWN) {
    const reasons = Object.values(SYMLINK_UNKNOWN_REASONS);
    if (!reasons.includes(target.reason)) {
      ctx.fail(`${path}.reason`, `must be one of: ${reasons.join(", ")}`);
    }
  } else if (target.reason !== null) {
    ctx.fail(`${path}.reason`, `must be null for a ${target.kind} target`);
  }
}

/** Validate the content-inspection section. */
function collectContentIssues(section, ctx, path) {
  if (!isPlainObject(section)) {
    ctx.fail(path, "must be a plain object");
    return;
  }
  for (const field of ["inspected", "complete", "truncated"]) {
    if (typeof section[field] !== "boolean") {
      ctx.fail(`${path}.${field}`, "must be a boolean");
    }
  }
  if (!isPlainObject(section.limits)) {
    ctx.fail(`${path}.limits`, "must be a plain object");
  }

  if (!Array.isArray(section.candidates)) {
    ctx.fail(`${path}.candidates`, "must be an array");
    return;
  }

  const reasons = Object.values(CONTENT_INSPECTION_REASONS);
  section.candidates.forEach((candidate, index) => {
    const at = `${path}.candidates[${index}]`;
    if (!isPlainObject(candidate)) {
      ctx.fail(at, "must be a plain object");
      return;
    }
    if (!isNonEmptyString(candidate.path)) ctx.fail(`${at}.path`, "must be a non-empty string");
    if (!isNonEmptyString(candidate.candidate)) {
      ctx.fail(`${at}.candidate`, "must record the candidate class");
    }
    if (typeof candidate.inspected !== "boolean") {
      ctx.fail(`${at}.inspected`, "must be a boolean");
    }
    if (candidate.reason !== null && !reasons.includes(candidate.reason)) {
      ctx.fail(`${at}.reason`, `must be null or one of: ${reasons.join(", ")}`);
    }
    if (candidate.inspected === false && candidate.reason === null) {
      ctx.fail(`${at}.reason`, "must record why an uninspected candidate was not inspected");
    }
    if (!isNonNegativeInteger(candidate.bytesInspected)) {
      ctx.fail(`${at}.bytesInspected`, "must be a non-negative integer");
    }
    if (typeof candidate.truncated !== "boolean") {
      ctx.fail(`${at}.truncated`, "must be a boolean");
    }
    if (!Array.isArray(candidate.patterns)) {
      ctx.fail(`${at}.patterns`, "must be an array of pattern ids");
      return;
    }
    candidate.patterns.forEach((pattern, patternIndex) => {
      if (!isNonEmptyString(pattern)) {
        ctx.fail(`${at}.patterns[${patternIndex}]`, "must be a non-empty string");
      }
    });
    for (let next = 1; next < candidate.patterns.length; next += 1) {
      if (candidate.patterns[next - 1] >= candidate.patterns[next]) {
        ctx.fail(`${at}.patterns`, "must be sorted and unique");
        break;
      }
    }
  });

  assertSortedByPath(section.candidates, ctx, `${path}.candidates`);

  // A section cannot claim completeness while a candidate is unknown: the two
  // facts are the same fact stated twice.
  const fullyInspected = section.candidates.every(
    (candidate) => candidate.inspected === true && candidate.truncated !== true,
  );
  if (section.complete === true && !fullyInspected) {
    ctx.fail(
      `${path}.complete`,
      "cannot be true while a candidate was not inspected or was truncated",
    );
  }
}

/**
 * Validate the container build-declaration section.
 *
 * A declaration states which Dockerfile a Compose service builds and from which
 * context root. Both are repository-relative paths, so no host location can travel
 * with a declaration; an entry that cannot be expressed that way is invalid rather
 * than tolerated.
 */
function collectContainersIssues(section, ctx, path) {
  if (!isPlainObject(section)) {
    ctx.fail(path, "must be a plain object");
    return;
  }
  if (typeof section.inspected !== "boolean") {
    ctx.fail(`${path}.inspected`, "must be a boolean");
  }
  if (!isPlainObject(section.limits)) {
    ctx.fail(`${path}.limits`, "must be a plain object");
  }

  if (!Array.isArray(section.declarations)) {
    ctx.fail(`${path}.declarations`, "must be an array");
  } else {
    section.declarations.forEach((declaration, index) => {
      const at = `${path}.declarations[${index}]`;
      if (!isPlainObject(declaration)) {
        ctx.fail(at, "must be a plain object");
        return;
      }
      for (const field of ["source", "service", "dockerfile"]) {
        if (!isNonEmptyString(declaration[field])) {
          ctx.fail(`${at}.${field}`, "must be a non-empty string");
        } else if (field === "dockerfile" && isAbsolutePath(declaration[field])) {
          ctx.fail(`${at}.${field}`, "must be a repository-relative path");
        }
      }
      // `context` is `null` for the repository root, which has no relative form, and a
      // repository-relative directory otherwise. An absolute host path is invalid.
      if (declaration.context !== null) {
        if (!isNonEmptyString(declaration.context)) {
          ctx.fail(`${at}.context`, "must be a repository-relative path or null");
        } else if (isAbsolutePath(declaration.context)) {
          ctx.fail(`${at}.context`, "must be a repository-relative path or null");
        }
      }
    });
    for (let index = 1; index < section.declarations.length; index += 1) {
      const previous = section.declarations[index - 1];
      const current = section.declarations[index];
      const key = (entry) =>
        `${entry.dockerfile}\u0000${entry.context ?? ""}\u0000${entry.service}\u0000${entry.source}`;
      if (key(previous) > key(current)) {
        ctx.fail(`${path}.declarations[${index}]`, "must be sorted deterministically");
        break;
      }
    }
  }

  if (!Array.isArray(section.unparsed)) {
    ctx.fail(`${path}.unparsed`, "must be an array");
    return;
  }
  const reasons = Object.values(CONTAINER_UNPARSED_REASONS);
  section.unparsed.forEach((entry, index) => {
    const at = `${path}.unparsed[${index}]`;
    if (!isPlainObject(entry)) {
      ctx.fail(at, "must be a plain object");
      return;
    }
    if (!isNonEmptyString(entry.source) || isAbsolutePath(entry.source)) {
      ctx.fail(`${at}.source`, "must be a repository-relative path");
    }
    if (!reasons.includes(entry.reason)) {
      ctx.fail(`${at}.reason`, `must be one of: ${reasons.join(", ")}`);
    }
    if (entry.detail !== null && !isNonEmptyString(entry.detail)) {
      ctx.fail(`${at}.detail`, "must be a bounded identifier or null");
    }
  });
  for (let index = 1; index < section.unparsed.length; index += 1) {
    if (section.unparsed[index - 1].source > section.unparsed[index].source) {
      ctx.fail(`${path}.unparsed[${index}]`, "must be sorted by source");
      break;
    }
  }
}

/**
 * Validate the dependency acquisition section.
 *
 * A record is per manifest, so a consumer can always tell which file a declaration
 * came from. What the section may *not* do is claim more than was established:
 *
 *   - `status: "parsed"` records must carry no `reason`;
 *   - every other status must carry one, so an uninterpreted manifest is never
 *     indistinguishable from a manifest that declares nothing;
 *   - `complete` may only be `true` when every record was parsed, was not
 *     truncated and reported no problem — the same "a bounded list is not a
 *     complete list" invariant the evidence sections enforce.
 */
function collectDependenciesIssues(section, ctx, path) {
  if (!isPlainObject(section)) {
    ctx.fail(path, "must be a plain object");
    return;
  }
  for (const field of ["inspected", "complete", "truncated"]) {
    if (typeof section[field] !== "boolean") {
      ctx.fail(`${path}.${field}`, "must be a boolean");
    }
  }
  if (!isPlainObject(section.limits)) {
    ctx.fail(`${path}.limits`, "must be a plain object");
  }

  if (!Array.isArray(section.manifests)) {
    ctx.fail(`${path}.manifests`, "must be an array");
    return;
  }

  const problemReasons = DEPENDENCY_PROBLEM_REASON_VALUES;
  const sourceReasons = Object.values(DEPENDENCY_SOURCE_REASONS);

  section.manifests.forEach((record, index) => {
    const at = `${path}.manifests[${index}]`;
    if (!isPlainObject(record)) {
      ctx.fail(at, "must be a plain object");
      return;
    }
    for (const field of ["path", "ecosystem", "kind", "format"]) {
      if (!isNonEmptyString(record[field])) {
        ctx.fail(`${at}.${field}`, "must be a non-empty string");
      }
    }
    if (isNonEmptyString(record.path) && isAbsolutePath(record.path)) {
      ctx.fail(`${at}.path`, "must be a repository-relative path");
    }
    if (!DEPENDENCY_SOURCE_STATUS_VALUES.includes(record.status)) {
      ctx.fail(`${at}.status`, `must be one of: ${DEPENDENCY_SOURCE_STATUS_VALUES.join(", ")}`);
    }
    if (record.reason !== null && record.reason !== undefined && !sourceReasons.includes(record.reason)) {
      ctx.fail(`${at}.reason`, `must be null or one of: ${sourceReasons.join(", ")}`);
    }
    if (record.status === DEPENDENCY_SOURCE_STATUSES.PARSED && record.reason != null) {
      ctx.fail(`${at}.reason`, "must be null for a parsed source");
    }
    if (record.status !== DEPENDENCY_SOURCE_STATUSES.PARSED && record.reason == null) {
      ctx.fail(`${at}.reason`, "must record why the source is not a parsed dependency source");
    }
    if (record.detail !== null && record.detail !== undefined && !isNonEmptyString(record.detail)) {
      ctx.fail(`${at}.detail`, "must be a bounded identifier or null");
    }
    if (typeof record.truncated !== "boolean") {
      ctx.fail(`${at}.truncated`, "must be a boolean");
    }

    if (!Array.isArray(record.problems)) {
      ctx.fail(`${at}.problems`, "must be an array");
    } else {
      record.problems.forEach((entry, problemIndex) => {
        const problemAt = `${at}.problems[${problemIndex}]`;
        if (!isPlainObject(entry)) {
          ctx.fail(problemAt, "must be a plain object");
          return;
        }
        if (!problemReasons.includes(entry.reason)) {
          ctx.fail(`${problemAt}.reason`, `must be one of: ${problemReasons.join(", ")}`);
        }
        if (entry.detail !== null && entry.detail !== undefined && !isNonEmptyString(entry.detail)) {
          ctx.fail(`${problemAt}.detail`, "must be a bounded identifier or null");
        }
      });
    }

    if (!Array.isArray(record.dependencies)) {
      ctx.fail(`${at}.dependencies`, "must be an array");
    } else {
      record.dependencies.forEach((declaration, declarationIndex) => {
        const declarationAt = `${at}.dependencies[${declarationIndex}]`;
        if (!isPlainObject(declaration)) {
          ctx.fail(declarationAt, "must be a plain object");
          return;
        }
        if (!isNonEmptyString(declaration.name)) {
          ctx.fail(`${declarationAt}.name`, "must be a non-empty string");
        }
        if (declaration.spec !== null && declaration.spec !== undefined && !isNonEmptyString(declaration.spec)) {
          ctx.fail(`${declarationAt}.spec`, "must be a version/spec string or null");
        }
        if (!DEPENDENCY_SPEC_KIND_VALUES.includes(declaration.specKind)) {
          ctx.fail(
            `${declarationAt}.specKind`,
            `must be one of: ${DEPENDENCY_SPEC_KIND_VALUES.join(", ")}`,
          );
        }
        if (!DEPENDENCY_SCOPE_VALUES.includes(declaration.scope)) {
          ctx.fail(`${declarationAt}.scope`, `must be one of: ${DEPENDENCY_SCOPE_VALUES.join(", ")}`);
        }
        if (typeof declaration.direct !== "boolean") {
          ctx.fail(`${declarationAt}.direct`, "must be a boolean");
        }
        if (declaration.conditional !== undefined && typeof declaration.conditional !== "boolean") {
          ctx.fail(`${declarationAt}.conditional`, "must be a boolean when present");
        }
      });
      for (let next = 1; next < record.dependencies.length; next += 1) {
        const previous = record.dependencies[next - 1];
        const current = record.dependencies[next];
        const key = (entry) => `${entry.name}\u0000${entry.scope}`;
        if (key(previous) >= key(current)) {
          ctx.fail(`${at}.dependencies[${next}]`, "must be sorted by name then scope, and unique");
          break;
        }
      }
    }

    if (!Array.isArray(record.resolved)) {
      ctx.fail(`${at}.resolved`, "must be an array");
    } else {
      record.resolved.forEach((entry, resolvedIndex) => {
        const resolvedAt = `${at}.resolved[${resolvedIndex}]`;
        if (
          !isPlainObject(entry) ||
          !isNonEmptyString(entry.name) ||
          !isNonEmptyString(entry.version)
        ) {
          ctx.fail(resolvedAt, "must carry a name and a version");
        }
      });
      for (let next = 1; next < record.resolved.length; next += 1) {
        const previous = record.resolved[next - 1];
        const current = record.resolved[next];
        const key = (entry) => `${entry.name}\u0000${entry.version}`;
        if (key(previous) >= key(current)) {
          ctx.fail(`${at}.resolved[${next}]`, "must be sorted by name then version, and unique");
          break;
        }
      }
    }

    if (!Array.isArray(record.edges)) {
      ctx.fail(`${at}.edges`, "must be an array");
    } else {
      record.edges.forEach((edge, edgeIndex) => {
        const edgeAt = `${at}.edges[${edgeIndex}]`;
        if (!isPlainObject(edge) || !isNonEmptyString(edge.from) || !isNonEmptyString(edge.to)) {
          ctx.fail(edgeAt, "must carry a from and a to dependency name");
        }
      });
      for (let next = 1; next < record.edges.length; next += 1) {
        const previous = record.edges[next - 1];
        const current = record.edges[next];
        const key = (entry) => `${entry.from}\u0000${entry.to}`;
        if (key(previous) >= key(current)) {
          ctx.fail(`${at}.edges[${next}]`, "must be sorted and unique");
          break;
        }
      }
    }
  });

  for (let index = 1; index < section.manifests.length; index += 1) {
    if (section.manifests[index - 1]?.path >= section.manifests[index]?.path) {
      ctx.fail(`${path}.manifests[${index}].path`, "must be sorted by path and unique");
      break;
    }
  }

  const everySourceEstablished = section.manifests.every(
    (record) =>
      isPlainObject(record) &&
      record.status === DEPENDENCY_SOURCE_STATUSES.PARSED &&
      record.truncated !== true &&
      Array.isArray(record.problems) &&
      record.problems.length === 0,
  );
  // `complete` may be true with `inspected: false` only in the honest shape of that
  // pair: a repository with no manifest at all has no unread dependency source. It
  // can never be true while a source was unsupported, unreadable or truncated.
  if (section.complete === true && !everySourceEstablished) {
    ctx.fail(
      `${path}.complete`,
      "cannot be true unless every dependency source was parsed without truncation or problems",
    );
  }
}

/**
 * Validate the import acquisition section.
 *
 * A record is per module source, so a consumer can always tell which file a
 * reference came from and which files could not be read. The invariants are the
 * dependency section's, applied to a different question:
 *
 *   - `parsed` records carry no `reason`; every other status carries one, so an
 *     unread module is never indistinguishable from one that imports nothing;
 *   - every reference kind, status, reason and problem is drawn from a closed
 *     vocabulary, so no free text (and therefore no hostile text) can travel
 *     through this section;
 *   - a specifier is bounded, non-empty, printable text;
 *   - `complete` may only be `true` when every module source was parsed without
 *     truncation or problems — the same "a bounded list is not a complete list"
 *     rule the other sections enforce, and the reason a file whose references were
 *     only partly established can never be reported as a complete parse.
 */
function collectImportsIssues(section, ctx, path) {
  if (!isPlainObject(section)) {
    ctx.fail(path, "must be a plain object");
    return;
  }
  for (const field of ["inspected", "complete", "truncated"]) {
    if (typeof section[field] !== "boolean") {
      ctx.fail(`${path}.${field}`, "must be a boolean");
    }
  }
  if (!isPlainObject(section.limits)) {
    ctx.fail(`${path}.limits`, "must be a plain object");
  }

  if (!Array.isArray(section.files)) {
    ctx.fail(`${path}.files`, "must be an array");
    return;
  }

  section.files.forEach((record, index) => {
    const at = `${path}.files[${index}]`;
    if (!isPlainObject(record)) {
      ctx.fail(at, "must be a plain object");
      return;
    }
    for (const field of ["path", "extension", "language"]) {
      if (!isNonEmptyString(record[field])) {
        ctx.fail(`${at}.${field}`, "must be a non-empty string");
      }
    }
    if (isNonEmptyString(record.path) && isAbsolutePath(record.path)) {
      ctx.fail(`${at}.path`, "must be a repository-relative path");
    }
    if (!IMPORT_SOURCE_STATUS_VALUES.includes(record.status)) {
      ctx.fail(`${at}.status`, `must be one of: ${IMPORT_SOURCE_STATUS_VALUES.join(", ")}`);
    }
    if (
      record.reason !== null &&
      record.reason !== undefined &&
      !IMPORT_SOURCE_REASON_VALUES.includes(record.reason)
    ) {
      ctx.fail(`${at}.reason`, `must be null or one of: ${IMPORT_SOURCE_REASON_VALUES.join(", ")}`);
    }
    if (record.status === IMPORT_SOURCE_STATUSES.PARSED && record.reason != null) {
      ctx.fail(`${at}.reason`, "must be null for a parsed module source");
    }
    if (record.status !== IMPORT_SOURCE_STATUSES.PARSED && record.reason == null) {
      ctx.fail(`${at}.reason`, "must record why the module source was not parsed");
    }
    if (record.detail !== null && record.detail !== undefined && !isNonEmptyString(record.detail)) {
      ctx.fail(`${at}.detail`, "must be a bounded identifier or null");
    }
    if (!isNonNegativeInteger(record.bytesInspected)) {
      ctx.fail(`${at}.bytesInspected`, "must be a non-negative integer");
    }
    if (typeof record.truncated !== "boolean") {
      ctx.fail(`${at}.truncated`, "must be a boolean");
    }
    if (!isNonNegativeInteger(record.nonStatic)) {
      ctx.fail(`${at}.nonStatic`, "must be a non-negative integer");
    }

    if (!Array.isArray(record.nonStaticReasons)) {
      ctx.fail(`${at}.nonStaticReasons`, "must be an array");
    } else {
      record.nonStaticReasons.forEach((reason, reasonIndex) => {
        if (!IMPORT_NON_STATIC_REASON_VALUES.includes(reason)) {
          ctx.fail(
            `${at}.nonStaticReasons[${reasonIndex}]`,
            `must be one of: ${IMPORT_NON_STATIC_REASON_VALUES.join(", ")}`,
          );
        }
      });
      for (let next = 1; next < record.nonStaticReasons.length; next += 1) {
        if (record.nonStaticReasons[next - 1] >= record.nonStaticReasons[next]) {
          ctx.fail(`${at}.nonStaticReasons`, "must be sorted and unique");
          break;
        }
      }
    }

    if (!Array.isArray(record.problems)) {
      ctx.fail(`${at}.problems`, "must be an array");
    } else {
      record.problems.forEach((problem, problemIndex) => {
        if (!IMPORT_PROBLEM_REASON_VALUES.includes(problem)) {
          ctx.fail(
            `${at}.problems[${problemIndex}]`,
            `must be one of: ${IMPORT_PROBLEM_REASON_VALUES.join(", ")}`,
          );
        }
      });
      for (let next = 1; next < record.problems.length; next += 1) {
        if (record.problems[next - 1] >= record.problems[next]) {
          ctx.fail(`${at}.problems`, "must be sorted and unique");
          break;
        }
      }
    }

    if (!Array.isArray(record.references)) {
      ctx.fail(`${at}.references`, "must be an array");
    } else {
      record.references.forEach((reference, referenceIndex) => {
        const referenceAt = `${at}.references[${referenceIndex}]`;
        if (!isPlainObject(reference)) {
          ctx.fail(referenceAt, "must be a plain object");
          return;
        }
        if (!IMPORT_SPECIFIER_KIND_VALUES.includes(reference.kind)) {
          ctx.fail(`${referenceAt}.kind`, `must be one of: ${IMPORT_SPECIFIER_KIND_VALUES.join(", ")}`);
        }
        if (!isUsableSpecifier(reference.specifier)) {
          ctx.fail(
            `${referenceAt}.specifier`,
            "must be bounded, printable, non-empty specifier text",
          );
        }
      });
      if (record.status !== IMPORT_SOURCE_STATUSES.PARSED && record.references.length > 0) {
        ctx.fail(`${at}.references`, "must be empty for a module source that was not parsed");
      }
    }
  });

  assertSortedByPath(section.files, ctx, `${path}.files`);
  for (let index = 1; index < section.files.length; index += 1) {
    if (section.files[index - 1]?.path >= section.files[index]?.path) {
      ctx.fail(`${path}.files[${index}].path`, "must be sorted by path and unique");
      break;
    }
  }

  const everySourceEstablished = section.files.every(
    (record) =>
      isPlainObject(record) &&
      record.status === IMPORT_SOURCE_STATUSES.PARSED &&
      record.truncated !== true &&
      Array.isArray(record.problems) &&
      record.problems.length === 0,
  );
  if (section.complete === true && !everySourceEstablished) {
    ctx.fail(
      `${path}.complete`,
      "cannot be true unless every module source was parsed without truncation or problems",
    );
  }
}

function collectDetectionIssues(section, ctx, path) {  if (!isPlainObject(section)) {
    ctx.fail(path, "must be a plain object");
    return;
  }
  if (typeof section.detected !== "boolean") {
    ctx.fail(`${path}.detected`, "must be a boolean");
  }
  if (
    section.evidenceTruncated !== undefined &&
    typeof section.evidenceTruncated !== "boolean"
  ) {
    ctx.fail(`${path}.evidenceTruncated`, "must be a boolean");
  }
  collectEvidenceIssues(section.evidence, ctx, `${path}.evidence`);
  if ("frameworks" in section && !Array.isArray(section.frameworks)) {
    ctx.fail(`${path}.frameworks`, "must be an array");
  }
  if ("providers" in section && !Array.isArray(section.providers)) {
    ctx.fail(`${path}.providers`, "must be an array");
  }
}

/**
 * Validate a scan result.
 *
 * @param {unknown} value
 * @returns {object} The same value when valid.
 * @throws {ValidationError} When any contract invariant is violated.
 */
export function validateScanResult(value) {
  const issues = [];
  const fail = (path, message) => issues.push(`${path}: ${message}`);
  const ctx = { fail };

  if (!isPlainObject(value)) {
    throw new ValidationError("Invalid scan result", {
      details: {
        contract: "ScanResult",
        issues: ["scanResult: must be a plain object"],
      },
    });
  }

  if (!isNonEmptyString(value.version)) fail("scanResult.version", "must be a non-empty string");
  if (!isNonEmptyString(value.root)) fail("scanResult.root", "must be a non-empty string");
  if (!isNonEmptyString(value.scannedAt)) {
    fail("scanResult.scannedAt", "must be a non-empty string");
  }

  for (const section of ARRAY_SECTIONS) {
    if (!Array.isArray(value[section])) fail(`scanResult.${section}`, "must be an array");
  }

  if (Array.isArray(value.files)) {
    value.files.forEach((entry, index) => {
      if (!isPlainObject(entry)) {
        fail(`scanResult.files[${index}]`, "must be a plain object");
        return;
      }
      if (!isNonEmptyString(entry.path)) {
        fail(`scanResult.files[${index}].path`, "must be a non-empty string");
      }
      if (!isNonEmptyString(entry.name)) {
        fail(`scanResult.files[${index}].name`, "must be a non-empty string");
      }
      if (!isNonNegativeInteger(entry.depth)) {
        fail(`scanResult.files[${index}].depth`, "must be a non-negative integer");
      }
    });
    assertSortedByPath(value.files, ctx, "scanResult.files");
  }

  if (Array.isArray(value.directories)) {
    value.directories.forEach((entry, index) => {
      if (!isPlainObject(entry) || !isNonEmptyString(entry.path)) {
        fail(`scanResult.directories[${index}].path`, "must be a non-empty string");
      }
    });
    assertSortedByPath(value.directories, ctx, "scanResult.directories");
  }

  if (Array.isArray(value.symlinks)) {
    assertSortedByPath(value.symlinks, ctx, "scanResult.symlinks");
    value.symlinks.forEach((entry, index) =>
      collectSymlinkTargetIssues(
        entry?.target,
        ctx,
        `scanResult.symlinks[${index}].target`,
      ),
    );
  }

  collectContentIssues(value.content, ctx, "scanResult.content");
  collectContainersIssues(value.containers, ctx, "scanResult.containers");
  collectDependenciesIssues(value.dependencies, ctx, "scanResult.dependencies");
  collectImportsIssues(value.imports, ctx, "scanResult.imports");
  if (Array.isArray(value.ignored)) {
    assertSortedByPath(value.ignored, ctx, "scanResult.ignored");
    value.ignored.forEach((entry, index) => {
      if (!isNonEmptyString(entry.policy)) {
        fail(`scanResult.ignored[${index}].policy`, "must record the ignore policy");
      }
    });
  }

  if (Array.isArray(value.languages)) {
    value.languages.forEach((entry, index) => {
      if (!isPlainObject(entry) || !isNonEmptyString(entry.id)) {
        fail(`scanResult.languages[${index}].id`, "must be a non-empty string");
        return;
      }
      if (!isNonNegativeInteger(entry.fileCount)) {
        fail(`scanResult.languages[${index}].fileCount`, "must be a non-negative integer");
      }
      if (Array.isArray(entry.evidence) && entry.evidence.length === 0) {
        fail(
          `scanResult.languages[${index}].evidence`,
          "a language must not be reported without evidence",
        );
      }
      collectEvidenceIssues(entry.evidence, ctx, `scanResult.languages[${index}].evidence`);
    });
    for (let index = 1; index < value.languages.length; index += 1) {
      if (value.languages[index - 1].id >= value.languages[index].id) {
        fail(`scanResult.languages[${index}].id`, "languages must be sorted by id and unique");
        break;
      }
    }
  }

  if (Array.isArray(value.manifests)) {
    assertSortedByPath(value.manifests, ctx, "scanResult.manifests");
    value.manifests.forEach((entry, index) => {
      if (!isNonEmptyString(entry.ecosystem)) {
        fail(`scanResult.manifests[${index}].ecosystem`, "must be a non-empty string");
      }
      if (!isPlainObject(entry.parse) || !isNonEmptyString(entry.parse.status)) {
        fail(`scanResult.manifests[${index}].parse.status`, "must record a parse status");
      }
    });
  }

  for (const section of DETECTION_SECTIONS) {
    collectDetectionIssues(value[section], ctx, `scanResult.${section}`);
  }

  if (!isPlainObject(value.git)) {
    fail("scanResult.git", "must be a plain object");
  } else {
    if (typeof value.git.detected !== "boolean") {
      fail("scanResult.git.detected", "must be a boolean");
    }
    collectEvidenceIssues(value.git.evidence, ctx, "scanResult.git.evidence");
  }

  if (!isPlainObject(value.statistics)) {
    fail("scanResult.statistics", "must be a plain object");
  } else {
    for (const field of [
      "filesScanned",
      "directoriesScanned",
      "symlinksScanned",
      "ignored",
      "unreadable",
    ]) {
      if (!isNonNegativeInteger(value.statistics[field])) {
        fail(`scanResult.statistics.${field}`, "must be a non-negative integer");
      }
    }
    if (!Array.isArray(value.statistics.truncatedBy)) {
      fail("scanResult.statistics.truncatedBy", "must be an array");
    }
  }

  if (!isPlainObject(value.ignore)) {
    fail("scanResult.ignore", "must be a plain object");
  } else {
    for (const field of ["sources", "defaultIgnoredDirectories", "unsupported"]) {
      if (!Array.isArray(value.ignore[field])) {
        fail(`scanResult.ignore.${field}`, "must be an array");
      }
    }
  }

  if (!isPlainObject(value.scan)) {
    fail("scanResult.scan", "must be a plain object");
  } else {
    if (typeof value.scan.complete !== "boolean") {
      fail("scanResult.scan.complete", "must be a boolean");
    }
    if (typeof value.scan.truncated !== "boolean") {
      fail("scanResult.scan.truncated", "must be a boolean");
    }
    if (!isPlainObject(value.scan.limits)) {
      fail("scanResult.scan.limits", "must be a plain object");
    }
    if (!Array.isArray(value.scan.errors)) {
      fail("scanResult.scan.errors", "must be an array");
    }
    if (value.scan.truncated === true && value.scan.complete === true) {
      fail(
        "scanResult.scan",
        "cannot be complete and truncated at once; a truncated scan must report complete: false",
      );
    }
  }

  if (issues.length > 0) {
    throw new ValidationError("Invalid scan result", {
      details: { contract: "ScanResult", issues },
    });
  }

  return value;
}

export { sortByPath };
