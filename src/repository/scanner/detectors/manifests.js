/**
 * Code Guardian — Manifest Detection (Phase 8C)
 *
 * Manifests and lockfiles are recognised by *file name* at any depth, so
 * monorepo packages are inventoried too. Recognition is evidence: it records
 * that a project declares itself in a given ecosystem, not that its dependencies
 * are healthy.
 *
 * Parsing is deliberately shallow — Phase 8C answers "what exists", not "what
 * does the dependency graph look like":
 *
 *   - Only `package.json` is read. It exposes a bounded set of declared fields
 *     (name, version, type, private, workspaces presence, script keys and
 *     dependency section names with counts). Dependency names are counted, never
 *     resolved, and no registry is contacted.
 *   - Every other manifest is inventoried by name only. Its contents are NOT
 *     read at all, which also keeps large lockfiles out of memory. That is
 *     recorded explicitly as `parse.status === "not-parsed"` with a documented
 *     reason, so an unread manifest can never be mistaken for an empty one.
 *
 * A manifest that cannot be read or parsed does **not** fail the scan: the entry
 * is preserved as evidence with a classified parse outcome.
 */

import { FILESYSTEM_ERROR_KINDS } from "../../filesystem/index.js";

import { parentDirectory } from "../policies/ignore.js";
import { findRule } from "./match.js";

/**
 * Largest manifest the scanner will read (bytes).
 *
 * The bound is applied to the bytes that were read and before `JSON.parse`, so a
 * hostile manifest cannot trigger parse amplification: the content is measured,
 * reported through `parse.bytes` and then discarded unparsed. Byte *sizing* is
 * bounded by the Phase 8A read contract, which does not expose a size-limited
 * read in this phase — an unreadable or absurdly large file therefore degrades to
 * a classified read failure instead of being silently truncated.
 */
export const MAX_MANIFEST_BYTES = 262144;

/** Bounded string fields accepted from `package.json`. */
const BOUNDED_STRING_LIMITS = Object.freeze({
  name: 200,
  version: 200,
  type: 50,
});

const MAX_SCRIPT_KEYS = 100;

const PACKAGE_DEPENDENCY_SECTIONS = Object.freeze([
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
]);

/** Parse outcomes recorded on every manifest entry. */
export const MANIFEST_PARSE_STATUS = Object.freeze({
  PARSED: "parsed",
  FAILED: "failed",
  NOT_PARSED: "not-parsed",
});

/** Deterministic, path-free reasons a manifest was not fully parsed. */
export const MANIFEST_PARSE_REASONS = Object.freeze({
  DEFERRED: "format-not-parsed-in-phase-8c",
  TOO_LARGE: "exceeds-max-manifest-bytes",
  INVALID_JSON: "invalid-json",
  NOT_AN_OBJECT: "json-value-is-not-an-object",
  UNREADABLE: "manifest-could-not-be-read",
});

/**
 * Recognised manifests and lockfiles.
 *
 * Each definition doubles as a match rule (see `detectors/match.js`), so the
 * table is both the recognition data and its own documentation. `languages`
 * lists the languages this file is evidence for; an empty list means the file
 * identifies a *project* but not a language (`CMakeLists.txt`, `Makefile` and
 * `*.sln` are used across C, C++ and .NET projects and therefore claim none).
 */
export const MANIFEST_DEFINITIONS = Object.freeze([
  // Node / JavaScript ecosystem.
  {
    basename: "package.json",
    ecosystem: "node",
    kind: "manifest",
    languages: ["javascript"],
    format: "json",
    structured: true,
  },
  { basename: "package-lock.json", ecosystem: "node", kind: "lockfile", languages: ["javascript"], format: "json" },
  { basename: "npm-shrinkwrap.json", ecosystem: "node", kind: "lockfile", languages: ["javascript"], format: "json" },
  { basename: "pnpm-lock.yaml", ecosystem: "node", kind: "lockfile", languages: ["javascript"], format: "yaml" },
  { basename: "yarn.lock", ecosystem: "node", kind: "lockfile", languages: ["javascript"], format: "text" },
  { basename: "bun.lockb", ecosystem: "node", kind: "lockfile", languages: ["javascript"], format: "binary" },
  // Deno.
  { basename: "deno.json", ecosystem: "deno", kind: "manifest", languages: ["typescript"], format: "json" },
  { basename: "deno.jsonc", ecosystem: "deno", kind: "manifest", languages: ["typescript"], format: "jsonc" },
  // Python.
  { basename: "pyproject.toml", ecosystem: "python", kind: "manifest", languages: ["python"], format: "toml" },
  { basename: "requirements.txt", ecosystem: "python", kind: "manifest", languages: ["python"], format: "text" },
  { basename: "Pipfile", ecosystem: "python", kind: "manifest", languages: ["python"], format: "toml" },
  { basename: "Pipfile.lock", ecosystem: "python", kind: "lockfile", languages: ["python"], format: "json" },
  { basename: "poetry.lock", ecosystem: "python", kind: "lockfile", languages: ["python"], format: "toml" },
  { basename: "setup.py", ecosystem: "python", kind: "manifest", languages: ["python"], format: "python" },
  { basename: "setup.cfg", ecosystem: "python", kind: "manifest", languages: ["python"], format: "ini" },
  // Java / JVM.
  { basename: "pom.xml", ecosystem: "java", kind: "manifest", languages: ["java"], format: "xml" },
  { basename: "build.gradle", ecosystem: "java", kind: "manifest", languages: ["java"], format: "gradle" },
  { basename: "build.gradle.kts", ecosystem: "java", kind: "manifest", languages: ["java"], format: "gradle" },
  { basename: "settings.gradle", ecosystem: "java", kind: "manifest", languages: ["java"], format: "gradle" },
  { basename: "settings.gradle.kts", ecosystem: "java", kind: "manifest", languages: ["java"], format: "gradle" },
  // Go.
  { basename: "go.mod", ecosystem: "go", kind: "manifest", languages: ["go"], format: "go" },
  { basename: "go.sum", ecosystem: "go", kind: "lockfile", languages: ["go"], format: "text" },
  // Rust.
  { basename: "Cargo.toml", ecosystem: "rust", kind: "manifest", languages: ["rust"], format: "toml" },
  { basename: "Cargo.lock", ecosystem: "rust", kind: "lockfile", languages: ["rust"], format: "toml" },
  // PHP.
  { basename: "composer.json", ecosystem: "php", kind: "manifest", languages: ["php"], format: "json" },
  { basename: "composer.lock", ecosystem: "php", kind: "lockfile", languages: ["php"], format: "json" },
  // Ruby.
  { basename: "Gemfile", ecosystem: "ruby", kind: "manifest", languages: ["ruby"], format: "ruby" },
  { basename: "Gemfile.lock", ecosystem: "ruby", kind: "lockfile", languages: ["ruby"], format: "text" },
  { basenamePattern: "*.gemspec", ecosystem: "ruby", kind: "manifest", languages: ["ruby"], format: "ruby" },
  // Dart / Flutter.
  { basename: "pubspec.yaml", ecosystem: "dart", kind: "manifest", languages: ["dart"], format: "yaml" },
  { basename: "pubspec.lock", ecosystem: "dart", kind: "lockfile", languages: ["dart"], format: "yaml" },
  // .NET.
  { basenamePattern: "*.csproj", ecosystem: "dotnet", kind: "manifest", languages: ["csharp"], format: "xml" },
  { basenamePattern: "*.fsproj", ecosystem: "dotnet", kind: "manifest", languages: ["fsharp"], format: "xml" },
  { basenamePattern: "*.sln", ecosystem: "dotnet", kind: "manifest", languages: [], format: "text" },
  { basename: "global.json", ecosystem: "dotnet", kind: "manifest", languages: [], format: "json" },
  // C / C++ build systems (no language claim: both share these files).
  { basename: "CMakeLists.txt", ecosystem: "c-cpp", kind: "manifest", languages: [], format: "cmake" },
  { basename: "Makefile", ecosystem: "c-cpp", kind: "manifest", languages: [], format: "make" },
  { basename: "meson.build", ecosystem: "c-cpp", kind: "manifest", languages: [], format: "meson" },
  // Other clearly identifiable ecosystems.
  { basename: "mix.exs", ecosystem: "elixir", kind: "manifest", languages: ["elixir"], format: "elixir" },
  { basename: "Package.swift", ecosystem: "swift", kind: "manifest", languages: ["swift"], format: "swift" },
  { basename: "build.sbt", ecosystem: "scala", kind: "manifest", languages: ["scala"], format: "sbt" },
]);

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function boundedString(value, limit) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (trimmed === "" || trimmed.length > limit) return null;
  return trimmed;
}

/**
 * Extract the documented shallow `package.json` metadata subset.
 *
 * Dependency *names* are counted per section and never listed, so no dependency
 * graph is built here.
 *
 * @param {object} value Parsed JSON object.
 * @returns {object}
 */
export function extractPackageManifest(value) {
  const scriptKeys = isPlainObject(value.scripts)
    ? Object.keys(value.scripts).sort()
    : [];

  const dependencySections = PACKAGE_DEPENDENCY_SECTIONS.filter((section) =>
    isPlainObject(value[section]),
  )
    .map((section) => ({ section, count: Object.keys(value[section]).length }))
    .sort((a, b) => (a.section < b.section ? -1 : 1));

  return {
    name: boundedString(value.name, BOUNDED_STRING_LIMITS.name),
    version: boundedString(value.version, BOUNDED_STRING_LIMITS.version),
    type: boundedString(value.type, BOUNDED_STRING_LIMITS.type),
    private: typeof value.private === "boolean" ? value.private : null,
    workspaces: value.workspaces !== undefined,
    scripts: scriptKeys.slice(0, MAX_SCRIPT_KEYS),
    scriptsTruncated: scriptKeys.length > MAX_SCRIPT_KEYS,
    dependencySections,
  };
}

function notParsed(definition) {
  return {
    status: MANIFEST_PARSE_STATUS.NOT_PARSED,
    format: definition.format,
    reason: MANIFEST_PARSE_REASONS.DEFERRED,
  };
}

async function parseStructured(view, definition, path) {
  const read = await view.read(path);
  if (!read.ok) {
    return {
      status: MANIFEST_PARSE_STATUS.FAILED,
      format: definition.format,
      reason: MANIFEST_PARSE_REASONS.UNREADABLE,
      errorKind: read.error?.kind ?? FILESYSTEM_ERROR_KINDS.FILESYSTEM_ERROR,
    };
  }

  const bytes = Buffer.byteLength(read.content, "utf8");
  if (bytes > MAX_MANIFEST_BYTES) {
    return {
      status: MANIFEST_PARSE_STATUS.NOT_PARSED,
      format: definition.format,
      reason: MANIFEST_PARSE_REASONS.TOO_LARGE,
      bytes,
    };
  }

  let value;
  try {
    value = JSON.parse(read.content);
  } catch {
    return {
      status: MANIFEST_PARSE_STATUS.FAILED,
      format: definition.format,
      reason: MANIFEST_PARSE_REASONS.INVALID_JSON,
      bytes,
    };
  }

  if (!isPlainObject(value)) {
    return {
      status: MANIFEST_PARSE_STATUS.FAILED,
      format: definition.format,
      reason: MANIFEST_PARSE_REASONS.NOT_AN_OBJECT,
      bytes,
    };
  }

  return {
    status: MANIFEST_PARSE_STATUS.PARSED,
    format: definition.format,
    bytes,
    metadata: extractPackageManifest(value),
  };
}

/**
 * Detect manifests/lockfiles and record their shallow parse outcome.
 *
 * @param {object} view Repository view.
 * @returns {Promise<object[]>} Manifest entries, sorted by path.
 */
export async function detectManifests(view) {
  const entries = [];

  // `view.files` is path-sorted, so the result is already deterministic.
  for (const file of view.files) {
    const definition = findRule(MANIFEST_DEFINITIONS, file);
    if (definition === null) continue;
    entries.push({
      path: file.path,
      name: file.name,
      directory: parentDirectory(file.path),
      ecosystem: definition.ecosystem,
      kind: definition.kind,
      languages: [...definition.languages],
      parse: definition.structured
        ? await parseStructured(view, definition, file.path)
        : notParsed(definition),
    });
  }

  return entries;
}
