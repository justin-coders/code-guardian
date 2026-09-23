/**
 * Code Guardian — Dependency Manifest Policy (Phase 13)
 *
 * Dependency intelligence starts here: this module turns the *text* of a manifest
 * into normalized dependency facts. It is a pure, bounded, deterministic parser
 * layer — no filesystem, no network, no registry, no package manager, no clock and
 * no randomness. The detector that supplies the text is the only caller, and the
 * Phase 8A boundary is the only thing that ever touched the disk.
 *
 * ### Why a strict subset, and why "unsupported" is a first-class answer
 *
 * A manifest format is interpreted only when its dependency declarations can be
 * read *deterministically*: JSON for npm, line-oriented grammar for
 * `requirements.txt` and `go.mod`. Everything else — `pyproject.toml`,
 * `Cargo.toml`, `pnpm-lock.yaml`, `pom.xml`, `Gemfile`, `*.csproj`, `yarn.lock`,
 * a binary `bun.lockb` — is recorded as **unsupported**, with a bounded reason.
 *
 * That is deliberate. This phase must not add a TOML/YAML/XML parser (guessing at
 * semantics is worse than abstaining), and an uninterpreted manifest must never
 * read as one that declares nothing: `unsupported` makes the section's `complete`
 * flag `false`, so the model reports *unknown* dependency coverage for a
 * repository whose manifests this phase cannot read.
 *
 * ### What is never invented
 *
 *   - A declaration is *what the manifest says*. `devDependencies` is
 *     development scope because npm says so, not because a package name looks
 *     like a test library.
 *   - A resolved package and an edge come only from a lockfile whose format
 *     defines them (npm's `packages` map, or the v1 nested tree with `requires`).
 *     An entry in a lockfile is never promoted to "direct".
 *   - A name that fails its ecosystem's charset rules is *reported* as a problem
 *     and not modelled, so hostile text can never become a dependency identity.
 *
 * Every bound below exists because a manifest is untrusted input: bytes per file,
 * bytes per scan, files per scan, declarations, resolved packages, edges, edges
 * per package, lockfile nesting depth and name/spec length. A bound that is hit is
 * recorded, never silently applied.
 */

/** Hard bounds on one scan's dependency acquisition. */
export const DEPENDENCY_LIMITS = Object.freeze({
  /** Bytes read from any single manifest. */
  maxManifestBytes: 262144,
  /** Bytes read across all manifest files in one scan. */
  maxTotalBytes: 2097152,
  /** Manifest files interpreted in one scan. */
  maxManifests: 32,
  /** Declaration records retained from one scan. */
  maxDeclarations: 2000,
  /** Resolved packages retained from one scan. */
  maxResolved: 5000,
  /** Dependency edges retained from one scan. */
  maxEdges: 10000,
  /** Edges read from a single package entry. */
  maxEdgesPerPackage: 256,
  /** Nesting depth walked inside a v1 npm lockfile. */
  maxLockfileDepth: 32,
  /** Longest accepted dependency name. */
  maxNameLength: 214,
  /** Longest accepted version/spec text. */
  maxSpecLength: 200,
  /** Lines examined in one text manifest. */
  maxLines: 20000,
});

/**
 * Status of one manifest as a dependency source.
 *
 *   parsed       the manifest's dependency declarations were read
 *   unsupported  the format is not interpreted in this phase
 *   failed       the file could not be read or is malformed
 */
export const DEPENDENCY_SOURCE_STATUSES = Object.freeze({
  PARSED: "parsed",
  UNSUPPORTED: "unsupported",
  FAILED: "failed",
});

/** Every source status as a list, for validation. */
export const DEPENDENCY_SOURCE_STATUS_VALUES = Object.freeze(
  Object.values(DEPENDENCY_SOURCE_STATUSES),
);

/**
 * Deterministic, path-free reasons a manifest is not a usable dependency source.
 *
 * The vocabulary is closed so a reason can never carry hostile text, and it is
 * intentionally *not* a failure: `format-not-interpreted` is the honest answer for
 * a format this phase refuses to guess at.
 */
export const DEPENDENCY_SOURCE_REASONS = Object.freeze({
  FORMAT_NOT_INTERPRETED: "format-not-interpreted",
  INVALID_JSON: "invalid-json",
  NOT_AN_OBJECT: "json-value-is-not-an-object",
  NOT_TEXT: "not-text",
  UNREADABLE: "manifest-could-not-be-read",
  TOO_LARGE: "exceeds-max-manifest-bytes",
  BUDGET_EXHAUSTED: "budget-exhausted",
});

const SOURCE_REASON_VALUES = Object.freeze(Object.values(DEPENDENCY_SOURCE_REASONS));

/** Whether a value is a source reason this policy can produce. */
export function isDependencySourceReason(value) {
  return typeof value === "string" && SOURCE_REASON_VALUES.includes(value);
}

/**
 * How a declared version specifier is sourced.
 *
 * Mirrors npm's documented spec prefixes (`workspace:`, `file:`, `link:`,
 * `npm:` alias, git and URL shorthands) and the PEP 508 `name @ url` form. It
 * exists so a consumer can tell a registry range from a path or a repository
 * reference without parsing the spec — and so the pack can word a finding honestly
 * ("declared from a local path") rather than pretending every spec is a version.
 */
export const DEPENDENCY_SPEC_KINDS = Object.freeze({
  REGISTRY: "registry",
  WORKSPACE: "workspace",
  LOCAL: "local",
  URL: "url",
  GIT: "git",
  ALIAS: "alias",
  UNKNOWN: "unknown",
});

/** Every spec kind as a list, for validation. */
export const DEPENDENCY_SPEC_KIND_VALUES = Object.freeze(Object.values(DEPENDENCY_SPEC_KINDS));

/**
 * The scope a declaration establishes.
 *
 * Only manifest semantics produce these values — npm's section names, Go's
 * `// indirect` marker, `requirements.txt`'s role as the runtime install set. A
 * package name never selects a scope; when a format does not state one, the value
 * is `unknown`.
 */
export const DEPENDENCY_SCOPES = Object.freeze({
  RUNTIME: "runtime",
  DEVELOPMENT: "development",
  OPTIONAL: "optional",
  PEER: "peer",
  UNKNOWN: "unknown",
});

/** Every scope as a list, for validation. */
export const DEPENDENCY_SCOPE_VALUES = Object.freeze(Object.values(DEPENDENCY_SCOPES));

/**
 * Bounded declarations of what a manifest contained but this phase did not model.
 *
 * A problem makes the manifest *incomplete*, which is why the reason vocabulary is
 * closed and the detail is a bounded identifier: a rejected declaration must never
 * be invisible, and it must never carry the hostile text that caused it.
 */
export const DEPENDENCY_PROBLEM_REASONS = Object.freeze({
  INVALID_NAME: "invalid-name",
  INVALID_SPEC: "invalid-spec",
  INVALID_VERSION: "invalid-version",
  INVALID_KEY: "invalid-entry-key",
  DUPLICATE_DECLARATION: "duplicate-declaration",
  DEPTH_LIMIT: "depth-limit",
  ENTRY_LIMIT: "entry-limit",
  EDGE_LIMIT: "edge-limit",
  INCLUDE_DIRECTIVE: "include-directive",
  EDITABLE_REQUIREMENT: "editable-requirement",
  LINE_CONTINUATION: "line-continuation-unsupported",
  REPLACE_DIRECTIVE: "replace-directive",
  EXCLUDE_DIRECTIVE: "exclude-directive",
});

/** Every problem reason as a list, for validation. */
export const DEPENDENCY_PROBLEM_REASON_VALUES = Object.freeze(
  Object.values(DEPENDENCY_PROBLEM_REASONS),
);

/** Whether a value is a problem reason this policy can produce. */
export function isDependencyProblemReason(value) {
  return typeof value === "string" && DEPENDENCY_PROBLEM_REASON_VALUES.includes(value);
}

/**
 * The parsers this phase implements, keyed by ecosystem + manifest format.
 *
 * The table is the whole supported set: a manifest that is not listed is
 * `unsupported`, never silently skipped. `kind` is included in the key because a
 * manifest and its lockfile can share a format while meaning different things
 * (`package.json` declares, `package-lock.json` resolves).
 */
export const DEPENDENCY_SOURCE_TABLE = Object.freeze([
  { ecosystem: "node", kind: "manifest", format: "json", parser: "package-json", basenames: ["package.json"] },
  {
    ecosystem: "node",
    kind: "lockfile",
    format: "json",
    parser: "npm-lockfile",
    basenames: ["package-lock.json", "npm-shrinkwrap.json"],
  },
  {
    ecosystem: "python",
    kind: "manifest",
    format: "text",
    parser: "requirements-txt",
    basenames: ["requirements.txt"],
  },
  {
    ecosystem: "go",
    kind: "manifest",
    format: "go",
    parser: "go-mod",
    basenames: ["go.mod"],
  },
]);

const PARSERS_BY_NAME = Object.freeze({
  "package-json": parsePackageJson,
  "npm-lockfile": parseNpmLockfile,
  "requirements-txt": parseRequirementsTxt,
  "go-mod": parseGoMod,
});

/** npm's declaration sections, and the scope each one establishes. */
export const NODE_DEPENDENCY_SECTIONS = Object.freeze([
  { section: "dependencies", scope: DEPENDENCY_SCOPES.RUNTIME },
  { section: "devDependencies", scope: DEPENDENCY_SCOPES.DEVELOPMENT },
  { section: "optionalDependencies", scope: DEPENDENCY_SCOPES.OPTIONAL },
  { section: "peerDependencies", scope: DEPENDENCY_SCOPES.PEER },
]);

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function asString(value) {
  return typeof value === "string" ? value : null;
}

/**
 * Bounded, path-free identifier text.
 *
 * Used for names and specs *after* the ecosystem charset rule has accepted them:
 * this is the second gate, keeping a declaration that reaches the model small,
 * printable and free of control characters, `\`, `:` or whitespace.
 */
const BOUNDED_TEXT = /^[A-Za-z0-9@][A-Za-z0-9@._/+-]*$/;

function isBoundedText(value, limit) {
  return typeof value === "string" && value.length <= limit && BOUNDED_TEXT.test(value);
}

/**
 * Whether a dependency name is acceptable for its ecosystem.
 *
 * Each ecosystem's own published charset is enforced — npm's lower-case scoped
 * names, PEP 508 names, Go module paths, Cargo-style names — so a name that
 * contains a path separator it must not have (npm), a `..` segment (Go) or a
 * control character is rejected rather than modelled. Rejection is reported as a
 * problem, never as a silent drop.
 *
 * @param {string} ecosystem
 * @param {string} name
 * @returns {boolean}
 */
export function isDependencyName(ecosystem, name) {
  if (!isBoundedText(name, DEPENDENCY_LIMITS.maxNameLength)) return false;
  if (name.includes("..") || name.startsWith("/") || name.startsWith(".")) return false;

  switch (ecosystem) {
    case "node":
      // npm: lower case, optionally scoped, no leading dot/underscore, no spaces or
      // path separators beyond the single scope slash.
      return /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/.test(name);
    case "python":
      // PEP 508: letters, digits, `-`, `_`, `.`, starting with a letter or digit.
      return /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name);
    case "go":
      // Module paths: one or more `/`-separated path elements, each of which may
      // contain letters, digits, `.`, `_`, `-`, `~`. No empty, `.` or `..` element
      // (the last two are rejected above).
      return name
        .split("/")
        .every((segment) => /^[A-Za-z0-9][A-Za-z0-9._~-]*$/.test(segment));
    default:
      return false;
  }
}

/**
 * The canonical name a dependency is identified by, per ecosystem.
 *
 * Normalization is published behaviour, not a convenience: npm names are already
 * lower case, and PEP 503 defines the Python form (lower case, runs of `-`, `_`
 * and `.` collapsed to `-`). Go module paths are case-sensitive and are kept
 * verbatim. Normalizing here is what makes `Flask` and `flask` one dependency in
 * a Python repository instead of two.
 *
 * @param {string} ecosystem
 * @param {string} name
 * @returns {{ok: true, name: string} | {ok: false}}
 */
export function normalizeDependencyName(ecosystem, name) {
  if (!isDependencyName(ecosystem, name)) return { ok: false };
  if (ecosystem === "python") {
    return { ok: true, name: name.toLowerCase().replace(/[-_.]+/g, "-") };
  }
  return { ok: true, name };
}

/**
 * Whether a version or resolved version text is acceptable.
 *
 * Versions are untrusted text: a bounded, printable, path-free charset, so a
 * lockfile cannot smuggle a host path or a control character through a version
 * string. Ranges (`^1.2.3 || ^2`) are accepted as *specs* by their own rule below;
 * this one governs a *resolved* version.
 */
export function isDependencyVersion(value) {
  return (
    typeof value === "string" &&
    value.length <= DEPENDENCY_LIMITS.maxSpecLength &&
    /^[A-Za-z0-9v][A-Za-z0-9.+_~!()-]*$/.test(value)
  );
}

/** Classify a declaration spec string into the closed spec-kind vocabulary. */
export function classifySpecKind(spec) {
  if (typeof spec !== "string" || spec.trim() === "") return DEPENDENCY_SPEC_KINDS.UNKNOWN;
  const value = spec.trim();
  if (value.startsWith("workspace:")) return DEPENDENCY_SPEC_KINDS.WORKSPACE;
  if (/^(file|link|portal):/.test(value)) return DEPENDENCY_SPEC_KINDS.LOCAL;
  if (value.startsWith("npm:")) return DEPENDENCY_SPEC_KINDS.ALIAS;
  if (/^(git\+|git:|github:|gitlab:|bitbucket:|gist:)/.test(value)) {
    return DEPENDENCY_SPEC_KINDS.GIT;
  }
  if (/^https?:\/\//.test(value)) return DEPENDENCY_SPEC_KINDS.URL;
  return DEPENDENCY_SPEC_KINDS.REGISTRY;
}

/**
 * Whether a declaration spec is safe to record.
 *
 * Specs are untrusted text. They are not required to look like a version — npm
 * allows `workspace:*`, `file:../x`, `git+https://…`, `>=1 <2` — but they must be
 * bounded, printable and free of control characters, so a spec can never carry a
 * NUL, a newline or an unbounded payload into the model.
 */
export function isDependencySpec(value) {
  if (typeof value !== "string") return false;
  if (value.length > DEPENDENCY_LIMITS.maxSpecLength) return false;
  // eslint-disable-next-line no-control-regex
  return !/[\u0000-\u001f\u007f]/.test(value);
}

function problem(reason, detail = null) {
  return { reason, detail };
}

function emptyResult() {
  return { ok: true, declarations: [], resolved: [], edges: [], problems: [] };
}

/**
 * Read one `name: spec` object as declarations for a scope.
 *
 * @param {object} section Parsed JSON object for one dependency section.
 * @param {string} scope
 * @param {object} out Accumulator (`declarations`, `problems`, `seen`).
 * @returns {void}
 */
function readDeclarationSection(section, scope, out) {
  for (const name of Object.keys(section).sort()) {
    const rawSpec = section[name];
    const normalized = normalizeDependencyName("node", name);
    if (!normalized.ok) {
      out.problems.push(problem(DEPENDENCY_PROBLEM_REASONS.INVALID_NAME));
      continue;
    }
    const key = `node:${normalized.name}`;
    if (out.seen.has(key)) {
      // The same dependency declared in two sections of one manifest. npm treats
      // this as an error, so it is preserved as a second declaration *and*
      // reported — never silently collapsed into one scope.
      out.problems.push(problem(DEPENDENCY_PROBLEM_REASONS.DUPLICATE_DECLARATION));
    }
    out.seen.add(key);

    if (!isDependencySpec(rawSpec)) {
      // The name is known and the spec is not usable: keep the declaration with an
      // unknown spec rather than dropping a fact, and report the spec.
      out.problems.push(problem(DEPENDENCY_PROBLEM_REASONS.INVALID_SPEC));
      out.declarations.push({
        name: normalized.name,
        spec: null,
        specKind: DEPENDENCY_SPEC_KINDS.UNKNOWN,
        scope,
        direct: true,
      });
      continue;
    }

    out.declarations.push({
      name: normalized.name,
      spec: rawSpec,
      specKind: classifySpecKind(rawSpec),
      scope,
      direct: true,
    });
  }
}

/**
 * Parse a `package.json` dependency declaration set.
 *
 * Only the four declaration sections are read. `bundledDependencies` is *not*
 * interpreted (it lists names with no version) and no other key can contribute a
 * dependency, so an unrelated field can never become one.
 *
 * @param {string} text
 * @returns {object} Parse result.
 */
export function parsePackageJson(text) {
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    return { ok: false, reason: DEPENDENCY_SOURCE_REASONS.INVALID_JSON, detail: null };
  }
  if (!isPlainObject(value)) {
    return { ok: false, reason: DEPENDENCY_SOURCE_REASONS.NOT_AN_OBJECT, detail: null };
  }

  const out = { declarations: [], problems: [], seen: new Set() };
  for (const { section, scope } of NODE_DEPENDENCY_SECTIONS) {
    if (!isPlainObject(value[section])) continue;
    readDeclarationSection(value[section], scope, out);
  }

  return {
    ok: true,
    declarations: out.declarations,
    resolved: [],
    edges: [],
    problems: out.problems,
  };
}

/** npm lockfile versions whose `packages` map is the resolved tree. */
const NPM_PACKAGES_FORMATS = Object.freeze([2, 3]);

/**
 * Extract the package name from an npm `packages` map key.
 *
 * `node_modules/react` → `react`, `node_modules/a/node_modules/b` → `b`. Keys that
 * contain no `node_modules/` segment describe workspace packages (they are
 * declared by their own `package.json`), so they are not resolved dependencies.
 */
function packageNameFromLockKey(key) {
  const marker = "node_modules/";
  const at = key.lastIndexOf(marker);
  if (at === -1) return null;
  const name = key.slice(at + marker.length);
  return name === "" ? null : name;
}

function readLockEntryEdges(entry, out) {
  const names = [];
  for (const section of ["dependencies", "optionalDependencies", "peerDependencies"]) {
    if (!isPlainObject(entry[section])) continue;
    for (const name of Object.keys(entry[section])) names.push(name);
  }
  names.sort();
  let added = 0;
  for (const name of names) {
    if (added >= DEPENDENCY_LIMITS.maxEdgesPerPackage) {
      out.problems.push(problem(DEPENDENCY_PROBLEM_REASONS.EDGE_LIMIT));
      break;
    }
    const normalized = normalizeDependencyName("node", name);
    if (!normalized.ok) {
      out.problems.push(problem(DEPENDENCY_PROBLEM_REASONS.INVALID_NAME));
      continue;
    }
    out.edges.push({ from: out.current, to: normalized.name });
    added += 1;
  }
}

/**
 * Parse an npm lockfile (`package-lock.json`, `npm-shrinkwrap.json`).
 *
 * Two formats, both interpreted from what the format *defines*:
 *
 *   - lockfileVersion 2/3 — the `packages` map is the resolved tree. Each
 *     `node_modules/<name>` key is a resolved package, and that entry's own
 *     dependency sections name its children, so the edges are the format's own
 *     resolution graph;
 *   - lockfileVersion 1 — the nested `dependencies` tree, walked with an explicit
 *     depth bound and a visited path, where each entry is a resolved package and
 *     `requires` names its children.
 *
 * Direct-vs-transitive is *not* decided here: the lockfile never says which
 * packages a repository line declares — that is the manifest's statement — so a
 * lockfile contributes resolved packages and edges only.
 *
 * @param {string} text
 * @returns {object} Parse result.
 */
export function parseNpmLockfile(text) {
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    return { ok: false, reason: DEPENDENCY_SOURCE_REASONS.INVALID_JSON, detail: null };
  }
  if (!isPlainObject(value)) {
    return { ok: false, reason: DEPENDENCY_SOURCE_REASONS.NOT_AN_OBJECT, detail: null };
  }

  const version = value.lockfileVersion;
  const usesPackages =
    isPlainObject(value.packages) && NPM_PACKAGES_FORMATS.includes(Number(version));

  if (usesPackages) return parseNpmPackagesMap(value.packages);
  if (isPlainObject(value.dependencies)) return parseNpmV1Tree(value.dependencies);

  // A lockfile whose structure this phase does not recognise is *unsupported*
  // rather than empty: its dependency graph is not established.
  return {
    ok: false,
    reason: DEPENDENCY_SOURCE_REASONS.FORMAT_NOT_INTERPRETED,
    detail: "lockfile-structure",
  };
}

function parseNpmPackagesMap(packages) {
  const out = { resolved: [], edges: [], problems: [], seen: new Set() };
  const keys = Object.keys(packages).sort();

  for (const key of keys) {
    if (key === "") continue; // The root package: declared by package.json.
    const entry = packages[key];
    if (!isPlainObject(entry)) continue;
    if (entry.link === true) continue; // A workspace link, not a resolved package.

    const name = packageNameFromLockKey(key);
    if (name === null) continue;
    const normalized = normalizeDependencyName("node", name);
    if (!normalized.ok) {
      out.problems.push(problem(DEPENDENCY_PROBLEM_REASONS.INVALID_NAME));
      continue;
    }
    if (out.seen.has(normalized.name)) continue; // Same name at two nestings.
    out.seen.add(normalized.name);

    if (isDependencyVersion(entry.version)) {
      out.resolved.push({ name: normalized.name, version: entry.version });
    } else if (entry.version !== undefined) {
      out.problems.push(problem(DEPENDENCY_PROBLEM_REASONS.INVALID_VERSION));
    }

    const edgesOut = { edges: out.edges, problems: out.problems, current: normalized.name };
    readLockEntryEdges(entry, edgesOut);
  }

  return { ok: true, declarations: [], resolved: out.resolved, edges: out.edges, problems: out.problems };
}

/**
 * Walk a v1 npm lockfile's nested `dependencies` tree.
 *
 * The walk is breadcrumb-guarded: a package already seen on the current path is
 * not descended into again, so a cyclic or absurdly deep tree cannot recurse
 * without bound. Depth and entry counts are bounded as well.
 */
function parseNpmV1Tree(root) {
  const out = { resolved: [], edges: [], problems: [], seen: new Set() };
  let entries = 0;

  const walk = (dependencies, depth, path) => {
    if (depth > DEPENDENCY_LIMITS.maxLockfileDepth) {
      out.problems.push(problem(DEPENDENCY_PROBLEM_REASONS.DEPTH_LIMIT));
      return;
    }
    for (const name of Object.keys(dependencies).sort()) {
      if (entries >= DEPENDENCY_LIMITS.maxResolved) {
        out.problems.push(problem(DEPENDENCY_PROBLEM_REASONS.ENTRY_LIMIT));
        return;
      }
      const normalized = normalizeDependencyName("node", name);
      if (!normalized.ok) {
        out.problems.push(problem(DEPENDENCY_PROBLEM_REASONS.INVALID_NAME));
        continue;
      }
      const entry = dependencies[name];
      if (!isPlainObject(entry)) continue;
      entries += 1;

      if (!out.seen.has(normalized.name)) {
        out.seen.add(normalized.name);
        if (isDependencyVersion(entry.version)) {
          out.resolved.push({ name: normalized.name, version: entry.version });
        } else if (entry.version !== undefined) {
          out.problems.push(problem(DEPENDENCY_PROBLEM_REASONS.INVALID_VERSION));
        }
      }

      if (isPlainObject(entry.requires)) {
        const names = Object.keys(entry.requires).sort();
        let added = 0;
        for (const required of names) {
          if (added >= DEPENDENCY_LIMITS.maxEdgesPerPackage) break;
          const child = normalizeDependencyName("node", required);
          if (!child.ok) {
            out.problems.push(problem(DEPENDENCY_PROBLEM_REASONS.INVALID_NAME));
            continue;
          }
          out.edges.push({ from: normalized.name, to: child.name });
          added += 1;
        }
      }

      if (isPlainObject(entry.dependencies) && !path.has(normalized.name)) {
        const next = new Set(path);
        next.add(normalized.name);
        walk(entry.dependencies, depth + 1, next);
      }
    }
  };

  walk(root, 1, new Set());
  return { ok: true, declarations: [], resolved: out.resolved, edges: out.edges, problems: out.problems };
}

/** A PEP 508 requirement name (before normalization). */
const PYTHON_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

/**
 * Parse a `requirements.txt`.
 *
 * The format is a line-oriented install list, so:
 *
 *   - `name`, `name[extras]` and `name==1.2.*` / `name>=1,<2` are declarations.
 *     `requirements.txt` is the runtime install set, so the scope is `runtime`;
 *     an environment marker (`; python_version < "3.9"`) is *recorded as present*
 *     rather than interpreted, and its text is never copied.
 *   - `name @ https://…` (PEP 508 URL form) is a declaration whose spec kind is
 *     `url`.
 *   - `-r`/`--requirement`, `-c`/`--constraint` includes and `-e`/`--editable`
 *     installs are *reported* as problems, never followed: following an include
 *     would read a file the scan may not have covered, and an editable install
 *     points outside the package registry entirely.
 *   - options (`--index-url`, `--hash`, …) are not requirements and are skipped.
 *
 * @param {string} text
 * @returns {object} Parse result.
 */
export function parseRequirementsTxt(text) {
  if (typeof text !== "string" || text.includes("\u0000")) {
    return { ok: false, reason: DEPENDENCY_SOURCE_REASONS.NOT_TEXT, detail: null };
  }

  const out = { declarations: [], problems: [], seen: new Set() };
  const lines = text.split(/\r?\n/);
  const limit = Math.min(lines.length, DEPENDENCY_LIMITS.maxLines);

  for (let index = 0; index < limit; index += 1) {
    const raw = lines[index];
    const withoutComment = raw.split("#")[0];
    const line = withoutComment.trim();
    if (line === "") continue;

    if (line.endsWith("\\")) {
      out.problems.push(problem(DEPENDENCY_PROBLEM_REASONS.LINE_CONTINUATION));
      continue;
    }
    if (/^(-r|--requirement|-c|--constraint)\b/.test(line)) {
      out.problems.push(problem(DEPENDENCY_PROBLEM_REASONS.INCLUDE_DIRECTIVE));
      continue;
    }
    if (/^(-e|--editable)\b/.test(line)) {
      out.problems.push(problem(DEPENDENCY_PROBLEM_REASONS.EDITABLE_REQUIREMENT));
      continue;
    }
    if (line.startsWith("-")) continue; // A pip option, not a requirement.

    const requirement = parsePythonRequirement(line);
    if (requirement === null) {
      out.problems.push(problem(DEPENDENCY_PROBLEM_REASONS.INVALID_SPEC));
      continue;
    }
    const normalized = normalizeDependencyName("python", requirement.name);
    if (!normalized.ok) {
      out.problems.push(problem(DEPENDENCY_PROBLEM_REASONS.INVALID_NAME));
      continue;
    }
    if (out.seen.has(normalized.name)) {
      out.problems.push(problem(DEPENDENCY_PROBLEM_REASONS.DUPLICATE_DECLARATION));
      continue;
    }
    out.seen.add(normalized.name);

    out.declarations.push({
      name: normalized.name,
      spec: requirement.spec,
      specKind: requirement.specKind,
      scope: DEPENDENCY_SCOPES.RUNTIME,
      // A marker makes the requirement conditional on the environment. The
      // condition is *not* evaluated (that would need an interpreter), so the
      // declaration is honestly marked as conditional.
      direct: true,
      conditional: requirement.conditional,
    });
  }

  return { ok: true, declarations: out.declarations, resolved: [], edges: [], problems: out.problems };
}

/**
 * Split one PEP 508 requirement line into a name, a spec and a marker flag.
 *
 * @param {string} line
 * @returns {{name: string, spec: string|null, specKind: string, conditional: boolean}|null}
 */
function parsePythonRequirement(line) {
  const [requirementPart, ...markerParts] = line.split(";");
  const body = requirementPart.trim();
  if (body === "") return null;
  const conditional = markerParts.join(";").trim() !== "";

  const nameMatch = /^([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(body);
  if (nameMatch === null) return null;
  const name = nameMatch[1];
  let rest = body.slice(name.length).trim();

  if (rest.startsWith("[")) {
    const close = rest.indexOf("]");
    if (close === -1) return null;
    const extras = rest.slice(1, close);
    if (extras.trim() === "" || !/^[A-Za-z0-9._,-]+$/.test(extras.replace(/\s+/g, ""))) {
      return null;
    }
    rest = rest.slice(close + 1).trim();
  }

  if (rest.startsWith("@")) {
    const url = rest.slice(1).trim();
    if (url === "" || !isDependencySpec(url)) return null;
    return { name, spec: url, specKind: DEPENDENCY_SPEC_KINDS.URL, conditional };
  }

  if (rest === "") {
    return { name, spec: null, specKind: DEPENDENCY_SPEC_KINDS.UNKNOWN, conditional };
  }
  if (!/^[<>=!~][^;]*$/.test(rest) || !isDependencySpec(rest)) return null;
  return { name, spec: rest, specKind: DEPENDENCY_SPEC_KINDS.REGISTRY, conditional };
}

/** A Go module path. */
function isGoModulePath(value) {
  return isDependencyName("go", value);
}

/** A Go version: `vX.Y.Z`, a pseudo-version, or a pre-release of either. */
function isGoVersion(value) {
  return (
    typeof value === "string" &&
    value.length <= 64 &&
    /^v\d[A-Za-z0-9.+-]*$/.test(value)
  );
}

/**
 * Parse a `go.mod`.
 *
 * The grammar is small and line-oriented: `require` entries (in a block or on one
 * line) are declarations, and Go's own `// indirect` marker is the one place a
 * format establishes "this is not a direct dependency". `replace` and `exclude`
 * change resolution, which this phase does not interpret, so both are reported as
 * problems instead of being applied or ignored.
 *
 * @param {string} text
 * @returns {object} Parse result.
 */
export function parseGoMod(text) {
  if (typeof text !== "string" || text.includes("\u0000")) {
    return { ok: false, reason: DEPENDENCY_SOURCE_REASONS.NOT_TEXT, detail: null };
  }

  const out = { declarations: [], problems: [], seen: new Set() };
  const lines = text.split(/\r?\n/);
  const limit = Math.min(lines.length, DEPENDENCY_LIMITS.maxLines);
  /** The directive block currently open, or `null` outside any block. */
  let block = null;

  for (let index = 0; index < limit; index += 1) {
    const raw = lines[index];
    const withoutComment = raw.split("//")[0];
    const line = withoutComment.trim();
    const comment = raw.slice(withoutComment.length);
    if (line === "") continue;

    if (line === ")") {
      block = null;
      continue;
    }

    const directive = /^(require|replace|exclude)\b/.exec(line);
    if (directive !== null) {
      const name = directive[1];
      const rest = line.slice(name.length).trim();
      if (name !== "require") {
        out.problems.push(
          problem(
            name === "replace"
              ? DEPENDENCY_PROBLEM_REASONS.REPLACE_DIRECTIVE
              : DEPENDENCY_PROBLEM_REASONS.EXCLUDE_DIRECTIVE,
          ),
        );
        if (rest === "(") block = name;
        continue;
      }
      if (rest === "(") {
        block = name;
        continue;
      }
      if (rest !== "") readGoRequire(rest, /\/\/\s*indirect\b/.test(comment), out);
      continue;
    }

    if (block === "require") {
      readGoRequire(line, /\/\/\s*indirect\b/.test(comment), out);
      continue;
    }
    if (block !== null) continue;
    // `module`, `go`, `toolchain` and anything else are not dependency
    // declarations and contribute nothing.
  }

  return { ok: true, declarations: out.declarations, resolved: [], edges: [], problems: out.problems };
}

function readGoRequire(line, indirect, out) {
  const parts = line.split(/\s+/);
  if (parts.length !== 2) {
    out.problems.push(problem(DEPENDENCY_PROBLEM_REASONS.INVALID_SPEC));
    return;
  }
  const [path, version] = parts;
  if (!isGoModulePath(path)) {
    out.problems.push(problem(DEPENDENCY_PROBLEM_REASONS.INVALID_NAME));
    return;
  }
  if (!isGoVersion(version)) {
    out.problems.push(problem(DEPENDENCY_PROBLEM_REASONS.INVALID_VERSION));
    return;
  }
  if (out.seen.has(path)) {
    out.problems.push(problem(DEPENDENCY_PROBLEM_REASONS.DUPLICATE_DECLARATION));
    return;
  }
  out.seen.add(path);

  out.declarations.push({
    name: path,
    spec: version,
    specKind: DEPENDENCY_SPEC_KINDS.REGISTRY,
    scope: DEPENDENCY_SCOPES.RUNTIME,
    // Go states this itself: an `// indirect` requirement is present because a
    // dependency needs it, not because the module declares it directly.
    direct: indirect !== true,
  });
}

/**
 * Resolve the parser for one inventory manifest.
 *
 * @param {{ ecosystem: string, kind: string, format: string }} source
 * @returns {{mode: "parse", parser: string} | {mode: "unsupported", reason: string}}
 */
export function dependencySourceFor(source) {
  for (const entry of DEPENDENCY_SOURCE_TABLE) {
    if (
      entry.ecosystem === source.ecosystem &&
      entry.kind === source.kind &&
      entry.format === source.format
    ) {
      return { mode: "parse", parser: entry.parser };
    }
  }
  return { mode: "unsupported", reason: DEPENDENCY_SOURCE_REASONS.FORMAT_NOT_INTERPRETED };
}

/**
 * Run one parser, normalizing its result into the acquisition contract.
 *
 * The returned object is exactly what the scan section records for one manifest,
 * so the detector can never hand the contract a shape the validator would reject.
 *
 * @param {string} parser One of `DEPENDENCY_SOURCE_TABLE[].parser`.
 * @param {string} text
 * @returns {{ok: true, declarations: object[], resolved: object[], edges: object[], problems: object[]}
 *   | {ok: false, reason: string, detail: string|null}}
 */
export function runDependencyParser(parser, text) {
  const implementation = PARSERS_BY_NAME[parser];
  if (implementation === undefined) {
    return { ok: false, reason: DEPENDENCY_SOURCE_REASONS.FORMAT_NOT_INTERPRETED, detail: null };
  }
  try {
    return implementation(text);
  } catch {
    // A parser is a pure function of text; a throw is a defect, and the honest
    // response is an unparsed source, not a crashed scan.
    return { ok: false, reason: DEPENDENCY_SOURCE_REASONS.INVALID_JSON, detail: "parser-failed" };
  }
}

/** Deterministic ordering for declarations: name, then scope. */
export function compareDeclarations(a, b) {
  if (a.name !== b.name) return a.name < b.name ? -1 : 1;
  if (a.scope === b.scope) return 0;
  return a.scope < b.scope ? -1 : 1;
}

/** Deterministic ordering for resolved packages and edges. */
export function compareResolved(a, b) {
  if (a.name !== b.name) return a.name < b.name ? -1 : 1;
  return a.version < b.version ? -1 : a.version > b.version ? 1 : 0;
}

export function compareEdges(a, b) {
  if (a.from !== b.from) return a.from < b.from ? -1 : 1;
  return a.to < b.to ? -1 : a.to > b.to ? 1 : 0;
}

/** Deterministic ordering for problem records. */
export function compareProblems(a, b) {
  if (a.reason !== b.reason) return a.reason < b.reason ? -1 : 1;
  const aDetail = a.detail ?? "";
  const bDetail = b.detail ?? "";
  if (aDetail === bDetail) return 0;
  return aDetail < bDetail ? -1 : 1;
}

/** A parse result that declares a manifest unusable as a dependency source. */
export function unsupportedSource(reason, detail = null) {
  return { ok: false, reason, detail };
}

/** An empty, valid parse result (used when a source contributes nothing). */
export function emptyParseResult() {
  return emptyResult();
}
