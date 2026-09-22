/**
 * Code Guardian — Scanner Container Build-Context Policy (Phase 12 correction)
 *
 * Docker applies exactly one `.dockerignore`, and it is the file at the **build
 * context root**. So "is this image built without ignoring anything?" has a precise
 * answer only when the context root is known — and the previous revision of the
 * container rule did not know it: it treated the presence of a repository-root
 * `.dockerignore` as evidence that a nested Dockerfile is built from that root, which
 * turns a possibility into a security conclusion.
 *
 * This module supplies the one piece of repository-local evidence that *does*
 * establish a context: a Compose file's `build` configuration. Compose is
 * declarative, is already inventoried by the configuration detector, and states the
 * relationship the rule needs:
 *
 *   services:
 *     web:
 *       build: ./docker                    # context, dockerfile defaults
 *     api:
 *       build:
 *         context: .
 *         dockerfile: docker/Dockerfile    # explicit pair
 *
 * ### A strict subset, parsed deterministically
 *
 * There is no YAML parser in this project and this phase must not add a dependency,
 * so the parser reads the *declarative subset* above and refuses, as `ambiguous`,
 * anything it cannot interpret with certainty:
 *
 *   - tabs in indentation, multiple documents, YAML directives;
 *   - an anchor, alias or merge key at a level this parser reads, because such a key
 *     can inject build configuration that is not visible here;
 *   - a `build`/`context`/`dockerfile` value that is not a plain scalar (a flow
 *     mapping, a block scalar, or a second declaration of the same key).
 *
 * Everything else is *skipped*, not rejected: a `ports:` sequence, a nested
 * `labels:` mapping, a `command: |` block, or unrelated service keys cannot change
 * what a `build` block says. Only the levels the parser actually reads are
 * interpreted — the service-key level and the build mapping's own child level — so a
 * deeper line that merely looks like `context:` can never be mistaken for one.
 *
 * A refusal is not a failure. It is the honest answer "this file's build declarations
 * are not established", which the rule reports as `unknown` instead of guessing.
 *
 * ### Resolution is container-local and contained
 *
 * A relative `context` is resolved against the Compose file's own directory —
 * Compose's default project directory, and the only interpretation a repository-local
 * file supports — and the resulting paths must stay inside the repository. A context
 * that escapes is *dropped* rather than reported: its Dockerfile is outside the
 * inventory too, so there is no observed artifact the model could make a claim about,
 * and the affected Dockerfile correctly falls back to `unknown`.
 *
 * Nothing here reads the filesystem: the text is supplied by the caller, which is why
 * every rule below can be unit-tested on any platform.
 */

/** Compose basenames. Shared with the configuration detector so they cannot drift. */
export const COMPOSE_FILENAMES = Object.freeze([
  "docker-compose.yml",
  "docker-compose.yaml",
  "compose.yml",
  "compose.yaml",
]);

/** Hard bounds on container-configuration inspection in one scan. */
export const CONTAINER_DECLARATION_LIMITS = Object.freeze({
  /** Bytes read from any single Compose file. */
  maxFileBytes: 65536,
  /** Compose files inspected in one scan. */
  maxFiles: 32,
  /** Build declarations retained from one scan. */
  maxDeclarations: 256,
});

/** The Dockerfile name Compose uses when `dockerfile` is not declared. */
export const DEFAULT_DOCKERFILE_NAME = "Dockerfile";

/**
 * Why a Compose file's build declarations are not established.
 *
 * `ambiguous` covers every structural refusal; `detail` records the exact cause as a
 * bounded identifier without widening the vocabulary.
 */
export const COMPOSE_UNPARSED_REASONS = Object.freeze({
  READ_FAILED: "read-failed",
  NOT_TEXT: "not-text",
  TOO_LARGE: "too-large",
  BUDGET_EXHAUSTED: "budget-exhausted",
  AMBIGUOUS: "ambiguous",
});

const REASON_VALUES = Object.freeze(Object.values(COMPOSE_UNPARSED_REASONS));

/** Whether a value is an unparsed reason this policy can produce. */
export function isComposeUnparsedReason(value) {
  return typeof value === "string" && REASON_VALUES.includes(value);
}

/**
 * Whether a Compose reference is absolute rather than container-relative.
 *
 * Compose requires `context` and `dockerfile` to be relative. An absolute reference
 * cannot be checked against the repository, so it is unresolvable from the model
 * (and its text must never be recorded, since it is a host location).
 */
export function isAbsoluteContainerReference(value) {
  return (
    typeof value === "string" &&
    (value.startsWith("/") || /^[a-zA-Z]:[\\/]/.test(value) || value.startsWith("\\\\"))
  );
}

function parsed(declarations) {
  return { ok: true, declarations };
}

function ambiguous(detail) {
  return { ok: false, reason: COMPOSE_UNPARSED_REASONS.AMBIGUOUS, detail };
}

/** Cut a trailing YAML comment (a `#` must be preceded by whitespace). */
function stripComment(text) {
  const at = text.indexOf(" #");
  return at === -1 ? text : text.slice(0, at).trimEnd();
}

/**
 * YAML features that can hide or redirect a declaration at a level this parser reads.
 *
 * Only anchors, aliases and merge keys qualify: they can pull in configuration from
 * elsewhere in the file or another document, so the parser cannot claim to know what a
 * `build` block says.
 */
function hiddenStructure(text) {
  if (text.startsWith("&") || text.startsWith("*") || text.startsWith("<<")) {
    return "anchor-or-alias";
  }
  if (text.includes(": &") || text.includes(": *") || text.includes(" <<")) {
    return "anchor-or-alias";
  }
  return null;
}

/**
 * Read a scalar that is meant to be a path.
 *
 * @param {string} raw
 * @returns {{value: string|null} | {unsupported: string}}
 */
function parsePathScalar(raw) {
  const value = raw.trim();
  if (value === "") return { value: null };
  const first = value[0];
  if (first === "{" || first === "[" || first === "|" || first === ">") {
    return { unsupported: "non-scalar-value" };
  }
  if (first === '"' || first === "'") {
    const end = value.indexOf(first, 1);
    if (end === -1) return { unsupported: "unterminated-quote" };
    const inner = value.slice(1, end);
    return { value: inner === "" ? null : inner };
  }
  return { value };
}

/** Split a `key: value` line, or `null` when it is not a mapping key. */
function parseKey(text) {
  const colon = text.indexOf(":");
  if (colon === -1) return null;
  const key = text.slice(0, colon).trim();
  if (key === "" || key.includes(":")) return null;
  return { key, rest: text.slice(colon + 1) };
}

/**
 * Extract the build declarations from one Compose file.
 *
 * Pure: it takes the file's text and returns declarations whose raw `context` /
 * `dockerfile` values are exactly as written. Path resolution belongs to the caller,
 * which owns the repository root.
 *
 * @param {unknown} text Compose file contents.
 * @returns {{ok: true, declarations: Array<{service: string, context: string, dockerfile: string|null}>}
 *   | {ok: false, reason: string, detail: string}}
 */
export function parseComposeBuildContexts(text) {
  if (typeof text !== "string" || text.includes("\u0000")) {
    return { ok: false, reason: COMPOSE_UNPARSED_REASONS.NOT_TEXT, detail: null };
  }

  const entries = [];
  for (const raw of text.split(/\r?\n/)) {
    if (raw.includes("\t")) return ambiguous("tab-indentation");
    const trimmed = raw.trim();
    if (trimmed === "") continue;
    if (trimmed.startsWith("---") || trimmed.startsWith("...")) return ambiguous("multi-document");
    if (trimmed.startsWith("%")) return ambiguous("directive");
    if (trimmed.startsWith("#")) continue;
    const indent = raw.length - raw.trimStart().length;
    entries.push({ indent, text: stripComment(trimmed) });
  }

  const servicesAt = entries
    .map((entry, index) => ({ entry, index }))
    .filter(({ entry }) => entry.indent === 0 && entry.text === "services:");
  if (servicesAt.length === 0) return parsed([]);
  if (servicesAt.length > 1) return ambiguous("duplicate-key");

  const declarations = [];
  const seenServices = new Set();
  let serviceIndent = null;
  let keyIndent = null;
  let service = null;
  let seenBuild = false;
  let build = null;

  /** Finish the open build block, keeping the service it belongs to. */
  const closeBuild = () => {
    if (build === null) return;
    declarations.push({
      service,
      context: build.context ?? ".",
      dockerfile: build.dockerfile ?? null,
    });
    build = null;
  };

  const closeService = () => {
    closeBuild();
    service = null;
    seenBuild = false;
    keyIndent = null;
  };

  /** A `context`/`dockerfile` line inside an open build mapping. */
  const readBuildChild = (text) => {
    const child = parseKey(text);
    if (child === null) return null;
    if (child.key !== "context" && child.key !== "dockerfile") return null;
    const scalar = parsePathScalar(child.rest);
    if (scalar.unsupported !== undefined) return { ambiguous: scalar.unsupported };
    if (scalar.value === null) return { ambiguous: "empty-value" };
    if (child.key === "context") {
      if (build.context !== null) return { ambiguous: "duplicate-key" };
      build.context = scalar.value;
    } else {
      if (build.dockerfile !== null) return { ambiguous: "duplicate-key" };
      build.dockerfile = scalar.value;
    }
    return { key: child.key };
  };

  for (let index = servicesAt[0].index + 1; index < entries.length; index += 1) {
    const entry = entries[index];
    if (entry.indent === 0) break;
    if (serviceIndent === null) serviceIndent = entry.indent;
    if (entry.indent < serviceIndent) break;

    // A line at or above the build block's own level ends that block; the entry is
    // then handled at the level it belongs to, still in this same pass.
    if (build !== null && entry.indent <= build.indent) closeBuild();

    if (entry.indent === serviceIndent) {
      const hidden = hiddenStructure(entry.text);
      if (hidden !== null) return ambiguous(hidden);
      const parsedKey = parseKey(entry.text);
      const name =
        parsedKey === null || parsedKey.rest.trim() !== "" ? null : parsedKey.key.trim();
      if (name === null || name === "") return ambiguous("unsupported-syntax");
      closeService();
      if (seenServices.has(name)) return ambiguous("duplicate-key");
      seenServices.add(name);
      service = name;
      continue;
    }

    if (service === null) continue;

    // Inside a build block: only its own first child level is read.
    if (build !== null) {
      if (build.childIndent === null) build.childIndent = entry.indent;
      if (entry.indent !== build.childIndent) continue;

      const hidden = hiddenStructure(entry.text);
      if (hidden !== null) return ambiguous(hidden);
      const child = readBuildChild(entry.text);
      if (child !== null && child.ambiguous !== undefined) return ambiguous(child.ambiguous);
      continue;
    }

    // The service's key level: the first line deeper than the service name. Anything
    // deeper than *that* belongs to a key this parser does not read (a `ports`
    // sequence, a nested `labels:` mapping, a `command: |` block) and is skipped,
    // which is why such a value can never be mistaken for a build key.
    if (keyIndent === null || entry.indent < keyIndent) keyIndent = entry.indent;
    if (entry.indent > keyIndent) continue;

    const hidden = hiddenStructure(entry.text);
    if (hidden !== null) return ambiguous(hidden);
    const parsedKey = parseKey(entry.text);
    if (parsedKey === null || parsedKey.key !== "build") continue;
    if (seenBuild) return ambiguous("duplicate-key");
    seenBuild = true;

    const scalar = parsePathScalar(parsedKey.rest);
    if (scalar.unsupported !== undefined) return ambiguous(scalar.unsupported);
    build = {
      indent: entry.indent,
      childIndent: null,
      context: scalar.value,
      dockerfile: null,
    };
  }
  closeService();

  return parsed(declarations);
}
