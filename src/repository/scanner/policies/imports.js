/**
 * Code Guardian — Import Acquisition Policy (Phase 16)
 *
 * A dependency-free, deterministic **tokenizer plus module-declaration scanner**
 * for JavaScript and TypeScript source.
 *
 * ### Why a tokenizer and not a regular expression
 *
 * The question this module answers is "which modules does this file reference?",
 * and the only honest way to answer it is to look at *code* rather than at *text*.
 * A pattern search over raw bytes cannot tell `import x from "./a"` from the same
 * characters inside a comment, a string, a template literal or a regular
 * expression, and it cannot tell `require("x")` from `foo.require("x")`. So this
 * module lexes the file into tokens first — strings, templates, regular
 * expressions and comments become single opaque tokens — and then scans the token
 * stream for module declarations. Text inside a comment or a string can therefore
 * never produce a reference, which is the property the whole graph depends on.
 *
 * ### What it extracts, exactly
 *
 *   static-import    `import a from "x"`, `import { a } from "x"`,
 *                    `import * as ns from "x"`, `import type { T } from "x"`,
 *                    `import "x"`
 *   export-from      `export { a } from "x"`, `export * from "x"`,
 *                    `export * as ns from "x"`, `export type { T } from "x"`
 *   require          `require("x")`, `require("x").thing`, and TypeScript's
 *                    `import x = require("x")`
 *   dynamic-import   `import("x")`
 *
 * and nothing else. Every other module-shaped expression is recorded as
 * **non-static** — counted, never guessed at:
 *
 *   computed-require         `require(name)`, `require(path.join(…))`
 *   concatenated-require     `require("a" + name)`
 *   computed-dynamic-import  `import(name)`
 *   template-specifier       ``require(`x`)``, ``import(`x`)``
 *   escaped-specifier        a specifier containing an escape the scanner cannot
 *                            decode into a path with certainty
 *
 * `import.meta`, `import.meta.resolve(…)`, `eval`, and any loader/alias mechanism
 * (tsconfig paths, webpack/Vite/Babel aliases) are deliberately invisible here:
 * they are not module *declarations*, and resolving them needs configuration this
 * layer must not read.
 *
 * A non-static reference is a **problem**, not a silent omission: it makes the
 * file's parse incomplete, which is what keeps a partially-understood import graph
 * from being reported as a complete one.
 *
 * ### What it does not do
 *
 * No symbol resolution, no type checking, no scope analysis, no shadowing
 * detection (a locally defined `require` is indistinguishable from CommonJS's
 * `require` by tokenizing alone — a documented limitation, not an oversight), no
 * path resolution (that is the model's job, against the observed inventory), no
 * process, no network, no clock, no filesystem.
 *
 * ### Determining a regular expression from a division
 *
 * `/` is ambiguous in JavaScript. The scanner uses the standard "previous
 * significant token" heuristic: after a token that can only end an expression
 * (`)`, `]`, `}`, `++`, `--`, an identifier, a number, a string or a template) a
 * `/` is division; otherwise it starts a regular expression. `}` is deliberately
 * treated as expression-ending, because the alternative mis-lexes an object
 * literal followed by division, and a mis-lexed *regular expression* is the more
 * dangerous of the two errors — it would let regular-expression text reach the
 * module scanner as if it were code. The heuristic's residual weakness (a regular
 * expression written immediately after `}`) is documented in the module header of
 * the Phase 16 report rather than hidden.
 *
 * Nothing in this file reads the filesystem, spawns a process, consults a clock or
 * the environment, or depends on any package. It is a pure function of the text it
 * is handed, which is what makes the import graph reproducible byte for byte.
 */

/** Module declaration kinds the scanner can establish. */
export const IMPORT_SPECIFIER_KINDS = Object.freeze({
  STATIC_IMPORT: "static-import",
  EXPORT_FROM: "export-from",
  REQUIRE: "require",
  DYNAMIC_IMPORT: "dynamic-import",
});

/** The kind vocabulary as a list, for validation. */
export const IMPORT_SPECIFIER_KIND_VALUES = Object.freeze(Object.values(IMPORT_SPECIFIER_KINDS));

/**
 * Why a module-shaped expression could not be established statically.
 *
 * Closed vocabulary. A reason is an identifier, never free text, so a hostile
 * specifier can never travel through this field.
 */
export const IMPORT_NON_STATIC_REASONS = Object.freeze({
  COMPUTED_REQUIRE: "computed-require",
  CONCATENATED_REQUIRE: "concatenated-require",
  COMPUTED_DYNAMIC_IMPORT: "computed-dynamic-import",
  TEMPLATE_SPECIFIER: "template-specifier",
  ESCAPED_SPECIFIER: "escaped-specifier",
});

/** The non-static reason vocabulary as a list, for validation. */
export const IMPORT_NON_STATIC_REASON_VALUES = Object.freeze(
  Object.values(IMPORT_NON_STATIC_REASONS),
);

/**
 * Problems that make a file's parse incomplete without discarding what was
 * established.
 *
 * Every one of these makes the file's own coverage incomplete (the model turns a
 * non-empty problem list into `partial`), because each means "this file may
 * reference modules we did not establish".
 */
export const IMPORT_PROBLEM_REASONS = Object.freeze({
  /** `import` with no clause and no specifier inside the bounded window. */
  UNTERMINATED_IMPORT_DECLARATION: "unterminated-import-declaration",
  /** A quoted string that reached a line terminator (invalid in JS/TS). */
  UNTERMINATED_STRING: "unterminated-string",
  /** A template literal that never closed, or nested past the depth bound. */
  UNTERMINATED_TEMPLATE: "unterminated-template",
  /** A block comment that never closed. */
  UNTERMINATED_COMMENT: "unterminated-comment",
  /** A `/` read as a regular expression that never closed. */
  UNTERMINATED_REGEX: "unterminated-regex",
  /** A character that cannot begin any token. Skipped, and reported. */
  UNLEXABLE_CHARACTER: "unlexable-character",
  /** The per-file token budget was reached; the tail of the file is unread. */
  TOKEN_LIMIT: "token-limit",
  /** The per-file reference budget was reached; later declarations are unread. */
  REFERENCE_LIMIT: "reference-limit",
  /** A module reference whose specifier is not a literal string. */
  NON_STATIC_SPECIFIER: "non-static-specifier",
});

/** The problem vocabulary as a list, for validation. */
export const IMPORT_PROBLEM_REASON_VALUES = Object.freeze(Object.values(IMPORT_PROBLEM_REASONS));

/**
 * Acquisition status of one module source file.
 *
 * `parsed` is the only status that yields references. The other three exist so an
 * unread file is never indistinguishable from a file that imports nothing —
 * `unsupported` (a format this build does not parse), `failed` (the bytes could
 * not be read or are not text) and `not-inspected` (a budget was spent before this
 * file was reached).
 */
export const IMPORT_SOURCE_STATUSES = Object.freeze({
  PARSED: "parsed",
  UNSUPPORTED: "unsupported",
  FAILED: "failed",
  NOT_INSPECTED: "not-inspected",
});

/** The source-status vocabulary as a list, for validation. */
export const IMPORT_SOURCE_STATUS_VALUES = Object.freeze(Object.values(IMPORT_SOURCE_STATUSES));

/**
 * Why a module source was not parsed. Closed vocabulary, one per status.
 *
 * The tokens deliberately match the Phase 13 dependency acquisition's own reasons
 * (`format-not-interpreted`, `manifest-could-not-be-read`, `not-text`,
 * `budget-exhausted`) so one consumer vocabulary covers both acquisition layers; a
 * contract test in `tests/import-graph.test.js` pins them together.
 */
export const IMPORT_SOURCE_REASONS = Object.freeze({
  /** The extension is a JavaScript-family module format this build does not parse. */
  FORMAT_NOT_INTERPRETED: "format-not-interpreted",
  /** The file could not be read (a classified filesystem condition). */
  UNREADABLE: "module-could-not-be-read",
  /** The file is not text (it contains a NUL byte in the inspected prefix). */
  NOT_TEXT: "not-text",
  /** A byte, file or token budget was exhausted before this source was read. */
  BUDGET_EXHAUSTED: "budget-exhausted",
});

/** The source-reason vocabulary as a list, for validation. */
export const IMPORT_SOURCE_REASON_VALUES = Object.freeze(Object.values(IMPORT_SOURCE_REASONS));

/**
 * Extensions this build parses, mapped to the language id the scanner reports.
 *
 * `.jsx` and `.tsx` are deliberately absent: JSX is a syntax this build does not
 * implement, so a JSX/TSX file is recorded as an *unsupported* module source rather
 * than parsed as if it were plain JavaScript. That distinction is what makes
 * "mixed JS + TSX" a `partial` graph instead of a silently wrong one.
 */
export const PARSED_MODULE_EXTENSIONS = Object.freeze({
  ".js": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".ts": "typescript",
  ".mts": "typescript",
  ".cts": "typescript",
});

/** JavaScript-family module formats recognized but not parsed. */
export const UNSUPPORTED_MODULE_EXTENSIONS = Object.freeze({
  ".jsx": "javascript",
  ".tsx": "typescript",
});

/** Every extension that is a module source for this graph (parsed or not). */
export const MODULE_FILE_EXTENSIONS = Object.freeze([
  ...Object.keys(PARSED_MODULE_EXTENSIONS),
  ...Object.keys(UNSUPPORTED_MODULE_EXTENSIONS),
]);

/**
 * Hard bounds on one scan's import acquisition.
 *
 * Every limit is declared and recorded on the result, so a bounded acquisition is
 * recognizable as bounded rather than mistaken for a complete one. Files are read
 * in the inventory's own sorted order, so which files fall inside the budget is
 * deterministic (the same repository always yields the same parsed set).
 */
export const IMPORT_ACQUISITION_LIMITS = Object.freeze({
  /** Module source files read in one scan. */
  maxFiles: 2000,
  /** Bytes read from any single module source. */
  maxFileBytes: 262144,
  /** Bytes read across all module sources in one scan. */
  maxTotalBytes: 33554432,
  /** Tokens lexed from any single module source. */
  maxTokensPerFile: 200000,
  /** Module references recorded from any single source. */
  maxReferencesPerFile: 512,
  /** Tokens a single import/export clause may span before it is abandoned. */
  maxClauseTokens: 64,
  /** Longest specifier text that may become a reference. */
  maxSpecifierLength: 512,
  /** Deepest template-substitution nesting the lexer will follow. */
  maxTemplateDepth: 8,
});

/** Whether an extension is a module source this scanner will look at. */
export function isModuleFileExtension(extension) {
  return MODULE_FILE_EXTENSIONS.includes(extension);
}

/**
 * The language id for a module source extension, or `null`.
 * @param {string} extension Lower-case extension including the dot.
 * @returns {string|null}
 */
export function moduleLanguageOf(extension) {
  return (
    PARSED_MODULE_EXTENSIONS[extension] ?? UNSUPPORTED_MODULE_EXTENSIONS[extension] ?? null
  );
}

/** Whether this build parses a module source extension. */
export function isParsedModuleExtension(extension) {
  return Object.prototype.hasOwnProperty.call(PARSED_MODULE_EXTENSIONS, extension);
}

// ── Character classification ─────────────────────────────────────────────────
//
// Explicit code-point tests rather than regular expressions: this module's whole
// purpose is to decide what is code and what is text, and it should not itself
// depend on pattern matching over raw text to do it.

function isIdentifierStart(code) {
  return (
    (code >= 97 && code <= 122) || // a-z
    (code >= 65 && code <= 90) || // A-Z
    code === 95 || // _
    code === 36 || // $
    code >= 0x80 // any non-ASCII code point: identifiers, never mis-read as syntax
  );
}

function isIdentifierPart(code) {
  return isIdentifierStart(code) || (code >= 48 && code <= 57);
}

function isDigit(code) {
  return code >= 48 && code <= 57;
}

function isSpace(code) {
  return (
    code === 32 ||
    code === 9 ||
    code === 11 ||
    code === 12 ||
    code === 0xa0 ||
    code === 0xfeff
  );
}

function isLineTerminator(code) {
  return code === 10 || code === 13 || code === 0x2028 || code === 0x2029;
}

/**
 * Punctuators, longest first.
 *
 * A single flat table: the longest match wins, and a character that appears in no
 * entry is an unlexable character (reported, skipped) rather than silently folded
 * into an identifier.
 */
const PUNCTUATORS = Object.freeze([
  ">>>=",
  "...",
  "===",
  "!==",
  "**=",
  "<<=",
  ">>=",
  "&&=",
  "||=",
  "??=",
  ">>>",
  "=>",
  "==",
  "!=",
  "<=",
  ">=",
  "&&",
  "||",
  "??",
  "?.",
  "++",
  "--",
  "+=",
  "-=",
  "*=",
  "/=",
  "%=",
  "&=",
  "|=",
  "^=",
  "**",
  "<<",
  ">>",
  "(",
  ")",
  "{",
  "}",
  "[",
  "]",
  ";",
  ",",
  "<",
  ">",
  "+",
  "-",
  "*",
  "/",
  "%",
  "&",
  "|",
  "^",
  "!",
  "~",
  "?",
  ":",
  "=",
  ".",
  "@",
  "#",
]);

const PUNCTUATOR_SET = new Set(PUNCTUATORS);
const MAX_PUNCTUATOR_LENGTH = 4;

/** Keywords after which a `/` can only begin a regular expression. */
const REGEX_ALLOWED_KEYWORDS = new Set([
  "return",
  "typeof",
  "instanceof",
  "in",
  "of",
  "new",
  "delete",
  "void",
  "throw",
  "case",
  "do",
  "else",
  "yield",
  "await",
  "default",
]);

/** Identifiers allowed inside an `import`/`export` clause (never statement starts). */
const CLAUSE_KEYWORDS = new Set(["as", "from", "type", "default", "namespace", "global"]);

/** Identifiers that begin a new statement, which ends a clause window. */
const STATEMENT_KEYWORDS = new Set([
  "const",
  "let",
  "var",
  "function",
  "class",
  "return",
  "if",
  "else",
  "for",
  "while",
  "switch",
  "try",
  "throw",
  "import",
  "export",
  "break",
  "continue",
  "do",
  "with",
  "yield",
  "await",
]);

/**
 * Tokens that continue an expression, which means a string followed by one of them
 * is not a plain specifier (`require("a" + b)`).
 *
 * Fail-closed by construction: anything in this set turns the reference into a
 * non-static one, which marks the file's parse incomplete rather than asserting a
 * module path the file did not literally state.
 */
const EXPRESSION_CONTINUATIONS = new Set([
  "+",
  "-",
  "*",
  "/",
  "%",
  "**",
  "==",
  "===",
  "!=",
  "!==",
  "<",
  ">",
  "<=",
  ">=",
  "&&",
  "||",
  "??",
  "&",
  "|",
  "^",
  "<<",
  ">>",
  ">>>",
  "?",
  ":",
  ",",
  "=",
  "=>",
  "+=",
  "-=",
  "*=",
  "/=",
  "%=",
  "instanceof",
  "in",
]);

// ── Low-level skips ──────────────────────────────────────────────────────────

/**
 * Skip a quoted string.
 * @returns {number} Index after the closing quote, or `-1` when unterminated.
 */
function skipQuoted(text, start, quoteCode) {
  let index = start + 1;
  while (index < text.length) {
    const code = text.charCodeAt(index);
    if (code === 92) {
      index += 2;
      continue;
    }
    if (code === quoteCode) return index + 1;
    if (isLineTerminator(code)) return -1;
    index += 1;
  }
  return -1;
}

/**
 * Skip a template literal, including nested templates inside substitutions.
 * @returns {number} Index after the closing backtick, or `-1` when unterminated.
 */
function skipTemplate(text, start, depth) {
  if (depth > IMPORT_ACQUISITION_LIMITS.maxTemplateDepth) return -1;
  let index = start + 1;
  while (index < text.length) {
    const code = text.charCodeAt(index);
    if (code === 92) {
      index += 2;
      continue;
    }
    if (code === 96) return index + 1;
    if (code === 36 && text.charCodeAt(index + 1) === 123) {
      index = skipSubstitution(text, index + 2, depth + 1);
      if (index < 0) return -1;
      continue;
    }
    index += 1;
  }
  return -1;
}

/**
 * Skip a `${ … }` substitution so brace counting stays inside the template.
 *
 * Strings, nested templates and comments are skipped properly, because a `}` inside
 * any of them would otherwise end the substitution early and let the rest of the
 * template be read as code.
 *
 * @returns {number} Index after the closing `}`, or `-1` when unterminated.
 */
function skipSubstitution(text, start, depth) {
  if (depth > IMPORT_ACQUISITION_LIMITS.maxTemplateDepth) return -1;
  let index = start;
  let braces = 1;
  while (index < text.length) {
    const code = text.charCodeAt(index);
    if (code === 92) {
      index += 2;
      continue;
    }
    if (code === 96) {
      const next = skipTemplate(text, index, depth);
      if (next < 0) return -1;
      index = next;
      continue;
    }
    if (code === 39 || code === 34) {
      const next = skipQuoted(text, index, code);
      if (next < 0) return -1;
      index = next;
      continue;
    }
    if (code === 47) {
      const next = text.charCodeAt(index + 1);
      if (next === 47) {
        const lineEnd = nextLineEnd(text, index);
        if (lineEnd < 0) return -1;
        index = lineEnd;
        continue;
      }
      if (next === 42) {
        const end = text.indexOf("*/", index + 2);
        if (end < 0) return -1;
        index = end + 2;
        continue;
      }
    }
    if (code === 123) {
      braces += 1;
      index += 1;
      continue;
    }
    if (code === 125) {
      braces -= 1;
      index += 1;
      if (braces === 0) return index;
      continue;
    }
    index += 1;
  }
  return -1;
}

/** Index just past the line terminator starting at or after `start`. */
function nextLineEnd(text, start) {
  let index = start;
  while (index < text.length) {
    if (isLineTerminator(text.charCodeAt(index))) {
      index += 1;
      if (text.charCodeAt(index) === 10) index += 1;
      return index;
    }
    index += 1;
  }
  return -1;
}

/** Skip a regular-expression literal body, character classes included. */
function skipRegex(text, start) {
  let index = start + 1;
  let inClass = false;
  while (index < text.length) {
    const code = text.charCodeAt(index);
    if (code === 92) {
      index += 2;
      continue;
    }
    if (isLineTerminator(code)) return -1;
    if (code === 91) inClass = true;
    else if (code === 93) inClass = false;
    else if (code === 47 && !inClass) return index + 1;
    index += 1;
  }
  return -1;
}

// ── Tokenizer ────────────────────────────────────────────────────────────────

/**
 * Whether a `/` after this token starts a regular expression.
 * @param {object|undefined} previous
 * @returns {boolean}
 */
function regexAllowedAfter(previous) {
  if (previous === undefined) return true;
  if (previous.type === "punct") {
    return !(
      previous.value === ")" ||
      previous.value === "]" ||
      previous.value === "}" ||
      previous.value === "++" ||
      previous.value === "--"
    );
  }
  if (previous.type === "identifier") return REGEX_ALLOWED_KEYWORDS.has(previous.value);
  return false;
}

/** Add a problem once. */
function note(problems, reason) {
  if (!problems.includes(reason)) problems.push(reason);
}

/**
 * Tokenize module source.
 *
 * @param {string} text Source text.
 * @param {object} [options]
 * @param {number} [options.maxTokens]
 * @returns {{ tokens: object[], problems: string[], truncated: boolean }}
 */
export function tokenizeModule(text, options = {}) {
  const maxTokens = options.maxTokens ?? IMPORT_ACQUISITION_LIMITS.maxTokensPerFile;
  const tokens = [];
  const problems = [];
  let truncated = false;
  let index = 0;

  while (index < text.length) {
    if (tokens.length >= maxTokens) {
      note(problems, IMPORT_PROBLEM_REASONS.TOKEN_LIMIT);
      truncated = true;
      break;
    }

    const code = text.charCodeAt(index);

    if (isSpace(code) || isLineTerminator(code)) {
      index += 1;
      continue;
    }

    // Comments.
    if (code === 47 && text.charCodeAt(index + 1) === 47) {
      const lineEnd = nextLineEnd(text, index);
      if (lineEnd < 0) {
        index = text.length;
        continue;
      }
      index = lineEnd;
      continue;
    }
    if (code === 47 && text.charCodeAt(index + 1) === 42) {
      const end = text.indexOf("*/", index + 2);
      if (end < 0) {
        note(problems, IMPORT_PROBLEM_REASONS.UNTERMINATED_COMMENT);
        truncated = true;
        break;
      }
      index = end + 2;
      continue;
    }

    // Strings.
    if (code === 39 || code === 34) {
      const end = skipQuoted(text, index, code);
      if (end < 0) {
        note(problems, IMPORT_PROBLEM_REASONS.UNTERMINATED_STRING);
        index = text.length;
        continue;
      }
      tokens.push({ type: "string", value: text.slice(index + 1, end - 1), quote: code });
      index = end;
      continue;
    }

    // Templates: one opaque token, whether or not they substitute.
    if (code === 96) {
      const end = skipTemplate(text, index, 0);
      if (end < 0) {
        note(problems, IMPORT_PROBLEM_REASONS.UNTERMINATED_TEMPLATE);
        index = text.length;
        continue;
      }
      const body = text.slice(index + 1, end - 1);
      tokens.push({ type: "template", value: body, computed: body.includes("${") });
      index = end;
      continue;
    }

    // Numbers.
    if (isDigit(code) || (code === 46 && isDigit(text.charCodeAt(index + 1)))) {
      let end = index;
      while (end < text.length) {
        const part = text.charCodeAt(end);
        const isExponentSign =
          (part === 43 || part === 45) &&
          (text.charCodeAt(end - 1) === 101 || text.charCodeAt(end - 1) === 69);
        if (isIdentifierPart(part) || part === 46 || isExponentSign) end += 1;
        else break;
      }
      tokens.push({ type: "number", value: text.slice(index, end) });
      index = end;
      continue;
    }

    // Identifiers (keywords included; the scanner decides what a word means).
    if (isIdentifierStart(code)) {
      let end = index + 1;
      while (end < text.length && isIdentifierPart(text.charCodeAt(end))) end += 1;
      tokens.push({ type: "identifier", value: text.slice(index, end) });
      index = end;
      continue;
    }

    // Punctuators, or a regular expression.
    if (code === 47) {
      if (regexAllowedAfter(tokens[tokens.length - 1])) {
        const end = skipRegex(text, index);
        if (end < 0) {
          note(problems, IMPORT_PROBLEM_REASONS.UNTERMINATED_REGEX);
          index = text.length;
          continue;
        }
        tokens.push({ type: "regex", value: "" });
        index = end;
        continue;
      }
      tokens.push({ type: "punct", value: "/" });
      index += 1;
      continue;
    }

    let matched = null;
    for (let length = MAX_PUNCTUATOR_LENGTH; length >= 1; length -= 1) {
      const candidate = text.slice(index, index + length);
      if (PUNCTUATOR_SET.has(candidate)) {
        matched = candidate;
        break;
      }
    }
    if (matched !== null) {
      tokens.push({ type: "punct", value: matched });
      index += matched.length;
      continue;
    }

    note(problems, IMPORT_PROBLEM_REASONS.UNLEXABLE_CHARACTER);
    index += 1;
  }

  return { tokens, problems, truncated };
}

// ── Module declaration scanning ──────────────────────────────────────────────

/** A reference's specifier is usable only when it is bounded, printable text. */
function decodeSpecifier(token) {
  const body = token.value;
  if (body === "") return { ok: false, reason: IMPORT_NON_STATIC_REASONS.ESCAPED_SPECIFIER };
  return { ok: true, specifier: body };
}

/**
 * Scan an `import` clause window for its specifier.
 *
 * The window is bounded, and it abandons as soon as a token appears that cannot be
 * part of a clause — so a malformed or hostile declaration costs a bounded amount
 * of work and produces a problem rather than a fabricated reference.
 */
function scanImportClause(tokens, start) {
  const limit = Math.min(tokens.length, start + IMPORT_ACQUISITION_LIMITS.maxClauseTokens);
  let depth = 0;
  let sawClause = false;

  for (let index = start; index < limit; index += 1) {
    const token = tokens[index];

    if (token.type === "string") {
      const previous = tokens[index - 1];
      const afterFrom =
        previous !== undefined && previous.type === "identifier" && previous.value === "from";
      if (depth === 0 && (afterFrom || (!sawClause && index === start))) {
        return { specifier: token };
      }
      return { specifier: null };
    }

    if (token.type === "template" || token.type === "regex" || token.type === "number") {
      return { specifier: null };
    }

    if (token.type === "punct") {
      if (token.value === "{" || token.value === "}") {
        depth += token.value === "{" ? 1 : -1;
        if (depth < 0) return { specifier: null };
        continue;
      }
      if (token.value === "," || token.value === "*") {
        sawClause = true;
        continue;
      }
      return { specifier: null };
    }

    // Identifier: a clause keyword, a binding name, or the end of the declaration.
    if (CLAUSE_KEYWORDS.has(token.value)) continue;
    if (depth > 0) continue;
    if (STATEMENT_KEYWORDS.has(token.value)) return { specifier: null };
    sawClause = true;
  }

  return { specifier: null };
}

/** Scan an `export` clause window for a `from "…"` re-export. */
function scanExportClause(tokens, start) {
  const limit = Math.min(tokens.length, start + IMPORT_ACQUISITION_LIMITS.maxClauseTokens);
  let depth = 0;

  for (let index = start; index < limit; index += 1) {
    const token = tokens[index];

    if (token.type === "identifier") {
      if (token.value === "from") {
        const next = tokens[index + 1];
        if (next !== undefined && next.type === "string") return { specifier: next };
        return { specifier: null };
      }
      if (depth === 0 && STATEMENT_KEYWORDS.has(token.value)) return { specifier: null };
      continue;
    }

    if (token.type === "punct") {
      if (token.value === "{") {
        depth += 1;
        continue;
      }
      if (token.value === "}") {
        depth -= 1;
        if (depth < 0) return { specifier: null };
        continue;
      }
      if (depth === 0 && [";", "=", "(", ")"].includes(token.value)) return { specifier: null };
      continue;
    }

    // A string/template/regex/number at clause level ends the re-export search.
    return { specifier: null };
  }

  return { specifier: null };
}

/** Parse a `require(…)` / `import(…)` argument list from the token after `(`. */
function scanCallArgument(tokens, openIndex, dynamic) {
  const first = tokens[openIndex + 1];
  const computed = dynamic
    ? IMPORT_NON_STATIC_REASONS.COMPUTED_DYNAMIC_IMPORT
    : IMPORT_NON_STATIC_REASONS.COMPUTED_REQUIRE;
  const concatenated = dynamic
    ? IMPORT_NON_STATIC_REASONS.COMPUTED_DYNAMIC_IMPORT
    : IMPORT_NON_STATIC_REASONS.CONCATENATED_REQUIRE;

  if (first === undefined) return { specifier: null, reason: computed };
  if (first.type === "template") {
    return { specifier: null, reason: IMPORT_NON_STATIC_REASONS.TEMPLATE_SPECIFIER };
  }
  if (first.type !== "string") return { specifier: null, reason: computed };

  const after = tokens[openIndex + 2];
  if (after === undefined) return { specifier: null, reason: computed };
  if (after.type === "punct" && after.value === "+") {
    return { specifier: null, reason: concatenated };
  }
  if (after.type === "punct" && EXPRESSION_CONTINUATIONS.has(after.value)) {
    return { specifier: null, reason: computed };
  }
  if (after.type === "identifier" && EXPRESSION_CONTINUATIONS.has(after.value)) {
    return { specifier: null, reason: computed };
  }
  return { specifier: first, reason: null };
}

/** Skip a `declare module "…" { … }` body, which declares no module reference. */
function skipDeclareModuleBody(tokens, start) {
  let depth = 0;
  let opened = false;
  const limit = tokens.length;
  for (let index = start; index < limit; index += 1) {
    const token = tokens[index];
    if (token.type !== "punct") continue;
    if (token.value === "{") {
      depth += 1;
      opened = true;
      continue;
    }
    if (token.value === "}") {
      depth -= 1;
      if (opened && depth <= 0) return index + 1;
    }
  }
  return limit;
}

/**
 * Extract the module references from source text.
 *
 * @param {string} text Source text of one module file.
 * @param {object} [options]
 * @param {string} [options.extension] Lower-case extension including the dot.
 * @returns {{ references: Array<{kind: string, specifier: string}>,
 *   nonStatic: Array<{kind: string|null, reason: string}>,
 *   problems: string[], truncated: boolean, tokens: number }}
 */
export function parseModuleReferences(text, options = {}) {
  const extension = options.extension ?? "";
  const isTypeScript = extension === ".ts" || extension === ".mts" || extension === ".cts";
  const { tokens, problems, truncated: lexTruncated } = tokenizeModule(text, options);

  const references = [];
  const nonStatic = [];
  const limits = IMPORT_ACQUISITION_LIMITS;
  const resolvedProblems = new Set(problems);
  let truncated = lexTruncated;

  const recordNonStatic = (kind, reason) => {
    nonStatic.push({ kind, reason });
    resolvedProblems.add(IMPORT_PROBLEM_REASONS.NON_STATIC_SPECIFIER);
  };

  const recordReference = (kind, specifierToken) => {
    if (references.length + nonStatic.length >= limits.maxReferencesPerFile) {
      resolvedProblems.add(IMPORT_PROBLEM_REASONS.REFERENCE_LIMIT);
      truncated = true;
      return false;
    }
    if (specifierToken.value.length > limits.maxSpecifierLength) {
      recordNonStatic(kind, IMPORT_NON_STATIC_REASONS.ESCAPED_SPECIFIER);
      return true;
    }
    const decoded = decodeSpecifier(specifierToken);
    if (!decoded.ok) {
      recordNonStatic(kind, decoded.reason);
      return true;
    }
    references.push({ kind, specifier: decoded.specifier });
    return true;
  };

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token.type !== "identifier") continue;

    const previous = tokens[index - 1];
    const precededByMember =
      previous !== undefined &&
      previous.type === "punct" &&
      (previous.value === "." || previous.value === "?.");

    if (token.value === "require" && !precededByMember) {
      const next = tokens[index + 1];
      if (next === undefined || next.type !== "punct" || next.value !== "(") continue;
      const parsed = scanCallArgument(tokens, index + 1, false);
      if (parsed.specifier === null) recordNonStatic(IMPORT_SPECIFIER_KINDS.REQUIRE, parsed.reason);
      else if (!recordReference(IMPORT_SPECIFIER_KINDS.REQUIRE, parsed.specifier)) break;
      continue;
    }

    if (token.value === "import" && !precededByMember) {
      const next = tokens[index + 1];
      if (next === undefined) continue;

      // `import.meta`, `import.meta.resolve(…)`: not a module declaration.
      if (next.type === "punct" && (next.value === "." || next.value === "?.")) continue;

      // `import("x")`
      if (next.type === "punct" && next.value === "(") {
        const parsed = scanCallArgument(tokens, index + 1, true);
        if (parsed.specifier === null) {
          recordNonStatic(IMPORT_SPECIFIER_KINDS.DYNAMIC_IMPORT, parsed.reason);
        } else if (!recordReference(IMPORT_SPECIFIER_KINDS.DYNAMIC_IMPORT, parsed.specifier)) {
          break;
        }
        continue;
      }

      // `import x = require("x")` (TypeScript import-equals): the `require` call
      // itself is the declaration, and the scan reaches it on its own.
      if (
        isTypeScript &&
        next.type === "identifier" &&
        tokens[index + 2] !== undefined &&
        tokens[index + 2].type === "punct" &&
        tokens[index + 2].value === "="
      ) {
        continue;
      }

      // Only a clause, a `{`, a `*` or a specifier string can follow a static
      // import. Anything else is this word being used as a name, not a
      // declaration, and must not be reported as a malformed one.
      const clauseStart =
        next.type === "identifier" ||
        next.type === "string" ||
        (next.type === "punct" && (next.value === "{" || next.value === "*"));
      if (!clauseStart) continue;

      const scanned = scanImportClause(tokens, index + 1);
      if (scanned.specifier === null) {
        resolvedProblems.add(IMPORT_PROBLEM_REASONS.UNTERMINATED_IMPORT_DECLARATION);
        continue;
      }
      if (!recordReference(IMPORT_SPECIFIER_KINDS.STATIC_IMPORT, scanned.specifier)) break;
      continue;
    }

    if (token.value === "export" && !precededByMember) {
      const next = tokens[index + 1];
      if (next === undefined) continue;
      const clauseStart =
        next.type === "identifier" ||
        (next.type === "punct" && (next.value === "{" || next.value === "*"));
      if (!clauseStart) continue;
      const scanned = scanExportClause(tokens, index + 1);
      if (scanned.specifier === null) continue;
      if (!recordReference(IMPORT_SPECIFIER_KINDS.EXPORT_FROM, scanned.specifier)) break;
      continue;
    }

    if (isTypeScript && token.value === "declare") {
      const next = tokens[index + 1];
      const after = tokens[index + 2];
      if (
        next !== undefined &&
        next.type === "identifier" &&
        next.value === "module" &&
        after !== undefined &&
        after.type === "string"
      ) {
        index = skipDeclareModuleBody(tokens, index + 2) - 1;
      }
    }
  }

  return {
    references,
    nonStatic,
    problems: [...resolvedProblems].sort(),
    truncated,
    tokens: tokens.length,
  };
}

/**
 * Whether a reference's specifier is usable by the resolver.
 *
 * Bounded, printable, non-empty text. A specifier containing a control character
 * cannot become a path or reach an error message.
 *
 * @param {unknown} specifier
 * @returns {boolean}
 */
export function isUsableSpecifier(specifier) {
  if (typeof specifier !== "string" || specifier === "") return false;
  if (specifier.length > IMPORT_ACQUISITION_LIMITS.maxSpecifierLength) return false;
  for (let index = 0; index < specifier.length; index += 1) {
    const code = specifier.charCodeAt(index);
    if (code < 0x20 || code === 0x7f) return false;
  }
  return true;
}
