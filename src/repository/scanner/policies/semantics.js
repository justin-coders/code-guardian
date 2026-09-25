/**
 * Code Guardian — Symbol & Call Acquisition Policy (Phase 17)
 *
 * A dependency-free, deterministic **structural scanner** that records the
 * source-level facts a semantic graph can be built from: declarations, import
 * bindings, exports, references and call *sites*.
 *
 * ### First, the honest boundary: there is no AST parser in this repository
 *
 * Phase 17 asked for a trustworthy semantic substrate and stated a hard gate: a
 * name-based approximation (`foo()` → "a symbol named `foo`") is **not** a resolved
 * call graph, and where reliable lexical scope and symbol identity cannot be
 * established the syntax observation must be kept while the semantic target is
 * marked unresolved.
 *
 * This repository has no JavaScript/TypeScript parser. `package.json` declares no
 * runtime dependency and every phase since 8A has kept it that way; the candidates
 * (the TypeScript compiler, Babel, acorn, tree-sitter) are either the project's
 * first runtime dependency or explicitly outside the boundary this phase restates.
 * A hand-written *grammar* for JS+TS would be the "syntactic approximation
 * presented as semantic certainty" the gate forbids: TypeScript alone (`as` casts,
 * generics, decorators, enums, namespaces, overloads, `satisfies`) makes a
 * partly-correct parser mis-attribute scope, and a mis-attributed scope fabricates
 * a reference.
 *
 * So this module builds the **smallest thing that can be proven** on top of the
 * lexer Phase 16 already ships:
 *
 *   - **Symbol nodes are module-scope name bindings.** A declaration counts as
 *     module scope only when the lexer can prove the token is at the top level of
 *     the module — no enclosing brace, bracket or paren group at all. A `const`
 *     inside a `for (…)`, a function body, a class body, an object literal or a
 *     namespace is therefore never a module-scope symbol.
 *   - **A reference resolves only when the name is *file-unique*.** The scanner
 *     computes a deliberately over-inclusive set of *possible binding positions*
 *     (see §Binding superset); if the name occurs anywhere in the file in a
 *     position that could be a binding other than its own module-scope
 *     declaration, the name is marked `shadowed` and **no** resolution is claimed
 *     for it. Uniqueness is a proof obligation, not a heuristic ordering: if the
 *     only thing a name can denote is its module-scope binding, then every
 *     non-binding occurrence of it denotes that binding — including occurrences
 *     inside function bodies, which is where real code lives.
 *   - **Nothing is resolved by name similarity, and no scope tree is invented.**
 *
 * ### Fail-closed, and what that costs
 *
 * Every rule below is biased toward *not* claiming. A construct the scanner does
 * not interpret produces a **problem** and the file's corresponding establishment
 * flag goes false, so the projection withholds that class of edge for the file
 * instead of guessing. Two examples carry most of the weight:
 *
 *   - `eval` and `with` can introduce a binding into an enclosing scope at
 *     runtime, which destroys every uniqueness proof in the file. A file that
 *     contains either has `resolutionEstablished: false` and contributes **no**
 *     reference or call edge, while still contributing its declarations, which
 *     remain syntactic facts.
 *   - A lexical failure (an unterminated string/template/regex/comment, an
 *     unlexable character, the token budget, unbalanced groups) means the scanner
 *     cannot be sure what is code. Such a file contributes **nothing** — no symbol
 *     and no edge — because a token believed to be at module scope may not be.
 *
 * ### Documented limits, stated where they are implemented
 *
 *   - **One declarator per statement.** `const a = 1, b = 2` records `a` and
 *     reports `unsupported-declarator`; following the comma would need statement
 *     boundaries the tokenizer does not expose, and guessing would fabricate a
 *     symbol out of a later sequence expression such as `foo, bar = 1`.
 *   - **CommonJS exports are not read.** `module.exports` / `exports.x` is a module
 *     system this build does not interpret, so a file using it records
 *     `commonjs-module-form` and `exportsEstablished: false`: a `require` binding's
 *     target is never claimed.
 *   - **Nested scopes are not modelled.** A name bound anywhere the superset can see
 *     — a parameter, a pattern, a `catch` target, a nested declaration — makes that
 *     *name* unresolvable rather than resolved to the wrong binding.
 *   - **Method calls, callbacks, computed calls and every runtime dispatch stay
 *     unresolved.** `a.b()` is never a call edge.
 *
 * ### What it records, exactly
 *
 *   declarations   module-scope bindings: `function`, `class`, `const`/`let`/`var`
 *                  (simple names and destructuring patterns), TypeScript
 *                  `interface` / `type` / `enum` / `namespace`, and import bindings
 *                  (named / default / namespace / `import x = require(…)`).
 *   exports        named clauses with `as` aliases, `export default`, `export *`,
 *                  re-exports, each with the specifier when the source states one.
 *   references     occurrence *counts* per `(name, form)` pair, where form is
 *                  `reference`, `call` or `construct`. Counts only: the lexer records
 *                  no positions, and a fabricated line number would be provenance
 *                  that does not exist.
 *
 * ### Binding superset (the soundness rule, stated as a rule)
 *
 * An identifier token is flagged as a possible binding when any of these holds.
 * Each is a *superset*: a construct the scanner mis-classifies can only cost
 * coverage, never soundness.
 *
 *   - it follows `const`, `let`, `var`, `function`, `class`, `import`, `catch`,
 *     `declare`, `interface`, `enum`, `namespace`, `type`, `as`, or a `function`'s
 *     `*`;
 *   - it is a paren-less arrow parameter (followed by `=>`);
 *   - it is a TypeScript type parameter (`<T>`, `<T, U>`);
 *   - it sits anywhere inside a group the scanner recognizes as a *parameter list*
 *     (a paren group after `function`/`catch`, followed by `=>`, or followed by a
 *     `{` body — over-inclusive on purpose, so `if (x) {` costs coverage rather
 *     than correctness) or inside a *binding pattern* (`{ … }` / `[ … ]` after
 *     `const`/`let`/`var`, in parameter position, or nested in another pattern).
 *
 * A name is unique when every position flagged for it is one of its own
 * module-scope declaration positions.
 *
 * ### What it deliberately does not do
 *
 * No scope tree, no symbol table, no type checker, no type resolution, no property
 * or method resolution, no closure analysis, no alias/`tsconfig` reading, no source
 * transformation, no process, no network, no clock, no environment, no filesystem.
 * Nothing here reads the filesystem, spawns a process, consults a clock or the
 * environment, or depends on a package: it is a pure function of the text it is
 * handed, which is what makes the resulting graph reproducible byte for byte.
 */

import {
  IMPORT_ACQUISITION_LIMITS,
  IMPORT_PROBLEM_REASONS,
  MODULE_FILE_EXTENSIONS,
  PARSED_MODULE_EXTENSIONS,
  UNSUPPORTED_MODULE_EXTENSIONS,
  isModuleFileExtension,
  isParsedModuleExtension,
  isUsableSpecifier,
  moduleLanguageOf,
  tokenizeModule,
} from "./imports.js";

/**
 * The kinds of module-scope name binding this build can establish.
 *
 * `imported-binding` is one of them because an import clause genuinely binds a
 * module-scope name; what the binding *points at* is a separate question, resolved
 * later and only where the repository can establish it.
 */
export const SYMBOL_KINDS = Object.freeze({
  FUNCTION: "function",
  CLASS: "class",
  VARIABLE: "variable",
  INTERFACE: "interface",
  TYPE_ALIAS: "type-alias",
  ENUM: "enum",
  NAMESPACE: "namespace",
  IMPORTED_BINDING: "imported-binding",
});

/** The declaration-kind vocabulary as a list, for validation. */
export const SYMBOL_KIND_VALUES = Object.freeze(Object.values(SYMBOL_KINDS));

/** How an imported binding was declared. */
export const SYMBOL_BINDING_KINDS = Object.freeze({
  DEFAULT: "default",
  NAMED: "named",
  NAMESPACE: "namespace",
  REQUIRE: "require",
});

/** The binding-kind vocabulary as a list, for validation. */
export const SYMBOL_BINDING_KIND_VALUES = Object.freeze(Object.values(SYMBOL_BINDING_KINDS));

/** How a file exposes a name. */
export const SYMBOL_EXPORT_FORMS = Object.freeze({
  NAMED: "named",
  DEFAULT: "default",
  STAR: "star",
  RE_EXPORT: "reexport",
});

/** The export-form vocabulary as a list, for validation. */
export const SYMBOL_EXPORT_FORM_VALUES = Object.freeze(Object.values(SYMBOL_EXPORT_FORMS));

/** The syntactic form of one recorded occurrence. */
export const SYMBOL_OCCURRENCE_FORMS = Object.freeze({
  REFERENCE: "reference",
  CALL: "call",
  CONSTRUCT: "construct",
});

/** The occurrence-form vocabulary as a list, for validation. */
export const SYMBOL_OCCURRENCE_FORM_VALUES = Object.freeze(Object.values(SYMBOL_OCCURRENCE_FORMS));

/**
 * Problems that make part of a file's semantics unestablished.
 *
 * The vocabulary is closed and every value is an identifier, so no source text — an
 * identifier, a specifier, a keyword — can travel through a problem field.
 */
export const SEMANTIC_PROBLEMS = Object.freeze({
  /** Lexical: the declaration set cannot be trusted (see §Lexical problems). */
  UNTERMINATED_STRING: "unterminated-string",
  UNTERMINATED_TEMPLATE: "unterminated-template",
  UNTERMINATED_COMMENT: "unterminated-comment",
  UNTERMINATED_REGEX: "unterminated-regex",
  UNLEXABLE_CHARACTER: "unlexable-character",
  TOKEN_LIMIT: "token-limit",
  /** The token stream ends inside a group, so brace depth is not trustworthy. */
  UNBALANCED_GROUPS: "unbalanced-groups",
  /** More module-scope declarations than the per-file bound. */
  DECLARATION_LIMIT: "declaration-limit",
  /** More distinct referenced names than the per-file bound. */
  REFERENCE_LIMIT: "reference-limit",
  /** More exports than the per-file bound. */
  EXPORT_LIMIT: "export-limit",
  /** `eval` or `with`: dynamic scope destroys every uniqueness proof. */
  DYNAMIC_SCOPE_CONSTRUCT: "dynamic-scope-construct",
  /** An export whose local binding cannot be named (a default expression). */
  ANONYMOUS_DEFAULT_EXPORT: "anonymous-default-export",
  /** An export form this build does not interpret (`export =`). */
  UNSUPPORTED_EXPORT_FORM: "unsupported-export-form",
  /** A declarator whose binding shape this build does not interpret. */
  UNSUPPORTED_DECLARATOR: "unsupported-declarator",
  /** An export clause that never reached its end inside the bound. */
  UNTERMINATED_EXPORT_CLAUSE: "unterminated-export-clause",
  /** `module.exports` / `exports.x`: a module system this build does not read. */
  COMMONJS_MODULE_FORM: "commonjs-module-form",
});

/** The problem vocabulary as a list, for validation. */
export const SEMANTIC_PROBLEM_VALUES = Object.freeze(Object.values(SEMANTIC_PROBLEMS));

/**
 * The problems that make the *declaration set* untrustworthy.
 *
 * Each means the lexer could not decide what is code, so a token the scanner
 * believes is at module scope may not be at module scope — the one error that
 * fabricates a symbol. A file carrying any of these contributes no symbol and no
 * edge; it is reported as unestablished instead.
 */
export const SEMANTIC_LEXICAL_PROBLEMS = Object.freeze([
  SEMANTIC_PROBLEMS.UNTERMINATED_STRING,
  SEMANTIC_PROBLEMS.UNTERMINATED_TEMPLATE,
  SEMANTIC_PROBLEMS.UNTERMINATED_COMMENT,
  SEMANTIC_PROBLEMS.UNTERMINATED_REGEX,
  SEMANTIC_PROBLEMS.UNLEXABLE_CHARACTER,
  SEMANTIC_PROBLEMS.TOKEN_LIMIT,
  SEMANTIC_PROBLEMS.UNBALANCED_GROUPS,
]);

/** Acquisition status of one module source. The same vocabulary Phase 16 uses. */
export const SEMANTIC_SOURCE_STATUSES = Object.freeze({
  PARSED: "parsed",
  UNSUPPORTED: "unsupported",
  FAILED: "failed",
  NOT_INSPECTED: "not-inspected",
});

/** The source-status vocabulary as a list, for validation. */
export const SEMANTIC_SOURCE_STATUS_VALUES = Object.freeze(Object.values(SEMANTIC_SOURCE_STATUSES));

/** Why a module source was not scanned. Tokens shared with Phase 16, on purpose. */
export const SEMANTIC_SOURCE_REASONS = Object.freeze({
  FORMAT_NOT_INTERPRETED: "format-not-interpreted",
  UNREADABLE: "module-could-not-be-read",
  NOT_TEXT: "not-text",
  BUDGET_EXHAUSTED: "budget-exhausted",
});

/** The source-reason vocabulary as a list, for validation. */
export const SEMANTIC_SOURCE_REASON_VALUES = Object.freeze(Object.values(SEMANTIC_SOURCE_REASONS));

/** Extensions this build scans: the same closed sets Phase 16 parses. */
export const SEMANTIC_PARSED_EXTENSIONS = PARSED_MODULE_EXTENSIONS;
export const SEMANTIC_UNSUPPORTED_EXTENSIONS = UNSUPPORTED_MODULE_EXTENSIONS;
export const SEMANTIC_MODULE_EXTENSIONS = MODULE_FILE_EXTENSIONS;

/**
 * Hard bounds on one scan's symbol acquisition.
 *
 * Everything is bounded and every bound that bites is recorded, so a bounded scan
 * is recognizable as bounded rather than mistaken for a complete one. Files are read
 * in the inventory's own sorted order, so which files fall inside the budget is
 * deterministic.
 */
export const SEMANTIC_ACQUISITION_LIMITS = Object.freeze({
  /** Module source files read in one scan. */
  maxFiles: 2000,
  /** Bytes read from any single module source. */
  maxFileBytes: IMPORT_ACQUISITION_LIMITS.maxFileBytes,
  /** Bytes read across all module sources in one scan. */
  maxTotalBytes: IMPORT_ACQUISITION_LIMITS.maxTotalBytes,
  /** Tokens lexed from any single module source. */
  maxTokensPerFile: IMPORT_ACQUISITION_LIMITS.maxTokensPerFile,
  /** Module-scope declarations recorded from any single source. */
  maxDeclarationsPerFile: 512,
  /** Exports recorded from any single source. */
  maxExportsPerFile: 512,
  /** Distinct referenced names recorded from any single source. */
  maxReferencedNamesPerFile: 2048,
  /** Tokens a single import/export clause may span before it is abandoned. */
  maxClauseTokens: IMPORT_ACQUISITION_LIMITS.maxClauseTokens,
  /** Longest binding name that may become a symbol identity. */
  maxNameLength: 256,
  /** Deepest binding-pattern nesting the scanner will follow. */
  maxPatternDepth: 8,
  /** Specifier text that may be recorded on an import binding. */
  maxSpecifierLength: IMPORT_ACQUISITION_LIMITS.maxSpecifierLength,
});

/** Whether an extension is a module source this scanner will look at. */
export function isSemanticModuleExtension(extension) {
  return isModuleFileExtension(extension);
}

export { isModuleFileExtension, isParsedModuleExtension, moduleLanguageOf };

// ── Token classification tables ──────────────────────────────────────────────

const OPENERS = new Set(["(", "[", "{"]);
const CLOSERS = new Set([")", "]", "}"]);

/**
 * Keywords that can never be a symbol name, a reference or a call target.
 *
 * A missing keyword could only cost coverage (a name spelled like one), never
 * fabricate a reference, because a module-scope binding cannot be named after a
 * keyword.
 */
const RESERVED_WORDS = new Set([
  "await", "break", "case", "catch", "class", "const", "continue", "debugger",
  "default", "delete", "do", "else", "enum", "export", "extends", "false",
  "finally", "for", "function", "if", "import", "in", "instanceof", "let", "new",
  "null", "of", "return", "static", "super", "switch", "this", "throw", "true",
  "try", "typeof", "var", "void", "while", "with", "yield",
]);

/**
 * Tokens after which a `function`/`class` token cannot begin a declaration.
 *
 * A closed superset of expression positions. `const f = function g() {}` puts `g`
 * in the function expression's own scope, not the module's, so reading `g` as a
 * module-scope binding would fabricate a symbol — and every token in this set means
 * the following `function`/`class` is being used as an expression. Statements that
 * follow each other through automatic semicolon insertion are deliberately *not*
 * in this set (`}\nfunction f() {}` and `1\nfunction f() {}` are ordinary
 * module-scope declarations).
 */
const EXPRESSION_PREFIXES = new Set([
  "=", "=>", ",", ":", "(", "[", ".", "?.", "+", "-", "*", "/", "%", "**", "&",
  "|", "^", "!", "~", "?", "<", ">", "<=", ">=", "==", "===", "!=", "!==", "&&",
  "||", "??", "...", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<", ">>",
  ">>>", "return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
  "throw", "yield", "extends", "satisfies",
]);

/** Group openers after which a paren group binds parameters even without `=>`. */
const PARAMETER_LIST_OPENERS = new Set(["function", "catch"]);

/**
 * Keywords whose paren group is *not* a parameter list.
 *
 * `if (x) {`, `while (x) {`, `for (…)` and `switch (x) {` all end in a `{` body,
 * which is exactly why they have to be excluded explicitly rather than inferred
 * from the shape of the group.
 */
const CONTROL_KEYWORDS = new Set([
  "if", "while", "for", "switch", "with", "return", "typeof", "new", "delete",
  "void", "in", "of", "case", "do", "else", "await", "yield", "instanceof",
]);

/** Keywords a `const`/`let`/`var` binding list can start. */
const DECLARATION_KEYWORDS = new Set(["const", "let", "var"]);

/**
 * Contextual keywords, which are not occurrences.
 *
 * Each is an ordinary identifier in JavaScript, so a module-scope binding could
 * legitimately be called `get` or `as`. Reading `get` in `get foo() {}` as a
 * *reference* to such a binding would be a fabricated edge, so these words are
 * skipped as occurrences and the (vanishingly unlikely) binding is left unresolved
 * instead. They are still read as bindings — `import { a as b }` and `const get = 1`
 * are handled before this test — because a binding position is a separate question.
 */
const CONTEXTUAL_KEYWORDS = new Set([
  "as",
  "async",
  "from",
  "get",
  "set",
  "of",
  "satisfies",
  "declare",
  "abstract",
  "readonly",
  "infer",
  "keyof",
  "is",
]);

/** TypeScript declaration keywords that introduce a named binding. */
const TS_NAMED_DECLARATIONS = new Set(["interface", "enum", "namespace"]);

/** Literal keyword initializers that are certainly not function values. */
const NON_FUNCTION_KEYWORDS = new Set(["true", "false", "null", "undefined"]);

/** Note a problem once, whether the collection is a Set or an array. */
function note(problems, reason) {
  if (typeof problems.add === "function") {
    problems.add(reason);
    return;
  }
  if (!problems.includes(reason)) problems.push(reason);
}

/** The lexer problems that are lexical failures for this scanner too. */
const IMPORT_LEXICAL_PROBLEMS = Object.freeze([
  IMPORT_PROBLEM_REASONS.UNTERMINATED_STRING,
  IMPORT_PROBLEM_REASONS.UNTERMINATED_TEMPLATE,
  IMPORT_PROBLEM_REASONS.UNTERMINATED_COMMENT,
  IMPORT_PROBLEM_REASONS.UNTERMINATED_REGEX,
  IMPORT_PROBLEM_REASONS.UNLEXABLE_CHARACTER,
  IMPORT_PROBLEM_REASONS.TOKEN_LIMIT,
]);

/** A name that may become a symbol identity: bounded identifier text. */
export function isUsableSymbolName(name) {
  if (typeof name !== "string" || name === "") return false;
  if (name.length > SEMANTIC_ACQUISITION_LIMITS.maxNameLength) return false;
  for (let index = 0; index < name.length; index += 1) {
    const code = name.charCodeAt(index);
    if (code < 0x20 || code === 0x7f) return false;
  }
  return true;
}

// ── Group classification ─────────────────────────────────────────────────────

/**
 * Match every bracket group and classify it.
 *
 * Produces, for each token index, the innermost group enclosing it; and for each
 * opener the group itself with the two facts the scanner needs — whether its
 * contents bind names (a parameter list or a binding pattern) and whether it is a
 * computed key inside a pattern (which binds nothing).
 *
 * @param {object[]} tokens
 * @returns {{enclosing: (object|null)[], opener: (object|null)[], unbalanced: boolean}}
 */
function classifyGroups(tokens) {
  const opener = new Array(tokens.length).fill(null);
  const enclosing = new Array(tokens.length).fill(null);
  const stack = [];
  let unbalanced = false;

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    enclosing[index] = stack.length === 0 ? null : stack[stack.length - 1];

    if (token.type !== "punct") continue;

    if (OPENERS.has(token.value)) {
      const group = {
        kind: token.value,
        open: index,
        close: -1,
        prev: tokens[index - 1] ?? null,
        nextToken: null,
        parent: stack.length === 0 ? null : stack[stack.length - 1],
        paramList: false,
        pattern: false,
        followsBody: false,
      };
      opener[index] = group;
      stack.push(group);
      continue;
    }

    if (CLOSERS.has(token.value)) {
      const group = stack.pop();
      if (group === undefined) {
        unbalanced = true;
        continue;
      }
      group.close = index;
      group.nextToken = tokens[index + 1] ?? null;
      enclosing[index] = group.parent;
    }
  }

  if (stack.length > 0) unbalanced = true;

  for (const group of opener) {
    if (group === null || group.close < 0) continue;
    group.pattern = isBindingPattern(group);
    group.followsBody = followsFunctionBody(tokens, opener, enclosing, group);
    group.paramList = isParameterList(group);
  }

  return { enclosing, opener, unbalanced };
}

/**
 * Whether the tokens after a group's closer lead into a function body or an arrow.
 *
 * A `)` is a parameter list here when what follows is a `{` body, an `=>`, or a
 * TypeScript return type annotation that itself ends in one of those
 * (`loadConfig(filePath: string): string { … }`). The scan is bounded and
 * over-inclusive: any other shape — a call followed by more expression, a `)` before
 * `;` — is not a parameter list.
 */
function followsFunctionBody(tokens, opener, enclosing, group) {
  if (group.kind !== "(") return false;
  const level = group.parent;
  let index = group.close + 1;
  let steps = 0;
  while (index < tokens.length && steps < 32) {
    const token = tokens[index];
    const own = (enclosing[index] ?? null) === level;
    if (own && token.type === "punct") {
      if (token.value === "{" || token.value === "=>") return true;
      if (token.value === ";" || token.value === "," || token.value === ")" || token.value === "]" || token.value === "}") {
        return false;
      }
    }
    index += 1;
    steps += 1;
  }
  return false;
}

/** Whether a paren group's contents are parameters (over-inclusive by design). */
function isParameterList(group) {
  if (group.kind !== "(") return false;
  const prev = group.prev;
  if (prev !== null && prev.type === "identifier") {
    if (PARAMETER_LIST_OPENERS.has(prev.value)) return true;
    if (CONTROL_KEYWORDS.has(prev.value)) return false;
  }
  return group.followsBody;
}

/** Whether an object-like group is a binding pattern. */
function isBindingPattern(group) {
  if (group.kind === "(") return false;
  const prev = group.prev;
  if (prev === null) return false;

  if (prev.type === "identifier" && DECLARATION_KEYWORDS.has(prev.value)) return true;

  const parent = group.parent;
  if (parent !== null && parent.paramList === true && prev.type === "punct") {
    return prev.value === "(" || prev.value === "," || prev.value === "=" || prev.value === "...";
  }
  if (parent !== null && parent.pattern === true) {
    // Inside a pattern, a nested group in a *value* position is a nested pattern
    // (`{ a: { b } }`, `[ [ a ] ]`); a group in *key* position inside a brace pattern
    // is a computed key, which binds nothing. Over-inclusion is safe here: a nested
    // pattern that is really a default value only costs coverage, because default
    // value regions are skipped when bindings are extracted.
    if (parent.kind === "{" && prev.type === "punct" && (prev.value === "{" || prev.value === ",")) {
      return false;
    }
    return true;
  }
  return false;
}

/** The innermost group enclosing a token, or `null` at module scope. */
function innermost(groupInfo, index) {
  return groupInfo.enclosing[index];
}

/** Whether a token sits inside a binding pattern. */
function inPattern(groupInfo, index) {
  let group = groupInfo.enclosing[index];
  while (group !== null) {
    if (group.pattern === true) return true;
    group = group.parent;
  }
  return false;
}

/** Whether a token sits inside a parameter list. */
function inParameterList(groupInfo, index) {
  let group = groupInfo.enclosing[index];
  while (group !== null) {
    if (group.paramList === true) return true;
    group = group.parent;
  }
  return false;
}

// ── Binding extraction from patterns ────────────────────────────────────────

/**
 * Collect the names a binding pattern binds.
 *
 * Only the pattern's own binding positions count: a `key: value` pair contributes
 * `value`, a shorthand property contributes its name, a rest element contributes its
 * target, and a *default value* (`= expr`) or *computed key* (`[expr]`) contributes
 * nothing — a computed key is an expression referencing other bindings, and reading
 * its identifiers as declarations would fabricate symbols.
 *
 * @param {object[]} tokens
 * @param {object} groupInfo
 * @param {number} openIndex Index of the pattern's opening bracket.
 * @param {{index: number, name: string}[]} out Collected binding positions.
 * @param {number} depth Remaining nesting budget.
 */
function collectPatternBindings(tokens, groupInfo, openIndex, out, depth) {
  if (depth <= 0) return;
  const group = groupInfo.opener[openIndex];
  if (group === null || group.close < 0) return;

  let index = openIndex + 1;
  while (index < group.close) {
    const token = tokens[index];

    if (token.type === "punct") {
      if (OPENERS.has(token.value)) {
        const nested = groupInfo.opener[index];
        if (nested === null || nested.close < 0) return;
        const afterSeparator =
          index === openIndex + 1 ||
          (tokens[index - 1].type === "punct" && tokens[index - 1].value === ",");
        const computedKey = group.kind === "{" && afterSeparator;
        if (!computedKey) {
          collectPatternBindings(tokens, groupInfo, index, out, depth - 1);
        }
        index = nested.close + 1;
        continue;
      }
      if (token.value === "=") {
        index = skipToSeparator(tokens, groupInfo, group, index + 1);
        continue;
      }
      index += 1;
      continue;
    }

    if (token.type === "identifier") {
      const next = tokens[index + 1];
      const isKey =
        next !== undefined && next.type === "punct" && (next.value === ":" || next.value === "?");
      if (!isKey && isUsableSymbolName(token.value)) out.push({ index, name: token.value });
    }

    index += 1;
  }
}

/** Index of the next `,` at the group's own level, or the group's closer. */
function skipToSeparator(tokens, groupInfo, group, start) {
  let index = start;
  while (index < group.close) {
    const token = tokens[index];
    if (token.type === "punct") {
      if (OPENERS.has(token.value)) {
        const nested = groupInfo.opener[index];
        if (nested === null || nested.close < 0) return group.close;
        index = nested.close + 1;
        continue;
      }
      if (token.value === ",") return index + 1;
    }
    index += 1;
  }
  return group.close;
}

// ── Clause analysis (imports and exports) ────────────────────────────────────

/** Read a specifier from a string token, or `null` when it is not usable. */
function specifierOf(token) {
  if (token === undefined || token.type !== "string") return null;
  return isUsableSpecifier(token.value) ? token.value : null;
}

/**
 * Find the next `from "…"` specifier inside a clause, if the clause states one.
 *
 * Bounded: the search abandons at the clause limit, at a statement keyword, or at a
 * `=` (which makes the clause a `require` form). A malformed declaration therefore
 * costs a bounded amount of work and produces a problem rather than a fabricated
 * specifier.
 */
function findClauseSpecifier(tokens, start, groupInfo) {
  const limit = Math.min(tokens.length, start + SEMANTIC_ACQUISITION_LIMITS.maxClauseTokens);
  const level = innermost(groupInfo, start);
  for (let index = start; index < limit; index += 1) {
    const token = tokens[index];
    const own = innermost(groupInfo, index) === level;
    if (token.type === "string") return { specifier: specifierOf(token), index };
    if (!own) continue;
    if (token.type === "punct" && (token.value === ";" || token.value === "=")) {
      return { specifier: null, index: null };
    }
    if (token.type === "identifier" && DECLARATION_KEYWORDS.has(token.value)) {
      return { specifier: null, index: null };
    }
  }
  return { specifier: null, index: null };
}

/**
 * Analyze every import and export declaration at module scope.
 *
 * One pass, because both statements share the clause grammar and the same
 * difficulty: knowing where a clause ends without a grammar. The pass records the
 * bindings and exports it establishes, the token ranges that belong to a clause
 * (which must never be read as references), the `declare module "…" { … }` bodies
 * (which declare no module-scope binding), and the `export` prefixes that make a
 * following declaration exported.
 *
 * @returns {{bindings: object[], exports: object[], starExports: string[],
 *   clauseRanges: Array<[number, number]>, exportFlags: Map<number, object>,
 *   problems: Set<string>}}
 */
function analyzeModuleClauses(tokens, groupInfo, isTypeScript) {
  const bindings = [];
  const exports = [];
  const starExports = [];
  const clauseRanges = [];
  const exportFlags = new Map();
  const problems = new Set();
  const enclosing = groupInfo.enclosing;

  const markRange = (start, end) => {
    if (end >= start) clauseRanges.push([start, Math.min(end, tokens.length - 1)]);
  };

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token.type !== "identifier" || enclosing[index] !== null) continue;

    if (token.value === "declare") {
      const moduleToken = tokens[index + 1];
      const nameToken = tokens[index + 2];
      const braceToken = tokens[index + 3];
      if (
        moduleToken !== undefined &&
        moduleToken.type === "identifier" &&
        moduleToken.value === "module" &&
        nameToken !== undefined &&
        nameToken.type === "string" &&
        braceToken !== undefined &&
        braceToken.type === "punct" &&
        braceToken.value === "{" &&
        groupInfo.opener[index + 3] !== null &&
        groupInfo.opener[index + 3].close >= 0
      ) {
        markRange(index, groupInfo.opener[index + 3].close);
      }
      continue;
    }

    if (token.value === "import") {
      const next = tokens[index + 1];
      if (next === undefined) continue;
      // `import.meta`, `import(…)`: not a declaration.
      if (
        next.type === "punct" &&
        (next.value === "." || next.value === "?." || next.value === "(")
      ) {
        continue;
      }

      let cursor = index + 1;
      let typeOnly = false;
      if (isTypeScript && tokens[cursor].value === "type") {
        const afterType = tokens[cursor + 1];
        if (afterType !== undefined && afterType.value !== "from") {
          typeOnly = true;
          cursor += 1;
        }
      }

      const specifierAt = findClauseSpecifier(tokens, cursor, groupInfo);
      markRange(index, specifierAt.index === null ? cursor : specifierAt.index);

      const head = tokens[cursor];
      if (head === undefined) continue;
      if (head.type === "string") continue; // side-effect import: binds nothing

      if (head.type === "punct" && head.value === "*") {
        const asToken = tokens[cursor + 1];
        const nameToken = tokens[cursor + 2];
        if (asToken !== undefined && asToken.value === "as" && nameToken !== undefined) {
          addBinding(bindings, {
            index: cursor + 2,
            name: nameToken.value,
            bindingKind: SYMBOL_BINDING_KINDS.NAMESPACE,
            importedName: "*",
            specifier: specifierAt.specifier,
            typeOnly,
          });
        }
        continue;
      }

      if (head.type === "punct" && head.value === "{") {
        readNamedClause(tokens, groupInfo, cursor, (entry) =>
          addBinding(bindings, {
            ...entry,
            bindingKind: SYMBOL_BINDING_KINDS.NAMED,
            specifier: specifierAt.specifier,
            typeOnly: typeOnly || entry.typeOnly,
          }),
        );
        continue;
      }

      if (head.type === "identifier") {
        addBinding(bindings, {
          index: cursor,
          name: head.value,
          bindingKind: SYMBOL_BINDING_KINDS.DEFAULT,
          importedName: "default",
          specifier: specifierAt.specifier,
          typeOnly,
        });

        // `import d, { a } from "…"`, `import d, * as ns from "…"`,
        // and TypeScript's `import d = require("…")`.
        let after = cursor + 1;
        if (tokens[after] !== undefined && tokens[after].value === ",") {
          after += 1;
          const clause = tokens[after];
          if (clause !== undefined && clause.value === "{") {
            readNamedClause(tokens, groupInfo, after, (entry) =>
              addBinding(bindings, {
                ...entry,
                bindingKind: SYMBOL_BINDING_KINDS.NAMED,
                specifier: specifierAt.specifier,
                typeOnly: typeOnly || entry.typeOnly,
              }),
            );
          } else if (clause !== undefined && clause.value === "*") {
            const nameToken = tokens[after + 2];
            if (nameToken !== undefined) {
              addBinding(bindings, {
                index: after + 2,
                name: nameToken.value,
                bindingKind: SYMBOL_BINDING_KINDS.NAMESPACE,
                importedName: "*",
                specifier: specifierAt.specifier,
                typeOnly,
              });
            }
          }
        } else if (tokens[after] !== undefined && tokens[after].value === "=") {
          // TypeScript `import x = require("…")`: the identifier above is the
          // binding, and the module is the require argument.
          const requireToken = tokens[after + 1];
          const openToken = tokens[after + 2];
          const stringToken = tokens[after + 3];
          if (
            requireToken !== undefined &&
            requireToken.value === "require" &&
            openToken !== undefined &&
            openToken.value === "("
          ) {
            const last = bindings[bindings.length - 1];
            bindings[bindings.length - 1] = {
              ...last,
              bindingKind: SYMBOL_BINDING_KINDS.REQUIRE,
              importedName: "*",
              specifier: specifierOf(stringToken),
            };
          }
        }
        continue;
      }
      continue;
    }

    if (token.value === "export") {
      const next = tokens[index + 1];
      if (next === undefined) continue;

      if (next.type === "identifier" && next.value === "type") {
        const afterType = tokens[index + 2];
        if (afterType !== undefined && afterType.value === "{") {
          readExportClause(tokens, groupInfo, index + 2, true, exports, markRange, problems);
          continue;
        }
        if (afterType !== undefined && afterType.value !== "from") {
          exportFlags.set(index + 2, { exported: true, default: false });
          continue;
        }
      }

      if (next.type === "identifier" && next.value === "default") {
        const afterDefault = tokens[index + 2];
        if (
          afterDefault !== undefined &&
          afterDefault.type === "identifier" &&
          (afterDefault.value === "function" || afterDefault.value === "class")
        ) {
          exportFlags.set(index + 2, { exported: true, default: true });
          continue;
        }
        // `export default <expression>`: the file exports a default whose local
        // binding this build cannot name. Recorded as an unestablished export rather
        // than given an invented name.
        exports.push({
          name: "default",
          localName: null,
          form: SYMBOL_EXPORT_FORMS.DEFAULT,
          specifier: null,
          typeOnly: false,
        });
        note(problems, SEMANTIC_PROBLEMS.ANONYMOUS_DEFAULT_EXPORT);
        continue;
      }

      if (next.type === "punct" && next.value === "{") {
        readExportClause(tokens, groupInfo, index + 1, false, exports, markRange, problems);
        continue;
      }

      if (next.type === "punct" && next.value === "*") {
        const specifierAt = findClauseSpecifier(tokens, index + 1, groupInfo);
        if (specifierAt.index === null) {
          note(problems, SEMANTIC_PROBLEMS.UNTERMINATED_EXPORT_CLAUSE);
          continue;
        }
        markRange(index, specifierAt.index);
        const asToken = tokens[index + 2];
        const nameToken = tokens[index + 3];
        if (asToken !== undefined && asToken.value === "as" && nameToken !== undefined) {
          // `export * as ns from "…"`: a named export bound to a namespace object
          // whose target this build cannot name.
          exports.push({
            name: nameToken.value,
            localName: null,
            form: SYMBOL_EXPORT_FORMS.STAR,
            specifier: specifierAt.specifier,
            typeOnly: false,
          });
        } else if (specifierAt.specifier !== null) {
          starExports.push(specifierAt.specifier);
          exports.push({
            name: null,
            localName: null,
            form: SYMBOL_EXPORT_FORMS.STAR,
            specifier: specifierAt.specifier,
            typeOnly: false,
          });
        }
        continue;
      }

      if (next.type === "punct" && next.value === "=") {
        // TypeScript `export =`: a module system this build does not interpret.
        note(problems, SEMANTIC_PROBLEMS.UNSUPPORTED_EXPORT_FORM);
        continue;
      }

      if (next.type === "identifier") {
        const known =
          next.value === "function" ||
          next.value === "class" ||
          DECLARATION_KEYWORDS.has(next.value) ||
          next.value === "async" ||
          next.value === "abstract" ||
          next.value === "declare" ||
          (isTypeScript && (TS_NAMED_DECLARATIONS.has(next.value) || next.value === "type"));
        if (known) exportFlags.set(index + 1, { exported: true, default: false });
        else note(problems, SEMANTIC_PROBLEMS.UNSUPPORTED_EXPORT_FORM);
        continue;
      }
    }
  }

  return { bindings, exports, starExports, clauseRanges, exportFlags, problems };
}

/** Add one import binding, skipping names that cannot become a symbol identity. */
function addBinding(bindings, entry) {
  if (!isUsableSymbolName(entry.name)) return;
  if (!Number.isInteger(entry.index)) return;
  bindings.push({
    index: entry.index,
    name: entry.name,
    bindingKind: entry.bindingKind,
    importedName: entry.importedName ?? null,
    specifier: entry.specifier ?? null,
    typeOnly: entry.typeOnly === true,
  });
}

/** Read a `{ a, b as c, type T }` clause, yielding one entry per binding. */
function readNamedClause(tokens, groupInfo, openIndex, visit) {
  const group = groupInfo.opener[openIndex];
  if (group === null || group.close < 0) return;
  let index = openIndex + 1;
  let typeOnly = false;

  while (index < group.close) {
    const token = tokens[index];
    if (token.type === "identifier" && token.value === "type") {
      typeOnly = true;
      index += 1;
      continue;
    }
    if (token.type === "identifier") {
      const asToken = tokens[index + 1];
      const nameToken = tokens[index + 2];
      if (
        asToken !== undefined &&
        asToken.type === "identifier" &&
        asToken.value === "as" &&
        nameToken !== undefined
      ) {
        visit({ index: index + 2, name: nameToken.value, importedName: token.value, typeOnly });
        index += 3;
        typeOnly = false;
        continue;
      }
      visit({ index, name: token.value, importedName: token.value, typeOnly });
      index += 1;
      typeOnly = false;
      continue;
    }
    index += 1;
  }
}

/** Read an `export { … } [from "…"]` clause. */
function readExportClause(tokens, groupInfo, openIndex, typeOnly, exports, markRange, problems) {
  const group = groupInfo.opener[openIndex];
  if (group === null || group.close < 0) {
    note(problems, SEMANTIC_PROBLEMS.UNTERMINATED_EXPORT_CLAUSE);
    return;
  }
  const specifierAt = findClauseSpecifier(tokens, group.close + 1, groupInfo);
  markRange(openIndex - 1, specifierAt.index === null ? group.close : specifierAt.index);
  const reExport = specifierAt.specifier !== null;

  let index = openIndex + 1;
  while (index < group.close) {
    const token = tokens[index];
    if (token.type !== "identifier") {
      index += 1;
      continue;
    }
    const asToken = tokens[index + 1];
    const nameToken = tokens[index + 2];
    const hasAlias =
      asToken !== undefined &&
      asToken.type === "identifier" &&
      asToken.value === "as" &&
      nameToken !== undefined &&
      nameToken.type === "identifier";
    const exportName = hasAlias ? nameToken.value : token.value;
    if (isUsableSymbolName(exportName)) {
      exports.push({
        name: exportName,
        localName: token.value,
        form: reExport ? SYMBOL_EXPORT_FORMS.RE_EXPORT : SYMBOL_EXPORT_FORMS.NAMED,
        specifier: specifierAt.specifier,
        typeOnly: typeOnly === true,
      });
    }
    index += hasAlias ? 3 : 1;
  }
}

// ── Initializer shape ────────────────────────────────────────────────────────

/**
 * Decide what a declarator's initializer establishes about the bound value.
 *
 * `callable`/`constructable` are three-valued on purpose: `true` means the source
 * states a function (or class) value, `false` means it states a value that cannot be
 * one, and `null` means this build does not establish either — which is the answer
 * for an alias (`const f = other`), a call result, a generic arrow, and everything
 * else outside the closed set below.
 *
 * @returns {{callable: boolean|null, constructable: boolean|null}}
 */
function initializerShape(tokens, groupInfo, startIndex) {
  const token = tokens[startIndex];
  if (token === undefined) return { callable: null, constructable: null };

  if (token.type === "identifier") {
    if (token.value === "function") return { callable: true, constructable: true };
    if (token.value === "class") return { callable: false, constructable: true };
    if (token.value === "async") {
      const after = tokens[startIndex + 1];
      if (after === undefined) return { callable: null, constructable: null };
      if (after.type === "identifier" && after.value === "function") {
        return { callable: true, constructable: true };
      }
      if (after.type === "punct" && after.value === "(") {
        return arrowShape(tokens, groupInfo, startIndex + 1);
      }
      if (after.type === "identifier") return { callable: true, constructable: false };
      return { callable: null, constructable: null };
    }
    if (NON_FUNCTION_KEYWORDS.has(token.value)) return { callable: false, constructable: false };
    return { callable: null, constructable: null };
  }

  if (token.type === "punct") {
    if (token.value === "(") return arrowShape(tokens, groupInfo, startIndex);
    if (token.value === "{" || token.value === "[") {
      return { callable: false, constructable: false };
    }
    if (token.value === "=>") return { callable: true, constructable: false };
    return { callable: null, constructable: null };
  }

  if (token.type === "template") return { callable: false, constructable: false };
  return { callable: false, constructable: false };
}

/** Whether a paren group at `openIndex` is an arrow function's parameter list. */
function arrowShape(tokens, groupInfo, openIndex) {
  const group = groupInfo.opener[openIndex];
  if (group === null || group.close < 0) return { callable: null, constructable: null };
  const next = group.nextToken;
  if (next !== null && next.type === "punct" && next.value === "=>") {
    return { callable: true, constructable: false };
  }
  return { callable: null, constructable: null };
}

// ── The scan ─────────────────────────────────────────────────────────────────

/** Prefix keywords that may sit between a statement boundary and a declaration. */
const DECLARATION_PREFIXES = new Set(["async", "export", "default", "declare", "abstract"]);

/**
 * Whether a `function`/`class` token can begin a declaration here.
 *
 * The check walks back over the modifier keywords a declaration may carry, then asks
 * whether the token before them can only sit in front of an *expression*. That is
 * exactly the case this has to reject: `const f = async function g() {}` binds `g`
 * inside the function expression, not at module scope, so reading it as a module
 * binding would fabricate a symbol. Statements that follow each other through
 * automatic semicolon insertion are deliberately not rejected (`}\nfunction f() {}`).
 */
function inStatementPosition(tokens, index) {
  let cursor = index - 1;
  let steps = 0;
  while (cursor >= 0 && steps < 8) {
    const token = tokens[cursor];
    if (token.type !== "identifier" || !DECLARATION_PREFIXES.has(token.value)) break;
    cursor -= 1;
    steps += 1;
  }
  if (cursor < 0) return true;
  const token = tokens[cursor];
  if (token.type === "identifier" || token.type === "punct") {
    return !EXPRESSION_PREFIXES.has(token.value);
  }
  return true;
}

/**
 * Scan one module source for its source-level semantic facts.
 *
 * @param {string} text Source text.
 * @param {object} [options]
 * @param {string} [options.extension] Lower-case extension including the dot.
 * @returns {object} The scanner's record for this file.
 */
export function scanModuleSemantics(text, options = {}) {
  const extension = options.extension ?? "";
  const isTypeScript = extension === ".ts" || extension === ".mts" || extension === ".cts";
  const limits = SEMANTIC_ACQUISITION_LIMITS;
  const lexed = tokenizeModule(text, { maxTokens: options.maxTokens ?? limits.maxTokensPerFile });
  const tokens = lexed.tokens;
  const problems = new Set();

  for (const problem of lexed.problems) {
    if (IMPORT_LEXICAL_PROBLEMS.includes(problem)) note(problems, problem);
  }

  const groupInfo = classifyGroups(tokens);
  if (groupInfo.unbalanced) note(problems, SEMANTIC_PROBLEMS.UNBALANCED_GROUPS);

  const clauses = analyzeModuleClauses(tokens, groupInfo, isTypeScript);
  for (const problem of clauses.problems) note(problems, problem);

  /** Whether a token index belongs to an import/export clause or a module body. */
  const inClause = new Array(tokens.length).fill(false);
  for (const [start, end] of clauses.clauseRanges) {
    for (let index = start; index <= end && index < tokens.length; index += 1) inClause[index] = true;
  }

  const binders = new Map();
  const declarations = new Map();
  const occurrences = new Map();
  const reassigned = new Set();
  let declarationCount = 0;
  let declarationLimitHit = false;

  const addBinder = (name, index) => {
    let set = binders.get(name);
    if (set === undefined) {
      set = new Set();
      binders.set(name, set);
    }
    set.add(index);
  };

  const addDeclaration = (entry) => {
    declarationCount += 1;
    if (declarationCount > limits.maxDeclarationsPerFile) {
      declarationLimitHit = true;
      note(problems, SEMANTIC_PROBLEMS.DECLARATION_LIMIT);
      return null;
    }
    const existing = declarations.get(entry.name);
    if (existing === undefined) {
      const record = {
        name: entry.name,
        kinds: [entry.kind],
        keywords: [entry.keyword],
        exported: entry.exported === true,
        // The names this declaration is exported under. A declaration carries its
        // own export prefix (`export const x`, `export default function f`), so the
        // export is recorded where the fact is, rather than reconstructed later.
        exportNames: [...(entry.exportNames ?? [])],
        callable: entry.callable ?? null,
        constructable: entry.constructable ?? null,
        binding: entry.binding ?? null,
        // The token positions the name is declared at. Uniqueness compares the
        // binder superset against exactly these, so they are kept per name.
        positions: new Set([entry.index]),
      };
      declarations.set(entry.name, record);
      return record;
    }
    existing.positions.add(entry.index);
    if (!existing.kinds.includes(entry.kind)) existing.kinds.push(entry.kind);
    if (!existing.keywords.includes(entry.keyword)) existing.keywords.push(entry.keyword);
    existing.exported = existing.exported || entry.exported === true;
    for (const exportName of entry.exportNames ?? []) {
      if (!existing.exportNames.includes(exportName)) existing.exportNames.push(exportName);
    }
    // Fail-closed merging: two declarations that disagree about the value shape
    // establish nothing about it.
    if (existing.callable !== (entry.callable ?? null)) existing.callable = null;
    if (existing.constructable !== (entry.constructable ?? null)) existing.constructable = null;
    if (existing.binding === null && entry.binding != null) existing.binding = entry.binding;
    return existing;
  };

  const addOccurrence = (name, form) => {
    const key = `${name}\u0000${form}`;
    const existing = occurrences.get(key);
    if (existing !== undefined) {
      existing.count += 1;
      return;
    }
    if (occurrences.size >= limits.maxReferencedNamesPerFile) {
      note(problems, SEMANTIC_PROBLEMS.REFERENCE_LIMIT);
      return;
    }
    occurrences.set(key, { name, form, count: 1 });
  };

  // An import clause binds a module-scope name whether or not its specifier could
  // be read: "the file binds `x`" and "what `x` points at is unknown" are different
  // facts, and the second must not erase the first.
  const clauseBindingByIndex = new Map();
  for (const binding of clauses.bindings) {
    clauseBindingByIndex.set(binding.index, binding);
    addBinder(binding.name, binding.index);
    addDeclaration({
      name: binding.name,
      index: binding.index,
      kind: SYMBOL_KINDS.IMPORTED_BINDING,
      keyword: `import:${binding.bindingKind}`,
      exported: false,
      exportNames: [],
      callable: null,
      constructable: null,
      binding: {
        bindingKind: binding.bindingKind,
        importedName: binding.importedName,
        specifier: binding.specifier,
        typeOnly: binding.typeOnly === true,
      },
    });
  }

  /**
   * The declarator list currently being followed.
   *
   * `phase` is `name` (the keyword's binding is expected), `afterName` (a type
   * annotation or an initializer may follow), `annotation` or `initializer`.
   */
  let declaratorList = null;

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    const atModuleScope = groupInfo.enclosing[index] === null;
    const exportFlag = atModuleScope ? clauses.exportFlags.get(index) : undefined;
    const previous = tokens[index - 1];
    const previousPrevious = tokens[index - 2];
    const next = tokens[index + 1];

    // ── Following a declarator list ──────────────────────────────────────────
    if (declaratorList !== null && groupInfo.enclosing[index] === declaratorList.base) {
      if (token.type === "punct") {
        // A TypeScript type argument list is not a bracket group: `Map<string,
        // number>` puts a comma at the declarator's own level, and counting angle
        // brackets is what keeps that comma from ending the declarator list.
        if (declaratorList.phase === "annotation") {
          if (token.value[0] === "<") declaratorList.angle += token.value.length;
          else if (token.value[0] === ">") {
            declaratorList.angle = Math.max(0, declaratorList.angle - token.value.length);
          }
        }
        if ((token.value === "," || token.value === ";") && declaratorList.angle > 0) {
          continue;
        }
        if (token.value === "=" && declaratorList.phase !== "initializer") {
          declaratorList.phase = "initializer";
          if (declaratorList.record !== null) {
            const shape = initializerShape(tokens, groupInfo, index + 1);
            declaratorList.record.callable = shape.callable;
            declaratorList.record.constructable = shape.constructable;
          }
          continue;
        }
        if (token.value === ":" && declaratorList.phase === "afterName") {
          declaratorList.phase = "annotation";
          continue;
        }
        if (token.value === ",") {
          // Multi-declarator lists are not followed (see the module header): the
          // tokenizer records no statement boundaries, and continuing on a comma
          // would read a later sequence expression such as `foo, bar = 1` as a
          // declaration. A comma followed by a name is therefore reported.
          if (
            next !== undefined &&
            next.type === "identifier" &&
            !RESERVED_WORDS.has(next.value)
          ) {
            note(problems, SEMANTIC_PROBLEMS.UNSUPPORTED_DECLARATOR);
          }
          declaratorList = null;
          continue;
        }
        if (token.value === ";") {
          declaratorList = null;
          continue;
        }
      }
      if (declaratorList.phase === "name") {
        if (token.type === "identifier" && !RESERVED_WORDS.has(token.value)) {
          declaratorList.record = addDeclaration({
            name: token.value,
            index,
            kind: SYMBOL_KINDS.VARIABLE,
            keyword: declaratorList.keyword,
            exported: declaratorList.exported,
            exportNames: declaratorList.exported ? [token.value] : [],
            callable: null,
            constructable: null,
            binding: null,
          });
          declaratorList.phase = "afterName";
          continue;
        }
        if (token.type === "punct" && (token.value === "{" || token.value === "[")) {
          const group = groupInfo.opener[index];
          if (group !== null && group.close >= 0) {
            const collected = [];
            collectPatternBindings(tokens, groupInfo, index, collected, limits.maxPatternDepth);
            for (const entry of collected) {
              addDeclaration({
                name: entry.name,
                index: entry.index,
                kind: SYMBOL_KINDS.VARIABLE,
                keyword: declaratorList.keyword,
                exported: declaratorList.exported,
                exportNames: declaratorList.exported ? [entry.name] : [],
                callable: null,
                constructable: null,
                binding: null,
              });
            }
          }
          declaratorList.phase = "afterName";
          declaratorList.record = null;
          continue;
        }
        note(problems, SEMANTIC_PROBLEMS.UNSUPPORTED_DECLARATOR);
        declaratorList = null;
        continue;
      }
      // Inside an annotation or an initializer the token is ordinary code: it is
      // read for bindings and occurrences below, never skipped, because skipping an
      // initializer would drop most of the references in the file.
    }

    if (token.type === "punct") continue;

    if (token.type !== "identifier") continue;

    // ── Clause tokens: bindings, never references ────────────────────────────
    if (inClause[index]) {
      const binding = clauseBindingByIndex.get(index);
      if (binding !== undefined) addBinder(binding.name, index);
      continue;
    }

    // ── Dynamic scope ────────────────────────────────────────────────────────
    //
    // A direct `eval(…)` or a `with (…)` statement can introduce a binding into an
    // enclosing scope at runtime. Every uniqueness proof in the file is void.
    if (token.value === "eval" && isDirectCall(tokens, index)) {
      note(problems, SEMANTIC_PROBLEMS.DYNAMIC_SCOPE_CONSTRUCT);
      continue;
    }
    if (token.value === "with" && isWithStatement(tokens, index)) {
      note(problems, SEMANTIC_PROBLEMS.DYNAMIC_SCOPE_CONSTRUCT);
      continue;
    }

    // ── Module-scope declarations ────────────────────────────────────────────
    if (atModuleScope) {
      if (DECLARATION_KEYWORDS.has(token.value)) {
        declaratorList = {
          base: groupInfo.enclosing[index],
          keyword: token.value,
          exported: exportFlag?.exported === true,
          phase: "name",
          angle: 0,
          record: null,
        };
        continue;
      }

      if (token.value === "function" && inStatementPosition(tokens, index)) {
        let cursor = index + 1;
        if (tokens[cursor] !== undefined && tokens[cursor].value === "*") cursor += 1;
        const nameToken = tokens[cursor];
        if (nameToken !== undefined && nameToken.type === "identifier" && !RESERVED_WORDS.has(nameToken.value)) {
          const afterName = tokens[cursor + 1];
          if (
            afterName !== undefined &&
            afterName.type === "punct" &&
            (afterName.value === "(" || afterName.value === "<")
          ) {
            addDeclaration({
              name: nameToken.value,
              index: cursor,
              kind: SYMBOL_KINDS.FUNCTION,
              keyword: "function",
              exported: exportFlag?.exported === true,
              exportNames: exportNamesFor(exportFlag, nameToken.value),
              callable: true,
              constructable: true,
              binding: null,
            });
            continue;
          }
        }
      }

      if (token.value === "class" && inStatementPosition(tokens, index)) {
        const nameToken = tokens[index + 1];
        if (nameToken !== undefined && nameToken.type === "identifier" && !RESERVED_WORDS.has(nameToken.value)) {
          const afterName = tokens[index + 2];
          const declares =
            afterName !== undefined &&
            ((afterName.type === "punct" && (afterName.value === "{" || afterName.value === "<")) ||
              (afterName.type === "identifier" &&
                (afterName.value === "extends" || afterName.value === "implements")));
          if (declares) {
            addDeclaration({
              name: nameToken.value,
              index: index + 1,
              kind: SYMBOL_KINDS.CLASS,
              keyword: "class",
              exported: exportFlag?.exported === true,
              exportNames: exportNamesFor(exportFlag, nameToken.value),
              callable: false,
              constructable: true,
              binding: null,
            });
            continue;
          }
        }
      }

      if (isTypeScript && (TS_NAMED_DECLARATIONS.has(token.value) || token.value === "type")) {
        const nameToken = tokens[index + 1];
        if (nameToken !== undefined && nameToken.type === "identifier" && !RESERVED_WORDS.has(nameToken.value)) {
          // Which token an `export` prefix marks depends on the form: `export interface X`
          // marks the keyword, while `export type X` has to mark the *name* (the keyword
          // after `export type` is `type`, and flagging it would make the type name look
          // unexported). So the flag of the name this declaration binds is the answer that
          // is right for every form, and the keyword's flag is the fallback.
          const declarationExportFlag = clauses.exportFlags.get(index + 1) ?? exportFlag;
          addDeclaration({
            name: nameToken.value,
            index: index + 1,
            kind:
              token.value === "type"
                ? SYMBOL_KINDS.TYPE_ALIAS
                : token.value === "interface"
                  ? SYMBOL_KINDS.INTERFACE
                  : token.value === "enum"
                    ? SYMBOL_KINDS.ENUM
                    : SYMBOL_KINDS.NAMESPACE,
            keyword: token.value,
            exported: declarationExportFlag?.exported === true,
            exportNames: exportNamesFor(declarationExportFlag, nameToken.value),
            callable: null,
            constructable: null,
            binding: null,
          });
          continue;
        }
      }

      // CommonJS module form: a module system this build does not read, so a
      // `require` binding's target is never claimed.
      if (
        token.value === "exports" &&
        next !== undefined &&
        next.type === "punct" &&
        next.value === "."
      ) {
        note(problems, SEMANTIC_PROBLEMS.COMMONJS_MODULE_FORM);
        continue;
      }
      if (
        token.value === "module" &&
        next !== undefined &&
        next.type === "punct" &&
        next.value === "." &&
        tokens[index + 2] !== undefined &&
        tokens[index + 2].value === "exports"
      ) {
        note(problems, SEMANTIC_PROBLEMS.COMMONJS_MODULE_FORM);
        continue;
      }
    }

    if (RESERVED_WORDS.has(token.value)) continue;

    // ── Possible binding positions (the soundness superset) ──────────────────
    if (possibleBinding(tokens, groupInfo, index, { previous, previousPrevious, next })) {
      addBinder(token.value, index);
      continue;
    }

    // ── Occurrences ──────────────────────────────────────────────────────────
    if (CONTEXTUAL_KEYWORDS.has(token.value)) continue;
    if (inPattern(groupInfo, index)) continue;
    if (
      previous !== undefined &&
      previous.type === "punct" &&
      (previous.value === "." || previous.value === "?.")
    ) {
      continue;
    }
    if (next !== undefined && next.type === "punct" && next.value === ":") continue;
    if (previous !== undefined && previous.type === "punct" && previous.value === "#") continue;

    const isCall = next !== undefined && next.type === "punct" && next.value === "(";
    const isConstruct =
      previous !== undefined &&
      previous.type === "identifier" &&
      previous.value === "new" &&
      !(
        previousPrevious !== undefined &&
        previousPrevious.type === "punct" &&
        (previousPrevious.value === "." || previousPrevious.value === "?.")
      );
    const form = isConstruct
      ? SYMBOL_OCCURRENCE_FORMS.CONSTRUCT
      : isCall
        ? SYMBOL_OCCURRENCE_FORMS.CALL
        : SYMBOL_OCCURRENCE_FORMS.REFERENCE;

    // An assignment target can hold anything by the time it is called, so a name
    // assigned anywhere in the file never becomes a *call* edge.
    const assigned =
      (next !== undefined &&
        next.type === "punct" &&
        (next.value === "=" || next.value === "++" || next.value === "--")) ||
      (previous !== undefined &&
        previous.type === "punct" &&
        (previous.value === "++" || previous.value === "--"));
    if (assigned) reassigned.add(token.value);

    addOccurrence(token.value, form);
  }

  // ── Export clauses point back at the declarations they publish ─────────────
  //
  // `export { local as name }` publishes a declaration without touching the statement
  // that declares it, so the fact has to be folded back here. Without it a declaration
  // the file *does* export would report `exported: false`, and the graph would state an
  // `exports` edge to a symbol whose own record denies being exported — two views of one
  // fact disagreeing, which is exactly what a semantic substrate must never do.
  //
  // Only a local clause qualifies: a clause with a specifier (`export { x } from "…"`)
  // names a binding in **another** module, and marking a local declaration of that name
  // as exported would attribute a publication this file never made.
  for (const clause of clauses.exports) {
    if (clause.localName === null || clause.name === null || clause.specifier !== null) continue;
    const record = declarations.get(clause.localName);
    if (record === undefined) continue;
    record.exported = true;
    if (!record.exportNames.includes(clause.name)) record.exportNames.push(clause.name);
  }

  // ── Finalize declarations ──────────────────────────────────────────────────
  //
  // Uniqueness is the whole resolution proof, so it is computed once, here, from the
  // finished binder set: a name is unique when nothing but its own module-scope
  // declaration positions was ever flagged as a possible binding of it.
  const finalized = [];
  for (const record of declarations.values()) {
    const own = record.positions;
    let shadowed = false;
    for (const position of binders.get(record.name) ?? []) {
      if (own.has(position)) continue;
      shadowed = true;
      break;
    }
    let callable = record.callable;
    let constructable = record.constructable;
    if (reassigned.has(record.name)) {
      callable = null;
      constructable = null;
    }
    if (record.kinds.includes(SYMBOL_KINDS.VARIABLE)) {
      // `let`/`var` bindings are reassignable by definition, so only a `const`
      // binding's initializer can establish a value shape.
      if (!record.keywords.every((keyword) => keyword === "const")) {
        callable = null;
        constructable = null;
      }
    }
    finalized.push(
      Object.freeze({
        name: record.name,
        kinds: Object.freeze([...record.kinds].sort()),
        keywords: Object.freeze([...record.keywords].sort()),
        exported: record.exported === true || record.exportNames.length > 0,
        exportNames: Object.freeze([...record.exportNames].sort()),
        callable,
        constructable,
        shadowed,
        reassigned: reassigned.has(record.name),
        binding: record.binding === null ? null : Object.freeze({ ...record.binding }),
      }),
    );
  }
  finalized.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

  const references = [...occurrences.values()]
    .map((entry) => Object.freeze({ ...entry }))
    .sort((a, b) => {
      if (a.name !== b.name) return a.name < b.name ? -1 : 1;
      return a.form < b.form ? -1 : a.form > b.form ? 1 : 0;
    });

  const exports = clauses.exports
    .slice(0, limits.maxExportsPerFile)
    .map((entry) => Object.freeze({ ...entry }))
    .sort(compareExports);
  if (clauses.exports.length > limits.maxExportsPerFile) {
    note(problems, SEMANTIC_PROBLEMS.EXPORT_LIMIT);
  }

  const sortedProblems = [...problems].sort();
  const lexical = SEMANTIC_LEXICAL_PROBLEMS.some((problem) => sortedProblems.includes(problem));
  const declarationsEstablished = !lexical;
  const resolutionEstablished =
    declarationsEstablished && !sortedProblems.includes(SEMANTIC_PROBLEMS.DYNAMIC_SCOPE_CONSTRUCT);
  const exportsEstablished =
    declarationsEstablished &&
    !sortedProblems.includes(SEMANTIC_PROBLEMS.ANONYMOUS_DEFAULT_EXPORT) &&
    !sortedProblems.includes(SEMANTIC_PROBLEMS.UNSUPPORTED_EXPORT_FORM) &&
    !sortedProblems.includes(SEMANTIC_PROBLEMS.COMMONJS_MODULE_FORM);

  const countForm = (form) =>
    references.filter((entry) => entry.form === form).reduce((total, entry) => total + entry.count, 0);

  return Object.freeze({
    declarations: Object.freeze(finalized),
    exports: Object.freeze(exports),
    starExports: Object.freeze([...new Set(clauses.starExports)].sort()),
    references: Object.freeze(references),
    problems: Object.freeze(sortedProblems),
    truncated:
      lexed.truncated ||
      declarationLimitHit ||
      sortedProblems.includes(SEMANTIC_PROBLEMS.TOKEN_LIMIT) ||
      sortedProblems.includes(SEMANTIC_PROBLEMS.REFERENCE_LIMIT),
    established: Object.freeze({
      declarations: declarationsEstablished,
      resolution: resolutionEstablished,
      exports: exportsEstablished,
    }),
    counts: Object.freeze({
      declarations: finalized.length,
      exports: exports.length,
      names: references.length,
      references: countForm(SYMBOL_OCCURRENCE_FORMS.REFERENCE),
      calls: countForm(SYMBOL_OCCURRENCE_FORMS.CALL),
      constructs: countForm(SYMBOL_OCCURRENCE_FORMS.CONSTRUCT),
      tokens: tokens.length,
    }),
  });
}

/**
 * The names a declaration is exported under, given its `export` prefix.
 *
 * A default export is exported under the name `default`, which is the name another
 * module imports — so the exported name, not the local one, is what a resolution
 * has to match.
 */
function exportNamesFor(exportFlag, localName) {
  if (exportFlag === undefined || exportFlag.exported !== true) return [];
  return [exportFlag.default === true ? "default" : localName];
}

/** Deterministic export ordering: name, then form, then local name. */
function compareExports(a, b) {
  const left = a.name ?? "";
  const right = b.name ?? "";
  if (left !== right) return left < right ? -1 : 1;
  if (a.form !== b.form) return a.form < b.form ? -1 : 1;
  const leftLocal = a.localName ?? "";
  const rightLocal = b.localName ?? "";
  if (leftLocal !== rightLocal) return leftLocal < rightLocal ? -1 : 1;
  return 0;
}

/** Whether a `new IDENT(` call's target is being constructed. */
function isDirectCall(tokens, index) {
  const previous = tokens[index - 1];
  if (
    previous !== undefined &&
    previous.type === "punct" &&
    (previous.value === "." || previous.value === "?.")
  ) {
    return false;
  }
  const next = tokens[index + 1];
  return next !== undefined && next.type === "punct" && next.value === "(";
}

/** Whether the keyword `with` opens a statement rather than naming something. */
function isWithStatement(tokens, index) {
  const next = tokens[index + 1];
  if (next === undefined || next.type !== "punct" || next.value !== "(") return false;
  const previous = tokens[index - 1];
  return !(
    previous !== undefined &&
    previous.type === "punct" &&
    (previous.value === "." || previous.value === "?.")
  );
}

/**
 * Whether a token sits in a position that could bind a name.
 *
 * Deliberately over-inclusive: every rule is chosen so a construct the scanner
 * mis-classifies can only cost coverage. A missed binding would be the one error
 * that fabricates a reference, so the superset is broad on purpose.
 */
function possibleBinding(tokens, groupInfo, index, context) {
  const { previous, previousPrevious, next } = context;

  if (previous !== undefined && previous.type === "identifier") {
    if (DECLARATION_KEYWORDS.has(previous.value)) return true;
    if (previous.value === "function" || previous.value === "class") return true;
    if (previous.value === "import" || previous.value === "catch") return true;
    if (previous.value === "declare" || previous.value === "interface") return true;
    if (previous.value === "enum" || previous.value === "namespace" || previous.value === "type") {
      return true;
    }
    if (previous.value === "as") return true;
    if (previous.value === "*") {
      return previousPrevious !== undefined && previousPrevious.value === "function";
    }
  }

  if (next !== undefined && next.type === "punct" && next.value === "=>") return true;
  if (previous !== undefined && previous.type === "punct" && previous.value === "<") return true;
  if (next !== undefined && next.type === "punct" && next.value === ">") return true;

  // A member position: a method definition (`run() { … }`) or a class field
  // (`load = 1`) in a class or object body. Neither is a reference, and neither is a
  // binding in any scope this scanner models — so a module-scope namesake must not be
  // resolved from one. Treating the name as a possible binding is the fail-closed
  // answer: the name stays unresolvable instead of resolving to a definition that is
  // not a use.
  if (previous !== undefined && previous.type === "punct") {
    const memberStart =
      previous.value === "{" ||
      previous.value === "}" ||
      previous.value === ";" ||
      previous.value === "," ||
      previous.value === "*";
    if (
      memberStart &&
      next !== undefined &&
      next.type === "punct" &&
      next.value === "(" &&
      groupInfo.opener[index + 1]?.followsBody === true
    ) {
      return true;
    }
    if (memberStart && next !== undefined && next.type === "punct" && next.value === "=") {
      return true;
    }
  }
  if (
    previous !== undefined &&
    previous.type === "identifier" &&
    (previous.value === "static" ||
      previous.value === "async" ||
      previous.value === "get" ||
      previous.value === "set") &&
    next !== undefined &&
    next.type === "punct" &&
    next.value === "(" &&
    groupInfo.opener[index + 1]?.followsBody === true
  ) {
    return true;
  }

  if (inParameterList(groupInfo, index)) return true;
  if (inPattern(groupInfo, index)) return true;

  return false;
}
