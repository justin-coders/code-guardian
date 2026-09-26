/**
 * Code Guardian — API Route Acquisition Policy (Phase 18)
 *
 * A dependency-free, deterministic **tokenizer plus route-declaration scanner** for
 * JavaScript and TypeScript source. It answers exactly one question: *which HTTP
 * routes does this module statically declare, on a route registrar whose framework
 * the module itself establishes?*
 *
 * ### Why a tokenizer and not a regular expression
 *
 * The same reason Phase 16 gave, restated because it is the whole security property:
 * a pattern search over raw bytes cannot tell `app.get("/users", h)` from the same
 * characters inside a comment, a string or a template. This module reuses the Phase 16
 * lexer (`tokenizeModule`), so strings, templates, regular expressions and comments
 * are opaque single tokens, and then scans the token stream. Text inside a comment or
 * a string can therefore never become a route.
 *
 * ### What "statically provable" means here
 *
 * A route is recorded only when *both* halves are established by the module's own
 * text:
 *
 *   1. the **receiver** is an object this module bound to a supported framework
 *      factory — `const app = express()`, `const router = express.Router()`,
 *      `const app = require("fastify")()`, or the same through an `import` alias; and
 *   2. the **path** is a plain string literal beginning with `/` — never a template,
 *      never a concatenation, never a computed value.
 *
 * Everything else that *looks* route-shaped is recorded as an **observation**, not a
 * route: `cache.get("/x")` (a receiver this module never bound to a framework),
 * `app.get(path, h)` (a computed path), `app.get("/a" + suffix, h)` (a concatenation),
 * `fastify.route({ method, url, handler })` (the object shorthand, whose `url` lives
 * inside an object this scanner does not interpret). An observation carries a closed
 * reason and makes no claim about what the occurrence denotes.
 *
 * ### Supported frameworks, and the unsupported ones
 *
 * Express and Fastify only, because those are the two whose registrar shape
 * (`RECEIVER.VERB("/path", handler)`) this scanner can establish from a token stream.
 * A module that imports a framework this build does not support (Koa, Hapi, NestJS,
 * Next.js, Remix, tRPC, GraphQL, Socket.IO, …) is recorded with that framework named
 * and `supported: false`; a route-shaped call on its receiver is an observation with
 * reason `framework-unsupported`, never a route. No unsupported framework is ever
 * guessed at.
 *
 * ### What it deliberately does not do
 *
 * No handler resolution (that needs the symbol graph and belongs to the model), no
 * middleware ordering, no route composition across modules, no runtime registration,
 * no decorators, no reflection, no `require`-time express enumeration, no process, no
 * network, no clock, no environment, no filesystem write.
 */

import {
  IMPORT_ACQUISITION_LIMITS,
  isModuleFileExtension,
  isParsedModuleExtension,
  moduleLanguageOf,
  tokenizeModule,
} from "./imports.js";

export { isModuleFileExtension, isParsedModuleExtension, moduleLanguageOf };

/** Version of the scanner's record shape (not of the model). */
export const API_SCANNER_VERSION = "1";

/** Frameworks whose registrar shape this scanner can establish. */
export const API_FRAMEWORKS = Object.freeze({
  EXPRESS: "express",
  FASTIFY: "fastify",
});

/** The supported framework vocabulary, as a list. */
export const API_FRAMEWORK_VALUES = Object.freeze(Object.values(API_FRAMEWORKS));

/** What kind of route registrar a binding is. */
export const API_RECEIVER_KINDS = Object.freeze({
  APP: "app",
  ROUTER: "router",
});

/**
 * Frameworks this build recognises by their module specifier but does not support.
 *
 * The map is deliberately conservative: a specifier that is not here produces no
 * framework attribution at all, so an unknown library is *unknown*, not "unsupported".
 * A specifier that *is* here makes a route-shaped call on its receiver an observation
 * with `framework-unsupported`, which is the honest answer for a Koa/Hapi/Nest app.
 */
export const API_UNSUPPORTED_FRAMEWORKS = Object.freeze({
  koa: "koa",
  "@koa/router": "koa",
  hapi: "hapi",
  "@hapi/hapi": "hapi",
  "@nestjs/common": "nestjs",
  "@nestjs/core": "nestjs",
  next: "next",
  "@remix-run/node": "remix",
  "@remix-run/express": "remix",
  "@remix-run/server-runtime": "remix",
  "@trpc/server": "trpc",
  graphql: "graphql",
  "apollo-server": "apollo",
  "@apollo/server": "apollo",
  "socket.io": "socket.io",
  ws: "ws",
  restify: "restify",
  polka: "polka",
  "@feathersjs/feathers": "feathers",
  "@adonisjs/core": "adonisjs",
  "@hono/node-server": "hono",
  hono: "hono",
});

/** The object-shorthand method whose argument this scanner refuses to interpret. */
export const API_OBJECT_SHORTHAND_METHOD = "route";

/** The HTTP methods a route declaration may state. A closed vocabulary. */
export const API_HTTP_METHODS = Object.freeze([
  "get",
  "post",
  "put",
  "patch",
  "delete",
  "head",
  "options",
  "all",
]);

const HTTP_METHOD_SET = new Set(API_HTTP_METHODS);

/** The upper-cased method vocabulary recorded on a route. */
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

const ROUTE_METHOD_SET = new Set(API_ROUTE_METHODS);

/**
 * Why a route-shaped occurrence produced no route. A closed vocabulary.
 *
 *   receiver-not-established   the `RECEIVER.VERB("/path")` receiver was never bound
 *                              to a framework factory in this module
 *   framework-unsupported      the receiver is bound to a framework this build does
 *                              not support (Koa, Hapi, NestJS, …)
 *   path-not-established       the first argument is not a plain string literal
 *   path-computed              the first argument is a template literal
 *   path-concatenated          the first argument is a string that is concatenated
 *   shorthand-not-established  the object shorthand (`route({ … })`) whose path is
 *                              inside an object this scanner does not interpret
 *   method-not-established     the chained call states a method this build does not
 *                              recognise
 */
export const API_SHAPE_REASONS = Object.freeze({
  RECEIVER_NOT_ESTABLISHED: "receiver-not-established",
  FRAMEWORK_UNSUPPORTED: "framework-unsupported",
  PATH_NOT_ESTABLISHED: "path-not-established",
  PATH_COMPUTED: "path-computed",
  PATH_CONCATENATED: "path-concatenated",
  SHORTHAND_NOT_ESTABLISHED: "shorthand-not-established",
  METHOD_NOT_ESTABLISHED: "method-not-established",
});

/** The shape-reason vocabulary as a list, for validation. */
export const API_SHAPE_REASON_VALUES = Object.freeze(Object.values(API_SHAPE_REASONS));

/** What a module source turned out to be, from the detector's point of view. */
export const API_SOURCE_STATUSES = Object.freeze({
  PARSED: "parsed",
  UNSUPPORTED: "unsupported",
  FAILED: "failed",
  NOT_INSPECTED: "not-inspected",
});

/** The source-status vocabulary as a list, for validation. */
export const API_SOURCE_STATUS_VALUES = Object.freeze(Object.values(API_SOURCE_STATUSES));

/** Why a module source could not be scanned. A closed vocabulary. */
export const API_SOURCE_REASONS = Object.freeze({
  FORMAT_NOT_INTERPRETED: "format-not-interpreted",
  UNREADABLE: "unreadable",
  NOT_TEXT: "not-text",
  BUDGET_EXHAUSTED: "budget-exhausted",
});

/** The source-reason vocabulary as a list, for validation. */
export const API_SOURCE_REASON_VALUES = Object.freeze(Object.values(API_SOURCE_REASONS));

/** Lexical problems that void this scanner's own establishment claim. */
export const API_LEXICAL_PROBLEMS = Object.freeze([
  "unterminated-comment",
  "unterminated-string",
  "unterminated-template",
  "unterminated-regex",
  "unlexable-character",
  "token-limit",
  "unbalanced-groups",
]);

/** Problems the scanner records on a source it could not fully establish. */
export const API_PROBLEMS = Object.freeze({
  LEXICAL_FAILURE: "lexical-failure",
  TOKEN_LIMIT: "token-limit",
  UNBALANCED_GROUPS: "unbalanced-groups",
  ROUTE_LIMIT: "route-limit",
  RECEIVER_LIMIT: "receiver-limit",
  SHAPE_LIMIT: "shape-limit",
});

/** The problem vocabulary as a list, for validation. */
export const API_PROBLEM_VALUES = Object.freeze(Object.values(API_PROBLEMS));

/**
 * Hard bounds on one file's route acquisition.
 *
 * Everything is bounded and every bound that bites is recorded, so a bounded scan is
 * recognizable as bounded rather than mistaken for a complete one.
 */
export const API_ACQUISITION_LIMITS = Object.freeze({
  /** Module source files read in one scan. */
  maxFiles: 2000,
  /** Bytes read from any single module source. */
  maxFileBytes: IMPORT_ACQUISITION_LIMITS.maxFileBytes,
  /** Bytes read across all module sources in one scan. */
  maxTotalBytes: IMPORT_ACQUISITION_LIMITS.maxTotalBytes,
  /** Tokens lexed from any single module source. */
  maxTokensPerFile: IMPORT_ACQUISITION_LIMITS.maxTokensPerFile,
  /** Route declarations recorded from any single source. */
  maxRoutesPerFile: 1024,
  /** Framework bindings recorded from any single source. */
  maxReceiversPerFile: 256,
  /** Route-shaped observations recorded from any single source. */
  maxShapesPerFile: 1024,
  /** Tokens a single import clause may span before it is abandoned. */
  maxClauseTokens: IMPORT_ACQUISITION_LIMITS.maxClauseTokens,
  /** Longest receiver/alias name recorded. */
  maxNameLength: 256,
  /** Longest route path recorded. */
  maxPathLength: 2048,
  /** Arguments of one route call this scanner will classify. */
  maxArgumentsPerCall: 64,
  /** Chained methods after `route("/x")` this scanner will follow. */
  maxChainMethods: 16,
});

// ── Token helpers ────────────────────────────────────────────────────────────

const OPENERS = new Map([
  ["(", ")"],
  ["[", "]"],
  ["{", "}"],
]);

const CLOSERS = new Set([")", "]", "}"]);

/** A punct token with a given value. */
function isPunct(token, value) {
  return token !== undefined && token.type === "punct" && token.value === value;
}

/** An identifier token with a given value. */
function isIdent(token, value) {
  return token !== undefined && token.type === "identifier" && token.value === value;
}

/** Any identifier token. */
function isAnyIdent(token) {
  return token !== undefined && token.type === "identifier";
}

/** A bounded, printable identifier. */
export function isUsableApiName(name) {
  if (typeof name !== "string" || name.length === 0) return false;
  if (name.length > API_ACQUISITION_LIMITS.maxNameLength) return false;
  for (let index = 0; index < name.length; index += 1) {
    const code = name.charCodeAt(index);
    if (code < 33 || code > 126) return false;
  }
  return true;
}

/** A bounded, printable route path. */
export function isUsableRoutePath(path) {
  if (typeof path !== "string" || path.length === 0) return false;
  if (path.length > API_ACQUISITION_LIMITS.maxPathLength) return false;
  for (let index = 0; index < path.length; index += 1) {
    const code = path.charCodeAt(index);
    if (code < 32 || code === 127) return false;
  }
  return true;
}

/** Add a problem once. */
function note(problems, reason) {
  if (!problems.includes(reason)) problems.push(reason);
}

/**
 * Find the token index of the closer matching the opener at `openIndex`.
 *
 * @returns {number} The closer index, or `-1` when the input is unbalanced.
 */
function findMatching(tokens, openIndex) {
  const open = tokens[openIndex]?.value;
  const close = OPENERS.get(open);
  if (close === undefined) return -1;
  let depth = 0;
  for (let index = openIndex; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token.type !== "punct") continue;
    if (token.value === open) depth += 1;
    else if (token.value === close) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

/**
 * Split a call's arguments into token ranges.
 *
 * @param {object[]} tokens
 * @param {number} openIndex Index of the `(`.
 * @param {number} limit Maximum arguments to return.
 * @returns {Array<{start: number, end: number}>} Ranges are inclusive `[start, end]`.
 */
function splitArguments(tokens, openIndex, limit) {
  const closeIndex = findMatching(tokens, openIndex);
  if (closeIndex < 0) return [];
  const args = [];
  let depth = 0;
  let start = openIndex + 1;
  for (let index = openIndex + 1; index < closeIndex; index += 1) {
    const token = tokens[index];
    if (token.type === "punct") {
      if (OPENERS.has(token.value)) depth += 1;
      else if (CLOSERS.has(token.value)) depth -= 1;
      else if (token.value === "," && depth === 0) {
        if (start < index) args.push({ start, end: index - 1 });
        else args.push({ start, end: start - 1, empty: true });
        start = index + 1;
        if (args.length >= limit) return args;
        continue;
      }
    }
  }
  if (start < closeIndex) args.push({ start, end: closeIndex - 1 });
  else if (start === closeIndex && args.length === 0) return [];
  return args;
}

/** The first significant token index of a range. */
function firstToken(tokens, range) {
  return range.start <= range.end ? tokens[range.start] : undefined;
}

/**
 * Classify a route-call argument.
 *
 * @returns {{form: string, name: string|null, member: string|null}|null}
 *   `form` is one of `reference`, `inline`, `options`, `other`; `null` when the range
 *   is empty.
 */
function classifyArgument(tokens, range) {
  if (range.empty === true || range.start > range.end) return null;
  const first = firstToken(tokens, range);

  // An object literal spanning the whole argument is an options bag.
  if (isPunct(first, "{")) return { form: "options", name: null, member: null };

  // `function (…) {…}` / `async function …`.
  if (isIdent(first, "function")) return { form: "inline", name: null, member: null };
  if (isIdent(first, "async") && isIdent(tokens[range.start + 1], "function")) {
    return { form: "inline", name: null, member: null };
  }

  // A single identifier: `handler`.
  if (range.start === range.end && isAnyIdent(first)) {
    return { form: "reference", name: first.value, member: null };
  }

  // A member expression: `controller.list`.
  if (
    range.end === range.start + 2 &&
    isAnyIdent(tokens[range.start]) &&
    isPunct(tokens[range.start + 1], ".") &&
    isAnyIdent(tokens[range.start + 2])
  ) {
    return {
      form: "reference",
      name: tokens[range.start].value,
      member: tokens[range.start + 2].value,
    };
  }

  // An arrow function, at top level of the argument.
  let depth = 0;
  for (let index = range.start; index <= range.end; index += 1) {
    const token = tokens[index];
    if (token.type !== "punct") continue;
    if (OPENERS.has(token.value)) depth += 1;
    else if (CLOSERS.has(token.value)) depth -= 1;
    else if (token.value === "=>" && depth === 0) {
      return { form: "inline", name: null, member: null };
    }
  }

  return { form: "other", name: null, member: null };
}

// ── Framework binding detection ──────────────────────────────────────────────

/** The framework a bare module specifier names, or `null`. */
function frameworkOfSpecifier(specifier) {
  if (specifier === "express") return { framework: API_FRAMEWORKS.EXPRESS, supported: true };
  if (specifier === "fastify") return { framework: API_FRAMEWORKS.FASTIFY, supported: true };
  const unsupported = API_UNSUPPORTED_FRAMEWORKS[specifier];
  if (unsupported !== undefined) return { framework: unsupported, supported: false };
  return null;
}

/**
 * Collect the module's framework aliases.
 *
 * An alias is a name the module bound to a framework *module* — through an `import`
 * default/namespace clause or through an assignment from `require("…")` — which is
 * what makes `express()` / `express.Router()` / `fastify()` recognisable as factory
 * calls without resolving anything.
 *
 * @returns {Map<string, {framework: string, supported: boolean}>}
 */
function collectAliases(tokens, problems, limits) {
  const aliases = new Map();
  const clauseLimit = limits.maxClauseTokens;

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];

    // `import X from "express"` / `import * as X from "express"`
    if (isIdent(token, "import")) {
      const windowEnd = Math.min(tokens.length, index + clauseLimit);
      for (let cursor = index + 1; cursor < windowEnd; cursor += 1) {
        const inner = tokens[cursor];
        if (inner.type === "string") break;
        if (isIdent(inner, "from")) {
          const spec = tokens[cursor + 1];
          if (spec !== undefined && spec.type === "string") {
            const found = frameworkOfSpecifier(spec.value);
            if (found !== null) {
              const alias = importAliasName(tokens, index, cursor);
              if (alias !== null && isUsableApiName(alias)) aliases.set(alias, found);
            }
          }
          break;
        }
      }
      continue;
    }

    // `const X = require("express")`
    if (isIdent(token, "require") && isPunct(tokens[index + 1], "(")) {
      const spec = tokens[index + 2];
      if (spec !== undefined && spec.type === "string") {
        const found = frameworkOfSpecifier(spec.value);
        if (found !== null) {
          const name = tokens[index - 2];
          if (isPunct(tokens[index - 1], "=") && isAnyIdent(name) && isUsableApiName(name.value)) {
            aliases.set(name.value, found);
          }
        }
      }
      continue;
    }
  }

  if (aliases.size > limits.maxReceiversPerFile) note(problems, API_PROBLEMS.RECEIVER_LIMIT);
  return aliases;
}

/**
 * The local name an `import` clause binds for a framework module.
 *
 * `import X from "…"` → `X`; `import * as X from "…"` → `X`; `import X, { … } from …`
 * → `X`. An import that binds only named members (`import { Router } from …`) binds no
 * module alias this scanner can turn into a factory, so it returns `null`.
 */
function importAliasName(tokens, importIndex, fromIndex) {
  const first = tokens[importIndex + 1];
  if (isIdent(first, "type")) {
    const after = tokens[importIndex + 2];
    if (isAnyIdent(after)) return after.value;
    return null;
  }
  if (isPunct(first, "*")) {
    // `* as X`
    if (isIdent(tokens[importIndex + 2], "as") && isAnyIdent(tokens[importIndex + 3])) {
      return tokens[importIndex + 3].value;
    }
    return null;
  }
  if (isPunct(first, "{")) return null;
  if (isAnyIdent(first) && importIndex + 1 < fromIndex) return first.value;
  return null;
}

/**
 * Collect the module's route registrars.
 *
 * A registrar is a name the module bound to the *result* of a framework factory call —
 * `const app = express()`, `const router = express.Router()`,
 * `const app = require("fastify")()`, `const app = new Koa()`.
 *
 * @returns {Array<{name: string, framework: string, supported: boolean, kind: string}>}
 */
function collectReceivers(tokens, aliases, problems, limits) {
  const receivers = [];

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (
      !(
        isIdent(token, "const") ||
        isIdent(token, "let") ||
        isIdent(token, "var")
      )
    ) {
      continue;
    }
    const name = tokens[index + 1];
    if (!isAnyIdent(name) || !isUsableApiName(name.value)) continue;
    if (!isPunct(tokens[index + 2], "=")) continue;

    let cursor = index + 3;
    if (isIdent(tokens[cursor], "new")) cursor += 1;

    // `require("…")(…)`
    if (isIdent(tokens[cursor], "require") && isPunct(tokens[cursor + 1], "(")) {
      const spec = tokens[cursor + 2];
      if (
        spec !== undefined &&
        spec.type === "string" &&
        isPunct(tokens[cursor + 3], ")") &&
        isPunct(tokens[cursor + 4], "(")
      ) {
        const found = frameworkOfSpecifier(spec.value);
        if (found !== null) {
          receivers.push({
            name: name.value,
            framework: found.framework,
            supported: found.supported,
            kind: API_RECEIVER_KINDS.APP,
          });
        }
      }
      continue;
    }

    if (!isAnyIdent(tokens[cursor])) continue;

    // `X.Router(…)`
    if (isPunct(tokens[cursor + 1], ".") && isAnyIdent(tokens[cursor + 2])) {
      const base = tokens[cursor].value;
      const member = tokens[cursor + 2].value;
      const alias = aliases.get(base);
      if (
        alias !== undefined &&
        alias.framework === API_FRAMEWORKS.EXPRESS &&
        member === "Router" &&
        isPunct(tokens[cursor + 3], "(")
      ) {
        receivers.push({
          name: name.value,
          framework: API_FRAMEWORKS.EXPRESS,
          supported: true,
          kind: API_RECEIVER_KINDS.ROUTER,
        });
      }
      continue;
    }

    // `X(…)`
    if (isPunct(tokens[cursor + 1], "(")) {
      const alias = aliases.get(tokens[cursor].value);
      if (alias !== undefined) {
        receivers.push({
          name: name.value,
          framework: alias.framework,
          supported: alias.supported,
          kind: API_RECEIVER_KINDS.APP,
        });
      }
    }
  }

  if (receivers.length > limits.maxReceiversPerFile) note(problems, API_PROBLEMS.RECEIVER_LIMIT);
  return receivers.slice(0, limits.maxReceiversPerFile);
}

// ── Route extraction ─────────────────────────────────────────────────────────

/** Normalise a lower-case verb to its recorded upper-case method. */
function routeMethodOf(verb) {
  return verb.toUpperCase();
}

/**
 * Classify a route call's arguments into handler and middleware references.
 *
 * The last argument that is a reference or an inline function is the handler; every
 * earlier reference/inline argument is a middleware candidate. An options object is
 * skipped. This is a *positional* reading of the call, and the model states it as
 * such: it is not a claim about runtime ordering.
 */
function classifyCallArguments(tokens, openIndex, limits) {
  const ranges = splitArguments(tokens, openIndex, limits.maxArgumentsPerCall);
  const classified = [];
  for (const range of ranges) {
    const entry = classifyArgument(tokens, range);
    if (entry === null) continue;
    classified.push(entry);
  }

  const callables = [];
  for (let index = 0; index < classified.length; index += 1) {
    const entry = classified[index];
    if (entry.form === "reference" || entry.form === "inline") {
      callables.push({ ...entry, position: index });
    }
  }

  const handler = callables.length === 0 ? null : callables[callables.length - 1];
  const middleware = callables.slice(0, Math.max(0, callables.length - 1));
  return { handler, middleware };
}

/** Read a literal path from the token after an opening paren, or explain why not. */
function readPath(tokens, openIndex) {
  const target = tokens[openIndex + 1];
  if (target === undefined) return { path: null, reason: API_SHAPE_REASONS.PATH_NOT_ESTABLISHED };
  if (target.type === "template") return { path: null, reason: API_SHAPE_REASONS.PATH_COMPUTED };
  if (target.type !== "string") {
    return { path: null, reason: API_SHAPE_REASONS.PATH_NOT_ESTABLISHED };
  }
  const following = tokens[openIndex + 2];
  if (isPunct(following, "+")) return { path: null, reason: API_SHAPE_REASONS.PATH_CONCATENATED };
  if (!target.value.startsWith("/")) {
    return { path: null, reason: API_SHAPE_REASONS.PATH_NOT_ESTABLISHED };
  }
  if (!isUsableRoutePath(target.value)) {
    return { path: null, reason: API_SHAPE_REASONS.PATH_NOT_ESTABLISHED };
  }
  return { path: target.value, reason: null };
}

/** Whether a route call's path token looks route-shaped at all. */
function looksRouteShaped(tokens, openIndex) {
  const target = tokens[openIndex + 1];
  if (target === undefined) return false;
  if (target.type === "template") return true;
  if (target.type !== "string") return false;
  return target.value.startsWith("/");
}

/**
 * Scan module source for its route declarations.
 *
 * @param {string} text Source text.
 * @param {object} [options]
 * @param {string} [options.extension] Lower-case extension including the dot.
 * @param {number} [options.maxTokens]
 * @returns {object} The scanner's record for this file.
 */
export function scanApiRoutes(text, options = {}) {
  const limits = API_ACQUISITION_LIMITS;
  const lexed = tokenizeModule(text, { maxTokens: options.maxTokens ?? limits.maxTokensPerFile });
  const tokens = lexed.tokens;
  const problems = [];

  for (const problem of lexed.problems) {
    if (API_LEXICAL_PROBLEMS.includes(problem)) note(problems, API_PROBLEMS.LEXICAL_FAILURE);
  }
  if (lexed.truncated && !problems.includes(API_PROBLEMS.LEXICAL_FAILURE)) {
    note(problems, API_PROBLEMS.TOKEN_LIMIT);
  }

  const aliases = collectAliases(tokens, problems, limits);
  const receiverList = collectReceivers(tokens, aliases, problems, limits);
  const receiverByName = new Map(receiverList.map((receiver) => [receiver.name, receiver]));

  const routes = [];
  const shapes = [];
  let routeLimitHit = false;
  let shapeLimitHit = false;

  const recordShape = (shape) => {
    if (shapes.length >= limits.maxShapesPerFile) {
      if (!shapeLimitHit) {
        shapeLimitHit = true;
        note(problems, API_PROBLEMS.SHAPE_LIMIT);
      }
      return;
    }
    shapes.push(shape);
  };

  const addRoute = (route) => {
    if (routes.length >= limits.maxRoutesPerFile) {
      if (!routeLimitHit) {
        routeLimitHit = true;
        note(problems, API_PROBLEMS.ROUTE_LIMIT);
      }
      return;
    }
    routes.push(route);
  };

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];

    // `RECEIVER.route("/path").VERB(handler…)`
    if (
      isIdent(token, "route") &&
      isPunct(tokens[index - 1], ".") &&
      isAnyIdent(tokens[index - 2]) &&
      isPunct(tokens[index + 1], "(")
    ) {
      const receiverName = tokens[index - 2].value;
      const receiver = receiverByName.get(receiverName);
      const openIndex = index + 1;
      const closeIndex = findMatching(tokens, openIndex);
      if (closeIndex < 0) continue;

      const read = readPath(tokens, openIndex);
      const receiverSupported = receiver !== undefined && receiver.supported;

      const chainStart = closeIndex + 1;
      const hasChain =
        isPunct(tokens[chainStart], ".") &&
        isAnyIdent(tokens[chainStart + 1]) &&
        isPunct(tokens[chainStart + 2], "(");

      if (!hasChain) {
        // `route("/x")` used as a value, or the object shorthand: a route-shaped
        // occurrence whose method this scanner cannot read.
        if (receiverSupported) {
          recordShape({
            receiver: receiverName,
            framework: receiver.framework,
            supported: true,
            method: null,
            path: read.path,
            reason: API_SHAPE_REASONS.SHORTHAND_NOT_ESTABLISHED,
          });
        }
        continue;
      }

      // Walk every chained method (`route("/x").get(h).post(h2)`), bounded by
      // `maxChainMethods`, so each `.VERB(...)` in the chain becomes its own route.
      let cursor = chainStart;
      let chained = 0;
      while (
        chained < limits.maxChainMethods &&
        isPunct(tokens[cursor], ".") &&
        isAnyIdent(tokens[cursor + 1]) &&
        isPunct(tokens[cursor + 2], "(")
      ) {
        const verb = tokens[cursor + 1].value;
        const callOpenIndex = cursor + 2;
        const callCloseIndex = findMatching(tokens, callOpenIndex);
        chained += 1;

        if (!HTTP_METHOD_SET.has(verb)) {
          if (receiverSupported) {
            recordShape({
              receiver: receiverName,
              framework: receiver.framework,
              supported: true,
              method: null,
              path: read.path,
              reason: API_SHAPE_REASONS.METHOD_NOT_ESTABLISHED,
            });
          }
          break;
        }

        if (!receiverSupported) {
          if (read.path !== null) {
            recordShape({
              receiver: receiverName,
              framework: receiver?.framework ?? null,
              supported: receiver?.supported === true,
              method: routeMethodOf(verb),
              path: read.path,
              reason:
                receiver !== undefined
                  ? API_SHAPE_REASONS.FRAMEWORK_UNSUPPORTED
                  : API_SHAPE_REASONS.RECEIVER_NOT_ESTABLISHED,
            });
          }
          break;
        }

        if (read.path === null) {
          recordShape({
            receiver: receiverName,
            framework: receiver.framework,
            supported: true,
            method: routeMethodOf(verb),
            path: null,
            reason: read.reason,
          });
          break;
        }

        const call = classifyCallArguments(tokens, callOpenIndex, limits);
        addRoute({
          method: routeMethodOf(verb),
          path: read.path,
          receiver: receiverName,
          framework: receiver.framework,
          receiverKind: receiver.kind,
          handler: call.handler,
          middleware: call.middleware,
          form: "chain",
        });

        if (callCloseIndex < 0) break;
        cursor = callCloseIndex + 1;
      }

      continue;
    }

    // `RECEIVER.VERB("/path", handler…)`
    if (isAnyIdent(token) && HTTP_METHOD_SET.has(token.value) && isPunct(tokens[index - 1], ".")) {
      const receiverToken = tokens[index - 2];
      if (!isAnyIdent(receiverToken)) continue;
      if (!isPunct(tokens[index + 1], "(")) continue;

      const receiverName = receiverToken.value;
      const receiver = receiverByName.get(receiverName);
      const openIndex = index + 1;

      const routeShaped = looksRouteShaped(tokens, openIndex);
      const read = readPath(tokens, openIndex);

      if (receiver === undefined || !receiver.supported) {
        // Only a path-shaped call on an unestablished/unsupported receiver is worth
        // recording: a bare `.get("x")` on an unknown object is not route-shaped.
        if (routeShaped) {
          recordShape({
            receiver: receiverName,
            framework: receiver?.framework ?? null,
            supported: receiver?.supported === true,
            method: routeMethodOf(token.value),
            path: read.path,
            reason:
              receiver !== undefined
                ? API_SHAPE_REASONS.FRAMEWORK_UNSUPPORTED
                : API_SHAPE_REASONS.RECEIVER_NOT_ESTABLISHED,
          });
        }
        continue;
      }

      if (read.path === null) {
        recordShape({
          receiver: receiverName,
          framework: receiver.framework,
          supported: true,
          method: routeMethodOf(token.value),
          path: null,
          reason: read.reason,
        });
        continue;
      }

      const call = classifyCallArguments(tokens, openIndex, limits);
      addRoute({
        method: routeMethodOf(token.value),
        path: read.path,
        receiver: receiverName,
        framework: receiver.framework,
        receiverKind: receiver.kind,
        handler: call.handler,
        middleware: call.middleware,
        form: "direct",
      });
    }
  }

  // `RECEIVER.route({ … })`, the object shorthand, was already recorded as an
  // observation by the branch above (its path token is `{`, so `readPath` establishes
  // no path and the missing chain is what makes it `shorthand-not-established`). Never
  // interpreted, because its `url` lives inside an object this scanner does not read.

  const unsupportedFrameworks = [];
  for (const receiver of receiverList) {
    if (!receiver.supported && !unsupportedFrameworks.includes(receiver.framework)) {
      unsupportedFrameworks.push(receiver.framework);
    }
  }
  unsupportedFrameworks.sort();

  const frameworks = [];
  for (const receiver of receiverList) {
    if (receiver.supported && !frameworks.includes(receiver.framework)) frameworks.push(receiver.framework);
  }
  frameworks.sort();

  const established = !problems.includes(API_PROBLEMS.LEXICAL_FAILURE);

  return {
    version: API_SCANNER_VERSION,
    established,
    truncated: routeLimitHit || shapeLimitHit || problems.includes(API_PROBLEMS.TOKEN_LIMIT),
    problems,
    frameworks,
    unsupportedFrameworks,
    aliases: [...aliases.entries()]
      .map(([name, entry]) => ({ name, framework: entry.framework, supported: entry.supported }))
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)),
    receivers: receiverList.slice().sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)),
    routes,
    shapes,
    counts: {
      tokens: tokens.length,
      routes: routes.length,
      shapes: shapes.length,
      receivers: receiverList.length,
    },
  };
}
