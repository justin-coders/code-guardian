/**
 * Code Guardian — Middleware & Authorization Acquisition Policy (Phase 19)
 *
 * A dependency-free, deterministic **tokenizer plus middleware-registration scanner** for
 * JavaScript and TypeScript source. It answers exactly one question: *which middleware
 * registrations does this module statically declare, on a framework receiver the module
 * itself establishes?*
 *
 * ### Why a tokenizer, and why the Phase 16 lexer again
 *
 * The same reason Phase 18 gave, restated because it is the whole security property: a
 * pattern search over raw bytes cannot tell `app.use(auth)` from the same characters
 * inside a comment, a string or a template. This module reuses `tokenizeModule`, so
 * strings, templates, regular expressions and comments are opaque single tokens, and then
 * scans the token stream. Text inside a comment or a string can therefore never become a
 * middleware registration.
 *
 * ### What "statically provable" means here
 *
 * A registration is recorded only when the *receiver* is an object this module bound to a
 * supported framework factory — established by exactly the Phase 18 detection, reused
 * verbatim through `establishFrameworkContext` rather than re-implemented, because a second
 * answer to "is this receiver an Express app?" is a second answer that can disagree.
 *
 *   app.use(auth)                  Express/Fastify `RECEIVER.use(…)`
 *   router.use(auth)               `RECEIVER.use(…)` on a `Router()` binding
 *   app.use("/api", auth)          a literal mount path prefix, then middleware
 *   app.use("/api", router)        a mount of a *receiver this module bound* — a router
 *   fastify.addHook("preHandler", auth)
 *                                  a lifecycle hook with a literal hook name
 *   fastify.register(plugin)       a plugin this module names
 *
 * Everything else middleware-shaped is recorded as an **observation**, not a registration:
 * `cache.use(value)` (a receiver this module never bound to a framework), `app.use([a, b])`
 * (a computed middleware array), `app.use(...middleware)` (a spread), `app.use(getMw())`
 * (runtime registration), `app.use(express.json())` (a member call), and any registration
 * inside a conditional or iterative block, whose applicability is not statically provable.
 * An observation carries a closed reason and makes no claim about what the occurrence
 * denotes.
 *
 * ### Ordering is the declared registration sequence, and nothing else
 *
 * Each registration carries a `sequence` — its ordinal position among the registrations
 * this module declares, in token order — plus the `path` prefix it was declared under.
 * That is the whole order model. This scanner never infers execution order, scheduling,
 * async flow, or whether a later registration can still affect an earlier route: those are
 * runtime facts and this layer is static.
 *
 * ### What it deliberately does not do
 *
 * No symbol resolution (that needs the symbol graph and belongs to the model), no
 * `require`-resolution of a mounted module, no function-body inspection, no decorator, no
 * reflection, no runtime enumeration, no process, no network, no clock, no environment, no
 * filesystem write. Whether a middleware was registered *before* or *after* a route
 * declaration in the same file is deliberately not modelled: the model states which
 * receiver a registration is on, which is the fact the text establishes.
 */

import { IMPORT_ACQUISITION_LIMITS, tokenizeModule } from "./imports.js";

import {
  API_ACQUISITION_LIMITS,
  API_RECEIVER_KINDS,
  API_SOURCE_REASONS,
  API_SOURCE_STATUSES,
  classifyArgument,
  establishFrameworkContext,
  isUsableApiName,
  isUsableRoutePath,
  splitArguments,
} from "./api.js";

export {
  isModuleFileExtension,
  isParsedModuleExtension,
  moduleLanguageOf,
} from "./imports.js";

/** Version of the scanner's record shape (not of the model). */
export const MIDDLEWARE_SCANNER_VERSION = "1";

/** The frameworks this scanner models middleware for. Reused from Phase 18. */
export const MIDDLEWARE_FRAMEWORKS = Object.freeze({
  EXPRESS: "express",
  FASTIFY: "fastify",
});

/** The source statuses, re-exported so the detector and the model share one vocabulary. */
export const MIDDLEWARE_SOURCE_STATUSES = API_SOURCE_STATUSES;
export const MIDDLEWARE_SOURCE_REASONS = API_SOURCE_REASONS;

/** Status/reason vocabularies as lists, for validation. */
export const MIDDLEWARE_SOURCE_STATUS_VALUES = Object.freeze(
  Object.values(MIDDLEWARE_SOURCE_STATUSES),
);
export const MIDDLEWARE_SOURCE_REASON_VALUES = Object.freeze(
  Object.values(MIDDLEWARE_SOURCE_REASONS),
);

/**
 * How a middleware became registered. A closed, three-value vocabulary.
 *
 *   use       `RECEIVER.use(…)`
 *   hook      `RECEIVER.addHook("name", …)`
 *   register  `RECEIVER.register(plugin)`
 */
export const MIDDLEWARE_REGISTRATIONS = Object.freeze({
  USE: "use",
  HOOK: "hook",
  REGISTER: "register",
});

/** The registration vocabulary as a list, for validation. */
export const MIDDLEWARE_REGISTRATION_VALUES = Object.freeze(
  Object.values(MIDDLEWARE_REGISTRATIONS),
);

/**
 * The receiver scope a registration declares. A closed, three-value vocabulary.
 *
 *   app     registered on a receiver bound to an application factory (`express()`)
 *   router  registered on a receiver bound to a router factory (`express.Router()`)
 *   hook    registered as a framework lifecycle hook (`addHook`)
 */
export const MIDDLEWARE_SCOPES = Object.freeze({
  APP: "app",
  ROUTER: "router",
  HOOK: "hook",
});

/** The scope vocabulary as a list, for validation. */
export const MIDDLEWARE_SCOPE_VALUES = Object.freeze(Object.values(MIDDLEWARE_SCOPES));

/**
 * The Fastify lifecycle hooks this build names.
 *
 * Documentation and reporting only: a hook whose name is a literal string is recorded even
 * when the name is not in this list, because the list is a property of one framework
 * version and refusing an unknown name would turn a version change into a false negative.
 * A hook whose name is *not* a literal is an observation.
 */
export const MIDDLEWARE_HOOK_NAMES = Object.freeze([
  "onRequest",
  "preParsing",
  "preValidation",
  "preHandler",
  "preSerialization",
  "onSend",
  "onResponse",
  "onError",
  "onTimeout",
  "onRequestAbort",
  "onReady",
  "onListen",
  "onRoute",
  "onRegister",
  "onClose",
  "preClose",
]);

/** The hook-name vocabulary as a list, for validation and reporting. */
export const MIDDLEWARE_HOOK_NAME_VALUES = MIDDLEWARE_HOOK_NAMES;

/**
 * Why a middleware-shaped occurrence produced no registration. A closed vocabulary.
 *
 *   middleware-not-established   no module-scope binding of that name exists in the file
 *   middleware-not-unique        the name is bound elsewhere in the file too
 *   resolution-not-established   the file contains a dynamic-scope construct (`eval` /
 *                                `with`), which voids every uniqueness proof in it
 *   member-expression            a member access (`express.json`, `security.auth`):
 *                                runtime dispatch, so no single symbol is established
 *   inline-middleware            an inline function the repository does not name
 *   array-not-established        a computed middleware array (`[a, b]`)
 *   spread-not-established       a spread argument (`...middleware`)
 *   registration-not-established a call, a concatenation or any other computed argument —
 *                                that is, runtime registration
 *   conditional-not-established  the registration sits inside a conditional or iterative
 *                                block, so whether it applies is not statically provable
 *   hook-name-not-established    `addHook` whose name is not a literal string
 *   framework-unsupported        the receiver is bound to a framework this build does not
 *                                support (Koa, Hapi, NestJS, …)
 */
export const MIDDLEWARE_UNRESOLVED_REASONS = Object.freeze({
  MIDDLEWARE_NOT_ESTABLISHED: "middleware-not-established",
  MIDDLEWARE_NOT_UNIQUE: "middleware-not-unique",
  RESOLUTION_NOT_ESTABLISHED: "resolution-not-established",
  MEMBER_EXPRESSION: "member-expression",
  INLINE_MIDDLEWARE: "inline-middleware",
  ARRAY_NOT_ESTABLISHED: "array-not-established",
  SPREAD_NOT_ESTABLISHED: "spread-not-established",
  REGISTRATION_NOT_ESTABLISHED: "registration-not-established",
  CONDITIONAL_NOT_ESTABLISHED: "conditional-not-established",
  HOOK_NAME_NOT_ESTABLISHED: "hook-name-not-established",
  FRAMEWORK_UNSUPPORTED: "framework-unsupported",
});

/** The unresolved-reason vocabulary as a list, for validation. */
export const MIDDLEWARE_UNRESOLVED_REASON_VALUES = Object.freeze(
  Object.values(MIDDLEWARE_UNRESOLVED_REASONS),
);

/** The callable forms a middleware candidate can take, matching the Phase 18 shape. */
export const MIDDLEWARE_CALLABLE_FORMS = Object.freeze(["reference", "inline"]);

/** Lexical problems that void this scanner's own establishment claim. */
export const MIDDLEWARE_LEXICAL_PROBLEMS = Object.freeze([
  "unterminated-comment",
  "unterminated-string",
  "unterminated-template",
  "unterminated-regex",
  "unlexable-character",
  "token-limit",
  "unbalanced-groups",
]);

/** Problems the scanner records on a source it could not fully establish. */
export const MIDDLEWARE_PROBLEMS = Object.freeze({
  LEXICAL_FAILURE: "lexical-failure",
  TOKEN_LIMIT: "token-limit",
  UNBALANCED_GROUPS: "unbalanced-groups",
  REGISTRATION_LIMIT: "registration-limit",
  MOUNT_LIMIT: "mount-limit",
  OBSERVATION_LIMIT: "observation-limit",
  RECEIVER_LIMIT: "receiver-limit",
});

/** The problem vocabulary as a list, for validation. */
export const MIDDLEWARE_PROBLEM_VALUES = Object.freeze(Object.values(MIDDLEWARE_PROBLEMS));

/**
 * Hard bounds on one file's middleware acquisition.
 *
 * Everything is bounded and every bound that bites is recorded, so a bounded scan is
 * recognizable as bounded rather than mistaken for a complete one.
 */
export const MIDDLEWARE_ACQUISITION_LIMITS = Object.freeze({
  /** Module source files read in one scan. */
  maxFiles: 2000,
  /** Bytes read from any single module source. */
  maxFileBytes: IMPORT_ACQUISITION_LIMITS.maxFileBytes,
  /** Bytes read across all module sources in one scan. */
  maxTotalBytes: IMPORT_ACQUISITION_LIMITS.maxTotalBytes,
  /** Tokens lexed from any single module source. */
  maxTokensPerFile: IMPORT_ACQUISITION_LIMITS.maxTokensPerFile,
  /** Registrations recorded from any single source. */
  maxRegistrationsPerFile: 1024,
  /** Mounts recorded from any single source. */
  maxMountsPerFile: 256,
  /** Middleware observations recorded from any single source. */
  maxObservationsPerFile: 1024,
  /** Framework bindings recorded from any single source. */
  maxReceiversPerFile: API_ACQUISITION_LIMITS.maxReceiversPerFile,
  /** Tokens a single import clause may span before it is abandoned. */
  maxClauseTokens: API_ACQUISITION_LIMITS.maxClauseTokens,
  /** Longest receiver/alias name recorded. */
  maxNameLength: API_ACQUISITION_LIMITS.maxNameLength,
  /** Longest mount path recorded. */
  maxPathLength: API_ACQUISITION_LIMITS.maxPathLength,
  /** Arguments of one registration call this scanner will classify. */
  maxArgumentsPerCall: API_ACQUISITION_LIMITS.maxArgumentsPerCall,
  /** Enclosing conditional blocks followed before a registration is called conditional. */
  maxConditionalDepth: 8,
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

/** Add a problem once. */
function note(problems, reason) {
  if (!problems.includes(reason)) problems.push(reason);
}

/** Whether an argument range begins with a spread operator. */
function isSpreadRange(tokens, range) {
  return isPunct(tokens[range.start], "...");
}

/** Whether an argument range is a single string literal. */
function isStringRange(tokens, range) {
  return range.start === range.end && tokens[range.start]?.type === "string";
}

/**
 * Identifiers that introduce a conditional or iterative block.
 *
 * A registration inside one of these blocks is not statically provable: whether it runs
 * depends on a condition or a loop. `try` and `finally` are deliberately absent — they are
 * not conditions, and rejecting a registration merely because it sits in a `try` would
 * trade a real fact for a false unknown.
 */
const CONDITIONAL_KEYWORDS = new Set(["if", "else", "for", "while", "switch", "catch", "do"]);

/** Find the opener matching the closer at `closeIndex`, or `-1`. */
function findOpener(tokens, closeIndex) {
  const close = tokens[closeIndex]?.value;
  if (!CLOSERS.has(close)) return -1;
  let open = null;
  for (const [candidate, closer] of OPENERS) {
    if (closer === close) {
      open = candidate;
      break;
    }
  }
  let depth = 0;
  for (let index = closeIndex; index >= 0; index -= 1) {
    const token = tokens[index];
    if (token.type !== "punct") continue;
    if (token.value === close) depth += 1;
    else if (token.value === open) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

/**
 * Whether the block opened by the `{` at `index` is a conditional or iterative block.
 *
 * The decision looks only at the tokens immediately before the brace — `if (…) {`,
 * `else {`, `for (…) {`, `while (…) {`, `switch (…) {`, `catch {`, `do {` — so a function
 * body, an object literal and a plain block are all *not* conditional. This is a lexical
 * judgement by construction: nothing here evaluates the condition.
 */
function opensConditionalBlock(tokens, index) {
  const before = tokens[index - 1];
  if (before === undefined) return false;
  if (before.type === "identifier") return CONDITIONAL_KEYWORDS.has(before.value);
  if (!isPunct(before, ")")) return false;
  const opener = findOpener(tokens, index - 1);
  if (opener < 0) return false;
  const head = tokens[opener - 1];
  return head !== undefined && head.type === "identifier" && CONDITIONAL_KEYWORDS.has(head.value);
}

/**
 * The number of enclosing conditional blocks for every token index.
 *
 * One bounded pass, so a registration can state whether its applicability was statically
 * provable without a second traversal.
 */
function conditionalDepths(tokens) {
  const depths = new Array(tokens.length).fill(0);
  const stack = [];
  let depth = 0;
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token.type === "punct" && token.value === "{") {
      const conditional = opensConditionalBlock(tokens, index);
      stack.push(conditional);
      depth += conditional ? 1 : 0;
    }
    depths[index] = depth;
    if (token.type === "punct" && token.value === "}") {
      const conditional = stack.pop() === true;
      if (conditional) depth -= 1;
    }
  }
  return depths;
}

// ── Argument classification ──────────────────────────────────────────────────

/**
 * The middleware candidates and observations one registration call states.
 *
 * @param {object[]} tokens
 * @param {number} openIndex Index of the call's `(`.
 * @param {number} skip Number of leading arguments to ignore (a mount path).
 * @param {Set<string>} receiverNames Names this module bound to a framework factory.
 * @returns {{middleware: object[], unresolved: object[], mounts: object[]}}
 */
function classifyRegistrationArguments(tokens, openIndex, skip, receiverNames) {
  const ranges = splitArguments(tokens, openIndex, MIDDLEWARE_ACQUISITION_LIMITS.maxArgumentsPerCall);
  const middleware = [];
  const unresolved = [];
  const mounts = [];

  for (let position = 0; position < ranges.length; position += 1) {
    if (position < skip) continue;
    const range = ranges[position];
    if (isSpreadRange(tokens, range)) {
      unresolved.push({ reason: MIDDLEWARE_UNRESOLVED_REASONS.SPREAD_NOT_ESTABLISHED, name: null, member: null, form: null });
      continue;
    }
    const first = tokens[range.start];
    if (isPunct(first, "[")) {
      unresolved.push({ reason: MIDDLEWARE_UNRESOLVED_REASONS.ARRAY_NOT_ESTABLISHED, name: null, member: null, form: null });
      continue;
    }

    const entry = classifyArgument(tokens, range);
    if (entry === null) {
      unresolved.push({ reason: MIDDLEWARE_UNRESOLVED_REASONS.REGISTRATION_NOT_ESTABLISHED, name: null, member: null, form: null });
      continue;
    }
    if (entry.form === "reference" && entry.member === null && receiverNames.has(entry.name)) {
      // A receiver this module itself bound, passed to `use`: a mount.
      mounts.push({ child: entry.name });
      continue;
    }
    if (entry.form === "reference") {
      middleware.push({ form: "reference", name: entry.name, member: entry.member });
      continue;
    }
    if (entry.form === "inline") {
      middleware.push({ form: "inline", name: null, member: null });
      continue;
    }
    unresolved.push({
      reason: MIDDLEWARE_UNRESOLVED_REASONS.REGISTRATION_NOT_ESTABLISHED,
      name: entry.name,
      member: entry.member,
      form: null,
    });
  }

  return { middleware, unresolved, mounts };
}

/**
 * Read a literal mount path prefix from a registration's first argument.
 *
 * @returns {{path: string|null, skip: number}}
 */
function readMountPath(tokens, range) {
  if (range === undefined) return { path: null, skip: 0 };
  const target = tokens[range.start];
  if (target === undefined || target.type !== "string") return { path: null, skip: 0 };
  if (!target.value.startsWith("/")) return { path: null, skip: 0 };
  // `use("/api" + suffix, …)` is a concatenation, not a literal mount path.
  if (isPunct(tokens[range.start + 1], "+")) return { path: null, skip: 0 };
  if (!isUsableRoutePath(target.value)) return { path: null, skip: 0 };
  return { path: target.value, skip: 1 };
}

// ── Scanner ──────────────────────────────────────────────────────────────────

/**
 * Scan module source for its middleware registrations.
 *
 * @param {string} text Source text.
 * @param {object} [options]
 * @param {number} [options.maxTokens]
 * @returns {object} The scanner's record for this file.
 */
export function scanMiddleware(text, options = {}) {
  const limits = MIDDLEWARE_ACQUISITION_LIMITS;
  const lexed = tokenizeModule(text, {
    maxTokens: options.maxTokens ?? limits.maxTokensPerFile,
  });
  const tokens = lexed.tokens;
  const problems = [];

  for (const problem of lexed.problems) {
    if (MIDDLEWARE_LEXICAL_PROBLEMS.includes(problem)) {
      note(problems, MIDDLEWARE_PROBLEMS.LEXICAL_FAILURE);
    }
  }
  if (lexed.truncated && !problems.includes(MIDDLEWARE_PROBLEMS.LEXICAL_FAILURE)) {
    note(problems, MIDDLEWARE_PROBLEMS.TOKEN_LIMIT);
  }

  const frameworkContext = establishFrameworkContext(tokens, problems, {
    ...API_ACQUISITION_LIMITS,
    maxReceiversPerFile: limits.maxReceiversPerFile,
    maxClauseTokens: limits.maxClauseTokens,
    maxNameLength: limits.maxNameLength,
  });
  const receiverByName = frameworkContext.receiversByName;
  const receiverNames = new Set(receiverByName.keys());
  const depths = conditionalDepths(tokens);

  const registrations = [];
  const mounts = [];
  let registrationLimitHit = false;
  let mountLimitHit = false;
  let observationLimitHit = false;
  let observations = 0;
  let sequence = 0;

  const addObservation = (registration, observation) => {
    if (observations >= limits.maxObservationsPerFile) {
      if (!observationLimitHit) {
        observationLimitHit = true;
        note(problems, MIDDLEWARE_PROBLEMS.OBSERVATION_LIMIT);
      }
      return;
    }
    observations += 1;
    registration.unresolved.push(observation);
  };

  const addRegistration = (registration) => {
    if (registrations.length >= limits.maxRegistrationsPerFile) {
      if (!registrationLimitHit) {
        registrationLimitHit = true;
        note(problems, MIDDLEWARE_PROBLEMS.REGISTRATION_LIMIT);
      }
      return null;
    }
    registrations.push(registration);
    return registration;
  };

  const addMount = (mount) => {
    if (mounts.length >= limits.maxMountsPerFile) {
      if (!mountLimitHit) {
        mountLimitHit = true;
        note(problems, MIDDLEWARE_PROBLEMS.MOUNT_LIMIT);
      }
      return;
    }
    mounts.push(mount);
  };

  /** The call shape this scanner recognises, or `null`. */
  const callShapeAt = (index) => {
    if (!isAnyIdent(tokens[index])) return null;
    const verb = tokens[index].value;
    if (verb !== "use" && verb !== "addHook" && verb !== "register") return null;
    if (!isPunct(tokens[index - 1], ".")) return null;
    const receiverToken = tokens[index - 2];
    if (!isAnyIdent(receiverToken)) return null;
    if (!isPunct(tokens[index + 1], "(")) return null;
    const receiverName = receiverToken.value;
    const receiver = receiverByName.get(receiverName);
    if (receiver === undefined) return null;
    return { verb, receiverName, receiver };
  };

  for (let index = 0; index < tokens.length; index += 1) {
    const shape = callShapeAt(index);
    if (shape === null) continue;

    const { verb, receiverName, receiver } = shape;
    const openIndex = index + 1;
    const conditional = depths[index] > 0;
    const registration = {
      receiver: receiverName,
      receiverKind: receiver.kind,
      framework: receiver.supported ? receiver.framework : null,
      registration:
        verb === "use"
          ? MIDDLEWARE_REGISTRATIONS.USE
          : verb === "addHook"
            ? MIDDLEWARE_REGISTRATIONS.HOOK
            : MIDDLEWARE_REGISTRATIONS.REGISTER,
      scope:
        verb === "addHook"
          ? MIDDLEWARE_SCOPES.HOOK
          : receiver.kind === API_RECEIVER_KINDS.ROUTER
            ? MIDDLEWARE_SCOPES.ROUTER
            : MIDDLEWARE_SCOPES.APP,
      path: null,
      hook: null,
      sequence,
      conditional,
      middleware: [],
      unresolved: [],
    };

    if (receiver.supported !== true) {
      // A middleware-shaped call on a framework this build does not support. Recorded as
      // an observation — never as a registration — because nothing here establishes what
      // that framework's `use` means.
      const recorded = addRegistration(registration);
      sequence += 1;
      if (recorded !== null) {
        addObservation(recorded, {
          reason: MIDDLEWARE_UNRESOLVED_REASONS.FRAMEWORK_UNSUPPORTED,
          name: null,
          member: null,
          form: null,
        });
      }
      continue;
    }

    const ranges = splitArguments(tokens, openIndex, limits.maxArgumentsPerCall);
    let payload = { middleware: [], unresolved: [], mounts: [] };

    if (verb === "use") {
      const address = readMountPath(tokens, ranges[0]);
      registration.path = address.path;
      payload = classifyRegistrationArguments(
        tokens,
        openIndex,
        address.skip,
        receiverNames,
      );
    } else if (verb === "register") {
      // A Fastify plugin's route prefix lives inside its options object, which this
      // scanner does not interpret, so a `register` call declares no mount path here.
      payload = classifyRegistrationArguments(tokens, openIndex, 0, new Set());
    } else {
      // `addHook("preHandler", …)`: the first argument is the hook name and must be a
      // literal string, because a computed hook name is not a statically provable hook.
      const nameRange = ranges[0];
      if (nameRange !== undefined && isStringRange(tokens, nameRange)) {
        registration.hook = tokens[nameRange.start].value;
      } else {
        registration.unresolved.push({
          reason: MIDDLEWARE_UNRESOLVED_REASONS.HOOK_NAME_NOT_ESTABLISHED,
          name: null,
          member: null,
          form: null,
        });
      }
      payload = classifyRegistrationArguments(tokens, openIndex, 1, new Set());
    }

    const recorded = addRegistration(registration);
    sequence += 1;
    if (recorded === null) continue;

    for (const entry of payload.unresolved) {
      addObservation(recorded, entry);
    }

    if (conditional) {
      // The applicability of every candidate depends on a condition or a loop, so none of
      // them is statically provable.
      for (const entry of payload.middleware) {
        addObservation(recorded, {
          reason: MIDDLEWARE_UNRESOLVED_REASONS.CONDITIONAL_NOT_ESTABLISHED,
          name: entry.name,
          member: entry.member,
          form: entry.form,
        });
      }
      for (const mount of payload.mounts) {
        addObservation(recorded, {
          reason: MIDDLEWARE_UNRESOLVED_REASONS.CONDITIONAL_NOT_ESTABLISHED,
          name: mount.child,
          member: null,
          form: "reference",
        });
      }
      continue;
    }

    recorded.middleware = payload.middleware;
    for (const mount of payload.mounts) {
      addMount({
        parent: receiverName,
        child: mount.child,
        path: registration.path,
        sequence: registration.sequence,
      });
    }
  }

  const unsupportedFrameworks = [];
  for (const receiver of frameworkContext.receivers) {
    if (!receiver.supported && !unsupportedFrameworks.includes(receiver.framework)) {
      unsupportedFrameworks.push(receiver.framework);
    }
  }
  unsupportedFrameworks.sort();

  const frameworks = [];
  for (const receiver of frameworkContext.receivers) {
    if (receiver.supported && !frameworks.includes(receiver.framework)) {
      frameworks.push(receiver.framework);
    }
  }
  frameworks.sort();

  let middlewareCount = 0;
  let unresolvedCount = 0;
  for (const registration of registrations) {
    middlewareCount += registration.middleware.length;
    unresolvedCount += registration.unresolved.length;
  }

  const established = !problems.includes(MIDDLEWARE_PROBLEMS.LEXICAL_FAILURE);

  return {
    version: MIDDLEWARE_SCANNER_VERSION,
    established,
    truncated:
      registrationLimitHit ||
      mountLimitHit ||
      observationLimitHit ||
      problems.includes(MIDDLEWARE_PROBLEMS.TOKEN_LIMIT),
    problems,
    frameworks,
    unsupportedFrameworks,
    receivers: frameworkContext.receivers
      .slice()
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)),
    registrations,
    mounts,
    counts: {
      tokens: tokens.length,
      registrations: registrations.length,
      mounts: mounts.length,
      middleware: middlewareCount,
      unresolved: unresolvedCount,
    },
  };
}
