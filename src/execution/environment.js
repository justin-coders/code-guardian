/**
 * Code Guardian — Environment Policy (Phase 8B)
 *
 * Trust model: by default the child inherits the parent environment, and the
 * caller may layer *explicit* string overrides on top. Inheritance exists
 * because tools such as `node`/`npm`/`git` require a usable `PATH` and platform
 * variables; the boundary is that the caller cannot ask the runner to hand the
 * child a *different* environment wholesale without opting out.
 *
 * Two independent protections keep environment overrides from undermining the
 * command boundary:
 *
 *   1. Structural — the runner resolves the executable against the *trusted*
 *      (inherited) environment and spawns the resolved absolute path, so a
 *      caller-supplied `PATH` cannot change which file runs. See
 *      `executable.js` / `runner.js`.
 *   2. Declarative — *execution-control* variable names are reserved: a caller
 *      may not override them at all. These are the variables that can inject
 *      code into, or re-point the loader of, an otherwise authorized command
 *      (`NODE_OPTIONS`, `LD_PRELOAD`, `PATH`, ...), so allowing them would let
 *      a caller re-engineer execution without changing `command`.
 *
 * The reserved list is a documented, deliberately bounded deny-list grouped by
 * ecosystem rather than an exhaustive sandbox: a variable that is *not* listed
 * still passes through, and the runner makes no claim to strip every possible
 * runtime hook. The guarantee that carries the weight is (1): authorization is
 * decided on the executable that will actually be spawned.
 *
 * Guarantees:
 *   - The returned object is a fresh copy; `process.env` is never mutated.
 *   - Only string values are propagated (Node's `process.env` can hold
 *     `undefined`, which is dropped).
 *   - Overrides are validated by the runner (names, value types, reserved
 *     names) before this function runs.
 *   - The full environment is never placed in an execution result, and reserved
 *     variable *values* are never echoed back in errors.
 */

const WINDOWS = process.platform === "win32";

/**
 * Execution-control variables a caller may not override.
 *
 * Grouped by ecosystem so the intent is auditable; the list is intentionally
 * about "what code runs / what gets loaded", not about every variable a tool
 * might read.
 */
export const EXECUTION_CONTROL_ENVIRONMENT_VARIABLES = Object.freeze([
  // Executable / shared-library resolution.
  "PATH",
  "PATHEXT",
  "LD_PRELOAD",
  "LD_LIBRARY_PATH",
  "LD_AUDIT",
  "DYLD_INSERT_LIBRARIES",
  "DYLD_LIBRARY_PATH",
  "DYLD_FRAMEWORK_PATH",
  "DYLD_FALLBACK_LIBRARY_PATH",
  // Node.
  "NODE_OPTIONS",
  "NODE_PATH",
  "NODE_REPL_EXTERNAL_MODULE",
  // Python.
  "PYTHONPATH",
  "PYTHONSTARTUP",
  "PYTHONHOME",
  // Ruby / Perl.
  "RUBYOPT",
  "RUBYLIB",
  "PERL5OPT",
  "PERL5LIB",
  // Shell startup, so an interactive/indirect shell cannot be re-configured.
  "BASH_ENV",
  "ENV",
  "SHELLOPTS",
  "PROMPT_COMMAND",
  // Git, which can be pointed at external commands via environment.
  "GIT_SSH",
  "GIT_SSH_COMMAND",
  "GIT_EXTERNAL_DIFF",
  "GIT_CONFIG_GLOBAL",
  "GIT_CONFIG_SYSTEM",
  "GIT_CONFIG_NOSYSTEM",
  "GIT_CONFIG_COUNT",
]);

const EXECUTION_CONTROL_KEYS = new Set(
  EXECUTION_CONTROL_ENVIRONMENT_VARIABLES.map((name) =>
    WINDOWS ? name.toUpperCase() : name,
  ),
);

/**
 * Whether an environment variable name is reserved.
 *
 * Comparison is exact per the host's platform semantics: Windows environment
 * names are case-insensitive, POSIX names are case-sensitive.
 *
 * @param {string} name
 * @returns {boolean}
 */
export function isExecutionControlVariable(name) {
  if (typeof name !== "string") return false;
  return EXECUTION_CONTROL_KEYS.has(WINDOWS ? name.toUpperCase() : name);
}

/**
 * Build the environment for a child process.
 *
 * @param {object} [overrides] Validated string overrides.
 * @param {NodeJS.ProcessEnv} [base] Base environment (default `process.env`).
 * @returns {Record<string, string>} A fresh, serializable environment object.
 */
export function buildEnvironment(overrides = {}, base = process.env) {
  const environment = {};
  for (const [key, value] of Object.entries(base ?? {})) {
    if (typeof value === "string") environment[key] = value;
  }
  for (const [key, value] of Object.entries(overrides ?? {})) {
    environment[key] = value;
  }
  return environment;
}
