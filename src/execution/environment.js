/**
 * Code Guardian — Environment Policy (Phase 8B)
 *
 * Trust model: by default the child inherits the parent environment, and the
 * caller may layer *explicit* string overrides on top. Inheritance exists
 * because tools such as `node`/`npm`/`git` require a usable `PATH` and
 * platform variables; the boundary is that the caller cannot ask the runner to
 * hand the child a *different* environment wholesale without opting out.
 *
 * Guarantees:
 *   - The returned object is a fresh copy; `process.env` is never mutated.
 *   - Only string values are propagated (Node's `process.env` can hold
 *     `undefined`, which is dropped).
 *   - Overrides are validated by the runner (names and value types) before
 *     this function runs.
 *   - The full environment is never placed in an execution result.
 */

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
