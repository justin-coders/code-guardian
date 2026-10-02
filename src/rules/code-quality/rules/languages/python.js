/**
 * Code Guardian — Python Quality Profile (Official Roadmap Phase 12)
 *
 * The Python half of the language-modular quality vocabulary: dependency names and script
 * words that establish linting, formatting and type checking for this ecosystem. The generic
 * domain rules consume the union of every profile, so this module is the only place Python
 * tooling names appear.
 */

/** The Python quality profile. */
export const PYTHON_QUALITY_PROFILE = Object.freeze({
  id: "python",
  languageIds: Object.freeze(["python"]),
  linting: Object.freeze({
    dependencies: Object.freeze(["ruff", "flake8", "pylint"]),
    scriptWords: Object.freeze(["lint", "ruff", "flake8", "pylint"]),
    ciTools: Object.freeze(["ruff", "flake8", "pylint"]),
  }),
  formatting: Object.freeze({
    dependencies: Object.freeze(["black", "ruff"]),
    scriptWords: Object.freeze(["format", "fmt", "black"]),
    ciTools: Object.freeze(["black"]),
  }),
  "type-checking": Object.freeze({
    dependencies: Object.freeze(["mypy", "pyright"]),
    scriptWords: Object.freeze(["typecheck", "mypy", "pyright"]),
    ciTools: Object.freeze(["mypy", "pyright"]),
  }),
});
