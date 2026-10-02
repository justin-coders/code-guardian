/**
 * Code Guardian — Rust Quality Profile (Official Roadmap Phase 12)
 *
 * The Rust half of the language-modular quality vocabulary. Rust has a first-class linter
 * (`clippy`) and formatter (`rustfmt`) but no separate type-checker dependency — the compiler
 * *is* the type checker — so the `type-checking` entry is deliberately empty rather than
 * guessing a tool. An empty entry means the profile contributes nothing to that domain; it
 * does not mean the domain is not applicable.
 */

/** The Rust quality profile. */
export const RUST_QUALITY_PROFILE = Object.freeze({
  id: "rust",
  languageIds: Object.freeze(["rust"]),
  linting: Object.freeze({
    dependencies: Object.freeze(["clippy"]),
    scriptWords: Object.freeze(["lint", "clippy"]),
    ciTools: Object.freeze(["clippy"]),
  }),
  formatting: Object.freeze({
    dependencies: Object.freeze(["rustfmt"]),
    scriptWords: Object.freeze(["format", "fmt"]),
    ciTools: Object.freeze(["rustfmt"]),
  }),
  "type-checking": Object.freeze({
    dependencies: Object.freeze([]),
    scriptWords: Object.freeze([]),
    ciTools: Object.freeze([]),
  }),
});
