/**
 * Code Guardian — Go Quality Profile (Official Roadmap Phase 12)
 *
 * The Go half of the language-modular quality vocabulary. Go's standard toolchain formats
 * (`gofmt`) and a widely used aggregator lints (`golangci-lint`); `go vet` is not a
 * dependency, so the `type-checking` entry is empty rather than guessed.
 */

/** The Go quality profile. */
export const GO_QUALITY_PROFILE = Object.freeze({
  id: "go",
  languageIds: Object.freeze(["go"]),
  linting: Object.freeze({
    dependencies: Object.freeze(["golangci-lint"]),
    scriptWords: Object.freeze(["lint", "vet"]),
    ciTools: Object.freeze(["golangci-lint"]),
  }),
  formatting: Object.freeze({
    dependencies: Object.freeze([]),
    scriptWords: Object.freeze(["format", "fmt"]),
    ciTools: Object.freeze(["gofmt"]),
  }),
  "type-checking": Object.freeze({
    dependencies: Object.freeze([]),
    scriptWords: Object.freeze([]),
    ciTools: Object.freeze([]),
  }),
});
