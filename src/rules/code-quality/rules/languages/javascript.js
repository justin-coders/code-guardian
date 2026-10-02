/**
 * Code Guardian — JavaScript / TypeScript Quality Profile (Official Roadmap Phase 12)
 *
 * The official Phase 12 requirement is that *language-specific rules remain modular*. This
 * module is that boundary for the JavaScript/TypeScript ecosystem: every fact that is
 * specific to these languages — which dependency names establish a linter, a formatter or a
 * type checker, and which script names a project conventionally gives them — lives here and
 * nowhere else. The generic domain rules read a **union** of these profiles, so adding a
 * language means adding a module, never editing a rule.
 *
 * A profile is data, not code. Nothing here reads a file, runs a command or consults
 * anything but the frozen model the generic rules hand it.
 *
 *   languageIds   the language entities whose observation makes the profile relevant
 *   dependencies  dependency names that establish each domain's tooling
 *   scriptWords   words a declared script name may contain to establish each domain
 *   ciTools       the closed quality-tool vocabulary ids that serve each domain in CI
 */

/** The JavaScript / TypeScript quality profile. */
export const JAVASCRIPT_QUALITY_PROFILE = Object.freeze({
  id: "javascript",
  languageIds: Object.freeze(["javascript", "typescript"]),
  linting: Object.freeze({
    dependencies: Object.freeze(["eslint", "biome", "oxlint", "stylelint"]),
    scriptWords: Object.freeze(["lint", "eslint"]),
    ciTools: Object.freeze(["eslint", "biome", "oxlint", "stylelint"]),
  }),
  formatting: Object.freeze({
    dependencies: Object.freeze(["prettier", "biome"]),
    scriptWords: Object.freeze(["format", "fmt", "prettier"]),
    ciTools: Object.freeze(["prettier"]),
  }),
  "type-checking": Object.freeze({
    dependencies: Object.freeze(["typescript", "flow-bin"]),
    scriptWords: Object.freeze(["typecheck", "tsc", "check"]),
    ciTools: Object.freeze(["tsc", "flow"]),
  }),
});
