/**
 * Code Guardian — Code-Quality Acquisition Policy (Official Roadmap Phase 12)
 *
 * The scanner's one place that interprets a *command string* into the closed vocabulary of
 * code-quality tools a CI workflow can be observed invoking. It exists because whether a
 * workflow actually runs a linter, a formatter or a type checker is a fact about **command
 * text**, not about the workflow's file name — and Phase 12 must be able to distinguish
 * "a tool is configured" from "CI is observed executing that tool".
 *
 * ### Pure, bounded, evidence-shaped
 *
 * `classifyQualityCommand` is a pure function of one string. It consults no filesystem,
 * clock, environment or process; matching is a fixed set of linear regular expressions over
 * a bounded input, so a hostile command cannot make the scanner super-linear. It returns a
 * sorted, de-duplicated list of the closed tool ids below — never a guess from the
 * repository's language.
 *
 * ### A workflow that runs a tool is not a workflow that passed a tool
 *
 * The fact this policy establishes is "a workflow's content contains this tool's documented
 * invocation". It says nothing about exit status; Phase 12 consumes it only to mark a domain
 * `verified`, which its own contracts define as *configured **and** observed executed in CI*,
 * never a claim about the run's result.
 *
 * ### Matching is deliberately narrow
 *
 * A tool id is reported only when its own documented command appears. `prettier --check .`
 * and `eslint .` establish their tools; `npm run lint` establishes nothing about *which*
 * tool the script delegates to (that is a separate fact the manifest script name records),
 * so a generic package-manager invocation is deliberately absent from this table.
 */

/** The quality domains a CI command can establish. */
export const QUALITY_COMMAND_DOMAINS = Object.freeze({
  LINTING: "linting",
  FORMATTING: "formatting",
  TYPE_CHECKING: "type-checking",
});

/**
 * The closed vocabulary of quality-tool invocations a command can establish.
 *
 * `domain` names which of the roadmap's quality domains the tool serves, so a consumer
 * never re-derives it. The table is data, not code — a reviewer can read the whole set at a
 * glance and no rule can widen it at runtime.
 */
export const QUALITY_TOOL_DEFINITIONS = Object.freeze([
  // ── Linters ───────────────────────────────────────────────────────────────
  { id: "eslint", domain: "linting", matcher: /(^|[\s;&|(])eslint(?:\s|$)/ },
  { id: "stylelint", domain: "linting", matcher: /(^|[\s;&|(])stylelint(?:\s|$)/ },
  { id: "oxlint", domain: "linting", matcher: /(^|[\s;&|(])oxlint(?:\s|$)/ },
  { id: "biome", domain: "linting", matcher: /(^|[\s;&|(])biome\s+(?:lint|check)(?:\s|$)/ },
  { id: "ruff", domain: "linting", matcher: /(^|[\s;&|(])ruff\s+(?:check|format)(?:\s|$)/ },
  { id: "flake8", domain: "linting", matcher: /(^|[\s;&|(])flake8(?:\s|$)/ },
  { id: "pylint", domain: "linting", matcher: /(^|[\s;&|(])pylint(?:\s|$)/ },
  { id: "golangci-lint", domain: "linting", matcher: /(^|[\s;&|(])golangci-lint(?:\s|$)/ },
  { id: "clippy", domain: "linting", matcher: /cargo\s+clippy(?:\s|$)|(^|[\s;&|(])clippy(?:\s|$)/ },

  // ── Formatters ────────────────────────────────────────────────────────────
  { id: "prettier", domain: "formatting", matcher: /(^|[\s;&|(])prettier(?:\s|$)/ },
  { id: "black", domain: "formatting", matcher: /(^|[\s;&|(])black(?:\s|$)/ },
  { id: "rustfmt", domain: "formatting", matcher: /cargo\s+(?:fmt|rustfmt)(?:\s|$)|(^|[\s;&|(])rustfmt(?:\s|$)/ },
  { id: "gofmt", domain: "formatting", matcher: /(^|[\s;&|(])gofmt(?:\s|$)|(^|[\s;&|(])gofumpt(?:\s|$)/ },
  { id: "clang-format", domain: "formatting", matcher: /(^|[\s;&|(])clang-format(?:\s|$)/ },
  { id: "dotnet-format", domain: "formatting", matcher: /(^|[\s;&|(])dotnet\s+format(?:\s|$)/ },

  // ── Type checkers ─────────────────────────────────────────────────────────
  { id: "tsc", domain: "type-checking", matcher: /(^|[\s;&|(])tsc(?:\s|$)/ },
  { id: "mypy", domain: "type-checking", matcher: /(^|[\s;&|(])mypy(?:\s|$)/ },
  { id: "pyright", domain: "type-checking", matcher: /(^|[\s;&|(])pyright(?:\s|$)/ },
  { id: "flow", domain: "type-checking", matcher: /(^|[\s;&|(])flow(?:\s|$)/ },
]);

/** Every quality-tool id this policy can report, sorted. */
export const QUALITY_TOOL_IDS = Object.freeze(
  [...new Set(QUALITY_TOOL_DEFINITIONS.map((definition) => definition.id))].sort(),
);

/** Tool id → domain, so a consumer reads the mapping instead of re-deriving it. */
export const QUALITY_TOOL_DOMAINS = Object.freeze(
  Object.fromEntries(QUALITY_TOOL_DEFINITIONS.map((definition) => [definition.id, definition.domain])),
);

/**
 * Classify one command string into the closed quality-tool vocabulary.
 *
 * @param {unknown} command A command string as written in a workflow.
 * @returns {{ tools: string[], domains: string[] }} Frozen, sorted, de-duplicated. Empty
 *   when nothing recognisable is present.
 */
export function classifyQualityCommand(command) {
  if (typeof command !== "string" || command === "") {
    return Object.freeze({ tools: [], domains: [] });
  }

  const tools = new Set();
  const domains = new Set();
  for (const definition of QUALITY_TOOL_DEFINITIONS) {
    if (definition.matcher.test(command)) {
      tools.add(definition.id);
      domains.add(definition.domain);
    }
  }

  return Object.freeze({
    tools: Object.freeze([...tools].sort()),
    domains: Object.freeze([...domains].sort()),
  });
}
