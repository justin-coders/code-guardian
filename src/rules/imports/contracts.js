/**
 * Code Guardian — Import Rule Pack Contracts (Phase 16)
 *
 * The import domain's vocabulary. This pack exists to prove one thing: the import
 * graph Phase 16 added is *consumable through the accepted Rule Engine* — a rule can
 * enumerate the file-to-file references the repository establishes, cite the
 * observation behind each one, distinguish a reference whose target is not
 * established from one that is, express `unknown` when the graph was never
 * established, and produce deterministic findings — without any rule reading a file,
 * parsing source, or resolving a specifier itself.
 *
 * ### It ships exactly one informational rule, on purpose
 *
 * `import.graph.inventory` enumerates what the graph establishes. There is no
 * circular-import rule, no coupling rule, no "unused file" rule and no layering rule
 * anywhere in this pack: each of those needs a judgment about what the code should
 * look like, and a static reference graph is not that judgment. A cycle is a fact
 * about topology, and reporting it as a *problem* would be a claim this phase has no
 * evidence for.
 *
 * ### Rule identity is a long-term contract
 *
 * Rule ids are namespace-shaped (`import.graph.inventory`) and appear in every
 * fingerprint the rule produces, so a rename retires every existing fingerprint.
 * `IMPORT_RULE_IDS` declares the shipped ids in one place and the registry fails if a
 * declared rule is missing or an id leaves the `import.` namespace.
 */

/** Version of the pack as a whole (analyzer version, rule set revision). */
export const IMPORT_RULE_PACK_VERSION = "1.0.0";

/** Initial version of every rule in the pack. */
export const IMPORT_RULE_VERSION = "1.0.0";

/**
 * Analyzer identity.
 *
 * `imports` is the domain namespace, not a rule. It is deliberately `imports`
 * (plural) so it can never be confused with the language keyword or with a rule id.
 */
export const IMPORT_ANALYZER_ID = "imports";
export const IMPORT_ANALYZER_NAME = "Imports";
export const IMPORT_ANALYZER_SCOPE = "imports";

/** Category recorded on every import finding (Core Finding contract). */
export const IMPORT_CATEGORY = "architecture";

/** Every import rule id must live in this namespace. */
export const IMPORT_RULE_ID_PREFIX = "import.";

/** The rules this pack ships. */
export const IMPORT_RULE_IDS = Object.freeze({
  GRAPH_INVENTORY: "import.graph.inventory",
});

/**
 * Confidence policy.
 *
 * One honest level, and it is not certainty: `OBSERVED_REFERENCE` means the
 * repository establishes the reference — a supported source file states a specifier,
 * and a file the scan observed is the target it resolves to — and the model preserved
 * it verbatim. It says nothing about whether the reference is *desirable*, reachable
 * at runtime, or the one a bundler would actually pick.
 */
export const IMPORT_CONFIDENCE = Object.freeze({
  OBSERVED_REFERENCE: 0.9,
});

/** `metadata.basis` recorded on every import finding. */
export const IMPORT_BASIS = "static-module-reference";

/** Findings one rule run will report before it stops and says so. */
export const MAX_IMPORT_FINDINGS = 200;

/**
 * How each declaration form reads in a finding description.
 *
 * A closed map over the graph's own `kinds` vocabulary: a kind the graph can state
 * but this map cannot describe is a contract mismatch, and the pack's own test pins
 * the two vocabularies together rather than letting a description silently fall back.
 */
export const KIND_WORDING = Object.freeze({
  "static-import": "a static import",
  "export-from": "a re-export",
  require: "a `require` call",
  "dynamic-import": "a dynamic `import()`",
});

/**
 * How each unresolved reason reads in a finding's metadata and in the abstention
 * message.
 *
 * Closed map for the same reason: a new reason must be described deliberately rather
 * than rendered as an identifier nobody can act on.
 */
export const UNRESOLVED_REASON_WORDING = Object.freeze({
  "bare-specifier": "a bare specifier (a package or an alias this build does not resolve)",
  "absolute-specifier": "an absolute path",
  "specifier-not-resolvable": "a specifier this build cannot treat as a path",
  "outside-repository": "a path that leaves the repository root",
  "specifier-invalid": "text that cannot be a module path",
  "module-not-observed": "a repository path the scan did not observe",
});
