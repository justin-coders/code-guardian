/**
 * Code Guardian — Symbol Rule Pack Contracts (Phase 17)
 *
 * The semantic domain's vocabulary. This pack exists to prove one thing: the symbol
 * graph Phase 17 added is *consumable through the accepted Rule Engine* — a rule can
 * enumerate the declarations, references, calls, exports and import bindings the
 * repository establishes, cite the observation behind each one, and state `unknown`
 * when the graph was never established, without any rule reading a file, parsing
 * source, resolving a name or walking a scope.
 *
 * ### It ships exactly one informational rule, on purpose
 *
 * `symbols.graph.inventory` enumerates what the graph establishes. There is no
 * complexity rule, no dead-code rule, no coupling rule, no "dangerous recursion" rule
 * and no call-graph-health rule anywhere in this pack: each of those needs a judgment
 * about what the code should look like, and a resolution graph is not that judgment. A
 * cycle is a fact about topology; reporting it as a *problem* is a claim this phase has
 * no evidence for.
 *
 * ### Rule identity is a long-term contract
 *
 * Rule ids are namespace-shaped (`symbols.graph.inventory`) and appear in every
 * fingerprint the rule produces, so a rename retires every existing fingerprint.
 * `SYMBOL_RULE_IDS` declares the shipped ids in one place and the registry fails if a
 * declared rule is missing or an id leaves the `symbols.` namespace.
 */

/** Version of the pack as a whole (analyzer version, rule set revision). */
export const SYMBOL_RULE_PACK_VERSION = "1.0.0";

/** Initial version of every rule in the pack. */
export const SYMBOL_RULE_VERSION = "1.0.0";

/**
 * Analyzer identity.
 *
 * `symbols` is the domain namespace, not a rule, and it is deliberately plural so it
 * can never be confused with a symbol name.
 */
export const SYMBOL_ANALYZER_ID = "symbols";
export const SYMBOL_ANALYZER_NAME = "Symbols";
export const SYMBOL_ANALYZER_SCOPE = "symbols";

/** Category recorded on every symbol finding (Core Finding contract). */
export const SYMBOL_CATEGORY = "architecture";

/** Every symbol rule id must live in this namespace. */
export const SYMBOL_RULE_ID_PREFIX = "symbols.";

/** The rules this pack ships. */
export const SYMBOL_RULE_IDS = Object.freeze({
  GRAPH_INVENTORY: "symbols.graph.inventory",
});

/**
 * Confidence policy.
 *
 * One honest level, and it is not certainty: `OBSERVED_RELATIONSHIP` means the
 * repository establishes the relationship — a supported source file was read to the
 * end, its declaration set was established, and (for a reference or a call) the name
 * was proved to denote exactly one binding in that file — and the model preserved the
 * observation. It says nothing about whether the code is *used* at runtime, whether a
 * call actually executes, or whether the symbol is reachable.
 *
 * A single level for all five edge types on purpose: they all rest on the same
 * establishment proof (the acquisition layer's per-file answer), and inventing a
 * higher number for declarations would imply a precision difference the substrate does
 * not have.
 */
export const SYMBOL_CONFIDENCE = Object.freeze({
  OBSERVED_RELATIONSHIP: 0.9,
});

/** `metadata.basis` recorded on every symbol finding. */
export const SYMBOL_BASIS = "static-symbol-resolution";

/** Findings one rule run will report before it stops and says so. */
export const MAX_SYMBOL_FINDINGS = 200;

/**
 * How each symbol-graph edge type reads in a finding.
 *
 * A closed map over the graph's own edge vocabulary: an edge type the graph can state
 * but this map cannot describe is a contract mismatch, and the pack's own test pins the
 * two vocabularies together rather than letting a description fall back to an
 * identifier nobody can act on.
 */
export const EDGE_TYPE_WORDING = Object.freeze({
  declares: "declares",
  exports: "exports",
  references: "references",
  calls: "calls",
  "imports-binding": "binds",
});

/**
 * How each declaration kind reads in a finding.
 *
 * Closed map over `SYMBOL_KINDS` for the same reason as the edge map. `imported-binding`
 * is described as a binding rather than as a declaration form, because that is what it
 * is: a module-scope name whose value comes from another module.
 */
export const SYMBOL_KIND_WORDING = Object.freeze({
  function: "a function",
  class: "a class",
  variable: "a variable",
  interface: "an interface",
  "type-alias": "a type alias",
  enum: "an enum",
  namespace: "a namespace",
  "imported-binding": "an imported binding",
});

/**
 * How each unresolved reason reads in the abstention's metadata.
 *
 * Closed map over the graph's own reason vocabulary, so a new reason has to be
 * described deliberately instead of appearing as a raw token.
 */
export const UNRESOLVED_SYMBOL_REASON_WORDING = Object.freeze({
  "name-not-declared": "no module-scope binding of that name exists in the file",
  "name-not-unique": "the name is bound elsewhere in the file too, so the occurrence denotes no single binding",
  "callee-not-established": "the name resolves to a binding whose value shape is not established as callable",
  "resolution-not-established":
    "the file contains a dynamic-scope construct (`eval` / `with`), which voids every uniqueness proof in it",
  "anonymous-export": "an export this build cannot name",
  "export-local-not-established": "the exported local name is not a declaration the file establishes",
  "export-not-established": "the target module could not be searched to the end",
  "export-not-found": "the target module establishes its exports and does not export that name",
  "export-ambiguous": "two declarations in the target claim the same name",
  "namespace-binding": "a namespace binding names a module, not a symbol",
  "module-not-interpreted": "the target module was not scanned as a semantic source",
  "specifier-not-recorded": "the binding states no module this build could read",
  "bare-specifier": "a bare specifier (a package or an alias this build does not resolve)",
  "absolute-specifier": "an absolute path",
  "specifier-not-resolvable": "a specifier this build cannot treat as a path",
  "outside-repository": "a path that leaves the repository root",
  "specifier-invalid": "text that cannot be a module path",
  "module-not-observed": "a repository path the scan did not observe",
});
