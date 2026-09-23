/**
 * Code Guardian — Dependency Rule Pack Contracts (Phase 13)
 *
 * The dependency domain's vocabulary. This pack exists to prove one thing: the
 * dependency substrate Phase 13 added is *consumable through the accepted Rule
 * Engine* — a rule can read dependency intelligence, cite its evidence, express
 * `unknown` when acquisition did not establish an answer, and produce deterministic
 * findings — without any rule reading a file, parsing a manifest, executing a
 * package manager or contacting a registry.
 *
 * ### It is not a vulnerability pack, on purpose
 *
 * There is no advisory database, no version comparison, no "outdated" judgment, no
 * risk score and no recommendation anywhere in this pack. The single rule it ships
 * is an **inventory** rule: it states which dependencies the repository declares,
 * with the scope and specifier each manifest stated. Deciding whether a declared
 * dependency is a *problem* needs evidence this phase does not acquire (a registry,
 * an advisory feed), and inventing that verdict from a version string would be
 * exactly the fabricated confidence the architecture forbids.
 *
 * ### Rule identity is a long-term contract
 *
 * Rule ids are namespace-shaped (`dependency.inventory.declarations`) and appear in
 * every fingerprint the rule produces, so a rename retires every existing
 * fingerprint. `DEPENDENCY_RULE_IDS` declares the shipped ids in one place and the
 * registry fails if a declared rule is missing or an id leaves the `dependency.`
 * namespace.
 */

/** Version of the pack as a whole (analyzer version, rule set revision). */
export const DEPENDENCY_RULE_PACK_VERSION = "1.0.0";

/** Initial version of every rule in the pack. */
export const DEPENDENCY_RULE_VERSION = "1.0.0";

/** Analyzer identity. `dependency` is the domain namespace, not a rule. */
export const DEPENDENCY_ANALYZER_ID = "dependency";
export const DEPENDENCY_ANALYZER_NAME = "Dependency";
export const DEPENDENCY_ANALYZER_SCOPE = "dependency";

/** Category recorded on every dependency finding (Core Finding contract). */
export const DEPENDENCY_CATEGORY = "dependency";

/** Every dependency rule id must live in this namespace. */
export const DEPENDENCY_RULE_ID_PREFIX = "dependency.";

/** The rules this pack ships. */
export const DEPENDENCY_RULE_IDS = Object.freeze({
  DECLARATIONS: "dependency.inventory.declarations",
  GRAPH_INVENTORY: "dependency.graph.inventory",
});

/**
 * Confidence policy.
 *
 * One honest level, and it is not certainty: `OBSERVED_DECLARATION` means the
 * manifest recorded the declaration and the model preserved it verbatim. What the
 * dependency's *published state* is — its age, its advisories, whether the version
 * exists — was not observed and is not claimed.
 */
export const DEPENDENCY_CONFIDENCE = Object.freeze({
  OBSERVED_DECLARATION: 0.9,
  /**
   * A relationship a supported lockfile stated and the model preserved verbatim.
   * Not certainty about the *installed* tree, and not a claim about whether either
   * package is current, safe or wanted — none of that was observed.
   */
  OBSERVED_RELATIONSHIP: 0.9,
});

/**
 * The signal ids the model writes onto dependency observations.
 *
 * Re-declared rather than imported from the repository layer, following the
 * security pack's convention: the rules layer depends on the model's *shape*, and a
 * test in `tests/dependency-intelligence.test.js` pins these against a real scan so
 * a rename on either side fails the suite.
 */
export const DEPENDENCY_SIGNALS = Object.freeze({
  SOURCE: "dependency-source",
  DECLARATION: "dependency-declaration",
  RESOLUTION: "dependency-resolution",
});

/** `metadata.basis` recorded on every declaration finding. */
export const DEPENDENCY_BASIS = "manifest-declaration";

/**
 * `metadata.basis` recorded on every graph finding.
 *
 * Different from `DEPENDENCY_BASIS` on purpose: a declaration finding rests on what
 * a manifest *declared*, a graph finding rests on a relationship a lockfile
 * *stated*. Collapsing the two would let a rule cite a declaration as proof of a
 * dependency edge.
 */
export const DEPENDENCY_GRAPH_BASIS = "lockfile-relationship";

/** Findings one rule run will report before it stops and says so. */
export const MAX_DECLARATION_FINDINGS = 200;

/** Findings the graph inventory rule will report before it stops and says so. */
export const MAX_GRAPH_FINDINGS = 200;

/** Deterministic ordering: declaration records are compared by manifest, then name. */
export function compareDeclarations(a, b) {
  if (a.manifestPath !== b.manifestPath) return a.manifestPath < b.manifestPath ? -1 : 1;
  if (a.name === b.name) return 0;
  return a.name < b.name ? -1 : 1;
}
