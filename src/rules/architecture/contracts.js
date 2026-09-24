/**
 * Code Guardian — Architecture Rule Pack Contracts (Phase 15)
 *
 * The architecture domain's vocabulary. This pack exists to prove one thing: the
 * architecture graph Phase 15 added is *consumable through the accepted Rule
 * Engine* — a rule can enumerate the architectural relationships the repository
 * establishes, cite the observation behind each one, express `unknown` when the
 * graph was not established, and produce deterministic findings — without any rule
 * reading the filesystem, parsing source code, or inferring an import, a call or a
 * tested-by relation.
 *
 * ### It ships exactly one informational rule, on purpose
 *
 * `architecture.graph.inventory` enumerates what the graph establishes. There is no
 * layering rule, no coupling rule, no "circular architecture" rule and no readiness
 * score anywhere in this pack: every one of those would need a judgment about what
 * the repository *should* look like, and this phase has no evidence for one. What it
 * has is the shape of the repository — directories, files, manifests, tests,
 * frameworks and container wiring — so that is what the finding states.
 *
 * ### Rule identity is a long-term contract
 *
 * Rule ids are namespace-shaped (`architecture.graph.inventory`) and appear in every
 * fingerprint the rule produces, so a rename retires every existing fingerprint.
 * `ARCHITECTURE_RULE_IDS` declares the shipped ids in one place and the registry
 * fails if a declared rule is missing or an id leaves the `architecture.` namespace.
 */

/** Version of the pack as a whole (analyzer version, rule set revision). */
export const ARCHITECTURE_RULE_PACK_VERSION = "1.0.0";

/** Initial version of every rule in the pack. */
export const ARCHITECTURE_RULE_VERSION = "1.0.0";

/** Analyzer identity. `architecture` is the domain namespace, not a rule. */
export const ARCHITECTURE_ANALYZER_ID = "architecture";
export const ARCHITECTURE_ANALYZER_NAME = "Architecture";
export const ARCHITECTURE_ANALYZER_SCOPE = "architecture";

/** Category recorded on every architecture finding (Core Finding contract). */
export const ARCHITECTURE_CATEGORY = "architecture";

/** Every architecture rule id must live in this namespace. */
export const ARCHITECTURE_RULE_ID_PREFIX = "architecture.";

/** The rules this pack ships. */
export const ARCHITECTURE_RULE_IDS = Object.freeze({
  GRAPH_INVENTORY: "architecture.graph.inventory",
});

/**
 * Confidence policy.
 *
 * One honest level, and it is not certainty: `OBSERVED_RELATIONSHIP` means the
 * repository established the relation — a path that says where an entity sits, a
 * manifest section that declared a package, a test artifact that named a framework,
 * a Compose service that declared a build — and the model preserved it verbatim. It
 * says nothing about whether the relation is *desirable*.
 */
export const ARCHITECTURE_CONFIDENCE = Object.freeze({
  OBSERVED_RELATIONSHIP: 0.9,
});

/** `metadata.basis` recorded on every architecture finding. */
export const ARCHITECTURE_BASIS = "repository-structure";

/** Findings one rule run will report before it stops and says so. */
export const MAX_ARCHITECTURE_FINDINGS = 200;

/**
 * How each edge type reads in a finding description.
 *
 * A closed map over the graph's own vocabulary: an edge type the graph can state but
 * this map cannot describe is a contract mismatch, and the rule's own test pins the
 * two vocabularies together rather than letting a description silently fall back.
 */
export const EDGE_WORDING = Object.freeze({
  contains: "sits in",
  "declares-dependency": "declares the dependency",
  framework: "reports using the framework",
  "declares-build": "declares a build of",
  "build-context": "is built from",
});
