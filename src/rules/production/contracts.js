/**
 * Code Guardian — Production Rule Pack Contracts (Phase 20)
 *
 * The production domain's vocabulary. This pack exists to prove one thing: the
 * ProductionReport Phase 20 projects is *consumable through the accepted Rule Engine* — a
 * rule can enumerate what each audit domain observed, cite the observation behind every
 * statement, and state `unknown` when the report could not read an input, without any rule
 * reading a file, parsing source, running a container, contacting a registry or scoring
 * anything.
 *
 * ### It ships six informational rules, one per audit domain, on purpose
 *
 * `production.environment.inventory`, `production.container.inventory`,
 * `production.ci.inventory`, `production.api.inventory`,
 * `production.dependencies.inventory` and `production.architecture.inventory` each
 * enumerate one section of the report. There is no readiness rule, no score, no grade, no
 * percentage, no traffic light, no severity above `info` and no pass/fail verdict anywhere
 * in the pack: whether a repository is ready for production is a judgment about what it
 * *should* be, and this architecture has no specification, no threat model, no policy and
 * no environment to compare against. What it has is evidence, so it reports evidence.
 *
 * ### Descriptions are closed maps over the report's own vocabularies
 *
 * A section, an observation kind, an abstention reason and a coverage state the report can
 * produce but this pack cannot describe is a contract mismatch. Each map below is a closed
 * phrase table over one of those vocabularies, and the pack's own test pins the two
 * together so a rename on either side fails the suite instead of silently retiring a value.
 *
 * ### Rule identity is a long-term contract
 *
 * Rule ids are namespace-shaped (`production.environment.inventory`) and appear in every
 * fingerprint the rule produces, so a rename retires every existing fingerprint.
 * `PRODUCTION_RULE_IDS` declares the shipped ids in one place and the registry fails if a
 * declared rule is missing or an id leaves the `production.` namespace.
 */

/** Version of the pack as a whole (analyzer version, rule set revision). */
export const PRODUCTION_RULE_PACK_VERSION = "1.0.0";

/** Initial version of every rule in the pack. */
export const PRODUCTION_RULE_VERSION = "1.0.0";

/** Analyzer identity. `production` is the domain namespace, not a rule. */
export const PRODUCTION_ANALYZER_ID = "production";
export const PRODUCTION_ANALYZER_NAME = "Production";
export const PRODUCTION_ANALYZER_SCOPE = "production";

/** Category recorded on every production finding (Core Finding contract). */
export const PRODUCTION_CATEGORY = "architecture";

/** Every production rule id must live in this namespace. */
export const PRODUCTION_RULE_ID_PREFIX = "production.";

/** The rules this pack ships: exactly one per audit domain. */
export const PRODUCTION_RULE_IDS = Object.freeze({
  ENVIRONMENT_INVENTORY: "production.environment.inventory",
  CONTAINER_INVENTORY: "production.container.inventory",
  CI_INVENTORY: "production.ci.inventory",
  API_INVENTORY: "production.api.inventory",
  DEPENDENCIES_INVENTORY: "production.dependencies.inventory",
  ARCHITECTURE_INVENTORY: "production.architecture.inventory",
});

/**
 * Confidence policy.
 *
 * One honest level, and it is not certainty: `OBSERVED_REPOSITORY_FACT` means the
 * repository establishes the fact — the scan read the inventory, the graph behind the
 * section was built from that inventory, and the observation cites the evidence behind it.
 * It says nothing about whether the fact is *good*, whether it is sufficient, or whether
 * the system works at runtime.
 */
export const PRODUCTION_CONFIDENCE = Object.freeze({
  OBSERVED_REPOSITORY_FACT: 0.9,
});

/** `metadata.basis` recorded on every production finding. */
export const PRODUCTION_BASIS = "static-production-report";

/** Findings one rule run will report before it stops and says so. */
export const MAX_PRODUCTION_FINDINGS = 200;

/** How each audit domain reads in a finding. */
export const PRODUCTION_SECTION_WORDING = Object.freeze({
  environment: "environment configuration",
  container: "container configuration",
  ci: "CI configuration",
  api: "API exposure inventory",
  dependencies: "dependency inventory",
  architecture: "architecture inventory",
});

/** How each report coverage state reads in a finding's metadata. */
export const PRODUCTION_STATE_WORDING = Object.freeze({
  complete: "every input this section reads was inspected, so the section established its answer — including an empty one",
  partial: "an answer exists, but an input was cut short, excluded or only partly established",
  unsupported:
    "the section has no answer: this implementation does not interpret the relevant domain",
  unknown: "the section has no answer: the scan or the graph behind it was not established",
  truncated: "a bound stopped the reading",
});

/**
 * How each observation kind reads.
 *
 * Closed over `PRODUCTION_OBSERVATION_KINDS` — every kind the report can produce is
 * described here, and the pack's test pins the two lists together.
 */
export const PRODUCTION_OBSERVATION_WORDING = Object.freeze({
  "environment-example": "an environment example file",
  "environment-template": "an environment template file",
  "environment-file": "an environment file",
  "sample-configuration": "a sample configuration file",
  "environment-template-duplicate": "a duplicated environment template class",
  "container-definition": "a container definition",
  "container-ignore": "a container ignore file",
  "container-composition": "a container composition file",
  "container-structure": "a container definition's declared structure",
  "container-healthcheck": "a declared healthcheck",
  "container-healthcheck-disabled": "a declared-disabled healthcheck",
  "container-multi-stage": "a multi-stage build",
  "container-build-context": "a declared build context",
  "ci-provider": "a CI provider",
  "ci-workflow": "a CI workflow file",
  "api-route": "a declared endpoint",
  "api-handler": "a resolved route handler",
  "dependency-manifest": "a dependency source file",
  "dependency-lockfile": "a lockfile that resolved dependencies",
  "dependency-ecosystem": "a package ecosystem",
  "architecture-layer": "a layer of observed entities",
  "architecture-module": "a module holding a manifest",
  "architecture-entrypoint": "an entrypoint-shaped file",
  "architecture-isolated-file": "a module file with no import relationship",
});

/**
 * How each abstention reason reads.
 *
 * Closed over `PRODUCTION_UNKNOWN_REASONS`. Every phrase describes a gap in *knowledge*,
 * never a defect: "the workflow body was not read" is in this map; "the workflow is
 * inadequate" is not, and could not be expressed through it.
 */
export const PRODUCTION_ABSTENTION_WORDING = Object.freeze({
  "secret-values-not-inspected":
    "environment files are never opened, so no value, key or default is established",
  "environment-configuration-ignored":
    "an ignore policy excludes an environment-shaped path, so its presence is not established",
  "no-environment-configuration-observed":
    "the scan covered the repository and observed no environment artifact",
  "environment-configuration-not-observed":
    "the scan did not cover the repository completely, so an environment artifact cannot be ruled out",
  "configuration-inventory-truncated":
    "the configuration inventory was cut short, so it is not the complete set of artifacts",
  "dockerfile-structure-not-established":
    "a container definition's instructions could not be read, so its structure is not established",
  "compose-build-declarations-not-established":
    "a composition file's build declarations could not be established",
  "no-container-configuration-observed":
    "the scan covered the repository and observed no container configuration",
  "container-configuration-not-observed":
    "the scan did not cover the repository completely, so container configuration cannot be ruled out",
  "container-inventory-truncated":
    "the configuration inventory was cut short, so it is not the complete set of container artifacts",
  "workflow-content-not-inspected":
    "workflow definitions are never opened, so nothing about their steps is established",
  "workflow-purpose-not-established":
    "a workflow's own file name states no purpose, so its purpose is not established",
  "no-ci-configuration-observed":
    "the scan covered the repository and observed no CI configuration",
  "ci-configuration-not-observed":
    "the scan did not cover the repository completely, so CI configuration cannot be ruled out",
  "ci-inventory-truncated": "the CI inventory was cut short, so it is not the complete set",
  "api-graph-not-established":
    "no API graph was established, so the repository's endpoints are not established",
  "middleware-graph-not-established":
    "no middleware graph was established, so route protection is not established",
  "route-occurrence-not-established":
    "a route-shaped occurrence was not established as an endpoint",
  "route-middleware-not-established":
    "a route's middleware-shaped occurrence was not established",
  "handler-not-established":
    "a declared route has no handler this build resolved",
  "api-framework-not-interpreted":
    "the repository declares an API framework this build does not read, so none of its endpoints is established",
  "api-source-not-interpreted":
    "module files in languages this build does not read were observed, so no endpoint of theirs is established",
  "section-observations-truncated":
    "the section's observation list reached its bound, so it is not the complete list",
  "dependency-graph-not-established":
    "no dependency graph was established, so the repository's dependencies are not established",
  "dependency-source-not-established":
    "a dependency source could not be interpreted, so what it declares is not established",
  "no-dependency-declaration-observed":
    "the scan covered the repository and observed no dependency declaration",
  "dependency-declarations-not-observed":
    "the scan did not cover the repository completely, so dependency declarations cannot be ruled out",
  "dependency-format-not-interpreted":
    "every dependency source is a format this build does not interpret, so nothing the repository declares is established",
  "architecture-graph-not-established":
    "no architecture graph was established, so the repository's structure is not established",
  "isolated-modules-not-established":
    "the import graph was not established, so no module can be reported as isolated",
  "entrypoint-detection-not-established":
    "entrypoints are recognised by file name only, so no entrypoint is established as one",
  "import-graph-not-established":
    "the import graph was not complete, so import-relationship claims are bounded by it",
  "repository-scan-not-complete":
    "the scan did not cover the repository, so this domain has no answer at all rather than an empty one",
});
