/**
 * Code Guardian — Production Risk Rule Pack Contracts (Phase 21)
 *
 * The vocabulary of the `production.risk.*` rules. This pack exists to prove one thing: the
 * ProductionRiskReport Phase 21 projects is *consumable through the accepted Rule Engine* — a
 * rule can enumerate the engineering gaps one domain's evidence proves, carry each finding's
 * own closed severity, name the basis it rests on, and abstain when the report withheld a
 * detection, without any rule reading a file, parsing source, running a container, resolving a
 * dependency, contacting a registry or a network, or scoring anything.
 *
 * ### It ships six rules, one per domain, and none of them scores
 *
 * `production.risk.environment`, `production.risk.container`, `production.risk.ci`,
 * `production.risk.api`, `production.risk.dependencies` and `production.risk.architecture`
 * each report one section's findings. There is no aggregate rule, no readiness verdict, no
 * percentage, no grade, no traffic light and no severity above `medium` anywhere in the pack.
 *
 * ### Prose is a closed map over the report's own vocabularies
 *
 * A section, a finding kind, a severity, a confidence or an abstention reason the report can
 * produce but this pack cannot describe is a contract mismatch. Each map below is a closed
 * phrase table over one of those vocabularies, and the pack's test pins each one to its source
 * so a rename on either side fails the suite instead of silently retiring a value.
 *
 * ### Rule identity is a long-term contract
 *
 * Rule ids appear in every fingerprint the rule produces, so a rename retires every existing
 * fingerprint. `PRODUCTION_RISK_RULE_IDS` declares the shipped ids in one place and the
 * registry fails if a declared rule is missing or an id leaves the `production.risk.`
 * namespace.
 */

/** Version of the pack as a whole (analyzer version, rule set revision). */
export const PRODUCTION_RISK_RULE_PACK_VERSION = "1.0.0";

/** Initial version of every rule in the pack. */
export const PRODUCTION_RISK_RULE_VERSION = "1.0.0";

/** Analyzer identity. `production-risk` is the domain namespace, not a rule. */
export const PRODUCTION_RISK_ANALYZER_ID = "production-risk";
export const PRODUCTION_RISK_ANALYZER_NAME = "Production Risk";
export const PRODUCTION_RISK_ANALYZER_SCOPE = "production-risk";

/** Category recorded on every risk finding (Core Finding contract). */
export const PRODUCTION_RISK_CATEGORY = "architecture";

/** Every risk rule id must live in this namespace. */
export const PRODUCTION_RISK_RULE_ID_PREFIX = "production.risk.";

/** The rules this pack ships: exactly one per audit domain, in the report's own order. */
export const PRODUCTION_RISK_RULE_IDS = Object.freeze({
  ENVIRONMENT: "production.risk.environment",
  CONTAINER: "production.risk.container",
  CI: "production.risk.ci",
  API: "production.risk.api",
  DEPENDENCIES: "production.risk.dependencies",
  ARCHITECTURE: "production.risk.architecture",
});

/**
 * The severity each rule declares.
 *
 * A rule's declared severity is the **strongest** severity its own detection table can produce,
 * so a consumer reading the registry sees the strongest statement the rule can make. Every
 * finding carries its own kind's severity from the report, which may be lower — the report's
 * tables are the source, and this map is the pack's summary of them.
 */
export const PRODUCTION_RISK_RULE_SEVERITIES = Object.freeze({
  environment: "low",
  container: "medium",
  ci: "low",
  api: "medium",
  dependencies: "low",
  architecture: "low",
});

/**
 * Confidence policy.
 *
 * One honest level, and it is not certainty: `OBSERVED_REPOSITORY_FACT` means the repository's
 * own evidence establishes the gap — the scan read the artifact, the projection cites the
 * observation behind it, and the report names the basis the finding rests on in its own
 * `confidence` field (`declared`, `absent`, `name-derived`, `graph-derived`). It says nothing
 * about how severe the gap is, and the report has no aggregate that could.
 */
export const PRODUCTION_RISK_CONFIDENCE = Object.freeze({
  OBSERVED_REPOSITORY_FACT: 0.9,
});

/** `metadata.basis` recorded on every risk finding. */
export const PRODUCTION_RISK_BASIS = "static-production-risk-report";

/** Findings one rule run will report before it stops and says so. */
export const MAX_PRODUCTION_RISK_FINDINGS = 200;

/** How each audit domain reads in a finding. */
export const PRODUCTION_RISK_SECTION_WORDING = Object.freeze({
  environment: "environment configuration",
  container: "container configuration",
  ci: "CI configuration",
  api: "API protection",
  dependencies: "dependency hygiene",
  architecture: "architecture integrity",
});

/** How each report coverage state reads in a finding's metadata. */
export const PRODUCTION_RISK_STATE_WORDING = Object.freeze({
  complete: "every input this domain reads was inspected, so the domain's answer is established",
  partial: "an answer exists, but an input was cut short, excluded or only partly established",
  unsupported: "the domain has no answer: this implementation does not interpret it",
  unknown: "the domain has no answer: the scan or the graph behind it was not established",
  truncated: "a bound stopped the reading, so the finding list is not the complete list",
});

/**
 * How each finding kind reads.
 *
 * Closed over the report's `PRODUCTION_RISK_FINDING_KINDS`: every kind the report can produce
 * is described here, and the pack's test pins the two lists together. Each phrase names the
 * gap, never its consequence.
 */
export const PRODUCTION_RISK_FINDING_WORDING = Object.freeze({
  "environment-file-without-template":
    "a live environment file with no example or template stating its keys",
  "environment-template-class-duplicated":
    "more than one file stating the same environment template class",
  "environment-template-classes-conflict":
    "the environment template stated under more than one naming class",
  "environment-configuration-without-sample":
    "environment configuration with no sample configuration file",
  "container-healthcheck-missing":
    "a container definition that declares no healthcheck instruction",
  "container-compose-dockerfile-not-observed":
    "a composition declaration naming a Dockerfile the repository does not contain",
  "container-compose-build-context-unresolved":
    "a composition build declaration that does not resolve inside the repository",
  "container-service-image-without-build":
    "a composition service running an image with no build context",
  "ci-release-without-test":
    "a release workflow name with no test-shaped workflow name beside it",
  "ci-release-without-lint":
    "a release workflow name with no lint-shaped workflow name beside it",
  "ci-workflows-unclassified":
    "workflow files whose names state no release, lint or test purpose",
  "ci-release-workflows-multiple": "more than one release workflow name",
  "api-route-protection-unresolved":
    "a route whose middleware could not be established at all",
  "api-protected-route-partially-unresolved":
    "a protected route whose middleware identity is only partly established",
  "api-router-inheritance-incomplete":
    "a route declared where a router-scope registration was not established",
  "dependency-manifest-without-lockfile": "a manifest with no lockfile in its ecosystem",
  "dependency-lockfile-without-manifest": "a lockfile with no manifest in its ecosystem",
  "dependency-ecosystems-multiple": "dependencies declared in more than one ecosystem",
  "dependency-source-unresolved":
    "a dependency source in a format this build does not interpret",
  "architecture-entrypoint-disconnected":
    "an entrypoint-shaped file no import relationship relates",
  "architecture-isolated-cluster":
    "a group of module files under one directory that nothing relates",
  "architecture-module-unconnected":
    "a container holding a manifest that no import edge touches",
});

/** How each severity reads. Closed over the report's three-word table. */
export const PRODUCTION_RISK_SEVERITY_WORDING = Object.freeze({
  info: "an inventory-only statement: the repository states a structural fact and nothing about a declaration is contradicted",
  low: "a declaration whose named counterpart the repository does not state, or states more than once",
  medium:
    "a declaration the repository makes that cannot hold as written, or a protection this build could not establish at all",
});

/** How each confidence reads. Closed over the report's four-word table. */
export const PRODUCTION_RISK_CONFIDENCE_WORDING = Object.freeze({
  declared: "the repository's own declaration states the gap, and the declaration was read",
  absent:
    "the gap is an absence, reported only over a reading that finished rather than one that was cut short",
  "name-derived": "the fact rests on the artifact's own file name and on nothing else",
  "graph-derived": "the fact is read from an accepted graph's own record",
});

/**
 * How each abstention reason reads.
 *
 * Closed over the report's abstention vocabulary — the inventory report's own reasons, which a
 * risk section inherits, plus the reasons the risk report adds. Every phrase describes a gap
 * in *knowledge*, never a defect: "the domain was only partly read, so this detection was
 * withheld" is in this map; "the container is insecure" is not, and could not be expressed
 * through it.
 */
export const PRODUCTION_RISK_ABSTENTION_WORDING = Object.freeze({
  // The reasons the risk report adds.
  "production-report-not-established":
    "no production report was established, so no domain has an answer to derive a gap from",
  "environment-coverage-not-complete":
    "the environment domain was only partly read, so an absence in it cannot be reported",
  "ci-coverage-not-complete":
    "the CI domain was only partly read, so an absence in it cannot be reported",
  "dependency-coverage-not-complete":
    "the dependency domain was only partly read, so an absence in it cannot be reported",
  "architecture-coverage-not-complete":
    "the architecture domain was only partly read, so an absence in it cannot be reported",
  "risk-finding-without-evidence":
    "a finding's provenance is not carried by the model, so the finding was withheld rather than reported unbacked",
  "risk-findings-truncated":
    "the domain's finding list reached its bound, so it is not the complete list",
  // The inventory report's reasons, which a risk section carries verbatim.
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
  "handler-not-established": "a declared route has no handler this build resolved",
  "api-framework-not-interpreted":
    "the repository declares an API framework this build does not read, so none of its endpoints is established",
  "api-source-not-interpreted":
    "module files in languages this build does not read were observed, so no endpoint of theirs is established",
  "section-observations-truncated":
    "the inventory section's observation list reached its bound, so it is not the complete list",
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
