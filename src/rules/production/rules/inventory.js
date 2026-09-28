/**
 * Code Guardian — Production Inventory Rules (Phase 20)
 *
 * The integration proof for Phase 20's ProductionReport, and deliberately six **inventory**
 * rules: one per audit domain, each reporting what the repository establishes in that domain
 * and nothing about whether it is good.
 *
 * ### What each rule proves about the report substrate
 *
 *   - it reads the report **only** through the Phase 11 query API (`productionReport`,
 *     `productionSection`, `productionCoverage`) — never the raw model area, never a file,
 *     never a parser, never a container runtime, never a registry;
 *   - every finding cites the observations the report itself cites, so provenance survives
 *     fingerprinting and "what proves this?" always has an answer;
 *   - every finding names the observation kind, its deterministic key and the section's own
 *     coverage state, so a reader can tell a complete reading from a partial one;
 *   - the abstention the report recorded is carried in the detection's metadata, and a
 *     domain the report could not establish makes the rule abstain rather than pass — so
 *     "nothing is declared here" is never claimed over a domain the report marked `unknown`;
 *   - an established-but-empty domain is the one case that reports no findings, and it is
 *     the honest one: the scan covered the repository and the domain is empty, which is an
 *     answer rather than a gap;
 *   - a bounded list is visibly bounded: a section that reached
 *     `PRODUCTION_REPORT_LIMITS.maxObservationsPerSection` records the truncation in its
 *     own abstentions, and this rule reports that abstention rather than presenting 200
 *     observations as the complete set.
 *
 * ### What is deliberately absent
 *
 * No score, no grade, no readiness percentage, no traffic light, no severity above `info`,
 * no "should", no environment comparison, no vulnerability lookup, no CVE, no package
 * audit and no runtime claim. A finding here states a fact the repository establishes, the
 * evidence behind it, and — in the same breath — what the report could not establish.
 */

import { createRule } from "../../../core/index.js";

import { APPLICABILITY_COVERAGE } from "../../contracts.js";
import { createRuleDetection } from "../../evaluation.js";

import {
  MAX_PRODUCTION_FINDINGS,
  PRODUCTION_ABSTENTION_WORDING,
  PRODUCTION_BASIS,
  PRODUCTION_CATEGORY,
  PRODUCTION_CONFIDENCE,
  PRODUCTION_OBSERVATION_WORDING,
  PRODUCTION_RULE_IDS,
  PRODUCTION_RULE_VERSION,
  PRODUCTION_SECTION_WORDING,
  PRODUCTION_STATE_WORDING,
} from "../contracts.js";
import { productionAbsence, productionCoverage, productionSection, queryFor } from "../signals.js";

/** How a workflow's name-derived purpose reads. */
const PURPOSE_WORDING = Object.freeze({
  release: "release-shaped",
  lint: "lint-shaped",
  test: "test-shaped",
  unclassified: "unclassified",
});

/** A parenthesised list, or an empty string. */
function list(values) {
  return values.length === 0 ? "" : ` (${values.map((value) => `\`${value}\``).join(", ")})`;
}

/** A count with a singular/plural noun. */
function count(value, noun) {
  return `${value} ${noun}${value === 1 ? "" : "s"}`;
}

/**
 * How one observation reads in a finding.
 *
 * A closed switch over the report's own observation kinds: a kind the report can produce but
 * this function cannot describe would be a contract mismatch, and the pack's test pins the
 * two vocabularies together. Every sentence states what the repository establishes, names
 * what was read, and — where a fact is name-derived — says so.
 */
function describeObservation(sectionName, observation) {
  const label = PRODUCTION_OBSERVATION_WORDING[observation.kind] ?? observation.kind;
  const path = typeof observation.path === "string" ? observation.path : null;

  switch (observation.kind) {
    case "environment-example":
    case "environment-template":
    case "environment-file":
    case "sample-configuration":
      return `The report records ${label} \`${path}\`, classified by its own file name. No environment artifact is opened, so no value, key or default in it is established.`;

    case "environment-template-duplicate":
      return `The report records ${label}: ${count(observation.count, "file")} in this repository state the same \`${observation.class}\` class${list(observation.paths ?? [])}${observation.pathsTruncated === true ? " and more" : ""}, each classified by its own file name.`;

    case "container-definition":
      return `The report records ${label}: \`${path}\` is a container definition the inventory observed. Whether it is complete, minimal or current is not established.`;

    case "container-ignore":
      return `The report records ${label}: \`${path}\` is a container ignore file the inventory observed. Which paths a build actually excludes is not established.`;

    case "container-composition":
      return `The report records ${label}: \`${path}\` is a container composition file the inventory observed.`;

    case "container-structure": {
      const healthcheck =
        observation.healthcheck === true
          ? "declares a healthcheck instruction"
          : observation.healthcheckDisabled === true
            ? "declares `HEALTHCHECK NONE`"
            : "declares no healthcheck instruction";
      return `The report records the declared structure of \`${path}\`, read from its own instructions: ${count(observation.stages, "build stage")}${list(observation.stageNames ?? [])}, ${count(observation.instructions, "instruction")} examined, and it ${healthcheck}. Whether the image built from it works is not established.`;
    }

    case "container-healthcheck":
      return `The report records ${label}: \`${path}\` declares a healthcheck instruction. What it checks, how often and whether it succeeds at runtime are not established.`;

    case "container-healthcheck-disabled":
      return `The report records ${label}: \`${path}\` declares \`HEALTHCHECK NONE\`, cancelling any inherited healthcheck.`;

    case "container-multi-stage":
      return `The report records ${label}: \`${path}\` declares ${count(observation.stages, "build stage")}${list(observation.stageNames ?? [])}, read from its own \`FROM\` instructions. Which stage a deployment uses is not established.`;

    case "container-build-context": {
      const context =
        observation.context === null
          ? "from the repository root"
          : `from the context \`${observation.context}\``;
      return `${label}: \`${observation.source}\` declares that service \`${observation.service}\` builds \`${path}\` ${context}. Whether that build succeeds is not established.`;
    }

    case "ci-provider":
      return `The report records ${label} \`${observation.provider}\` with ${count(observation.workflows, "workflow file")}${list((observation.files ?? []).slice(0, 5))}${observation.filesTruncated === true ? " and more" : ""}.`;

    case "ci-workflow":
      return `The report records ${label} \`${path}\` of provider \`${observation.provider}\`, whose own file name reads as ${PURPOSE_WORDING[observation.purpose] ?? "unclassified"}. The workflow body is never opened, so its steps, triggers and outcome are not established.`;

    case "api-route":
      return `The report records ${label} \`${observation.method} ${path}\`${list(observation.frameworks ?? [])}, with ${count(observation.handlers, "resolved handler")} and ${count(observation.middlewareReferences + observation.middlewareApplied, "middleware reference")}. Its structural protection state is \`${observation.protection ?? "unknown"}\`. Reachability at runtime and the correctness of that protection are not established.`;

    case "api-handler":
      return `${label}: \`${observation.route}\` is handled by \`${observation.name}\` in \`${path}\`. This is a static resolution of the declared name, not a statement about what the handler does.`;

    case "dependency-manifest":
      return `The report records ${label} \`${path}\` in ecosystem \`${observation.ecosystem}\` as \`${observation.role}\`, which the acquisition read as \`${observation.status}\`${observation.reason === null ? "" : ` (\`${observation.reason}\`)`}.`;

    case "dependency-lockfile":
      return `${label}: \`${path}\` resolved ${count(observation.resolved, "package")} and stated ${count(observation.edges, "edge")}. Whether those versions are current, safe or installable is not established.`;

    case "dependency-ecosystem":
      return `Ecosystem \`${observation.ecosystem}\` is declared by ${count(observation.manifests, "source")}: ${count(observation.runtime, "runtime declaration")}, ${count(observation.development, "development declaration")}, ${count(observation.optional, "optional declaration")}, ${count(observation.peer, "peer declaration")} and ${count(observation.unknownScope, "unscoped declaration")}. No vulnerability, currency or licence analysis is performed.`;

    case "architecture-layer":
      return `${count(observation.nodes, "observed entity")} of kind \`${observation.layer}\` take part in the architecture graph. Layering correctness, cohesion and coupling are not established.`;

    case "architecture-module":
      return `${label}: the container \`${observation.container}\` directly holds ${count(observation.manifestCount, "manifest")}${list((observation.manifests ?? []).slice(0, 5))}.`;

    case "architecture-entrypoint":
      return `${label}: \`${path}\` matches the entrypoint name table. That it is executed, or that it is the only way in, is not established.`;

    case "architecture-isolated-file":
      return `${label}: \`${path}\` neither imports nor is imported by a module the import graph established. Whether that is intended is not established.`;

    default:
      // Unreachable for a report this build produced (the test pins the vocabularies), but
      // stated rather than silently omitted: an undescribed kind must still be reported with
      // its own label and evidence.
      return `The report records ${label} in the ${PRODUCTION_SECTION_WORDING[sectionName]} section.`;
  }
}

/** One section's abstentions, in the report's own order, with their wording. */
function abstentionMetadata(section) {
  return section.unknown.map((record) => ({
    reason: record.reason,
    detail: record.detail,
    count: record.count,
    wording: PRODUCTION_ABSTENTION_WORDING[record.reason] ?? null,
  }));
}

/**
 * Detect one audit domain's inventory.
 *
 * @param {object} context A validated AnalysisContext.
 * @param {string} name The audit domain (one of `PRODUCTION_SECTIONS`).
 * @returns {object} A detection object.
 */
function detectSection(context, name) {
  const query = queryFor(context);
  const report = productionCoverage(query);
  const section = productionSection(query, name);

  if (section === null) {
    return createRuleDetection({
      findings: [],
      coverage: APPLICABILITY_COVERAGE.UNKNOWN,
      reason:
        "this model carries no production report, so no production domain can be reported",
    });
  }

  const findings = [];
  for (const observation of section.observations) {
    if (findings.length >= MAX_PRODUCTION_FINDINGS) break;
    findings.push({
      confidence: PRODUCTION_CONFIDENCE.OBSERVED_REPOSITORY_FACT,
      description: describeObservation(name, observation),
      evidence: [...observation.evidenceIds],
      metadata: {
        basis: PRODUCTION_BASIS,
        section: name,
        sectionState: section.state,
        sectionStateWording: PRODUCTION_STATE_WORDING[section.state] ?? null,
        kind: observation.kind,
        key: observation.key,
        fingerprintKey: observation.fingerprintKey,
        basis_detail: observation.basis ?? null,
        observation: { ...observation },
      },
    });
  }

  const metadata = {
    basis: PRODUCTION_BASIS,
    section: name,
    state: section.state,
    stateWording: PRODUCTION_STATE_WORDING[section.state] ?? null,
    established: section.established === true,
    sectionCoverage: { ...section.coverage },
    reportState: report?.state ?? null,
    reportEstablished: report?.established === true,
    counts: { ...section.counts },
    abstentions: abstentionMetadata(section),
    observations: section.observations.length,
    reported: findings.length,
    // Bounded twice over, and both bounds are reported as one fact: this rule may stop at
    // `MAX_PRODUCTION_FINDINGS`, and the report itself may have stopped at
    // `maxObservationsPerSection`, in which case the observations beyond the bound are not
    // in the model at all. Presenting either case as the complete set would be the one thing
    // this phase forbids, so `capped` is true whenever the finding list is not the whole
    // domain.
    capped:
      findings.length < section.observations.length || section.coverage.truncated === true,
  };

  if (findings.length > 0) {
    return { findings, evidence: [], metadata };
  }

  const absence = productionAbsence(query, name);
  if (!absence.established) {
    return {
      ...createRuleDetection({
        findings: [],
        coverage: APPLICABILITY_COVERAGE.UNKNOWN,
        reason: `no ${PRODUCTION_SECTION_WORDING[name]} observation is supported, because ${absence.reason}`,
      }),
      metadata,
    };
  }

  return { findings, evidence: [], metadata };
}

/**
 * The declarative half of one rule, shared by all six.
 *
 * The id, title, description and tags differ per domain; the severity is always `info`, the
 * applicability is always the whole repository (the report already says which domains it
 * could read), and the remediation is always empty — a rule that scores nothing has nothing
 * to recommend, and inventing a recommendation would be exactly the judgment this phase
 * forbids.
 */
function sectionRule({ id, section, title, description, tags, falsePositives }) {
  return createRule({
    id,
    version: PRODUCTION_RULE_VERSION,
    category: PRODUCTION_CATEGORY,
    title,
    description,
    severity: "info",
    applicability: {},
    detect: (context) => detectSection(context, section),
    remediation: {},
    metadata: { basis: PRODUCTION_BASIS, tags, falsePositives },
  });
}

const NOT_READ =
  "Nothing here reads a file, parses source, opens a container, resolves a dependency, contacts a registry or a network, or applies a vulnerability database: every statement comes from the repository model's already-validated report.";

export const productionRules = Object.freeze([
  sectionRule({
    id: PRODUCTION_RULE_IDS.ENVIRONMENT_INVENTORY,
    section: "environment",
    title: "Environment configuration artifacts",
    description:
      `An inventory of the environment configuration the repository states: example files, template files, environment files and sample configuration files, each classified by its own file name, plus which example/template classes are stated more than once. No environment file is opened, so no value, key or default is established, and the rule says so as its own abstention rather than reporting an empty result as a clean one. ${NOT_READ}`,
    tags: ["production", "environment", "inventory"],
    falsePositives: [
      "an environment artifact is classified by its own file name, so a file named `.env.production` is reported as an environment file whether or not it is used in production",
      "an environment-shaped path an ignore policy excludes is reported as an abstention, not as a present or absent file",
      "a duplicated template class is a statement about names, not about content: two files with the same class need not hold the same keys",
    ],
  }),
  sectionRule({
    id: PRODUCTION_RULE_IDS.CONTAINER_INVENTORY,
    section: "container",
    title: "Container configuration the repository declares",
    description:
      `An inventory of the container configuration the repository declares: container definitions, container ignore files, composition files, the build context each composition service states, and the structure each container definition's own instructions declare — its build stages, its named stages and whether it declares or disables a healthcheck. Only observed structure is reported; image quality, layer ordering, base-image currency, ignore coverage and reproducibility are never evaluated, and a definition whose instructions could not be read is reported as an abstention. ${NOT_READ}`,
    tags: ["production", "container", "inventory"],
    falsePositives: [
      "a healthcheck instruction is reported as declared, not as working: whether it runs, what it checks and whether it succeeds at runtime are not established",
      "a multi-stage definition is reported as declaring more than one stage, not as deploying a specific one",
      "a container definition no composition file mentions is still reported, because presence does not depend on anything declaring it used",
    ],
  }),
  sectionRule({
    id: PRODUCTION_RULE_IDS.CI_INVENTORY,
    section: "ci",
    title: "CI configuration the repository declares",
    description:
      `An inventory of the continuous-integration configuration the repository declares: which providers are configured, how many workflow files each contributes, and how each workflow's own file name reads — release-shaped, lint-shaped, test-shaped or unclassified. Workflow bodies are never opened, so no step, trigger, permission or outcome is established, and a workflow whose name states no purpose is reported as unclassified rather than guessed at. Workflow correctness is never judged. ${NOT_READ}`,
    tags: ["production", "ci", "inventory"],
    falsePositives: [
      "a workflow's purpose is derived from its file name, so `test.yml` reads as test-shaped whether or not it runs tests",
      "`ci.yml` and `build.yml` are deliberately unclassified: neither name establishes that tests run",
      "a provider's presence is reported as configuration, not as a pipeline that runs or that gates a merge",
    ],
  }),
  sectionRule({
    id: PRODUCTION_RULE_IDS.API_INVENTORY,
    section: "api",
    title: "API surface the repository declares",
    description:
      `An inventory of the endpoints the repository declares and how each is handled: the route's method, path and framework, the handler symbols resolved for it, the middleware references its own declaration states and the receiver-scope middleware the middleware graph established for it, plus each route's structural protection state. It is an inventory, not an exposure verdict: whether an endpoint should be reachable, whether its protection is sufficient and whether its handler is correct are not established and are not claimed. ${NOT_READ}`,
    tags: ["production", "api", "inventory"],
    falsePositives: [
      "a route is reported as declared by its own source file, not as reachable at runtime",
      "a protection state of `protected` means middleware was established for the route, not that it authenticates, authorizes or rate-limits anything",
      "a route whose middleware could not be established is reported as an abstention, so a route with unresolved middleware is never presented as unprotected",
    ],
  }),
  sectionRule({
    id: PRODUCTION_RULE_IDS.DEPENDENCIES_INVENTORY,
    section: "dependencies",
    title: "Dependency inventory the repository declares",
    description:
      `An inventory of the dependency substrate: which sources were read and what they turned out to be, which lockfiles resolved something along with what they resolved, and how each ecosystem's declarations fall across scopes — runtime, development, optional, peer and unscoped. There is no vulnerability analysis, no CVE lookup, no package audit, no outdated-version check, no licence check and no registry or network access of any kind. A source that could not be interpreted is reported as an abstention with its bounded reason. ${NOT_READ}`,
    tags: ["production", "dependencies", "inventory"],
    falsePositives: [
      "a lockfile that is present and resolves nothing is reported as present, because presence does not depend on a resolution",
      "a scope count is derived from what a manifest declared, so a runtime dependency of one manifest and a development dependency of another count once each",
      "no statement is made about whether a declared version exists, is installable or is current",
    ],
  }),
  sectionRule({
    id: PRODUCTION_RULE_IDS.ARCHITECTURE_INVENTORY,
    section: "architecture",
    title: "Architecture the repository establishes",
    description:
      `An inventory of four structural facts: how observed entities are distributed across the architecture graph's node kinds, which containers directly hold a manifest, which observed files are entrypoint-shaped **by name**, and which module files neither import nor are imported — the last only when the import graph was actually established. There is no coupling score, no cohesion metric, no layering verdict, no circular-dependency claim and no dead-code claim anywhere in it. ${NOT_READ}`,
    tags: ["production", "architecture", "inventory"],
    falsePositives: [
      "entrypoints are recognised by file name only, so a file named `main.js` is reported as entrypoint-shaped whether or not anything starts there",
      "an isolated file is a file the import graph established no relationship for, which is not a claim that it is unused",
      "a layer is a census of observed entity kinds, not an assertion about how the system is designed",
    ],
  }),
]);
