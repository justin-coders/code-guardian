/**
 * Code Guardian — Production Risk Rules (Phase 21)
 *
 * The integration proof for Phase 21's ProductionRiskReport, and deliberately six **audit**
 * rules: one per domain, each reporting the engineering gaps that domain's own evidence
 * proves and abstaining where the report withheld a detection.
 *
 * ### What each rule proves about the report substrate
 *
 *   - it reads the report **only** through the Phase 11 query API (`productionRiskReport`,
 *     `productionRiskCoverage`, `productionRiskSection`) — never the raw model area, never a
 *     file, never a parser, never a container runtime, never a registry;
 *   - every finding cites the evidence the report itself cites, so provenance survives
 *     fingerprinting and "what proves this?" always has an answer;
 *   - every finding carries **its own** closed severity from the report's per-kind table, the
 *     basis it rests on, and the report's own `confidence` word — so the rule's declared
 *     severity is a summary of the strongest statement it can make, never a substitute for the
 *     finding's;
 *   - the abstentions the report recorded are carried in the detection's metadata, and a domain
 *     the report could not establish makes the rule abstain rather than pass — so "this
 *     domain's evidence shows no gap" is never claimed over a domain that was not read;
 *   - an established domain with no findings is the one case that reports nothing, and it is
 *     the honest one: every input was inspected and the evidence shows no gap;
 *   - a bounded list is visibly bounded: a domain that reached its finding bound records the
 *     truncation in its own abstentions and the rule reports `capped`, rather than presenting
 *     the bound as the whole story.
 *
 * ### What is deliberately absent
 *
 * No score, no grade, no percentage, no traffic light, no severity above `medium`, no
 * vulnerability lookup, no CVE, no package audit, no outdated-version check, no licence check,
 * no runtime claim and no comparison against any environment. A finding here states a gap the
 * repository's own evidence proves, the evidence behind it, the basis it rests on, and — in
 * the same breath — what the report could not establish.
 */

import { createRule } from "../../../../core/index.js";

import { APPLICABILITY_COVERAGE } from "../../../contracts.js";
import { createRuleDetection } from "../../../evaluation.js";

import {
  MAX_PRODUCTION_RISK_FINDINGS,
  PRODUCTION_RISK_BASIS,
  PRODUCTION_RISK_CATEGORY,
  PRODUCTION_RISK_CONFIDENCE,
  PRODUCTION_RISK_FINDING_WORDING,
  PRODUCTION_RISK_RULE_IDS,
  PRODUCTION_RISK_RULE_SEVERITIES,
  PRODUCTION_RISK_RULE_VERSION,
  PRODUCTION_RISK_SECTION_WORDING,
  PRODUCTION_RISK_STATE_WORDING,
} from "../contracts.js";
import {
  productionRiskAbsence,
  productionRiskCoverage,
  productionRiskSection,
  queryFor,
} from "../signals.js";

/**
 * Detect one domain's gaps.
 *
 * @param {object} context A validated AnalysisContext.
 * @param {string} name The audit domain.
 * @returns {object} A detection object.
 */
function detectSection(context, name) {
  const query = queryFor(context);
  const report = productionRiskCoverage(query);
  const section = productionRiskSection(query, name);

  if (section === null) {
    return createRuleDetection({
      findings: [],
      coverage: APPLICABILITY_COVERAGE.UNKNOWN,
      reason:
        "this model carries no production risk report, so no domain's evidence can be reported",
    });
  }

  const findings = [];
  for (const finding of section.findings) {
    if (findings.length >= MAX_PRODUCTION_RISK_FINDINGS) break;
    findings.push({
      severity: finding.severity,
      title: `${section.title}: ${PRODUCTION_RISK_FINDING_WORDING[finding.kind] ?? finding.kind}`,
      description: finding.statement,
      confidence: PRODUCTION_RISK_CONFIDENCE.OBSERVED_REPOSITORY_FACT,
      evidence: [...finding.evidenceIds],
      // The report's remediation *text* is carried in `metadata.remediation`, never in the
      // finding's own `remediation` field: the Core Finding contract types that field as a
      // structured object and every accepted pack leaves it empty, so attaching a sentence there
      // would be inventing a contract rather than reading one.
      metadata: {
        basis: PRODUCTION_RISK_BASIS,
        section: name,
        sectionState: section.state,
        sectionStateWording: PRODUCTION_RISK_STATE_WORDING[section.state] ?? null,
        reportState: report?.state ?? null,
        reportEstablished: report?.established === true,
        kind: finding.kind,
        kindWording: PRODUCTION_RISK_FINDING_WORDING[finding.kind] ?? null,
        severityWording: finding.severityWording ?? null,
        confidence: finding.confidence,
        confidenceWording: finding.confidenceWording ?? null,
        basisDetail: finding.basis,
        findingId: finding.id,
        key: finding.key,
        statement: finding.statement,
        // `null` is a statement, not an omission: nothing is implied about the repository, so
        // nothing is recommended. See `renderRiskRemediation` for the policy.
        remediation: finding.remediation,
        remediationStated: typeof finding.remediation === "string",
        fingerprintKey: finding.fingerprintKey,
      },
    });
  }

  const metadata = {
    basis: PRODUCTION_RISK_BASIS,
    section: name,
    state: section.state,
    stateWording: PRODUCTION_RISK_STATE_WORDING[section.state] ?? null,
    established: section.established === true,
    sectionCoverage: { ...section.coverage },
    reportState: report?.state ?? null,
    reportEstablished: report?.established === true,
    counts: { ...section.counts },
    abstentions: section.unknown.map((record) => ({ ...record })),
    findings: section.findings.length,
    reported: findings.length,
    // Bounded twice over, and both bounds are reported as one fact: this rule may stop at
    // `MAX_PRODUCTION_RISK_FINDINGS`, and the report itself may have stopped at
    // `maxFindingsPerSection`, in which case the findings beyond the bound are not in the model
    // at all. Presenting either case as the whole story is the one thing this phase forbids, so
    // `capped` is true whenever the reported list is not the domain's complete list.
    capped: findings.length < section.findings.length || section.coverage.truncated === true,
  };

  if (findings.length > 0) {
    return { findings, evidence: [], metadata };
  }

  // No finding is the *answer* when the domain was established — every input was inspected and
  // the evidence shows no gap. When it was not, this rule abstains rather than passing.
  const absence = productionRiskAbsence(query, name);
  if (!absence.established) {
    return {
      ...createRuleDetection({
        findings: [],
        coverage: APPLICABILITY_COVERAGE.UNKNOWN,
        reason: `no ${PRODUCTION_RISK_SECTION_WORDING[name]} gap is supported, because ${absence.reason}`,
      }),
      metadata,
    };
  }

  return { findings, evidence: [], metadata };
}

/**
 * The declarative half of one rule, shared by all six.
 *
 * The id, title, description and tags differ per domain; the applicability is always the whole
 * repository (the report already says which domains it could read), the declared severity is
 * the strongest its own detection table can produce, and the remediation is empty at the rule
 * level — a recommendation is stated on a finding only when that finding's own evidence implies
 * one, and never as a rule-wide default.
 */
function sectionRule({ id, section, title, description, tags, falsePositives }) {
  return createRule({
    id,
    version: PRODUCTION_RISK_RULE_VERSION,
    category: PRODUCTION_RISK_CATEGORY,
    title,
    description,
    severity: PRODUCTION_RISK_RULE_SEVERITIES[section],
    applicability: {},
    detect: (context) => detectSection(context, section),
    remediation: {},
    metadata: { basis: PRODUCTION_RISK_BASIS, tags, falsePositives },
  });
}

const NOT_READ =
  "Nothing here reads a file, parses source, opens a container, resolves a dependency, contacts a registry or a network, or applies a vulnerability database: every statement comes from the repository model's already-validated risk report, and every finding cites the evidence behind it.";

const NO_SCORING =
  "No score, grade, percentage, traffic light or aggregate is produced: a finding states the gap the evidence proves, the basis it rests on, and what the report could not establish.";

export const productionRiskRules = Object.freeze([
  sectionRule({
    id: PRODUCTION_RISK_RULE_IDS.ENVIRONMENT,
    section: "environment",
    title: "Environment configuration gaps",
    description:
      `The environment configuration gaps the repository's own evidence proves: a live environment file with no example or template stating its keys, a template class stated more than once, the template stated under more than one naming class, and environment configuration with no sample configuration file. Detection is name-based and no environment file is ever opened, so no value, key or default is established — and every absence claim is withheld while the domain was only partly read, which is what an ignore policy excluding \`.env\` produces. ${NO_SCORING} ${NOT_READ}`,
    tags: ["production", "environment", "configuration", "risk"],
    falsePositives: [
      "an environment artifact is classified by its own file name, so a file named `.env.production` is treated as a live environment file whether or not it is used in production",
      "an environment-shaped path an ignore policy excludes is reported as an abstention, so no absence is claimed over it",
      "a template class is a naming fact: two files in one class need not hold the same keys",
    ],
  }),
  sectionRule({
    id: PRODUCTION_RISK_RULE_IDS.CONTAINER,
    section: "container",
    title: "Container configuration gaps",
    description:
      `The container configuration gaps the repository's declarations prove: a container definition whose own instructions declare no healthcheck and do not disable one, a composition service whose build names a Dockerfile the repository does not contain, a composition build declaration that does not resolve inside the repository, and a service that runs an image with no build context. Only observed structure is reported: image quality, layer ordering, base-image currency and ignore coverage are never evaluated, and a definition whose instructions could not be read is an abstention rather than a finding. ${NO_SCORING} ${NOT_READ}`,
    tags: ["production", "container", "docker", "risk"],
    falsePositives: [
      "a missing healthcheck instruction is reported as absent from the definition, not as an unhealthy image: whether a healthcheck would pass is not established",
      "an image reference is reported as declared, and the reference itself is never carried into the model, so no registry host travels with the finding",
      "a composition declaration whose context escapes the repository is a finding about the declaration's own text, which is never carried either",
    ],
  }),
  sectionRule({
    id: PRODUCTION_RISK_RULE_IDS.CI,
    section: "ci",
    title: "CI configuration gaps",
    description:
      `The CI configuration gaps the repository's workflow file names prove: a release-shaped name with no test- or lint-shaped name beside it, workflow files whose names state no purpose at all, and more than one release-shaped name. Classification is name-based and workflow bodies are never opened, so no step, trigger, permission or outcome is established — and the absence claims are withheld while any name is unclassified, because \`ci.yml\` may well be the test pipeline. ${NO_SCORING} ${NOT_READ}`,
    tags: ["production", "ci", "workflow", "risk"],
    falsePositives: [
      "a workflow's purpose is derived from its file name, so `test.yml` reads as test-shaped whether or not it runs tests",
      "`ci.yml` and `build.yml` are unclassified by design, so a release name with one of them beside it is an abstention rather than a finding",
      "a release-shaped name is not a statement that a release happens, gates a merge, or succeeds",
    ],
  }),
  sectionRule({
    id: PRODUCTION_RISK_RULE_IDS.API,
    section: "api",
    title: "API protection gaps",
    description:
      `The structural route-protection gaps the accepted API and middleware graphs establish: a route whose middleware could not be established at all, a protected route whose middleware identity is only partly established, and a route declared in a file where a router-scope registration was not established. Missing authentication, weak authorization, administrative exposure, CORS policy and rate limiting are **not** detected and cannot be: this build has no policy, no threat model and no runtime observation to compare a route against. ${NO_SCORING} ${NOT_READ}`,
    tags: ["production", "api", "middleware", "risk"],
    falsePositives: [
      "a route with unresolved middleware is reported as unresolved, never as unprotected: the report cannot tell whether the middleware exists",
      "a route is reported as declared by its own source file, not as reachable at runtime",
      "a protection state is a structural claim about declared registrations, never about authentication, authorization or rate limiting",
    ],
  }),
  sectionRule({
    id: PRODUCTION_RISK_RULE_IDS.DEPENDENCIES,
    section: "dependencies",
    title: "Dependency hygiene gaps",
    description:
      `The structural dependency gaps the manifests and lockfiles prove: a manifest with no lockfile in its ecosystem, a lockfile with no manifest, dependencies declared in more than one ecosystem, and a dependency source in a format this build does not interpret. There is no vulnerability analysis, no CVE lookup, no package audit, no outdated-version check, no licence check and no registry or network access of any kind — the absence claims are made only over a reading in which every source was parsed. ${NO_SCORING} ${NOT_READ}`,
    tags: ["production", "dependencies", "lockfile", "risk"],
    falsePositives: [
      "a missing lockfile is a statement about what the repository declares, never about whether its dependencies are safe, current or installable",
      "an uninterpreted source is a statement about the source's format and this build's readers, not about the dependency",
      "two ecosystems are reported as declared, not as a defect: whether each is maintained by its own toolchain is not established",
    ],
  }),
  sectionRule({
    id: PRODUCTION_RISK_RULE_IDS.ARCHITECTURE,
    section: "architecture",
    title: "Architecture integrity gaps",
    description:
      `The structural gaps the architecture and import graphs establish: an entrypoint-shaped file no import relationship relates, a group of such files under one directory, and a container holding a manifest that no import edge touches. There is no coupling score, no complexity metric, no layering verdict, no circular-dependency detection and no dead-code claim — and every one of the three is withheld unless the import graph was complete, because an absence is only reportable over a finished reading. ${NO_SCORING} ${NOT_READ}`,
    tags: ["production", "architecture", "imports", "risk"],
    falsePositives: [
      "an entrypoint is recognised by file name, so `main.js` is entrypoint-shaped whether or not anything starts there",
      "an unconnected container is one no import edge touches *and* that the import graph actually carries a file for: a container of files no reader covers is skipped rather than reported",
      "an isolated file is a file the import graph established no relationship for, which is not a claim that it is unused",
    ],
  }),
]);
