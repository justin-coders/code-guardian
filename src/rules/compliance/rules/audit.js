/**
 * Code Guardian — Compliance Rules (Phase 22)
 *
 * The integration proof for Phase 22's ComplianceReport, and deliberately six **audit** rules: one
 * per policy domain, each reporting the requirements that domain's declared policy contradicts and
 * abstaining where nothing could be measured.
 *
 * ### What each rule proves about the report substrate
 *
 *   - it reads the report **only** through the Phase 11 query API (`complianceReport`,
 *     `complianceCoverage`, `complianceSection`, `policy`) — never the raw model area, never a
 *     file, never a parser, never a container runtime, never a package manager;
 *   - every finding cites **both** sides of the statement: the repository observation that proves
 *     the condition, and the policy document that makes the condition wrong. A finding with one
 *     side would be an accusation without a rule, and the rule refuses to emit one;
 *   - every finding carries the item's own closed fields — its policy key, the declared value, the
 *     observed token, the basis and the item's own rationale — so a consumer can audit the
 *     sentence back to the tuple it came from;
 *   - **a domain with no policy abstains.** It does not pass, it does not report a finding, and the
 *     reason it gives is the report's own: `policy-domain-not-declared`, or the domain was not
 *     established, or nothing in it could be measured. "No requirement is stated" and "every
 *     requirement is satisfied" are different answers and are reported differently;
 *   - a domain that was measured *and* partly unmeasured also abstains, because a `partial` section
 *     means some requirement has no measurement — reporting silence over it would be the one thing
 *     this phase exists to prevent;
 *   - a bounded list is visibly bounded: a domain that reached its item bound records the truncation
 *     in its own abstentions and the rule reports `capped` rather than presenting the bound as the
 *     whole story.
 *
 * ### What is deliberately absent
 *
 * No compliance percentage, no grade, no traffic light, no severity above `medium`, no vulnerability
 * lookup, no licence check, no runtime claim and no comparison against any environment. A finding
 * here states the requirement, the observation that contradicts it, the policy that declares it, and
 * the evidence for both.
 */

import { createRule } from "../../../core/index.js";

import { APPLICABILITY_COVERAGE } from "../../contracts.js";
import { createRuleDetection } from "../../evaluation.js";

import {
  COMPLIANCE_BASIS,
  COMPLIANCE_CATEGORY,
  COMPLIANCE_CONFIDENCE,
  COMPLIANCE_RULE_IDS,
  COMPLIANCE_RULE_SEVERITIES,
  COMPLIANCE_RULE_VERSION,
  COMPLIANCE_SECTION_WORDING,
  COMPLIANCE_STATE_WORDING,
  MAX_COMPLIANCE_FINDINGS,
} from "../contracts.js";
import {
  complianceAbsence,
  complianceCoverage,
  compliancePolicy,
  complianceSection,
  complianceUnmeasuredReason,
  queryFor,
} from "../signals.js";

/**
 * Detect one domain's violations.
 *
 * @param {object} context A validated AnalysisContext.
 * @param {string} name The policy domain.
 * @returns {object} A detection object.
 */
function detectDomain(context, name) {
  const query = queryFor(context);
  const report = complianceCoverage(query);
  const section = complianceSection(query, name);
  const policy = compliancePolicy(query);

  if (section === null) {
    return createRuleDetection({
      findings: [],
      coverage: APPLICABILITY_COVERAGE.UNKNOWN,
      reason:
        "this model carries no compliance report, so no declared requirement can be measured",
    });
  }

  const findings = [];
  for (const item of section.items) {
    if (item.status !== "violation") continue;
    if (findings.length >= MAX_COMPLIANCE_FINDINGS) break;
    findings.push({
      severity: COMPLIANCE_RULE_SEVERITIES[name],
      title: `Policy violation: ${item.policyKey}${item.subject === null ? "" : ` (${item.subject})`}`,
      // The report's own sentence, with the subject it is about in front of it when the item is
      // about one artifact. Nothing is re-worded here: the description a consumer reads is the
      // rationale the report rendered from the item's own fields.
      description: item.subject === null ? item.rationale : `${item.subject}: ${item.rationale}`,
      confidence: COMPLIANCE_CONFIDENCE.DECLARED_POLICY_VIOLATION,
      // Both sides of the accusation, in one list: the repository observation and the policy
      // document. The model refuses a violation with either side missing; this repeats the rule at
      // the pack's own boundary.
      evidence: [...new Set([...item.evidenceIds, ...item.policyEvidenceIds])].sort(),
      metadata: {
        basis: COMPLIANCE_BASIS,
        domain: name,
        domainWording: COMPLIANCE_SECTION_WORDING[name] ?? null,
        sectionState: section.state,
        sectionStateWording: COMPLIANCE_STATE_WORDING[section.state] ?? null,
        policyState: policy?.state ?? null,
        policyEstablished: policy?.established === true,
        policyDeclared: section.policyDeclared === true,
        reportState: report?.state ?? null,
        reportEstablished: report?.established === true,
        policyKey: item.policyKey,
        key: item.key,
        expected: item.expected,
        observed: item.observed,
        status: item.status,
        statusWording: item.statusWording ?? null,
        subject: item.subject,
        itemBasis: item.basis,
        itemId: item.id,
        rationale: item.rationale,
        policyEvidenceIds: [...item.policyEvidenceIds],
        repositoryEvidenceIds: [...item.evidenceIds],
        fingerprintKey: item.fingerprintKey,
      },
    });
  }

  const metadata = {
    basis: COMPLIANCE_BASIS,
    domain: name,
    domainWording: COMPLIANCE_SECTION_WORDING[name] ?? null,
    state: section.state,
    stateWording: COMPLIANCE_STATE_WORDING[section.state] ?? null,
    established: section.established === true,
    policyDeclared: section.policyDeclared === true,
    policyState: policy?.state ?? null,
    policyEstablished: policy?.established === true,
    policyKeys: [...section.policyKeys],
    counts: { ...section.counts },
    abstentions: section.unknown.map((record) => ({ ...record })),
    reportState: report?.state ?? null,
    reportEstablished: report?.established === true,
    findings: section.items.filter((item) => item.status === "violation").length,
    reported: findings.length,
    // Bounded twice over, and both bounds are reported as one fact: this rule may stop at
    // `MAX_COMPLIANCE_FINDINGS`, and the report itself may have stopped at
    // `maxItemsPerSection`, in which case the items beyond the bound are not in the model at all.
    capped: findings.length < section.counts.violations || section.coverage.truncated === true,
  };

  if (findings.length > 0) {
    return { findings, evidence: [], metadata };
  }

  // No violation. That is only an answer when every requirement in the domain was measured:
  // otherwise the rule abstains with the model's own reasons rather than reporting silence over
  // something nobody measured.
  const absence = complianceAbsence(query, name);
  if (!absence.established) {
    return {
      ...createRuleDetection({
        findings: [],
        coverage: APPLICABILITY_COVERAGE.UNKNOWN,
        reason: `no ${COMPLIANCE_SECTION_WORDING[name] ?? name} violation is supported, because ${absence.reason}`,
      }),
      metadata,
    };
  }

  if (section.state === "partial") {
    return {
      ...createRuleDetection({
        findings: [],
        coverage: APPLICABILITY_COVERAGE.UNKNOWN,
        reason: `no ${COMPLIANCE_SECTION_WORDING[name] ?? name} violation is reported, but the policy is not satisfied either: ${complianceUnmeasuredReason(section)}`,
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
 * repository (the report already says which domains it could read), the declared severity is the
 * strongest its own detection table can produce, and the remediation is empty at the rule level — a
 * policy violation is a statement about a declaration, and this pack recommends nothing.
 */
function domainRule({ id, domain, title, description, tags, falsePositives }) {
  return createRule({
    id,
    version: COMPLIANCE_RULE_VERSION,
    category: COMPLIANCE_CATEGORY,
    title,
    description,
    severity: COMPLIANCE_RULE_SEVERITIES[domain],
    applicability: {},
    detect: (context) => detectDomain(context, domain),
    remediation: {},
    metadata: { basis: COMPLIANCE_BASIS, tags, falsePositives },
  });
}

const NOT_READ =
  "Nothing here reads a file, parses source, opens a container, resolves a dependency, contacts a registry or a network, or applies a vulnerability database: every statement comes from the repository model's already-validated policy and compliance projection, and every finding cites both the observation behind it and the declaration it contradicts.";

const NO_SCORING =
  "No score, grade, percentage, traffic light or aggregate is produced: a finding states the requirement, the observation that contradicts it, and the policy document that declares it.";

const NO_POLICY_NO_PASS =
  "A domain whose policy declares no requirement, or whose reading established nothing, makes this rule abstain rather than pass — `unknown` is never a satisfied requirement.";

export const complianceRules = Object.freeze([
  domainRule({
    id: COMPLIANCE_RULE_IDS.ENVIRONMENT,
    domain: "environment",
    title: "Environment policy compliance",
    description:
      `The environment requirements this repository's own policy declares and its own evidence contradicts: a required environment template that the environment reading observed none of, and a policy that allows at most one environment template beside more than one observed. Every violation cites both the naming observation it rests on and the policy document that requires the opposite. Whether a template's keys match the live file's is not established — no environment file is ever opened — so no violation is claimed about content. ${NO_POLICY_NO_PASS} ${NO_SCORING} ${NOT_READ}`,
    tags: ["compliance", "policy", "environment", "configuration"],
    falsePositives: [
      "an environment artifact is classified by its own file name, so `.env.production` is treated as a live environment file whether or not it is used in production",
      "`requireTemplate: true` is violated by the absence of a template *name* the report observed, never by a missing key, a wrong value or a stale template",
      "a policy that sets `requireTemplate: false` states no requirement, so nothing is measured and no finding can come from it",
    ],
  }),
  domainRule({
    id: COMPLIANCE_RULE_IDS.CONTAINER,
    domain: "container",
    title: "Container policy compliance",
    description:
      `The container requirements this repository's own policy declares and its own container definitions contradict: a required healthcheck that a Dockerfile declares none of, and a required healthcheck that a Dockerfile disables. Each finding cites the Dockerfile's own instruction observation and the policy that requires the opposite. Image quality, layer ordering and base-image currency are never evaluated, a definition whose instructions were not established produces no finding, and a repository that declares no container definition produces no finding either — the policy requires a healthcheck of the definitions that exist, and with none there is nothing the requirement ranges over. ${NO_POLICY_NO_PASS} ${NO_SCORING} ${NOT_READ}`,
    tags: ["compliance", "policy", "container", "docker"],
    falsePositives: [
      "a healthcheck is measured from the Dockerfile's own instructions: this build never runs the container and never establishes that an image is unhealthy",
      "`HEALTHCHECK NONE` contradicts `requireHealthcheck: true` and is reported as a *disabled* healthcheck, so the two cases stay distinguishable",
      "a Dockerfile the container reading could not interpret produces an abstention rather than a finding",
      "a repository with no container definition declares no subject for the requirement, so the rule abstains instead of reading the emptiness as compliance",
    ],
  }),
  domainRule({
    id: COMPLIANCE_RULE_IDS.CI,
    domain: "ci",
    title: "CI policy compliance",
    description:
      `The CI requirements this repository's own policy declares and its own workflow names contradict: a required test or lint workflow beside a release workflow that none was observed for, and a release-workflow limit that the observed release-shaped names exceed. A workflow's purpose is its own file name; no workflow body is ever opened. When a workflow file name states no purpose the requirement is *abstained*, not violated, because a file named ci.yml may be the pipeline the policy asks for — and a release limit is only measured against the count the names establish. ${NO_POLICY_NO_PASS} ${NO_SCORING} ${NOT_READ}`,
    tags: ["compliance", "policy", "ci", "workflow"],
    falsePositives: [
      "a workflow's purpose is derived from its file name, so `test.yml` reads as test-shaped whether or not it runs tests",
      "an unclassified workflow name withholds the claim rather than producing a finding: the rule abstains and says why",
      "a repository that declares no release workflow has no release path for the requirement to range over, so the domain abstains rather than passing it",
    ],
  }),
  domainRule({
    id: COMPLIANCE_RULE_IDS.API,
    domain: "api",
    title: "API policy compliance",
    description:
      `The API requirement this repository's own policy declares and its own middleware graph contradicts: a route whose middleware could not be resolved while the policy requires every route's middleware to be established. The finding cites the route's own protection observation and the policy document that requires the opposite — it is never a claim that the route is unprotected, and a route whose middleware is established as *none* satisfies the requirement because the answer is established. Authentication, authorization, rate limiting, CORS and administrative exposure are never evaluated: this build has no policy key for them. ${NO_POLICY_NO_PASS} ${NO_SCORING} ${NOT_READ}`,
    tags: ["compliance", "policy", "api", "middleware"],
    falsePositives: [
      "`requireResolvedMiddleware` requires the middleware state to be *established*, not the route to be protected: an unresolved registration violates it and a route with no middleware does not",
      "a route whose protection state the graph never established produces an abstention rather than a finding",
      "the routes measured are the accepted API graph's own nodes, so this rule cannot disagree with any other pack about which routes exist",
    ],
  }),
  domainRule({
    id: COMPLIANCE_RULE_IDS.DEPENDENCIES,
    domain: "dependencies",
    title: "Dependency policy compliance",
    description:
      `The dependency requirements this repository's own policy declares and its own manifests contradict: a required lockfile that a manifest's ecosystem does not have, and a single-ecosystem policy beside more than one declared ecosystem. Each finding cites the manifest or the ecosystem census it rests on and the policy that requires the opposite. There is no vulnerability analysis, no CVE lookup, no package audit and no outdated-version check: a required lockfile is a requirement about a *file*, and the finding never claims the dependencies are unsafe, outdated or unresolvable. A source that was not interpreted produces an abstention rather than a finding. ${NO_POLICY_NO_PASS} ${NO_SCORING} ${NOT_READ}`,
    tags: ["compliance", "policy", "dependencies", "lockfile"],
    falsePositives: [
      "`requireLockfile` measures whether a lockfile was *observed* in the manifest's ecosystem, never whether the versions it pins are correct, current or installable",
      "a lockfile with no manifest, or a manifest whose lockfile is unread, is a reading gap: it is reported as an abstention",
      "`allowMultipleManagers: false` is violated by two declared ecosystems, whatever each one is used for",
    ],
  }),
  domainRule({
    id: COMPLIANCE_RULE_IDS.ARCHITECTURE,
    domain: "architecture",
    title: "Architecture policy compliance",
    description:
      `The architecture requirement this repository's own policy declares and its own import graph contradicts: an entrypoint-shaped file that no import edge relates while the policy requires entrypoints to be connected. Entrypoint recognition is name-based, and the finding cites the entrypoint's own observation beside the policy that requires the opposite. It is never a claim that the file is unused, dead or unreachable at runtime, and it is only made when the import graph was read completely — the graph's silence about a file is not proof unless the graph is whole. ${NO_POLICY_NO_PASS} ${NO_SCORING} ${NOT_READ}`,
    tags: ["compliance", "policy", "architecture", "imports"],
    falsePositives: [
      "`main.js` with no import edge is entrypoint-shaped by name, and the finding rests on the import graph's own isolated-file observation",
      "a partial import graph makes the item unmeasured, so the rule abstains instead of reporting a disconnected entrypoint",
      "there is no coupling score, no complexity metric and no dead-code claim anywhere in this rule",
    ],
  }),
]);
