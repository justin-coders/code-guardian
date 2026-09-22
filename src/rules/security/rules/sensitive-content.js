/**
 * Code Guardian — Sensitive Content Security Rules (Phase 12 correction)
 *
 * Two rules over the model's bounded content observations. They exist because a
 * name is not a fact: a `.npmrc` with a registry token and a `.npmrc` that only
 * pins a registry are the same filename, and a `.tfvars` with a database password
 * and one with a region are the same filename. Reporting both as findings is noise;
 * reporting neither is a blind spot. These rules report the ones where a
 * credential-shaped value was actually observed.
 *
 * ### What the rules may say, and what they may not
 *
 * The finding states that a credential-shaped value was observed in a named file,
 * and names the *pattern* that matched — never the value, the line or the surrounding
 * text. The model never carries them (the scanner records pattern ids only), so a
 * finding physically cannot leak a secret, and the wording never claims more than the
 * pattern proves: a matched `password = …` assignment is not proof of a live
 * credential, and the description says so.
 *
 * ### Three outcomes per candidate, and why they differ
 *
 *   inspected, pattern matched   → one finding, citing the file's own observations
 *                                   plus the pattern observation
 *   inspected, nothing matched   → no finding: the coverage was good enough to say
 *                                   the bounded inspection found nothing
 *   not inspected / truncated    → `unknown`: a file whose size, budget or type
 *                                   stopped the inspection is not a clean file, and a
 *                                   candidate with *no* observation at all (an older
 *                                   scan) is not one either
 *
 * A rule that observed a match reports it regardless of coverage, because findings
 * always win over abstention.
 */

import { createRule } from "../../../core/index.js";

import { APPLICABILITY_COVERAGE } from "../../contracts.js";
import { createRuleDetection } from "../../evaluation.js";

import {
  CONTENT_CANDIDATE_FILES,
  CONTENT_PATTERNS,
  FINDING_BASES,
  SECURITY_CATEGORY,
  SECURITY_CONFIDENCE,
  SECURITY_RULE_IDS,
  SECURITY_RULE_VERSION,
} from "../contracts.js";
import { defineFileSpec } from "../matching.js";
import {
  contentInspectionFor,
  filesMatching,
  inventoryAbsence,
  isCompleteContentInspection,
  queryFor,
} from "../signals.js";

/** The observed files the content rules consider, validated and frozen once. */
const CONTENT_SPEC = defineFileSpec(CONTENT_CANDIDATE_FILES, { name: "contentCandidateSpec" });

/** A bounded description of why a candidate could not be settled. */
function describeUnresolved(entries) {
  const reasons = [...new Set(entries.map((entry) => entry.reason))].sort();
  return `${entries.length} candidate file(s) could not be fully inspected (${reasons.join(
    ", ",
  )})`;
}

/**
 * Detect one family of content patterns.
 *
 * @param {object} context A validated AnalysisContext.
 * @param {string[]} patternIds The patterns this rule owns.
 * @returns {object} A detection object.
 */
function detectContentPatterns(context, patternIds) {
  const query = queryFor(context);
  const candidates = filesMatching(query, CONTENT_SPEC);

  const findings = [];
  const unresolved = [];
  let inspected = 0;

  for (const file of candidates) {
    const inspection = contentInspectionFor(query, file);

    if (!isCompleteContentInspection(inspection)) {
      unresolved.push({
        path: file.path,
        reason: inspection === null ? "no-inspection-recorded" : inspection.reason ?? inspection.status,
      });
      continue;
    }

    inspected += 1;
    const matched = inspection.patterns.filter((entry) => patternIds.includes(entry.pattern));
    if (matched.length === 0) continue;

    findings.push({
      confidence: SECURITY_CONFIDENCE.OBSERVED_CONTENT,
      // The file's own observations (what it is) plus the pattern observation (what
      // was found in it). Both are the model's records, referenced rather than
      // rebuilt, and neither carries the matched text.
      evidence: [
        ...new Set([...file.evidenceIds, ...matched.map((entry) => entry.evidenceId)]),
      ].sort(),
      metadata: {
        path: file.path,
        patterns: [...new Set(matched.map((entry) => entry.pattern))].sort(),
        basis: FINDING_BASES.CONTENT,
      },
    });
  }

  if (findings.length > 0) {
    return {
      findings,
      evidence: [],
      metadata: {
        basis: FINDING_BASES.CONTENT,
        candidates: candidates.length,
        inspected,
        unresolved: unresolved.length,
      },
    };
  }

  // Nothing matched. Either because nothing was worth inspecting (an absence claim
  // over the inventory, which needs coverage) or because the inspection itself could
  // not settle every candidate.
  if (candidates.length === 0) {
    const absence = inventoryAbsence(query);
    if (!absence.established) {
      return createRuleDetection({
        findings: [],
        coverage: APPLICABILITY_COVERAGE.UNKNOWN,
        reason: `no candidate file was observed, but ${absence.reason}`,
      });
    }
    return {
      findings: [],
      evidence: [],
      metadata: {
        basis: FINDING_BASES.CONTENT,
        candidates: 0,
        observedFiles: absence.observedFiles,
        ignoredPaths: absence.ignoredPaths,
      },
    };
  }

  if (unresolved.length > 0) {
    return createRuleDetection({
      findings: [],
      coverage: APPLICABILITY_COVERAGE.UNKNOWN,
      reason: `${describeUnresolved(
        unresolved,
      )}, so no supported credential pattern was established as present or absent`,
    });
  }

  return {
    findings: [],
    evidence: [],
    metadata: { basis: FINDING_BASES.CONTENT, candidates: candidates.length, inspected },
  };
}

function contentRule({ id, title, description, severity, patterns, tags, metadata = {} }) {
  return createRule({
    id,
    version: SECURITY_RULE_VERSION,
    category: SECURITY_CATEGORY,
    title,
    description,
    severity,
    applicability: {},
    detect: (context) => detectContentPatterns(context, patterns),
    remediation: {},
    metadata: { basis: FINDING_BASES.CONTENT, tags, ...metadata },
  });
}

export const sensitiveContentRules = Object.freeze([
  contentRule({
    id: SECURITY_RULE_IDS.CREDENTIAL_CONTENT,
    title: "Credential-shaped value is present in a repository file",
    description:
      "Bounded content inspection of a package-manager, direnv, dotenv, Terraform variable or SQL file matched a credential-shaped pattern: a `name = value` assignment mentioning a password, secret, token, key or auth field; an AWS secret access key or session token assignment; a URL with inline user:password credentials; or a SQL password statement. The matching pattern is named on the finding; the value itself is never read out of the file, stored in the repository model, or reproduced here, so this finding does not identify or validate the credential.",
    severity: "high",
    patterns: [
      CONTENT_PATTERNS.CREDENTIAL_ASSIGNMENT,
      CONTENT_PATTERNS.AWS_CREDENTIAL_ASSIGNMENT,
      CONTENT_PATTERNS.BASIC_AUTH_URL,
      CONTENT_PATTERNS.SQL_PASSWORD_STATEMENT,
    ],
    tags: ["secrets", "credentials", "content"],
    metadata: {
      falsePositives: [
        "a placeholder or example value that is not a live credential",
        "a committed value that has been revoked",
      ],
    },
  }),
  contentRule({
    id: SECURITY_RULE_IDS.PRIVATE_KEY_CONTENT,
    title: "Private key material is present in a repository file",
    description:
      "Bounded content inspection of a candidate file matched a PEM private-key header (`-----BEGIN … PRIVATE KEY-----`). Public certificates use a different header and do not match. The header was observed; no key material was read out of the file, stored in the repository model, or reproduced here.",
    severity: "high",
    patterns: [CONTENT_PATTERNS.PRIVATE_KEY_BLOCK],
    tags: ["secrets", "keys", "content"],
  }),
]);
