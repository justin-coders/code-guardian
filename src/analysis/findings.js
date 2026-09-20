/**
 * Code Guardian — Finding Engine (Phase 9)
 *
 * The Finding Engine is the canonical path from "an analyzer thinks something is
 * wrong" to "a validated, fingerprinted Finding". Analyzers do not have to
 * implement any of it, and consumers are guaranteed that every finding they see
 * has been through it.
 *
 * ### Lifecycle
 *
 *   1. raw          the analyzer returns findings (validated as *raw* findings by
 *                   `validateAnalyzerResult` — no fingerprint required, because
 *                   Phase 7 deliberately left fingerprint generation to this
 *                   phase);
 *   2. normalized   this module fills what the analyzer omitted from the matched
 *                   Rule, sanitizes metadata, resolves evidence references and
 *                   rejects anything it cannot represent;
 *   3. canonical    a fingerprint is generated (or verified), the id defaults to
 *                   the fingerprint, and `validateFinding` proves the result is a
 *                   canonical Finding.
 *
 * No step can skip the next: the engine calls this module for every raw finding,
 * and a finding that fails anywhere fails the analyzer's run rather than reaching
 * the aggregate result.
 *
 * ### Fingerprint semantics
 *
 * A fingerprint identifies the **logical condition**, not its presentation. It is
 * derived from exactly these inputs:
 *
 *   algorithm     the fingerprint algorithm id (`cg-fp1`)
 *   ruleId        which rule fired
 *   category      the domain category
 *   evidence      the sorted evidence reference ids (the observation set)
 *   fingerprintKey  `metadata.fingerprintKey`, an optional analyzer-supplied
 *                   disambiguator for two findings at one observation set
 *
 * Everything else is explicitly **not** identity: severity, confidence, title,
 * description, status, remediation, impact, every other metadata key, the
 * analyzer id/version, run duration and wall-clock time. Rewording a finding,
 * raising its severity, or reporting it from a second analyzer therefore keeps
 * the same fingerprint — which is what makes baselining, deduplication and
 * regression detection meaningful.
 *
 * `sha256` truncated to 128 bits is used because the fingerprint is a
 * deduplication and baseline key: a 32-bit hash would collide often enough
 * (~1% at 10k findings) to silently merge distinct findings, and a silently
 * merged finding is worse than a duplicate one. No timestamp, uuid, pid, memory
 * address or host path takes part.
 */

import { createHash } from "node:crypto";

import {
  DEFAULT_FINDING_STATUS,
  FINDING_SEVERITIES,
  FINDING_STATUSES,
  createFinding,
  validateFinding,
} from "../core/index.js";

import {
  ANALYZER_FAILURE_KINDS,
  FINDING_FINGERPRINT_ALGORITHM,
  FINDING_FINGERPRINT_PREFIX,
  FINDING_ID_PREFIX,
  FINGERPRINT_KEY_METADATA_KEY,
  MAX_FINGERPRINT_KEY_LENGTH,
  MAX_IDENTIFIER_LENGTH,
} from "./contracts.js";
import { AnalyzerFrameworkError, sanitizeMessage } from "./errors.js";
import { sanitizeDeclarativeValue } from "./values.js";

/** Shape of an analyzer-supplied disambiguator. */
const FINGERPRINT_KEY_PATTERN = /^[A-Za-z0-9._:-]{1,120}$/;

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function invalidFinding(analyzer, message, details = {}) {
  return new AnalyzerFrameworkError(ANALYZER_FAILURE_KINDS.INVALID_FINDING, message, {
    analyzerId: analyzer?.id ?? null,
    ...details,
  });
}

function unknownEvidence(analyzer, references) {
  return new AnalyzerFrameworkError(
    ANALYZER_FAILURE_KINDS.UNKNOWN_EVIDENCE_REFERENCE,
    "a finding cites evidence that is neither in the repository model nor produced by this analyzer",
    { analyzerId: analyzer?.id ?? null, evidence: references },
  );
}

/**
 * Read the analyzer-supplied disambiguator, validating its shape.
 *
 * @param {object} metadata Raw metadata (before sanitization).
 * @param {object} analyzer For diagnostics.
 * @returns {string|null}
 */
export function fingerprintKeyOf(metadata, analyzer = null) {
  if (!isPlainObject(metadata)) return null;
  const value = metadata[FINGERPRINT_KEY_METADATA_KEY];
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || !FINGERPRINT_KEY_PATTERN.test(value)) {
    throw invalidFinding(
      analyzer,
      `metadata.${FINGERPRINT_KEY_METADATA_KEY} must be a bounded identifier (letters, digits, . _ : -, max ${MAX_FINGERPRINT_KEY_LENGTH})`,
    );
  }
  return value;
}

/**
 * Compute the canonical fingerprint for a finding identity.
 *
 * @param {object} input
 * @param {string} input.ruleId
 * @param {string} input.category
 * @param {string[]} [input.evidence] Evidence reference ids.
 * @param {string|null} [input.fingerprintKey]
 * @returns {string} `cg-fp1-<32 hex characters>`.
 */
export function findingFingerprint({ ruleId, category, evidence = [], fingerprintKey = null }) {
  const material = [
    `algorithm:${FINDING_FINGERPRINT_ALGORITHM}`,
    `rule:${String(ruleId)}`,
    `category:${String(category)}`,
    `key:${fingerprintKey ?? "-"}`,
    ...[...evidence].map((id) => String(id)).sort().map((id) => `evidence:${id}`),
  ].join("\n");
  const digest = createHash("sha256").update(material, "utf8").digest("hex");
  return `${FINDING_FINGERPRINT_PREFIX}${digest.slice(0, 32)}`;
}

/**
 * Normalize one analyzer-supplied finding into a canonical, frozen Finding.
 *
 * @param {object} input The analyzer's raw finding.
 * @param {object} options
 * @param {object} options.analyzer The producing analyzer (for provenance).
 * @param {object|null} [options.rule] The matched Rule, used to fill omitted
 *   static fields (`category`, `severity`, `title`, `description`).
 * @param {Set<string>} options.allowedEvidenceIds Evidence the finding may cite.
 * @returns {object} A canonical Finding (fingerprint present, validated, frozen).
 * @throws {AnalyzerFrameworkError} For any contract violation, with a kind that
 *   says exactly which contract was violated.
 */
export function normalizeFinding(input, { analyzer, rule = null, allowedEvidenceIds }) {
  if (!isPlainObject(input)) {
    throw invalidFinding(analyzer, "a finding must be a plain object");
  }

  const ruleId = input.ruleId ?? rule?.id;
  if (typeof ruleId !== "string" || ruleId.trim() === "" || ruleId.length > MAX_IDENTIFIER_LENGTH) {
    throw invalidFinding(
      analyzer,
      "a finding must declare a bounded ruleId (or be produced by a rule)",
    );
  }

  const category = input.category ?? rule?.category;
  if (typeof category !== "string" || category.trim() === "") {
    throw invalidFinding(
      analyzer,
      `rule "${ruleId}" declares no category, so the finding must supply one`,
    );
  }

  const severity = input.severity ?? rule?.severity;
  if (!FINDING_SEVERITIES.includes(severity)) {
    throw invalidFinding(
      analyzer,
      `severity must be one of ${FINDING_SEVERITIES.join(", ")} (supplied by the finding or its rule)`,
    );
  }

  const title = input.title ?? rule?.title;
  if (typeof title !== "string" || title.trim() === "" || title.length > MAX_IDENTIFIER_LENGTH) {
    throw invalidFinding(analyzer, "a finding must declare a bounded title");
  }

  // Confidence is a claim about the analysis. The framework refuses to assert it
  // on the analyzer's behalf, exactly as the Evidence contract refuses to assert
  // `provenance.deterministic` (Phase 7 correction §2).
  if (input.confidence === undefined || input.confidence === null) {
    throw invalidFinding(
      analyzer,
      "a finding must declare confidence; the framework never asserts certainty on the analyzer's behalf",
    );
  }

  const status = input.status ?? DEFAULT_FINDING_STATUS;
  if (!FINDING_STATUSES.includes(status)) {
    throw invalidFinding(analyzer, `status must be one of ${FINDING_STATUSES.join(", ")}`);
  }

  if (input.description !== undefined && typeof input.description !== "string") {
    throw invalidFinding(analyzer, "description must be a string");
  }

  const references = input.evidence ?? [];
  if (!Array.isArray(references)) {
    throw invalidFinding(analyzer, "evidence must be an array of evidence reference ids");
  }
  const evidence = [];
  for (const reference of references) {
    if (typeof reference !== "string" || reference.trim() === "") {
      throw invalidFinding(
        analyzer,
        "evidence entries must be evidence reference ids (strings), not embedded objects",
      );
    }
    if (!allowedEvidenceIds.has(reference)) throw unknownEvidence(analyzer, [reference]);
    if (!evidence.includes(reference)) evidence.push(reference);
  }
  evidence.sort();

  const fingerprintKey = fingerprintKeyOf(input.metadata, analyzer);
  const fingerprint = findingFingerprint({ ruleId, category, evidence, fingerprintKey });

  if (input.fingerprint !== undefined && input.fingerprint !== fingerprint) {
    throw invalidFinding(
      analyzer,
      "fingerprints are generated by the finding engine; an analyzer must not supply its own",
    );
  }

  const id = input.id ?? `${FINDING_ID_PREFIX}${fingerprint}`;
  if (typeof id !== "string" || id.trim() === "" || id.length > MAX_IDENTIFIER_LENGTH * 2) {
    throw invalidFinding(analyzer, "a finding id must be a bounded non-empty string");
  }

  const metadata = sanitizeDeclarativeValue(input.metadata ?? {}) ?? {};
  // Framework provenance: which analyzer produced this finding and under which
  // rule version. Metadata is explicitly not part of identity, so this does not
  // affect the fingerprint.
  metadata.analyzer = {
    id: analyzer.id,
    name: analyzer.name,
    version: analyzer.version,
    scope: analyzer.scope,
  };

  let finding;
  try {
    finding = createFinding({
      id,
      ruleId,
      category,
      severity,
      confidence: input.confidence,
      title,
      description: input.description ?? rule?.description ?? "",
      evidence,
      status,
      metadata,
      fingerprint,
      impact: input.impact,
      remediation: input.remediation ?? (isPlainObject(rule?.remediation) ? rule.remediation : undefined),
    });
    validateFinding(finding);
  } catch (error) {
    // Re-thrown with the framework's own vocabulary: the Finding contract is
    // Core's, but *who* violated it is the framework's to report.
    throw invalidFinding(analyzer, sanitizeMessage(error?.message ?? "invalid finding"), {
      issues: error?.details?.issues ?? [],
    });
  }

  return Object.freeze(finding);
}

/**
 * Deterministic finding order: fingerprint, then the presentation fields that
 * differ between two findings sharing a fingerprint, then the producing
 * analyzer's id.
 *
 * The analyzer id is part of the tie-break so that two findings which are
 * identical in every other respect are ordered — and therefore deduplicated — by
 * *who reported them* rather than by scheduling order. Duration, discovery order
 * and analyzer scheduling never take part.
 */
export function orderFindings(findings) {
  return [...findings].sort((a, b) => {
    if (a.fingerprint !== b.fingerprint) return a.fingerprint < b.fingerprint ? -1 : 1;
    if (a.title !== b.title) return a.title < b.title ? -1 : 1;
    if (a.severity !== b.severity) return a.severity < b.severity ? -1 : 1;
    const analyzerA = String(a.metadata?.analyzer?.id ?? "");
    const analyzerB = String(b.metadata?.analyzer?.id ?? "");
    if (analyzerA !== analyzerB) return analyzerA < analyzerB ? -1 : 1;
    if (a.id === b.id) return 0;
    return a.id < b.id ? -1 : 1;
  });
}

/**
 * Deduplicate findings by canonical fingerprint.
 *
 * Deduplication is justified *by the fingerprint's semantics*: its inputs are
 * exactly the logical identity of a finding (rule, category, observation set,
 * explicit disambiguator), so two findings sharing one are the same condition
 * reported twice — typically by two analyzers whose scopes overlap.
 *
 * Behaviour is deterministic and lossless:
 *
 *   - the first finding in canonical order survives in `findings` — which, for two
 *     otherwise identical findings, means the one from the alphabetically first
 *     analyzer, so the survivor never depends on scheduling;
 *   - every other one is recorded in a duplicate group with its analyzer id,
 *     rule id, title and evidence references, so provenance and evidence survive
 *     even though the duplicate is not repeated in the aggregate list.
 *
 * @param {object[]} findings Canonical findings.
 * @returns {{findings: object[], duplicates: object[]}}
 */
export function deduplicateFindings(findings) {
  const ordered = orderFindings(findings);
  const survivors = [];
  const groups = new Map();

  for (const finding of ordered) {
    const existing = groups.get(finding.fingerprint);
    if (existing === undefined) {
      groups.set(finding.fingerprint, { surviving: finding, duplicates: [] });
      survivors.push(finding);
      continue;
    }
    existing.duplicates.push({
      analyzerId: finding.metadata?.analyzer?.id ?? null,
      findingId: finding.id,
      ruleId: finding.ruleId,
      title: finding.title,
      severity: finding.severity,
      evidence: [...finding.evidence],
    });
  }

  const duplicates = [...groups.values()]
    .filter((group) => group.duplicates.length > 0)
    .map((group) => ({
      fingerprint: group.surviving.fingerprint,
      findingId: group.surviving.id,
      analyzerId: group.surviving.metadata?.analyzer?.id ?? null,
      duplicates: group.duplicates,
    }))
    .sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : 1));

  return { findings: survivors, duplicates };
}
