/**
 * Code Guardian — Reliability Analysis Usage Rule Engine (Official Roadmap Phase 17)
 *
 * The shared engine behind the domains whose evidence is an observed *usage* of a reliability
 * mechanism. Seven of the ten official domains read the same fact — a module imports a known
 * reliability package and the symbol graph observed it calling or constructing the imported
 * binding, or a module declares and uses a callable whose name matches the closed local
 * vocabulary — and ask the same shape of question about it, so the shape is written once here and
 * each domain supplies only its vocabulary.
 *
 * ### What "established" means, and does not mean
 *
 * A package-usage finding says the repository **imports a named package and uses the imported
 * binding**; its confidence is `PACKAGE_USAGE` (0.7) and its wording says exactly that. It never
 * claims the mechanism is configured correctly or fires at runtime. A local-symbol finding's
 * vocabulary is a *name*, so its confidence is `NAME_DERIVED` (0.5) and its wording says so.
 *
 * ### Two absence semantics, both honest
 *
 * The roadmap forces the distinction. A domain whose mechanism may be configured **inline** —
 * a timeout, a retry policy, a shutdown handler, an error handler, a cleanup call, a circuit
 * breaker — cannot be concluded absent from source this build does not read, so its absence is
 * `unknown` with a reason. A domain that needs a **subject** first — a queue, a transaction —
 * concludes `not_applicable` over a complete semantic graph when no subject is established
 * (§48/§49), and `unknown` when the graph is incomplete.
 */

import { createRule } from "../../../core/index.js";

import {
  RELIABILITY_ANALYSIS_BASES,
  RELIABILITY_ANALYSIS_CONFIDENCE,
  RELIABILITY_ANALYSIS_STATES,
  RELIABILITY_ANALYSIS_SUBJECTS,
} from "../contracts.js";
import { queryFor, symbolCoverageGap, usagesForDomain } from "../signals.js";

import { capFindings, gateOnReliabilitySubject, notApplicable, unknownDetection } from "./shared.js";

const BASIS = RELIABILITY_ANALYSIS_BASES.SYMBOL_GRAPH;

/**
 * A neutral sentence describing one usage, shared by the domain rules so wording stays consistent.
 *
 * @param {object} usage
 * @returns {string}
 */
export function usageSentence(usage) {
  const where = `\`${usage.path}\``;
  const counts = usage.counts ?? {};
  const occurrences = counts.references + counts.calls + counts.constructs;
  const how =
    usage.usage === "constructed"
      ? "constructs"
      : usage.usage === "called"
        ? "calls"
        : usage.usage === "referenced"
          ? "references"
          : "imports";
  const subject = usage.packageName === null ? `\`${usage.name}\`` : `\`${usage.name}\` from \`${usage.packageName}\``;
  const basisNote = usage.nameDerived
    ? "The match is derived from the symbol's name alone."
    : "The match is an import of a named package plus an observed occurrence of the imported binding.";
  return `${where} ${how} ${subject}${occurrences > 0 ? ` (${occurrences} observed occurrence(s))` : ""}. ${basisNote}`;
}

/** One established usage finding. */
function usageFinding(usage, spec) {
  return {
    confidence: usage.nameDerived
      ? RELIABILITY_ANALYSIS_CONFIDENCE.NAME_DERIVED
      : RELIABILITY_ANALYSIS_CONFIDENCE.PACKAGE_USAGE,
    title: spec.establishedTitle,
    description: spec.establishedDescription(usage),
    evidence: [...usage.evidenceIds],
    metadata: {
      basis: BASIS,
      state: RELIABILITY_ANALYSIS_STATES.ESTABLISHED,
      fingerprintKey: usage.fingerprintKey,
      domain: spec.domain,
      name: usage.name,
      packageName: usage.packageName,
      usage: usage.usage,
      nameDerived: usage.nameDerived,
      sourcePath: usage.path,
    },
  };
}

/** The shared detection flow for a usage-based domain. */
function detectUsage(context, spec) {
  const query = queryFor(context);

  const gated = gateOnReliabilitySubject(query, BASIS);
  if (gated !== null) return gated;

  const gap = symbolCoverageGap(query);
  if (gap !== null) return unknownDetection(gap);

  const { usages, truncated } = usagesForDomain(query, spec.domain);

  if (usages.length > 0) {
    const { entries, truncated: capped } = capFindings(usages.map((usage) => usageFinding(usage, spec)));
    return {
      findings: entries,
      evidence: [],
      metadata: {
        basis: BASIS,
        state: RELIABILITY_ANALYSIS_STATES.ESTABLISHED,
        domain: spec.domain,
        reported: entries.length,
        capped: capped || truncated,
      },
    };
  }

  if (spec.absenceState === RELIABILITY_ANALYSIS_SUBJECTS.NOT_APPLICABLE) {
    return notApplicable(BASIS, { domain: spec.domain, reported: 0 });
  }

  return unknownDetection(spec.absentReason(query));
}

/**
 * Build a usage-based reliability rule from a domain specification.
 *
 * @param {object} spec
 * @param {string} spec.id Rule id (already namespaced).
 * @param {string} spec.domain The official domain name.
 * @param {string} spec.version Rule version.
 * @param {string} spec.category Finding category.
 * @param {string} spec.severity Finding severity.
 * @param {string} spec.ruleTitle Rule-level title.
 * @param {string} spec.ruleDescription Rule-level description.
 * @param {string} spec.establishedTitle Finding title for an established usage.
 * @param {Function} spec.establishedDescription Finding description for an established usage.
 * @param {string} [spec.absenceState] `"not_applicable"` or `"unknown"` (default `"unknown"`).
 * @param {string|Function} spec.absentReason Why no usage could be established.
 * @param {string[]} [spec.tags]
 * @param {string[]} [spec.falsePositives]
 * @returns {object} A Core rule descriptor.
 */
export function createUsageRule(spec) {
  return createRule({
    id: spec.id,
    version: spec.version,
    category: spec.category,
    title: spec.ruleTitle,
    description: spec.ruleDescription,
    severity: spec.severity,
    applicability: {},
    detect: (context) => detectUsage(context, spec),
    remediation: {},
    metadata: {
      basis: BASIS,
      domain: spec.domain,
      mode: "usage",
      tags: spec.tags ?? ["reliability", spec.domain],
      falsePositives: spec.falsePositives ?? [],
    },
  });
}
