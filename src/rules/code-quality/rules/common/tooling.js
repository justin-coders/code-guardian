/**
 * Code Guardian — Tooling Rules: linting, formatting, type checking (Official Roadmap Phase 12)
 *
 * Three rules, one per roadmap tooling domain, built from one factory because they differ only
 * in the vocabulary they read. Each is deliberately conservative:
 *
 *   detected   a recognized configuration, script or dependency was observed. Configuration
 *              is not execution, and the finding never claims the tool runs.
 *   verified   the above **and** a CI workflow whose content contains the tool's documented
 *              invocation. This is the strongest claim this phase makes, and it is never a
 *              claim that the run passed.
 *   unknown    source code exists but no marker was established. A linter, formatter or
 *              compiler can be invoked without any configuration file, script or declared
 *              dependency, so the absence of every marker does **not** establish the absence
 *              of the tooling. The rule reports the observation and labels the domain
 *              `unknown` rather than manufacturing a clean pass — the Phase 11 discipline.
 *
 * Nothing here says a tool is *missing*. It says no recognized marker was observed, which is
 * exactly what the repository model can prove.
 */

import { createRule } from "../../../../core/index.js";

import {
  CODE_QUALITY_BASES,
  CODE_QUALITY_CATEGORY,
  CODE_QUALITY_CONFIDENCE,
  CODE_QUALITY_RULE_IDS,
  CODE_QUALITY_RULE_VERSION,
} from "../../contracts.js";
import { languageEntities, queryFor } from "../../signals.js";
import { toolingEvidence } from "../../tooling.js";

import { absenceOutcome, evidenceIdsFor } from "../shared.js";

/** Per-domain wording. Kept beside the factory so the three rules read consistently. */
const DOMAIN_META = Object.freeze({
  linting: {
    id: CODE_QUALITY_RULE_IDS.LINTING_UNCONFIGURED,
    title: "No recognized linting tooling was established",
    description:
      "Source code was observed, but no recognized lint configuration file, lint-named script, linter dependency or CI lint invocation was established. A linter can be invoked without any of these markers, so this is not a claim that the repository has no linting — it is the analyzer's honest `unknown`, reported so an empty result is never read as \"linting is fine\". A configuration file on its own is `detected`, never proof the linter runs or passes.",
  },
  formatting: {
    id: CODE_QUALITY_RULE_IDS.FORMATTING_UNCONFIGURED,
    title: "No recognized formatting tooling was established",
    description:
      "Source code was observed, but no recognized formatter configuration file, format-named script, formatter dependency or CI formatting invocation was established. A formatter can be invoked without any of these markers, so this is the analyzer's honest `unknown`. A formatter configuration on its own is `detected`; it is never a claim that the code is formatted.",
  },
  "type-checking": {
    id: CODE_QUALITY_RULE_IDS.TYPE_CHECKING_UNCONFIGURED,
    title: "No recognized type-checking tooling was established",
    description:
      "Source code was observed, but no recognized compiler configuration (`tsconfig.json`, `jsconfig.json`), type-check-named script, type-checker dependency or CI type-check invocation was established. A type checker can be invoked without any of these markers, so this is the analyzer's honest `unknown`. A compiler configuration on its own is `detected`; it is never a claim that the code type-checks.",
  },
});

/**
 * Build one tooling rule.
 *
 * @param {string} domain One of the roadmap's tooling domains.
 * @returns {object} A Core Rule.
 */
function toolingRule(domain) {
  const meta = DOMAIN_META[domain];
  return createRule({
    id: meta.id,
    version: CODE_QUALITY_RULE_VERSION,
    category: CODE_QUALITY_CATEGORY,
    title: meta.title,
    description: meta.description,
    severity: "info",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const evidence = toolingEvidence(query, domain);
      const basis = CODE_QUALITY_BASES.CONFIGURATION;

      const facts = {
        basis,
        domain,
        state: null,
        configurations: evidence.configurations.map((entity) => entity.path).sort(),
        scripts: [...evidence.scriptNames],
        dependencies: [...evidence.dependencyNames],
        ciTools: [...evidence.ciTools],
        languages: [...evidence.languageIds],
        // A manifest that failed to parse blocks its declared scripts. Recorded on the
        // facts so a reader can tell "no marker was observed" from "a channel could not
        // be read" — the tooling domain stays `unknown`, but the reason is visible.
        failedManifests: [...evidence.failedManifests],
      };

      // Configured **and** observed invoked in CI: the defined verification condition.
      if (evidence.verified) {
        return {
          findings: [],
          evidence: [],
          metadata: { ...facts, state: "verified" },
        };
      }

      // A recognized marker was observed: `detected`, never `verified`.
      if (evidence.observed) {
        return {
          findings: [],
          evidence: [],
          metadata: { ...facts, state: "detected" },
        };
      }

      // No marker. Without a source subject the domain genuinely does not apply; with one,
      // the markers cannot prove the tooling's absence, so the domain is `unknown`.
      if (!evidence.hasSource) {
        const gap = absenceOutcome(context, "no source code was observed");
        if (gap.outcome) return gap.outcome;
        return {
          findings: [],
          evidence: [],
          metadata: { ...facts, state: "not_applicable" },
        };
      }

      const gap = absenceOutcome(
        context,
        `source code was observed but no recognized ${domain} tooling was established`,
      );
      if (gap.outcome) return gap.outcome;

      return {
        findings: [
          {
            confidence: CODE_QUALITY_CONFIDENCE.GAP_CONDITION,
            evidence: evidenceIdsFor(languageEntities(query)),
            metadata: { ...facts, state: "unknown" },
          },
        ],
        evidence: [],
      };
    },
    remediation: {},
    metadata: {
      tags: ["code-quality", domain],
      falsePositives: [
        `a ${domain} tool invoked directly without a configuration file, a matching script name or a declared dependency`,
      ],
    },
  });
}

export const toolingRules = Object.freeze([
  toolingRule("linting"),
  toolingRule("formatting"),
  toolingRule("type-checking"),
]);
