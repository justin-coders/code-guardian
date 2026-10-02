/**
 * Code Guardian — Configuration Consistency Rule (Official Roadmap Phase 12)
 *
 * The roadmap's "configuration consistency" domain. The rule reports only two shapes, each of
 * which the model can actually establish, and explains exactly what it observed:
 *
 *   conflicting compiler configuration   a repository that carries **both** a `tsconfig.json`
 *                                        and a `jsconfig.json`. The two declare different
 *                                        compiler behaviours for the same workspace, so one of
 *                                        them is not the answer; the finding names both paths.
 *   configuration with no execution path a quality tool configuration was observed, but no
 *                                        script, dependency or CI invocation of that tool was
 *                                        established. The configuration is not connected to
 *                                        anything the model can see — an *observation*, not a
 *                                        verdict, and the finding says so.
 *
 * It deliberately does **not** treat multiple configuration files of one tool as a violation:
 * a repository migrating from `.eslintrc` to `eslint.config.js` legitimately has both, and
 * "unusual" is not "inconsistent".
 */

import { createRule } from "../../../../core/index.js";

import {
  CODE_QUALITY_BASES,
  CODE_QUALITY_CATEGORY,
  CODE_QUALITY_CONFIDENCE,
  CODE_QUALITY_RULE_IDS,
  CODE_QUALITY_RULE_VERSION,
  QUALITY_CONFIGURATION_SIGNALS,
  TYPE_CHECK_CONFIG_BASENAMES,
} from "../../contracts.js";
import { basenameOf, configurationBySignal, queryFor } from "../../signals.js";
import { TOOLING_DOMAINS, toolingEvidence } from "../../tooling.js";

import { absenceOutcome, evidenceIdsFor } from "../shared.js";

/** The configuration signal each tooling domain is read through (mirrors `tooling.js`). */
const SIGNAL_FOR_DOMAIN = Object.freeze({
  linting: QUALITY_CONFIGURATION_SIGNALS.LINT,
  formatting: QUALITY_CONFIGURATION_SIGNALS.FORMAT,
  "type-checking": QUALITY_CONFIGURATION_SIGNALS.BUILD,
});

/** Compiler configurations whose coexistence is a genuine contradiction. */
function conflictingCompilerConfigurations(query) {
  const configurations = configurationBySignal(query, SIGNAL_FOR_DOMAIN["type-checking"]).filter(
    (entity) => TYPE_CHECK_CONFIG_BASENAMES.includes(basenameOf(entity.path)),
  );
  const basenames = new Set(configurations.map((entity) => basenameOf(entity.path)));
  if (!basenames.has("tsconfig.json") || !basenames.has("jsconfig.json")) return null;
  return configurations.filter((entity) => TYPE_CHECK_CONFIG_BASENAMES.includes(basenameOf(entity.path)));
}

export const configurationRules = Object.freeze([
  createRule({
    id: CODE_QUALITY_RULE_IDS.CONFIGURATION_INCONSISTENT,
    version: CODE_QUALITY_RULE_VERSION,
    category: CODE_QUALITY_CATEGORY,
    title: "A quality configuration is inconsistent with the rest of the repository",
    description:
      "The repository carries a quality configuration the model shows contradicting or disconnected. Two shapes are reported: both a `tsconfig.json` and a `jsconfig.json` (two compiler behaviours for one workspace), and a quality tool configuration with no script, dependency or CI invocation of that tool established. The finding names exactly what was observed — it never treats an unusual-but-valid configuration as a violation.",
    severity: "info",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const findings = [];

      const conflict = conflictingCompilerConfigurations(query);
      if (conflict !== null) {
        findings.push({
          confidence: CODE_QUALITY_CONFIDENCE.DERIVED_CONDITION,
          evidence: evidenceIdsFor(conflict),
          metadata: {
            basis: CODE_QUALITY_BASES.CONFIGURATION,
            state: "detected",
            fingerprintKey: "conflicting-compiler-configuration",
            kind: "conflicting-compiler-configuration",
            configurations: conflict.map((entity) => entity.path).sort(),
          },
        });
      }

      for (const domain of TOOLING_DOMAINS) {
        const evidence = toolingEvidence(query, domain);
        if (evidence.configurations.length === 0) continue;
        const connected =
          evidence.scriptNames.length > 0 ||
          evidence.dependencyNames.length > 0 ||
          evidence.ciTools.length > 0;
        if (connected) continue;
        findings.push({
          confidence: CODE_QUALITY_CONFIDENCE.DERIVED_CONDITION,
          evidence: evidenceIdsFor(evidence.configurations),
          metadata: {
            basis: CODE_QUALITY_BASES.CONFIGURATION,
            state: "detected",
            fingerprintKey: `configuration-without-execution-path:${domain}`,
            kind: "configuration-without-execution-path",
            domain,
            configurations: evidence.configurations.map((entity) => entity.path).sort(),
          },
        });
      }

      if (findings.length > 0) {
        return {
          findings,
          evidence: [],
          metadata: { basis: CODE_QUALITY_BASES.CONFIGURATION, state: "detected" },
        };
      }

      // Nothing inconsistent was observed. Without any quality configuration at all the
      // domain has no subject; with coverage incomplete the absence is not established.
      const anyConfiguration = TOOLING_DOMAINS.some(
        (domain) => configurationBySignal(query, SIGNAL_FOR_DOMAIN[domain]).length > 0,
      );
      if (!anyConfiguration) {
        const gap = absenceOutcome(context, "no quality configuration was observed");
        if (gap.outcome) return gap.outcome;
      }

      return {
        findings: [],
        evidence: [],
        metadata: { basis: CODE_QUALITY_BASES.CONFIGURATION, state: "not_applicable" },
      };
    },
    remediation: {},
    metadata: {
      tags: ["code-quality", "configuration"],
      falsePositives: ["a configuration consumed through a wrapper the model does not observe"],
    },
  }),
]);
