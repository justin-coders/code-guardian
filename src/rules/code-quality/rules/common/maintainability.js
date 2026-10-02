/**
 * Code Guardian — Maintainability Rule (Official Roadmap Phase 12)
 *
 * The roadmap's "maintainability" domain. There is deliberately **no score**: this phase
 * refuses to invent a proprietary "maintainability = 73/100" number with no defined model
 * behind it. Instead the rule reports one concrete, checkable observation — source code was
 * observed with no recognized linting, formatting or type-checking tooling established — and
 * points at exactly which of the three the repository does not show.
 *
 * The finding is an *indicator*, worded as such: the absence of a recognized marker is not
 * proof that the repository has no tooling (the tooling domains are open — a tool can be
 * invoked without a config, script or declared dependency), which is why the finding lists
 * what was not observed rather than asserting what is missing.
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
import { TOOLING_DOMAINS, toolingEvidence } from "../../tooling.js";

import { absenceOutcome, evidenceIdsFor } from "../shared.js";

export const maintainabilityRules = Object.freeze([
  createRule({
    id: CODE_QUALITY_RULE_IDS.MAINTAINABILITY_NO_TOOLING,
    version: CODE_QUALITY_RULE_VERSION,
    category: CODE_QUALITY_CATEGORY,
    title: "Source was observed with no recognized quality tooling",
    description:
      "Source code was observed, but no recognized linting, formatting or type-checking tooling was established through any channel the model records (a configuration file, a script whose name names the tool, a declared dependency, or a CI invocation). This is a maintainability *indicator*: it names the concrete tooling the repository does not show, never a maintainability score, and it is not a claim that the tooling is absent — each domain is `unknown` when no marker is observed.",
    severity: "low",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);

      const domains = TOOLING_DOMAINS.map((domain) => ({ domain, evidence: toolingEvidence(query, domain) }));
      const hasSource = domains.some((entry) => entry.evidence.hasSource);

      if (!hasSource) {
        const gap = absenceOutcome(context, "no source code was observed");
        if (gap.outcome) return gap.outcome;
        return {
          findings: [],
          evidence: [],
          metadata: { basis: CODE_QUALITY_BASES.LANGUAGE, state: "not_applicable" },
        };
      }

      const unestablished = domains
        .filter((entry) => !entry.evidence.observed)
        .map((entry) => entry.domain);

      if (unestablished.length === 0) {
        return {
          findings: [],
          evidence: [],
          metadata: {
            basis: CODE_QUALITY_BASES.CONFIGURATION,
            state: "not_applicable",
            establishedDomains: domains.map((entry) => entry.domain),
          },
        };
      }

      // "No recognized tooling was observed" is a *gap* claim, so it may only be made
      // over established coverage: over a truncated or partly unreadable scan the
      // tooling may sit in the part that was never read. Abstain rather than report a
      // maintainability indicator the acquisition cannot support.
      const gap = absenceOutcome(
        context,
        "source was observed but no recognized quality tooling was established",
      );
      if (gap.outcome) return gap.outcome;

      return {
        findings: [
          {
            confidence: CODE_QUALITY_CONFIDENCE.DERIVED_CONDITION,
            evidence: evidenceIdsFor(languageEntities(query)),
            metadata: {
              basis: CODE_QUALITY_BASES.LANGUAGE,
              state: "detected",
              unestablishedDomains: unestablished,
              languages: domains.flatMap((entry) => entry.evidence.languageIds).sort(),
            },
          },
        ],
        evidence: [],
        metadata: {
          basis: CODE_QUALITY_BASES.LANGUAGE,
          state: "detected",
          unestablishedDomains: unestablished,
        },
      };
    },
    remediation: {},
    metadata: {
      tags: ["code-quality", "maintainability"],
      falsePositives: ["tooling invoked without any configuration file, script name or declared dependency"],
    },
  }),
]);
