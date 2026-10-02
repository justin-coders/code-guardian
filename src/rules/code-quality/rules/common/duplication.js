/**
 * Code Guardian — Duplication Rule (Official Roadmap Phase 12)
 *
 * The roadmap's "duplication" domain. The repository model exposes **no** normalized source,
 * token stream, fingerprint or clone relationship, and this phase deliberately builds no
 * clone-detection engine: the roadmap does not require a sophisticated clone detector here,
 * and manufacturing one from trivial string repetition would be exactly the false certainty
 * the architecture forbids.
 *
 * The rule therefore reports the honest answer — `unknown` — with the reason, over a
 * repository that has source to analyze. It exists for one purpose: so that "no duplication
 * finding" can never be read as "this repository has no duplication". When the repository has
 * no source at all, the domain genuinely does not apply.
 */

import { createRule } from "../../../../core/index.js";

import {
  CODE_QUALITY_BASES,
  CODE_QUALITY_CATEGORY,
  CODE_QUALITY_RULE_IDS,
  CODE_QUALITY_RULE_VERSION,
} from "../../contracts.js";
import { hasSourceSubject, queryFor } from "../../signals.js";

import { absenceOutcome } from "../shared.js";

export const duplicationRules = Object.freeze([
  createRule({
    id: CODE_QUALITY_RULE_IDS.DUPLICATION_UNMEASURED,
    version: CODE_QUALITY_RULE_VERSION,
    category: CODE_QUALITY_CATEGORY,
    title: "Duplication could not be measured",
    description:
      "Source code was observed, but the repository model exposes no normalized-source or token evidence from which duplication could be established, and this phase builds no clone detector. The domain is therefore reported `unknown`, never clean: an absent duplication finding is the analyzer's abstention, not a statement that the repository contains no duplicated code.",
    severity: "info",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);

      if (!hasSourceSubject(query)) {
        const gap = absenceOutcome(context, "no source code was observed");
        if (gap.outcome) return gap.outcome;
        return {
          findings: [],
          evidence: [],
          metadata: { basis: CODE_QUALITY_BASES.CONFIGURATION, state: "not_applicable" },
        };
      }

      return {
        findings: [],
        evidence: [],
        coverage: "unknown",
        reason:
          "the repository model exposes no normalized-source or token evidence, so duplication cannot be measured in this phase",
        metadata: { basis: CODE_QUALITY_BASES.CONFIGURATION, state: "unknown" },
      };
    },
    remediation: {},
    metadata: {
      tags: ["code-quality", "duplication"],
      falsePositives: ["none — the rule reports an abstention, never a finding"],
    },
  }),
]);
