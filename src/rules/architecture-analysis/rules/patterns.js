/**
 * Code Guardian — Architecture Pattern Rule (Official Roadmap Phase 14)
 *
 * The "architecture patterns" domain, deliberately conservative.
 *
 * The roadmap asks the analyzer to identify patterns, not to prescribe one. A pattern is
 * claimed only from **multiple independent pieces of evidence**, and this build establishes
 * exactly one: a **workspace monorepo**, which requires both (1) a manifest that declares
 * `workspaces` and (2) at least two distinct sub-directories that each declare their own named
 * package. One of those facts alone establishes nothing — the ambiguous fixture checks exactly
 * that — and a directory name is never evidence. When the evidence is insufficient the rule
 * answers `unknown`; it never declares that a repository "is a monorepo" on weak evidence, and
 * it has no classifier keyed on directory names.
 */

import { createRule } from "../../../core/index.js";

import {
  ARCHITECTURE_ANALYSIS_BASES,
  ARCHITECTURE_ANALYSIS_CATEGORY,
  ARCHITECTURE_ANALYSIS_CONFIDENCE,
  ARCHITECTURE_ANALYSIS_RULE_IDS,
  ARCHITECTURE_ANALYSIS_RULE_VERSION,
  ARCHITECTURE_ANALYSIS_STATES,
  ARCHITECTURE_PATTERNS,
} from "../contracts.js";
import { queryFor, workspacePatternFacts } from "../signals.js";

import { keyFragment, unknownDetection } from "./shared.js";

const CATEGORY = ARCHITECTURE_ANALYSIS_CATEGORY;
const VERSION = ARCHITECTURE_ANALYSIS_RULE_VERSION;
const IDS = ARCHITECTURE_ANALYSIS_RULE_IDS;
const BASES = ARCHITECTURE_ANALYSIS_BASES;
const STATES = ARCHITECTURE_ANALYSIS_STATES;
const CONFIDENCE = ARCHITECTURE_ANALYSIS_CONFIDENCE;

export const architecturePatternRules = Object.freeze([
  createRule({
    id: IDS.PATTERN_ESTABLISHED,
    version: VERSION,
    category: CATEGORY,
    title: "An architecture pattern established by multiple independent facts",
    description:
      "The repository establishes an architecture pattern from more than one independent piece of evidence. This build recognizes a workspace monorepo: a manifest declaring `workspaces` and at least two distinct sub-directories each declaring their own named package. The finding cites those manifests. No pattern is claimed from a directory name, and insufficient evidence answers `unknown` rather than a guess.",
    severity: "info",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const facts = workspacePatternFacts(query);

      if (facts.manifestCount === 0) {
        return {
          findings: [],
          evidence: [],
          metadata: { basis: BASES.MANIFEST, state: STATES.NOT_APPLICABLE, manifests: 0 },
        };
      }

      const namedModules = [...new Set(facts.named.map((entry) => entry.module))].sort();
      const established = facts.workspacesDeclared && namedModules.length >= 2;

      if (!established) {
        return unknownDetection(
          "no architecture pattern is established by multiple independent pieces of evidence",
        );
      }

      const stated = facts.named.filter((entry) => namedModules.includes(entry.module));
      const evidence = [
        ...new Set([
          ...facts.workspacesDeclaredBy.flatMap((entry) => entry.evidenceIds),
          ...stated.flatMap((entry) => entry.evidenceIds),
        ]),
      ].sort();

      if (evidence.length === 0) {
        return unknownDetection(
          "a pattern's evidence exists, but no observation behind it could be cited",
        );
      }

      const findings = [
        {
          confidence: CONFIDENCE.OBSERVED_RELATIONSHIP,
          description: `The repository establishes a workspace monorepo: a manifest declares \`workspaces\` (${facts.workspacesDeclaredBy.map((entry) => `\`${entry.path}\``).join(", ")}) and ${namedModules.length} distinct directories declare their own named package (${stated.map((entry) => `\`${entry.path}\``).join(", ")}). This is a pattern established from two independent facts the repository states; it is not inferred from directory names.`,
          evidence,
          metadata: {
            basis: BASES.MANIFEST,
            state: STATES.ESTABLISHED,
            fingerprintKey: `pattern:${keyFragment(ARCHITECTURE_PATTERNS.WORKSPACE_MONOREPO)}`,
            pattern: ARCHITECTURE_PATTERNS.WORKSPACE_MONOREPO,
            workspaceManifests: facts.workspacesDeclaredBy.map((entry) => entry.path),
            namedPackages: stated.map((entry) => ({ path: entry.path, name: entry.name })),
          },
        },
      ];

      return {
        findings,
        evidence: [],
        metadata: {
          basis: BASES.MANIFEST,
          state: STATES.ESTABLISHED,
          manifests: facts.manifestCount,
          namedModules: namedModules.length,
        },
      };
    },
    remediation: {},
    metadata: {
      tags: ["architecture", "patterns"],
      falsePositives: ["a workspace declaration whose packages live outside the scanned root"],
    },
  }),
]);
