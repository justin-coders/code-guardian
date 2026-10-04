/**
 * Code Guardian — Dependency Unused Rule (Official Roadmap Phase 15)
 *
 * The "unused dependencies" domain. A declared dependency being absent from an obvious import
 * list does **not** mean it is unused, so this rule consumes the name evidence the repository
 * holds across every channel the roadmap lists (imports, build tooling, configuration, CLI usage,
 * framework conventions, test tooling, package scripts) and reports an indicator only when none
 * of them mention the dependency.
 *
 * It also refuses to conclude from incomplete evidence: if the import graph is not `complete`,
 * or the dependency's ecosystem is one whose usage this build cannot read, the domain answers
 * `unknown`.
 */

import { createRule } from "../../../core/index.js";

import {
  DEPENDENCY_ANALYSIS_BASES,
  DEPENDENCY_ANALYSIS_CATEGORY,
  DEPENDENCY_ANALYSIS_CONFIDENCE,
  DEPENDENCY_ANALYSIS_RULE_IDS,
  DEPENDENCY_ANALYSIS_RULE_VERSION,
  DEPENDENCY_ANALYSIS_STATES,
} from "../contracts.js";
import { dependencyDeclarations, queryFor } from "../signals.js";
import { isReferenced, usageEvidence } from "../usage.js";

import { capFindings, keyFragment, unknownDetection } from "./shared.js";

const CATEGORY = DEPENDENCY_ANALYSIS_CATEGORY;
const VERSION = DEPENDENCY_ANALYSIS_RULE_VERSION;
const IDS = DEPENDENCY_ANALYSIS_RULE_IDS;
const BASES = DEPENDENCY_ANALYSIS_BASES;
const STATES = DEPENDENCY_ANALYSIS_STATES;

/** The ecosystem whose import/usage semantics this build reads. */
const READABLE_USAGE_ECOSYSTEM = "node";

export const dependencyUnusedRules = Object.freeze([
  createRule({
    id: IDS.UNUSED,
    version: VERSION,
    category: CATEGORY,
    title: "A declared dependency is referenced by nothing the repository shows",
    description:
      "A directly declared dependency in an ecosystem whose usage this build reads is absent from every usage channel the model holds — import specifiers, package scripts, CI tool commands and observed file names. The finding names the manifest that declared it and states that it is an *indicator*, not a verdict: a dependency loaded through a mechanism this build cannot see (a plugin resolver, a runtime string, generated code) would look identical. It is reported only over a complete import graph.",
    severity: "low",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const usage = usageEvidence(query);

      if (!usage.complete) {
        return unknownDetection(
          `the import graph is "${usage.state}", so no dependency's usage can be concluded`,
        );
      }

      const declarations = dependencyDeclarations(query).filter(
        (declaration) => declaration.ecosystem === READABLE_USAGE_ECOSYSTEM && declaration.direct,
      );

      if (declarations.length === 0) {
        return {
          findings: [],
          evidence: [],
          metadata: { basis: BASES.IMPORT_USAGE, state: STATES.NOT_APPLICABLE, declarations: 0 },
        };
      }

      const candidates = declarations
        .filter((declaration) => !isReferenced(usage, declaration.name))
        .sort((a, b) => {
          if (a.name !== b.name) return a.name < b.name ? -1 : 1;
          return a.manifestPath < b.manifestPath ? -1 : a.manifestPath > b.manifestPath ? 1 : 0;
        })
        .filter((declaration) => declaration.evidenceIds.length > 0);

      const { entries, truncated } = capFindings(candidates);
      const findings = entries.map((declaration) => ({
        confidence: DEPENDENCY_ANALYSIS_CONFIDENCE.STRUCTURAL_INDICATOR,
        description: `\`${declaration.name}\` is declared directly in \`${declaration.manifestPath}\` (scope \`${declaration.scope}\`) but appears in none of the usage channels this build reads: no import specifier, package script, CI tool command or observed file name references it. This is a *possibly unused* indicator, not a verdict — a dependency resolved through a plugin, a runtime string or generated code looks identical.`,
        evidence: [...declaration.evidenceIds],
        metadata: {
          basis: BASES.IMPORT_USAGE,
          state: STATES.DETECTED,
          fingerprintKey: `unused:${keyFragment(declaration.ecosystem)}:${keyFragment(declaration.name)}:${keyFragment(declaration.manifestPath)}`,
          ecosystem: declaration.ecosystem,
          package: declaration.name,
          manifestPath: declaration.manifestPath,
          scope: declaration.scope,
        },
      }));

      return {
        findings,
        evidence: [],
        metadata: {
          basis: BASES.IMPORT_USAGE,
          state: findings.length > 0 ? STATES.DETECTED : STATES.ESTABLISHED,
          importGraphState: usage.state,
          specifiers: usage.specifiers,
          declarations: declarations.length,
          reported: findings.length,
          truncated,
        },
      };
    },
    remediation: {},
    metadata: {
      tags: ["dependency", "unused"],
      falsePositives: [
        "a dependency loaded dynamically or through a plugin the build cannot see",
        "a dependency used only by generated code",
      ],
    },
  }),
]);
