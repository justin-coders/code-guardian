/**
 * Code Guardian — Dependency Supply-Chain Indicator Rule (Official Roadmap Phase 15)
 *
 * The "supply-chain risk indicators" domain, kept strictly an **indicator** domain. It reports
 * dependencies sourced through a mechanism other than the ecosystem's registry — a git
 * repository, a direct URL, or an npm alias — because those are observable facts about where a
 * dependency comes from.
 *
 * It never claims compromise: an out-of-registry source is an indicator, worded with exactly the
 * evidence behind it. It also stays inside its own domain: it does not re-check secrets, CI or
 * container security, which the Security Analyzer already owns.
 */

import { createRule } from "../../../core/index.js";

import {
  DEPENDENCY_ANALYSIS_BASES,
  DEPENDENCY_ANALYSIS_CATEGORY,
  DEPENDENCY_ANALYSIS_CONFIDENCE,
  DEPENDENCY_ANALYSIS_RULE_IDS,
  DEPENDENCY_ANALYSIS_RULE_VERSION,
  DEPENDENCY_ANALYSIS_STATES,
  UNUSUAL_SOURCE_SPEC_KINDS,
} from "../contracts.js";
import { dependencyDeclarations, queryFor } from "../signals.js";

import { capFindings, keyFragment, unknownDetection } from "./shared.js";

const CATEGORY = DEPENDENCY_ANALYSIS_CATEGORY;
const VERSION = DEPENDENCY_ANALYSIS_RULE_VERSION;
const IDS = DEPENDENCY_ANALYSIS_RULE_IDS;
const BASES = DEPENDENCY_ANALYSIS_BASES;
const STATES = DEPENDENCY_ANALYSIS_STATES;

const SOURCE_WORDING = Object.freeze({
  git: "a git repository",
  url: "a direct URL",
  alias: "an aliased package (`npm:` alias)",
});

export const dependencySupplyChainRules = Object.freeze([
  createRule({
    id: IDS.SUPPLY_CHAIN,
    version: VERSION,
    category: CATEGORY,
    title: "A dependency is sourced outside the ecosystem registry",
    description:
      "A manifest declares a dependency sourced from a git repository, a direct URL or an npm alias rather than the ecosystem's registry. The finding names the package, the source kind and the manifest. It is a supply-chain indicator — a statement about where the dependency comes from — not a claim that the package is unsafe, and it does not duplicate the Security Analyzer's own detections.",
    severity: "low",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const declarations = dependencyDeclarations(query);

      if (declarations.length === 0) {
        return {
          findings: [],
          evidence: [],
          metadata: { basis: BASES.MANIFEST_DECLARATION, state: STATES.NOT_APPLICABLE, declarations: 0 },
        };
      }

      const candidates = declarations
        .filter((declaration) => UNUSUAL_SOURCE_SPEC_KINDS.includes(declaration.specKind))
        .sort((a, b) => {
          if (a.ecosystem !== b.ecosystem) return a.ecosystem < b.ecosystem ? -1 : 1;
          if (a.name !== b.name) return a.name < b.name ? -1 : 1;
          return a.manifestPath < b.manifestPath ? -1 : a.manifestPath > b.manifestPath ? 1 : 0;
        })
        .filter((declaration) => declaration.evidenceIds.length > 0);

      const { entries, truncated } = capFindings(candidates);
      const findings = entries.map((declaration) => ({
        confidence: DEPENDENCY_ANALYSIS_CONFIDENCE.OBSERVED_FACT,
        description: `\`${declaration.name}\` (${declaration.ecosystem}) is declared in \`${declaration.manifestPath}\` from ${SOURCE_WORDING[declaration.specKind] ?? `a \`${declaration.specKind}\` source`} rather than the ecosystem registry. This is an observable supply-chain indicator about the dependency's source; it is not a statement that the dependency is unsafe.`,
        evidence: [...declaration.evidenceIds],
        metadata: {
          basis: BASES.MANIFEST_DECLARATION,
          state: STATES.DETECTED,
          fingerprintKey: `supply-chain:${keyFragment(declaration.ecosystem)}:${keyFragment(declaration.name)}:${keyFragment(declaration.manifestPath)}`,
          ecosystem: declaration.ecosystem,
          package: declaration.name,
          manifestPath: declaration.manifestPath,
          specKind: declaration.specKind,
        },
      }));

      if (findings.length > 0) {
        return {
          findings,
          evidence: [],
          metadata: {
            basis: BASES.MANIFEST_DECLARATION,
            state: STATES.DETECTED,
            declarations: declarations.length,
            reported: findings.length,
            truncated,
          },
        };
      }

      // No unusual source was observed. Over a partial dependency acquisition that is a claim
      // that cannot be supported, so abstain rather than report a clean supply chain.
      const coverage = query.dependencyCoverage();
      if (coverage.complete !== true || (coverage.unestablishedSources ?? []).length > 0) {
        return unknownDetection(
          "no out-of-registry source was observed, but dependency acquisition is incomplete",
        );
      }

      return {
        findings: [],
        evidence: [],
        metadata: {
          basis: BASES.MANIFEST_DECLARATION,
          state: STATES.ESTABLISHED,
          declarations: declarations.length,
          reported: 0,
        },
      };
    },
    remediation: {},
    metadata: {
      tags: ["dependency", "supply-chain", "indicator"],
      falsePositives: ["a git or URL dependency chosen deliberately for an unreleased fix"],
    },
  }),
]);
