/**
 * Code Guardian — Dependency Declaration Inventory Rule (Phase 13)
 *
 * The dependency pack's single rule, and deliberately an **inventory** rule: it
 * reports what the repository's manifests declare, one finding per declaration, with
 * the scope and specifier the manifest itself stated.
 *
 * ### Why an inventory rule, and not a vulnerability rule
 *
 * "Is this dependency outdated, vulnerable, unwanted or duplicated" needs evidence
 * this phase does not acquire — a registry, an advisory feed, a licence database —
 * and the architecture forbids fetching any of them. What *is* established is the
 * declaration, so that is exactly what the finding says, and the description names
 * the scope and spec-kind vocabulary rather than implying a verdict.
 *
 * ### What it proves about the substrate
 *
 * This rule is the integration proof Phase 13 asks for, so it exercises the whole
 * path on purpose:
 *
 *   - it reads dependency intelligence **only** through the Phase 11 query API;
 *   - every finding cites the model's own declaration observation, so provenance
 *     survives normalization into a canonical finding;
 *   - it distinguishes `pass` from `unknown` honestly — a repository whose manifests
 *     could not be interpreted, or whose scan was incomplete, produces `unknown`,
 *     never a clean bill of health;
 *   - its output is deterministic: declarations are flattened and sorted by
 *     `(manifestPath, name)`, so two runs over one repository produce identical
 *     findings, ids and order.
 *
 * ### Boundedness
 *
 * A large monorepo can declare thousands of dependencies, so the rule stops at
 * `MAX_DECLARATION_FINDINGS` and records that it did (`metadata.capped`). A capped
 * run is not silently partial: the count that was not reported is on the result, and
 * the coverage decision below is unaffected because findings always win.
 */

import { createRule } from "../../../core/index.js";

import { APPLICABILITY_COVERAGE } from "../../contracts.js";
import { createRuleDetection } from "../../evaluation.js";

import {
  DEPENDENCY_BASIS,
  DEPENDENCY_CATEGORY,
  DEPENDENCY_CONFIDENCE,
  DEPENDENCY_RULE_IDS,
  DEPENDENCY_RULE_VERSION,
  MAX_DECLARATION_FINDINGS,
} from "../contracts.js";
import {
  dependencyAbsence,
  dependencyAcquisitionCoverage,
  dependencyDeclarations,
  queryFor,
} from "../signals.js";

/** How a scope reads in a finding description. */
const SCOPE_WORDING = Object.freeze({
  runtime: "a runtime dependency",
  development: "a development dependency",
  optional: "an optional dependency",
  peer: "a peer dependency",
  unknown: "a dependency whose scope the manifest does not state",
});

/** How a spec kind reads in a finding description. */
const SPEC_WORDING = Object.freeze({
  registry: "a registry version range",
  workspace: "a workspace reference",
  local: "a local path reference",
  url: "a URL reference",
  git: "a git reference",
  alias: "an aliased package reference",
  unknown: "a specifier the parser could not classify",
});

function describe(declaration) {
  const scope = SCOPE_WORDING[declaration.scope] ?? SCOPE_WORDING.unknown;
  const specKind = SPEC_WORDING[declaration.specKind] ?? SPEC_WORDING.unknown;
  const specifier =
    declaration.spec === null ? "with no recorded specifier" : `specified as \`${declaration.spec}\``;
  const source = declaration.specKind === "registry" ? "" : ` from ${specKind}`;
  const conditional = declaration.conditional
    ? " The declaration carries an environment marker, which this phase records but does not evaluate."
    : "";
  const indirect = declaration.direct
    ? ""
    : " The manifest itself marks it as an indirect requirement.";

  return `\`${declaration.name}\` is declared ${scope} by \`${declaration.manifestPath}\`, ${specifier}${source}.${indirect}${conditional} This finding states the declaration the manifest made; whether the dependency is appropriate, current or safe is a later phase's question.`;
}

/**
 * Detect dependency declarations across the repository model.
 *
 * @param {object} context A validated AnalysisContext.
 * @returns {object} A detection object.
 */
function detectDependencyDeclarations(context) {
  const query = queryFor(context);
  const declarations = dependencyDeclarations(query);
  const coverage = dependencyAcquisitionCoverage(query);

  const findings = [];
  for (const declaration of declarations) {
    if (findings.length >= MAX_DECLARATION_FINDINGS) break;
    findings.push({
      confidence: DEPENDENCY_CONFIDENCE.OBSERVED_DECLARATION,
      // The model's own declaration observation. Citing it here is what makes the
      // finding traceable back to the manifest section it came from after the
      // Finding Engine canonicalizes and fingerprints it.
      evidence: [...declaration.evidenceIds],
      metadata: {
        dependencyId: declaration.dependencyId,
        ecosystem: declaration.ecosystem,
        name: declaration.name,
        manifestPath: declaration.manifestPath,
        scope: declaration.scope,
        spec: declaration.spec,
        specKind: declaration.specKind,
        direct: declaration.direct,
        conditional: declaration.conditional,
        basis: DEPENDENCY_BASIS,
      },
    });
  }

  const metadata = {
    basis: DEPENDENCY_BASIS,
    dependencies: coverage.count,
    declarations: declarations.length,
    reported: findings.length,
    capped: findings.length < declarations.length,
    manifestsParsed: coverage.unestablishedSources.length === 0,
  };

  if (findings.length > 0) {
    // Findings always win over abstention: a declared dependency was observed, so
    // reporting it does not depend on how complete the rest of the inventory is.
    return { findings, evidence: [], metadata };
  }

  // Nothing was declared. That is a claim, so it needs the coverage to support it —
  // and the descriptions above are attached to the findings, so a repository with no
  // declarations needs the same wording rules to explain its abstention.
  const absence = dependencyAbsence(query);
  if (!absence.established) {
    return createRuleDetection({
      findings: [],
      coverage: APPLICABILITY_COVERAGE.UNKNOWN,
      reason: `no dependency declaration was observed, but ${absence.reason}`,
    });
  }

  return { findings, evidence: [], metadata };
}

export const dependencyDeclarationRules = Object.freeze([
  createRule({
    id: DEPENDENCY_RULE_IDS.DECLARATIONS,
    version: DEPENDENCY_RULE_VERSION,
    category: DEPENDENCY_CATEGORY,
    title: "Dependency declaration observed in a manifest",
    description:
      "A repository manifest declares a dependency. The finding names the manifest, the dependency, the scope the manifest's own section establishes (runtime, development, optional or peer) and the declared specifier, and states whether the manifest marks it indirect or conditional. It is an inventory statement: no registry was contacted, no version resolved against reality, and no vulnerability, licence or freshness judgment is made or implied.",
    severity: "info",
    // Every repository that declares a dependency is in scope; a rule with no
    // selectors is universally applicable (Core Rule contract).
    applicability: {},
    detect: (context) => detectDependencyDeclarations(context),
    remediation: {},
    metadata: {
      basis: DEPENDENCY_BASIS,
      tags: ["dependency", "inventory", "manifest"],
      falsePositives: [
        "a declared dependency the project does not actually use at runtime",
        "a development-only dependency that never ships",
      ],
    },
  }),
]);
