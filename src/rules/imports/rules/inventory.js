/**
 * Code Guardian — Import Inventory Rule (Phase 16)
 *
 * The integration proof for Phase 16's import graph, and deliberately an
 * **inventory** rule: it reports the static module references the repository
 * establishes, one finding per file-to-file reference, naming the importing file, the
 * file it resolves to, the specifier(s) that stated it and the declaration form(s)
 * used.
 *
 * ### Why this is not a dead-code or coupling rule
 *
 * "This file imports that one" is a fact about the code. Whether a file *should* be
 * imported, whether a cycle is a problem, whether a module is dead, whether the
 * layering is right and whether the tree is too deep all need a model of what the
 * project is trying to be — and this architecture has no such model, so the rule
 * reports structure and stops. There is no reachability verdict, no cycle verdict, no
 * coupling score and no readiness statement anywhere in it.
 *
 * ### What it proves about the graph substrate
 *
 *   - it reads the graph **only** through the Phase 11 query API (`importGraph`,
 *     `importCoverage`, `unresolvedImports`) — never the raw model area, never a
 *     file, never a resolver;
 *   - every finding cites the importing file's own observation, so provenance
 *     survives fingerprinting;
 *   - it never claims a call, an execution order, a symbol, a type or a runtime
 *     dependency: those relations do not exist in the graph, because a static
 *     reference graph cannot establish them;
 *   - an empty import list is only reported as `pass` when the graph was actually
 *     established *and* complete, so "this repository has no imports" is never
 *     claimed over a repository whose scan was incomplete or whose sources could not
 *     be parsed;
 *   - unresolved references are **not** findings: they are reported in the detection
 *     metadata, because a reference whose target the repository does not establish is
 *     not a relationship a finding may claim;
 *   - output is deterministic: references are flattened and sorted by `(from, to)`.
 *
 * ### Boundedness
 *
 * A large repository has one reference per import statement. The rule stops at
 * `MAX_IMPORT_FINDINGS` and records that it did (`metadata.capped`), so a capped run
 * is never silently partial.
 */

import { createRule } from "../../../core/index.js";

import { APPLICABILITY_COVERAGE } from "../../contracts.js";
import { createRuleDetection } from "../../evaluation.js";

import {
  IMPORT_BASIS,
  IMPORT_CATEGORY,
  IMPORT_CONFIDENCE,
  IMPORT_RULE_IDS,
  IMPORT_RULE_VERSION,
  MAX_IMPORT_FINDINGS,
} from "../contracts.js";
import { importCoverage, importRelationships, importUnresolved, importsAbsence, queryFor } from "../signals.js";

/** A short label for a module: its path, or its id when it has none. */
function moduleLabel(path, id) {
  return typeof path === "string" ? `\`${path}\`` : `\`${id}\``;
}

/** A human-readable statement of one established import reference. */
function describe(relationship) {
  const from = moduleLabel(relationship.fromPath, relationship.from);
  const to = moduleLabel(relationship.toPath, relationship.to);
  const specifiers = relationship.specifiers.map((specifier) => `\`${specifier}\``).join(", ");
  const forms = relationship.kindWording.length === 0 ? "" : relationship.kindWording.join(", ");
  const stated =
    relationship.sourcePaths.length === 0
      ? ""
      : ` The observation behind it is at ${relationship.sourcePaths
          .map((path) => `\`${path}\``)
          .join(", ")}.`;

  return `${from} imports ${to}, stated by ${specifiers} in the source file${
    forms === "" ? "" : ` (declared with ${forms})`
  }.${stated} This finding states a static module reference the repository establishes; it is not a call, an execution order, a symbol, a type or a runtime dependency, and it makes no judgment about cycles, coupling, layering or dead code.`;
}

/** The bounded, reason-summarised view of the references that produced no edge. */
function unresolvedSummary(unresolved) {
  const byReason = {};
  for (const record of unresolved) {
    byReason[record.reason] = (byReason[record.reason] ?? 0) + 1;
  }
  return {
    count: unresolved.length,
    byReason,
    // Bounded so one pathological file cannot inflate a detection result. The count
    // above stays the true total, so a truncated list is never mistaken for all of it.
    records: unresolved.slice(0, 50).map((record) => ({
      path: record.path,
      specifier: record.specifier,
      kind: record.kind,
      reason: record.reason,
    })),
    truncated: unresolved.length > 50,
  };
}

/**
 * Detect established import references across the repository model.
 *
 * @param {object} context A validated AnalysisContext.
 * @returns {object} A detection object.
 */
function detectImports(context) {
  const query = queryFor(context);
  const relationships = importRelationships(query);
  const coverage = importCoverage(query);
  const unresolved = importUnresolved(query);

  const findings = [];
  for (const relationship of relationships) {
    if (findings.length >= MAX_IMPORT_FINDINGS) break;
    findings.push({
      confidence: IMPORT_CONFIDENCE.OBSERVED_REFERENCE,
      description: describe(relationship),
      // The importing file's observation. Citing it is what makes the finding
      // traceable after the Finding Engine canonicalizes it.
      evidence: [...relationship.evidenceIds],
      metadata: {
        from: relationship.from,
        fromPath: relationship.fromPath,
        fromLanguage: relationship.fromLanguage,
        to: relationship.to,
        toPath: relationship.toPath,
        toLanguage: relationship.toLanguage,
        toIsModule: relationship.toIsModule,
        relationshipType: relationship.type,
        specifiers: [...relationship.specifiers],
        kinds: [...relationship.kinds],
        sourcePaths: [...relationship.sourcePaths],
        // Every reference from one file cites that file's single observation, and a
        // canonical fingerprint is derived from the evidence set. Without this key two
        // references from one file would fingerprint identically and the run would
        // fail as a duplicate. The key names the reference, not its order.
        fingerprintKey: relationship.fingerprintKey,
        basis: IMPORT_BASIS,
      },
    });
  }

  const metadata = {
    basis: IMPORT_BASIS,
    state: coverage.state,
    established: coverage.established === true,
    nodes: coverage.nodes,
    edges: coverage.edges,
    moduleFiles: coverage.moduleFiles,
    references: coverage.references,
    nonStatic: coverage.nonStatic,
    reported: findings.length,
    capped: findings.length < relationships.length,
    // References whose target the repository does not establish are evidence, not
    // findings: they are neither relationships nor absences.
    unresolved: unresolvedSummary(unresolved),
    unestablishedSources: (coverage.unestablishedSources ?? []).length,
    // The other half of the scope statement: source files in languages this build does
    // not read. A rule that reports `pass` has to say what it did *not* look at, and
    // these are the files that make `unsupported` the honest state.
    uninterpretedSources: coverage.uninterpretedSources ?? 0,
    uninterpretedExtensions: [...(coverage.uninterpretedExtensions ?? [])],
  };

  if (findings.length > 0) {
    // Findings always win over abstention: an established reference was observed, so
    // reporting it does not depend on how complete the rest of the graph is.
    return { findings, evidence: [], metadata };
  }

  // No reference was observed. That is a claim, so it needs the coverage to support
  // it: a graph that was never established, or was only partly established, must
  // abstain rather than report a repository with no imports.
  const absence = importsAbsence(query);
  if (!absence.established) {
    return {
      ...createRuleDetection({
        findings: [],
        coverage: APPLICABILITY_COVERAGE.UNKNOWN,
        reason: `no import reference was observed, but ${absence.reason}`,
      }),
      metadata,
    };
  }

  return { findings, evidence: [], metadata };
}

export const importRules = Object.freeze([
  createRule({
    id: IMPORT_RULE_IDS.GRAPH_INVENTORY,
    version: IMPORT_RULE_VERSION,
    category: IMPORT_CATEGORY,
    title: "Static module reference established by the repository",
    description:
      "A supported JavaScript or TypeScript source file states a module reference that the repository's own inventory establishes as another file: a static import, a re-export, a `require` call or a dynamic `import()`. The finding names both files, the specifier(s) that stated the reference, the declaration form(s) used and the file whose observation recorded it, and cites the importing file's own observation. It is an inventory statement: no call, execution order, symbol, type, runtime dependency, cycle, coupling or dead-code claim is made, and a reference whose target the repository does not establish is reported as metadata rather than as a finding.",
    severity: "info",
    // Every repository that was scanned is in scope; a rule with no selectors is
    // universally applicable (Core Rule contract).
    applicability: {},
    detect: (context) => detectImports(context),
    remediation: {},
    metadata: {
      basis: IMPORT_BASIS,
      tags: ["imports", "modules", "inventory"],
      falsePositives: [
        "a file that declares a local function named `require` (tokenizing cannot see scope)",
        "a reference the bundler resolves through an alias the repository does not declare in a form this build reads",
      ],
    },
  }),
]);
