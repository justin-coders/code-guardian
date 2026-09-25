/**
 * Code Guardian — Symbol Graph Inventory Rule (Phase 17)
 *
 * The integration proof for Phase 17's symbol graph, and deliberately an
 * **inventory** rule: it reports the semantic relationships the repository
 * establishes, one finding per relationship, naming the file that states it, the
 * symbol it concerns, the relationship's own established wording and the observation
 * behind it.
 *
 * ### Why this is not a complexity, dead-code or call-graph-health rule
 *
 * "This file calls that symbol" is a fact about the code. Whether the symbol *should*
 * be called, whether a module is dead, whether the recursion is dangerous, whether the
 * coupling is too high and whether the graph is healthy all need a model of what the
 * project is trying to be — and this architecture has no such model, so the rule
 * reports structure and stops. There is no reachability verdict, no complexity score,
 * no cycle verdict and no readiness statement anywhere in it.
 *
 * ### What it proves about the graph substrate
 *
 *   - it reads the graph **only** through the Phase 11 query API (`symbolGraph`,
 *     `symbolCoverage`, `unresolvedSymbolReferences`) — never the raw model area, never
 *     a file, never a parser, never a scope;
 *   - every finding cites the stating file's own observation, so provenance survives
 *     fingerprinting;
 *   - it never claims a type, a runtime call, an execution order, an ownership or a
 *     data flow: those relations do not exist in the graph, because a static
 *     resolution graph cannot establish them;
 *   - a symbol whose name could be bound elsewhere in its file carries that fact in the
 *     finding's metadata (`targetShadowed`), because "nothing references this" and "this
 *     build cannot say what references it" are different answers;
 *   - an empty graph is only reported as `pass` when it was actually established *and*
 *     complete, so "this repository declares nothing" is never claimed over a
 *     repository whose scan was incomplete or whose sources could not be read;
 *   - unresolved occurrences are **not** findings: they are reported in the detection
 *     metadata, because an occurrence whose target is not established is not a
 *     relationship a finding may claim;
 *   - output is deterministic: relationships are flattened and sorted by
 *     `(from, type, to)`.
 *
 * ### Boundedness
 *
 * A large repository has one relationship per reference and per call. The rule stops at
 * `MAX_SYMBOL_FINDINGS` and records that it did (`metadata.capped`), so a capped run is
 * never silently partial.
 */

import { createRule } from "../../../core/index.js";

import { APPLICABILITY_COVERAGE } from "../../contracts.js";
import { createRuleDetection } from "../../evaluation.js";

import {
  MAX_SYMBOL_FINDINGS,
  SYMBOL_BASIS,
  SYMBOL_CATEGORY,
  SYMBOL_CONFIDENCE,
  SYMBOL_KIND_WORDING,
  SYMBOL_RULE_IDS,
  SYMBOL_RULE_VERSION,
} from "../contracts.js";
import {
  symbolCoverage,
  symbolRelationships,
  symbolUnresolved,
  symbolsAbsence,
  queryFor,
} from "../signals.js";

/** A short label for an entity: its path, or its id when it has none. */
function label(path, id) {
  return typeof path === "string" ? `\`${path}\`` : `\`${id}\``;
}

/** A parenthesised list of declaration kinds, or an empty string. */
function kindsPhrase(kinds) {
  if (kinds.length === 0) return "";
  const words = kinds.map((kind) => SYMBOL_KIND_WORDING[kind] ?? kind);
  return ` (${words.join(", ")})`;
}

/** A parenthesised count phrase, or an empty string when the count is unknown. */
function countPhrase(count) {
  return typeof count === "number" && count > 1 ? ` ${count} times` : "";
}

/**
 * A human-readable statement of one established semantic relationship.
 *
 * One builder per edge type, over the graph's closed vocabulary. A relationship the
 * graph can state but this module cannot describe would be a contract mismatch; the
 * test suite pins the two vocabularies together.
 */
function describe(relationship) {
  const from = label(relationship.fromPath, relationship.from);
  const target = relationship.toName === null ? label(relationship.toPath, relationship.to) : `\`${relationship.toName}\``;
  const targetKinds = kindsPhrase(relationship.toKinds);
  const state = `${from} ${relationship.wording} the symbol ${target}`;
  const names =
    relationship.names.length === 0
      ? ""
      : ` The names the file states for it are ${relationship.names
          .map((name) => `\`${name}\``)
          .join(", ")}.`;

  switch (relationship.type) {
    case "declares":
      return `${state}${targetKinds}, declared at module scope in that file. This finding states a declaration the repository establishes; it says nothing about whether the symbol is used, reachable or correct.`;
    case "exports":
      return `${state}${names} This finding states an export the file itself declares; it says nothing about whether anything imports it.`;
    case "references":
      return `${state}${targetKinds}, which is the only module-scope binding of that name in the file, so every non-binding occurrence of it is this one. The occurrence was observed${countPhrase(
        relationship.count,
      )}. It is a reference, not a call, an execution order, a type or a data flow.`;
    case "calls":
      return `${state}${targetKinds}, whose value shape the file establishes as callable and which no part of the file assigns. The call expression was observed${countPhrase(
        relationship.count,
      )}. It is a statically established call site, not a claim that the call executes, resolves at runtime as written, or returns anything.`;
    case "imports-binding":
      return `${state}, resolved through this file's own import clause to the symbol ${label(
        relationship.toPath,
        relationship.to,
      )} exports.${names} This finding states an import binding the repository establishes; it says nothing about whether the binding is used.`;
    default:
      return `${state}${targetKinds}.`;
  }
}

/** The bounded, reason-summarised view of the occurrences that produced no edge. */
function unresolvedSummary(unresolved) {
  const byReason = {};
  const byKind = {};
  for (const record of unresolved) {
    byReason[record.reason] = (byReason[record.reason] ?? 0) + 1;
    byKind[record.kind] = (byKind[record.kind] ?? 0) + 1;
  }
  return {
    count: unresolved.length,
    byReason,
    byKind,
    // Bounded so one pathological file cannot inflate a detection result. The counts
    // above stay the true totals, so a truncated list is never mistaken for all of it.
    records: unresolved.slice(0, 50).map((record) => ({
      path: record.path,
      name: record.name,
      kind: record.kind,
      reason: record.reason,
    })),
    truncated: unresolved.length > 50,
  };
}

/**
 * Detect established semantic relationships across the repository model.
 *
 * @param {object} context A validated AnalysisContext.
 * @returns {object} A detection object.
 */
function detectSymbols(context) {
  const query = queryFor(context);
  const relationships = symbolRelationships(query);
  const coverage = symbolCoverage(query);
  const unresolved = symbolUnresolved(query);

  const findings = [];
  for (const relationship of relationships) {
    if (findings.length >= MAX_SYMBOL_FINDINGS) break;
    findings.push({
      confidence: SYMBOL_CONFIDENCE.OBSERVED_RELATIONSHIP,
      description: describe(relationship),
      // The stating file's observation. Citing it is what makes the finding traceable
      // after the Finding Engine canonicalizes it.
      evidence: [...relationship.evidenceIds],
      metadata: {
        from: relationship.from,
        fromPath: relationship.fromPath,
        fromName: relationship.fromName,
        to: relationship.to,
        toPath: relationship.toPath,
        toName: relationship.toName,
        toKinds: [...relationship.toKinds],
        // Why an occurrence may be withheld from the target: the name can be bound
        // elsewhere in its file, so no single binding is established for it.
        targetShadowed: relationship.toShadowed,
        relationshipType: relationship.type,
        count: relationship.count,
        names: [...relationship.names],
        sourcePaths: [...relationship.sourcePaths],
        // Every relationship one file states cites that file's single observation, and a
        // canonical fingerprint is derived from the evidence set. Without this key two
        // relationships from one file would fingerprint identically and the run would
        // fail as a duplicate. The key names the relationship, not its order.
        fingerprintKey: relationship.fingerprintKey,
        basis: SYMBOL_BASIS,
      },
    });
  }

  const metadata = {
    basis: SYMBOL_BASIS,
    state: coverage.state,
    established: coverage.established === true,
    symbols: coverage.symbols,
    edges: coverage.edges,
    sources: coverage.sources,
    moduleFiles: coverage.moduleFiles,
    declaredSymbols: coverage.declaredSymbols,
    exportedSymbols: coverage.exportedSymbols,
    referenceEdges: coverage.referenceEdges,
    callEdges: coverage.callEdges,
    bindingEdges: coverage.bindingEdges,
    references: coverage.references,
    shadowedSymbols: coverage.shadowedSymbols,
    reported: findings.length,
    capped: findings.length < relationships.length,
    // Occurrences whose target the repository does not establish are evidence, not
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
    // Findings always win over abstention: an established relationship was observed, so
    // reporting it does not depend on how complete the rest of the graph is.
    return { findings, evidence: [], metadata };
  }

  // Nothing was observed. That is a claim, so it needs the coverage to support it: a
  // graph that was never established, or was only partly established, must abstain
  // rather than report a repository with no semantic relationships.
  const absence = symbolsAbsence(query);
  if (!absence.established) {
    return {
      ...createRuleDetection({
        findings: [],
        coverage: APPLICABILITY_COVERAGE.UNKNOWN,
        reason: `no semantic relationship was observed, but ${absence.reason}`,
      }),
      metadata,
    };
  }

  return { findings, evidence: [], metadata };
}

export const symbolRules = Object.freeze([
  createRule({
    id: SYMBOL_RULE_IDS.GRAPH_INVENTORY,
    version: SYMBOL_RULE_VERSION,
    category: SYMBOL_CATEGORY,
    title: "Semantic relationship established by the repository",
    description:
      "A supported JavaScript or TypeScript source file states a semantic relationship the repository's own resolution establishes: a module-scope declaration, an export, a reference to the only binding of that name in the file, a statically established call site whose callee's value shape is established, or an import binding resolved to the symbol another file exports. The finding names the stating file, the symbol, the relationship's established kind and the observation behind it, and cites the stating file's own observation. It is an inventory statement: no complexity, coupling, reachability, dead-code, cycle, type, execution-order or data-flow claim is made, an occurrence whose target is not established is reported as metadata rather than as a finding, and a symbol whose name could be bound elsewhere in its file carries that fact rather than being reported as unreferenced.",
    severity: "info",
    // Every repository that was scanned is in scope; a rule with no selectors is
    // universally applicable (Core Rule contract).
    applicability: {},
    detect: (context) => detectSymbols(context),
    remediation: {},
    metadata: {
      basis: SYMBOL_BASIS,
      tags: ["symbols", "declarations", "references", "inventory"],
      falsePositives: [
        "a file whose lexer could not be run to the end still yields no declaration, and the graph says so rather than guessing",
        "a name that is also bound elsewhere in its file is never reported as a resolved reference (the occurrence is listed as unresolved instead)",
        "a property access on an object (`obj.method()`) is never a call edge, because a method call is runtime dispatch",
      ],
    },
  }),
]);
