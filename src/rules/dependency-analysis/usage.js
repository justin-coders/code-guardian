/**
 * Code Guardian — Dependency Usage Evidence (Official Roadmap Phase 15)
 *
 * Unused-dependency analysis must be evidence-driven, and the roadmap lists the many channels a
 * dependency can be used through: runtime imports, build tooling, configuration, CLI usage,
 * generated code, framework conventions, test tooling, peer/plugin mechanisms and package
 * scripts. This module gathers the *name evidence* the repository model actually holds across
 * those channels, so "not imported" never becomes "unused".
 *
 * ### Conservative by construction
 *
 * The result is a set of names the repository `references`, gathered from:
 *
 *   - the import graph's specifiers (resolved edges and bare unresolved references),
 *   - manifest script names and the bounded test-script command text,
 *   - the CI tool/runner ids the acquisition classified, and
 *   - every observed file path's segments and words (a tool configured as `eslint.config.js` is
 *     referenced even if no module imports it).
 *
 * A dependency is reported as a *possibly unused* indicator only when **none** of those channels
 * mention it, the import graph was `complete`, and the ecosystem's usage semantics are ones this
 * build can read. Any other case is `unknown`.
 */

import { ENTITY_KINDS, IMPORT_GRAPH_STATES, QUERY_LIMITS } from "../../repository/model/index.js";

import { manifestEntities } from "./signals.js";

/** The package name a module specifier names, or `null` for a relative/aliased/absolute one. */
export function packageRootOf(specifier) {
  if (typeof specifier !== "string") return null;
  const text = specifier.trim();
  if (text === "" || text.startsWith(".") || text.startsWith("/") || text.startsWith("#")) return null;
  if (/:/.test(text) || /\\/.test(text)) return null;
  const segments = text.split("/").filter((segment) => segment !== "");
  if (segments.length === 0) return null;
  if (text.startsWith("@")) {
    return segments.length >= 2 ? `${segments[0]}/${segments[1]}`.toLowerCase() : null;
  }
  return segments[0].toLowerCase();
}

/**
 * Lower-case tokens for a string, so a name can be matched inside a path or a command.
 *
 * The whole lower-cased string is included (so an exact name like `left-pad` or `@scope/pkg`
 * matches), followed by every alphanumeric run (`eslint.config.js` yields `eslint`, `config`,
 * `js`). Matching is deliberately generous: for an *indicator* domain, a false "unused" is far
 * worse than a missed one.
 */
export function wordTokens(text) {
  if (typeof text !== "string") return [];
  const lowered = text.toLowerCase().trim();
  const out = [];
  if (lowered !== "") out.push(lowered);
  for (const token of lowered.split(/[^a-z0-9]+/)) {
    if (token !== "") out.push(token);
  }
  return out;
}

/**
 * The names the repository references, and the coverage behind them.
 *
 * @param {object} query
 * @returns {object} Frozen `{complete, state, referenced, specifiers}`.
 */
export function usageEvidence(query) {
  const graph = query.importGraph();
  const referenced = new Set();
  let specifierCount = 0;

  for (const edge of graph.edges ?? []) {
    for (const specifier of edge.specifiers ?? []) {
      const root = packageRootOf(specifier);
      if (root !== null) {
        referenced.add(root);
        specifierCount += 1;
      }
    }
  }
  // A bare package specifier does not resolve to a file the repository observed, so the graph
  // records it as an *unresolved reference* rather than an edge — including the side-effect
  // form `import "pkg"`. That bounded list is where a dependency's own name evidence lives, so
  // it is read through its own query method rather than assumed present on the graph.
  const unresolvedRefs = query.unresolvedImports({ maxResults: QUERY_LIMITS.MAX_RESULTS });
  for (const record of unresolvedRefs.unresolved ?? []) {
    if (record.reason !== "bare-specifier") continue;
    const root = packageRootOf(record.specifier);
    if (root !== null) {
      referenced.add(root);
      specifierCount += 1;
    }
  }

  for (const manifest of manifestEntities(query)) {
    const metadata = manifest.parse?.metadata ?? null;
    if (metadata === null) continue;
    for (const name of metadata.scripts ?? []) {
      for (const token of wordTokens(name)) referenced.add(token);
    }
    for (const record of metadata.testScripts ?? []) {
      for (const token of wordTokens(record.command ?? "")) referenced.add(token);
      for (const token of wordTokens(record.name ?? "")) referenced.add(token);
    }
  }

  for (const ci of query.listEntities(ENTITY_KINDS.CICD).entities) {
    for (const list of [ci.coverageCommands, ci.qualityCommands, ci.testRunners, ci.builds]) {
      for (const id of list ?? []) {
        if (typeof id === "string") referenced.add(id.toLowerCase());
      }
    }
  }

  for (const file of query.listEntities(ENTITY_KINDS.FILE).entities) {
    if (typeof file.path !== "string") continue;
    for (const token of wordTokens(file.path)) referenced.add(token);
    for (const segment of file.path.toLowerCase().split("/")) {
      if (segment !== "") referenced.add(segment);
    }
  }

  return Object.freeze({
    // A complete graph is necessary but not sufficient: if the bounded unresolved-reference list
    // was cut short, some bare specifiers were never seen, so absence cannot be concluded.
    complete: graph.state === IMPORT_GRAPH_STATES.COMPLETE && unresolvedRefs.limited !== true,
    state: graph.state,
    specifiers: specifierCount,
    referenced,
  });
}

/** Whether a package name is referenced anywhere the usage evidence covers. */
export function isReferenced(evidence, name) {
  if (typeof name !== "string" || name === "") return false;
  const lowered = name.toLowerCase();
  if (evidence.referenced.has(lowered)) return true;
  const lastSegment = lowered.split("/").pop();
  return lastSegment !== undefined && evidence.referenced.has(lastSegment);
}
