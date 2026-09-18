/**
 * Code Guardian Core — Evidence Contract
 *
 * Evidence is a first-class object: it records *what was observed* and where
 * that observation came from. Findings reference evidence by ID rather than
 * duplicating it.
 *
 * Evidence must always carry provenance so a conclusion can be traced back to
 * its collector (deterministic analysis, and later LLM-assisted reasoning).
 *
 * This module defines the shape/constants/factory only.
 */

/** Controlled vocabulary of evidence types (Phase 7 Blueprint §8). */
export const EVIDENCE_TYPES = Object.freeze([
  "file",
  "directory",
  "line",
  "symbol",
  "ast",
  "dependency",
  "configuration",
  "git",
  "command",
  "workflow",
  "test",
  "runtime",
  "graph",
  "documentation",
]);

/** Location fields evidence may carry. None are individually mandatory. */
export const EVIDENCE_LOCATION_FIELDS = Object.freeze([
  "path",
  "line",
  "column",
]);

/**
 * Build an Evidence object.
 *
 * `data` intentionally holds small, structured facts (e.g. a symbol name)
 * rather than large source snippets; renderers can retrieve source later.
 *
 * @param {object} [input]
 * @param {string} [input.id] Stable evidence identifier referenced by findings.
 * @param {string} [input.type] One of `EVIDENCE_TYPES`.
 * @param {object} [input.location] `{ path, line, column }` subset.
 * @param {object} [input.source] `{ analyzer, method }` producer details.
 * @param {object} [input.data] Small structured observation payload.
 * @param {object} [input.provenance] `{ deterministic, collector, ... }`.
 * @returns {object} An Evidence-shaped object.
 */
export function createEvidence(input = {}) {
  return {
    id: input.id,
    type: input.type,
    location: { ...(input.location ?? {}) },
    source: { ...(input.source ?? {}) },
    data: { ...(input.data ?? {}) },
    provenance: { deterministic: true, ...(input.provenance ?? {}) },
  };
}
