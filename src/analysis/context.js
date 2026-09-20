/**
 * Code Guardian — AnalysisContext Construction (Phase 9)
 *
 * The AnalysisContext is the *only* thing an analyzer receives. Building it is
 * therefore the main place where the analyzer boundary is enforced, and the
 * enforcement is deliberately structural rather than advisory:
 *
 *   - **Key allowlist.** Only the six Core context fields may be supplied.
 *     There is no `filesystem`, no `spawn`, no `fetch`, no `mcp`, no
 *     `toolRegistry`, no `modelBuilder`. An attempt to hand an analyzer a
 *     capability fails loudly at construction instead of quietly widening the
 *     contract every analyzer is written against.
 *   - **Data only, by construction.** The framework never puts a function or a
 *     live handle on the context's own keys; the model is already deeply frozen
 *     by Phase 8D, and the framework freezes the rest. An analyzer therefore
 *     cannot obtain repository access from the framework at all in this phase.
 *   - **Validated.** The context is validated against the Core contract
 *     (including the nested RepositoryModel, Rules and Evidence) before it is
 *     handed to any analyzer, so an analyzer can trust its inputs.
 *
 * `execution` is a **policy descriptor**, not a runner: it describes what
 * execution would be permitted (see the Phase 7/8B execution contracts). Phase 9
 * exposes no way to execute anything, because an analyzer that needs a process
 * must go through the accepted Phase 8B boundary in a later phase — adding a
 * capability here would be a security decision, not a convenience.
 *
 * Re-scanning is equally impossible: `repository` is a validated RepositoryModel,
 * and the model layer never touches the filesystem.
 */

import {
  ValidationError,
  createAnalysisContext,
  validateAnalysisContext,
} from "../core/index.js";

import { deepFreeze } from "./values.js";

/**
 * The only keys a caller may supply.
 *
 * Kept in sync with Core `ANALYSIS_CONTEXT_FIELDS`; the builder rejects unknown
 * keys rather than ignoring them, because an ignored capability is a capability
 * someone believed they had.
 */
export const ANALYSIS_CONTEXT_INPUT_KEYS = Object.freeze([
  "repository",
  "configuration",
  "execution",
  "rules",
  "evidence",
  "options",
]);

/**
 * Build a validated, frozen AnalysisContext.
 *
 * @param {object} input
 * @param {object} input.repository The shared RepositoryModel (required).
 * @param {object} [input.configuration] Resolved configuration (data only).
 * @param {object} [input.execution] Execution policy descriptor (data only).
 * @param {object[]} [input.rules] Rules available to analyzers.
 * @param {object[]} [input.evidence] Evidence carried into the run.
 * @param {object} [input.options] Analysis options.
 * @returns {object} A deeply frozen AnalysisContext.
 * @throws {ValidationError} When a capability key is supplied or the context
 *   does not satisfy the Core contract.
 */
export function buildAnalysisContext(input = {}) {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new ValidationError("Invalid analysis context input", {
      details: {
        contract: "AnalysisContext",
        issues: ["input: must be a plain object"],
      },
    });
  }

  const issues = [];
  for (const key of Object.keys(input)) {
    if (!ANALYSIS_CONTEXT_INPUT_KEYS.includes(key)) {
      issues.push(
        `input.${key}: unknown context field (analyzers receive only: ${ANALYSIS_CONTEXT_INPUT_KEYS.join(", ")})`,
      );
    }
  }
  if (input.repository === undefined || input.repository === null) {
    issues.push("input.repository: a validated RepositoryModel is required");
  }
  if (issues.length > 0) {
    throw new ValidationError("Invalid analysis context", {
      details: { contract: "AnalysisContext", issues },
    });
  }

  // Core assembles and validates the composite contract, including the nested
  // RepositoryModel, every Rule and every Evidence record.
  const context = validateAnalysisContext(
    createAnalysisContext({
      repository: input.repository,
      configuration: input.configuration,
      execution: input.execution,
      rules: input.rules,
      evidence: input.evidence,
      options: input.options,
    }),
  );

  // The model is already frozen by Phase 8D; freezing the context (and any
  // caller-supplied configuration data) stops one analyzer from leaving state
  // behind for the next one.
  return deepFreeze(context);
}

/**
 * Index the context's rules by id for deterministic normalization lookups.
 *
 * A later rule with the same id does not overwrite an earlier one, so the result
 * does not depend on how the caller ordered the rule list.
 *
 * @param {object} context A validated AnalysisContext.
 * @returns {Map<string, object>}
 */
export function indexRulesById(context) {
  const byId = new Map();
  for (const rule of context.rules) {
    if (typeof rule?.id === "string" && !byId.has(rule.id)) byId.set(rule.id, rule);
  }
  return byId;
}

/**
 * The set of evidence ids an analyzer may reference without inventing evidence.
 *
 * Model evidence is the shared, scanner-derived provenance; an analyzer may add
 * its own observations on top (validated separately), but never cite evidence it
 * neither owns nor can point at in the model.
 *
 * @param {object} context A validated AnalysisContext.
 * @returns {Set<string>}
 */
export function modelEvidenceIds(context) {
  return new Set(Object.keys(context.repository.indexes?.evidenceById ?? {}));
}
