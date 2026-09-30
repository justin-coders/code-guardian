/**
 * Code Guardian — Built-in Policy Presets (Phase 23)
 *
 * Five immutable, complete policy documents, and nothing else. Each one states all six domains and
 * every key those domains declare, so resolving one can never depend on which keys a repository
 * happened to omit: the preset is the whole starting point and the repository's own document is
 * applied on top of it.
 *
 * ### Why completeness matters
 *
 * A partial preset would make provenance depend on the order in which two documents were merged,
 * and would leave "the preset requires nothing here" indistinguishable to a reader to the case where
 * the preset declares no such key at all. Because every built-in preset is complete, `resolvePolicyDocument` has
 * exactly one merge rule — the repository's value wins where it states one, the preset's value
 * otherwise — and every resolved key always has a source.
 *
 * ### `minimal` states no requirement, deliberately
 *
 * `minimal` is complete and every requirement in it is *off*: `requireTemplate: false`,
 * `requireHealthcheck: false`, and so on. That is not a loophole. A policy key that is `false`
 * makes no requirement, so `minimal` declares nothing and the compliance engine measures nothing
 * against it — the same answer a repository that declared no policy at all receives. It exists so a
 * repository can say "start from nothing and opt in", which is exactly what a small project wants.
 *
 * ### The four other presets are stated, not derived
 *
 * Each is written out in full rather than computed from another, because a preset that inherited
 * from another preset would be preset-to-preset inheritance — which this phase does not implement.
 * `backend-service` differing from `web-production` in one key is a fact recorded twice on purpose.
 *
 * `purpose` is a bounded, developer-facing sentence. It is never shown to a repository author as
 * advice, and this layer never recommends one preset over another.
 */

import { POLICY_PRESET_LIMITS, isPresetName, isPlainObject } from "./contracts.js";

/**
 * The five built-in presets, in the order this build declares them.
 *
 * The declaration order here is the order tests print and reason about; the *registry* sorts its
 * names, so the two are deliberately independent and a store that reorders its input cannot change
 * any answer.
 */
const definitions = [
  {
    name: "minimal",
    purpose: "A small project that requires nothing of itself and opts in key by key.",
    document: {
      environment: { requireTemplate: false, allowMultipleTemplates: true },
      container: { requireHealthcheck: false },
      ci: { requireTestsForRelease: false, requireLintForRelease: false, maxReleaseWorkflows: 5 },
      api: { requireResolvedMiddleware: false },
      dependencies: { requireLockfile: false, allowMultipleManagers: true },
      architecture: { requireConnectedEntrypoints: false },
    },
  },
  {
    name: "web-production",
    purpose:
      "A production web application: healthcheck, tests, lint, lockfile, middleware and connected entrypoints required.",
    document: {
      environment: { requireTemplate: false, allowMultipleTemplates: true },
      container: { requireHealthcheck: true },
      ci: { requireTestsForRelease: true, requireLintForRelease: true, maxReleaseWorkflows: 5 },
      api: { requireResolvedMiddleware: true },
      dependencies: { requireLockfile: true, allowMultipleManagers: true },
      architecture: { requireConnectedEntrypoints: true },
    },
  },
  {
    name: "backend-service",
    purpose: "A web-production application whose release path is deliberately narrow.",
    document: {
      environment: { requireTemplate: false, allowMultipleTemplates: true },
      container: { requireHealthcheck: true },
      ci: { requireTestsForRelease: true, requireLintForRelease: true, maxReleaseWorkflows: 2 },
      api: { requireResolvedMiddleware: true },
      dependencies: { requireLockfile: true, allowMultipleManagers: true },
      architecture: { requireConnectedEntrypoints: true },
    },
  },
  {
    name: "library",
    purpose: "A package or SDK: no container, no middleware, but a lockfile and a CI gate.",
    document: {
      environment: { requireTemplate: false, allowMultipleTemplates: true },
      container: { requireHealthcheck: false },
      ci: { requireTestsForRelease: true, requireLintForRelease: true, maxReleaseWorkflows: 5 },
      api: { requireResolvedMiddleware: false },
      dependencies: { requireLockfile: true, allowMultipleManagers: true },
      architecture: { requireConnectedEntrypoints: false },
    },
  },
  {
    name: "strict",
    purpose: "Maximum structural compliance: every requirement this build can measure is on.",
    document: {
      environment: { requireTemplate: true, allowMultipleTemplates: false },
      container: { requireHealthcheck: true },
      ci: { requireTestsForRelease: true, requireLintForRelease: true, maxReleaseWorkflows: 1 },
      api: { requireResolvedMiddleware: true },
      dependencies: { requireLockfile: true, allowMultipleManagers: false },
      architecture: { requireConnectedEntrypoints: true },
    },
  },
];

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const key of Object.keys(value)) deepFreeze(value[key]);
  return value;
}

/**
 * Freeze a preset definition.
 *
 * @param {object} definition
 * @returns {object} A deeply frozen `{name, purpose, document}`.
 */
export function freezePreset(definition) {
  return deepFreeze({
    name: definition.name,
    purpose: definition.purpose,
    document: isPlainObject(definition.document) ? definition.document : {},
  });
}

/** The built-in presets, in declared order, deeply frozen. */
export const BUILT_IN_PRESETS = Object.freeze(definitions.map(freezePreset));

/** The built-in preset names, in declared order. */
export const PRESET_NAMES = Object.freeze(BUILT_IN_PRESETS.map((preset) => preset.name));

/** Whether a name is one of the built-in presets — the closed vocabulary. */
export function isBuiltInPresetName(name) {
  return typeof name === "string" && PRESET_NAMES.includes(name);
}

/** The longest built-in purpose, so a caller can pin the bound. */
export const MAX_BUILT_IN_PURPOSE_LENGTH = Object.freeze(
  BUILT_IN_PRESETS.map((preset) => preset.purpose.length).reduce((a, b) => Math.max(a, b), 0),
);

/**
 * Assert the built-in set is well-formed.
 *
 * Deliberately *not* run at module load: a thrown error at import time would take down every
 * consumer of the package, including one that never touches presets. The test suite calls it, so a
 * broken built-in preset is a failing test rather than a silent one — and the registry validates
 * whatever it is handed anyway.
 *
 * @returns {string[]} Empty when the built-in set satisfies the contract.
 */
export function builtInPresetIssues() {
  const issues = [];
  if (BUILT_IN_PRESETS.length === 0) issues.push("BUILT_IN_PRESETS: must declare at least one preset");
  if (BUILT_IN_PRESETS.length > POLICY_PRESET_LIMITS.maxPresets) {
    issues.push("BUILT_IN_PRESETS: must stay within the declared preset bound");
  }
  const seen = new Set();
  for (const preset of BUILT_IN_PRESETS) {
    if (!isPresetName(preset.name)) {
      issues.push(`BUILT_IN_PRESETS: "${String(preset.name)}" is not a well-formed preset name`);
      continue;
    }
    if (seen.has(preset.name)) issues.push(`BUILT_IN_PRESETS: "${preset.name}" is declared twice`);
    seen.add(preset.name);
    if (typeof preset.purpose !== "string" || preset.purpose === "") {
      issues.push(`BUILT_IN_PRESETS.${preset.name}: purpose must be a non-empty sentence`);
    } else if (preset.purpose.length > POLICY_PRESET_LIMITS.maxPurposeLength) {
      issues.push(`BUILT_IN_PRESETS.${preset.name}: purpose must stay within the declared bound`);
    }
  }
  return issues;
}
