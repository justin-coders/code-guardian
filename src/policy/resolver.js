/**
 * Code Guardian — Policy Preset Resolver (Phase 23)
 *
 * The one pure function that turns what a repository wrote into the policy this build measures:
 *
 *     declared PolicyDocument  →  resolvePolicyDocument  →  effective document + provenance
 *
 * ### One merge rule, and no exceptions to it
 *
 * The preset is applied first; a value the repository's own document states replaces it. That is
 * the whole algorithm. There is no expression language, no interpolation, no `extends`, no
 * reference to another preset and no environment: `resolvePolicyDocument` reads two in-memory
 * objects and writes one, so two calls with the same inputs cannot disagree and no result depends
 * on the surrounding process.
 *
 * ### Unknown preset means the whole document is invalid
 *
 * A document that names a preset the registry does not hold resolves to *nothing*: not the
 * repository's own values, not a partly-applied preset. The caller publishes a policy reading that
 * established nothing, with the reason. The alternative — applying the domains the document happened
 * to state and dropping the preset — would silently measure a repository against a policy it never
 * declared, which is the failure mode this phase exists to prevent.
 *
 * ### Provenance is produced here, once
 *
 * Every effective key gets exactly one source token: `user` when the repository stated it,
 * `preset:<name>` when the preset did. `inherited` and `overridden` are the same fact read two ways
 * — the keys the preset supplied, and the preset keys the repository replaced — so a consumer never
 * has to reconstruct provenance by diffing two documents, and a compliance item can always name the
 * preset a requirement came from.
 */

import {
  MAX_PRESET_RELEASE_WORKFLOWS,
  POLICY_PRESET_DOMAINS,
  POLICY_PRESET_KEYS,
  POLICY_PRESET_LIMITS,
  POLICY_PRESET_ORIGIN,
  POLICY_PRESET_SCHEMA,
  POLICY_PRESET_SOURCES,
  POLICY_PRESET_VERSION,
  POLICY_RESOLUTION_FAILURES,
  isPlainObject,
  isPresetName,
  presetSource,
} from "./contracts.js";
import { DEFAULT_PRESET_REGISTRY } from "./registry.js";

/**
 * Bound a repository-authored name before it travels as a detail.
 *
 * The only repository-authored string this layer ever carries is a preset name, and it travels as a
 * bounded identifier rather than free text — the same discipline every other acquisition detail
 * follows.
 *
 * @param {unknown} value
 * @returns {string|null}
 */
export function boundedPresetName(value) {
  if (typeof value !== "string") return null;
  const sanitized = value.replace(/[^A-Za-z0-9_.-]/g, "");
  if (sanitized === "") return null;
  return sanitized.slice(0, POLICY_PRESET_LIMITS.maxPresetNameLength);
}

/** The declared domains of a document, in declared order. */
function declaredDomains(document) {
  return POLICY_PRESET_DOMAINS.filter((domain) => isPlainObject(document[domain]));
}

/** Rebuild a declared document in canonical order: version, preset, then the declared domains. */
function canonicalDeclared(document, presetName) {
  const canonical = { version: POLICY_PRESET_VERSION };
  if (presetName !== null) canonical.preset = presetName;
  for (const domain of declaredDomains(document)) {
    const settings = {};
    for (const key of POLICY_PRESET_KEYS[domain]) {
      if (Object.hasOwn(document[domain], key)) settings[key] = document[domain][key];
    }
    canonical[domain] = settings;
  }
  return canonical;
}

function sortedRecord(record) {
  const sorted = {};
  for (const key of Object.keys(record).sort()) sorted[key] = record[key];
  return sorted;
}

/**
 * Deep-freeze a resolved document.
 *
 * A shallow `Object.freeze` would leave each domain's settings object mutable, and this layer's whole
 * promise is that what it returns cannot be changed after the fact — an inherited value that a
 * caller *can* edit would make the next resolution and the published policy disagree. The freeze is
 * recursive for that reason, and the objects are freshly built here, so nothing shared with the
 * registry or the caller is affected.
 */
function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const key of Object.keys(value)) deepFreeze(value[key]);
  return value;
}

/**
 * Resolve a declared policy document into an effective one.
 *
 * @param {object} input
 * @param {unknown} input.document The declared document: `{version?, preset?, ...domains}`.
 * @param {object} [input.registry] The preset registry to resolve against.
 * @returns {{ok: true, effective: object, declared: object, preset: object|null, provenance: object}
 *   | {ok: false, reason: string, detail: string|null}} A deeply frozen result either way.
 */
export function resolvePolicyDocument({ document, registry = DEFAULT_PRESET_REGISTRY } = {}) {
  if (!isPlainObject(document)) {
    return Object.freeze({
      ok: false,
      reason: POLICY_RESOLUTION_FAILURES.DOCUMENT_NOT_INTERPRETED,
      detail: null,
    });
  }

  // The version is pinned. The acquisition layer refuses a document that states another one, so a
  // mismatch here can only come from a hand-built model — and it is refused rather than assumed.
  if (document.version !== undefined && document.version !== POLICY_PRESET_VERSION) {
    return Object.freeze({
      ok: false,
      reason: POLICY_RESOLUTION_FAILURES.VERSION_NOT_SUPPORTED,
      detail: boundedPresetName(document.version),
    });
  }

  if (document.preset !== undefined && typeof document.preset !== "string") {
    return Object.freeze({
      ok: false,
      reason: POLICY_RESOLUTION_FAILURES.PRESET_NOT_ESTABLISHED,
      detail: null,
    });
  }

  const presetName = typeof document.preset === "string" ? document.preset : null;
  let base = null;
  if (presetName !== null) {
    const preset = registry?.get?.(presetName) ?? null;
    if (preset === null) {
      return Object.freeze({
        ok: false,
        reason: POLICY_RESOLUTION_FAILURES.PRESET_NOT_ESTABLISHED,
        detail: boundedPresetName(presetName),
      });
    }
    base = preset.document;
  }

  const effective = {};
  const sources = {};
  const inherited = [];
  const overridden = [];

  for (const domain of POLICY_PRESET_DOMAINS) {
    const stated = isPlainObject(document[domain]) ? document[domain] : null;
    const presetSettings = base === null ? null : base[domain] ?? null;
    if (stated === null && presetSettings === null) continue;

    const settings = {};
    for (const key of POLICY_PRESET_KEYS[domain]) {
      const id = `${domain}.${key}`;
      const userStated = stated !== null && Object.hasOwn(stated, key);
      if (userStated) {
        settings[key] = stated[key];
        sources[id] = POLICY_PRESET_SOURCES.USER;
        if (presetSettings !== null && Object.hasOwn(presetSettings, key)) overridden.push(id);
        continue;
      }
      if (presetSettings !== null && Object.hasOwn(presetSettings, key)) {
        settings[key] = presetSettings[key];
        sources[id] = presetSource(presetName);
        inherited.push(id);
      }
    }
    effective[domain] = settings;
  }

  const provenance = deepFreeze({
    version: POLICY_PRESET_VERSION,
    preset: presetName,
    sources: sortedRecord(sources),
    inherited: [...inherited].sort(),
    overridden: [...overridden].sort(),
    limits: {
      maxSources: POLICY_PRESET_LIMITS.maxSources,
      maxReleaseWorkflows: MAX_PRESET_RELEASE_WORKFLOWS,
    },
  });

  return deepFreeze({
    ok: true,
    effective,
    declared: canonicalDeclared(document, presetName),
    preset:
      presetName === null
        ? null
        : {
            name: presetName,
            version: POLICY_PRESET_VERSION,
            origin: POLICY_PRESET_ORIGIN,
          },
    provenance,
  });
}

/**
 * Re-resolve a declared document and check it reproduces a published effective policy.
 *
 * Exposed so the model's contract can prove an effective document is *derived* from the declared
 * one rather than merely shaped like it — the same "recompute, don't sample" discipline the
 * compliance report's contract follows.
 *
 * @param {object} input
 * @param {unknown} input.declared The published declared document.
 * @param {unknown} input.effective The published effective document.
 * @param {unknown} input.provenance The published provenance.
 * @param {object} [input.registry]
 * @returns {string[]} Empty when the published values are the resolved ones.
 */
export function effectivePolicyIssues({ declared, effective, provenance, registry }) {
  const resolution = resolvePolicyDocument({ document: declared, registry });
  if (!resolution.ok) {
    return [`declared: could not be resolved (${resolution.reason})`];
  }
  const issues = [];
  if (JSON.stringify(resolution.effective) !== JSON.stringify(effective)) {
    issues.push("effective: must be the document the declared policy resolves to");
  }
  if (JSON.stringify(resolution.provenance) !== JSON.stringify(provenance)) {
    issues.push("provenance: must be the provenance the declared policy resolves to");
  }
  return issues;
}
