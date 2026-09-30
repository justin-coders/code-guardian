/**
 * Code Guardian — Repository Policy Document Acquisition Policy (Phase 22)
 *
 * The one repository document this build interprets as a *contract* rather than as an
 * observation: `.codeguardian/policy.json`.
 *
 * ### What it is, and what it is not
 *
 * It is not scanner configuration. Nothing here changes what the scan reads, which paths are
 * ignored, which limits apply or which detectors run: the document is consumed by the model,
 * where it becomes the *declared* engineering requirements a compliance report is measured
 * against. A scanner option and a repository policy are answers to different questions, and
 * collapsing them would let a repository change what it is *observed* to be by editing a file
 * it is *judged* by.
 *
 * ### JSON only, and only the keys this build declares
 *
 * Exactly one format is supported. The schema is closed at both levels: six domains, and
 * within each domain the keys listed here. An unknown domain, an unknown key, a value of the
 * wrong type and a value out of range are all *refusals* — the document is not partly applied,
 * because a policy that was silently half-honoured would make every compliance answer wrong in
 * a way no consumer could see.
 *
 * YAML is deliberately **not** interpreted. A repository that states a policy in
 * `.codeguardian/policy.yaml` is not told "you have no policy" — that would be a fabricated
 * fact, and this architecture never converts "not read" into "not there". It is recorded as a
 * policy document in a format this build does not read, which is what
 * `POLICY_UNSUPPORTED_REASONS` exists to say.
 *
 * ### Determinism and safety
 *
 * The parsed document is rebuilt in canonical domain and key order, so two spellings of the
 * same policy serialize identically. Failure `detail` values are sanitized through
 * `boundedPolicyToken`, so a hostile key name cannot travel through this layer as free text.
 * Nothing is written and no process, network or clock is involved.
 */

/** The contracted policy path. Exactly one, and it decides the document. */
export const POLICY_DOCUMENT_PATH = ".codeguardian/policy.json";

/**
 * The one policy document version this build interprets.
 *
 * The version is pinned rather than negotiated: a document that states another one is *refused*, not
 * read on a best-effort basis, because a policy this build only partly understands is exactly the
 * policy a compliance answer must not be measured against.
 */
export const POLICY_DOCUMENT_VERSION = "1";

/** The top-level keys a policy document may state beside its domains. */
export const POLICY_DOCUMENT_METADATA_KEYS = Object.freeze(["version", "preset"]);

/** The directory the policy document lives in. */
export const POLICY_DIRECTORY = ".codeguardian";

/** The only format this build interprets. */
export const POLICY_FORMAT = "json";

/**
 * Policy-shaped paths in a format this build does not read.
 *
 * Their presence is recorded so the model can say `unsupported` — "a policy exists, this build
 * does not read its format" — instead of "this repository declares no policy", which would be
 * false.
 */
export const POLICY_UNREAD_FORMATS = Object.freeze([
  Object.freeze({ path: ".codeguardian/policy.yaml", format: "yaml" }),
  Object.freeze({ path: ".codeguardian/policy.yml", format: "yaml" }),
]);

/** The six policy domains, in the order the model declares them. */
export const POLICY_DOMAINS = Object.freeze([
  "environment",
  "container",
  "ci",
  "api",
  "dependencies",
  "architecture",
]);

/**
 * The closed schema: every domain, every key it may state, and the type each key must have.
 *
 * `boolean` keys are `true`/`false` and nothing else; `integer` keys are whole numbers in
 * `[0, POLICY_LIMITS.maxReleaseWorkflows]`. The list is exhaustive — a key absent from this
 * table is an unknown key and refuses the document.
 */
export const POLICY_SCHEMA = Object.freeze({
  environment: Object.freeze({
    requireTemplate: "boolean",
    allowMultipleTemplates: "boolean",
  }),
  container: Object.freeze({
    requireHealthcheck: "boolean",
  }),
  ci: Object.freeze({
    requireTestsForRelease: "boolean",
    requireLintForRelease: "boolean",
    maxReleaseWorkflows: "integer",
  }),
  api: Object.freeze({
    requireResolvedMiddleware: "boolean",
  }),
  dependencies: Object.freeze({
    requireLockfile: "boolean",
    allowMultipleManagers: "boolean",
  }),
  architecture: Object.freeze({
    requireConnectedEntrypoints: "boolean",
  }),
});

/** Every key the schema declares, per domain, in schema order. */
export const POLICY_KEYS_BY_DOMAIN = Object.freeze(
  POLICY_DOMAINS.reduce((accumulator, domain) => {
    accumulator[domain] = Object.freeze(Object.keys(POLICY_SCHEMA[domain]));
    return accumulator;
  }, {}),
);

/** Every `(domain, key)` pair the schema declares. */
export const POLICY_KEYS = Object.freeze(
  POLICY_DOMAINS.flatMap((domain) =>
    POLICY_KEYS_BY_DOMAIN[domain].map((key) => Object.freeze({ domain, key })),
  ),
);

/** Bounds on what the acquisition will read and retain. */
export const POLICY_LIMITS = Object.freeze({
  /** Bytes read from the policy document. A policy larger than this is not interpreted. */
  maxFileBytes: 65536,
  /** Domains the schema declares. */
  maxDomains: POLICY_DOMAINS.length,
  /** Keys any one domain declares. */
  maxKeysPerDomain: Math.max(
    ...POLICY_DOMAINS.map((domain) => POLICY_KEYS_BY_DOMAIN[domain].length),
  ),    /** Largest accepted `maxReleaseWorkflows`. */
    maxReleaseWorkflows: 1000,
    /** Characters retained from a key name in a failure `detail`. */
    maxDetailLength: 48,
    /** Characters a declared preset name may occupy. */
    maxPresetNameLength: 32,
  });

/** What the acquisition established about the policy document. */
export const POLICY_SOURCE_STATUSES = Object.freeze({
  /** No policy document, and no policy-shaped path, was observed. */
  ABSENT: "absent",
  /** The document was read, parsed and satisfied the schema. */
  PARSED: "parsed",
  /** The document was observed but could not be interpreted. */
  FAILED: "failed",
  /** A policy document was observed in a format this build does not read. */
  UNSUPPORTED: "unsupported",
});

/** The status vocabulary as a list, for validation. */
export const POLICY_SOURCE_STATUS_VALUES = Object.freeze(
  Object.values(POLICY_SOURCE_STATUSES),
);

/**
 * Why a policy document was not interpreted. Closed vocabulary.
 *
 * Each reason is a statement about the *reading*, never about the policy: nothing here says a
 * policy is wrong, only that this build could not establish what it says.
 */
export const POLICY_FAILURE_REASONS = Object.freeze({
  READ_FAILED: "read-failed",
  TOO_LARGE: "too-large",
  NOT_TEXT: "not-text",
  INVALID_JSON: "invalid-json",
  NOT_AN_OBJECT: "not-an-object",
  UNKNOWN_DOMAIN: "unknown-domain",
  UNKNOWN_KEY: "unknown-key",
  WRONG_TYPE: "wrong-type",
  OUT_OF_RANGE: "out-of-range",
  // Phase 23 — the document states a policy version this build does not interpret. Like every
  // other refusal here it is a statement about the *reading*: the document may be perfectly good
  // policy for a later build, and this one says so rather than guessing at its meaning.
  UNSUPPORTED_VERSION: "unsupported-version",
});

/** The failure vocabulary as a list, for validation. */
export const POLICY_FAILURE_REASON_VALUES = Object.freeze(
  Object.values(POLICY_FAILURE_REASONS),
);

/** Why a policy document this build does not read as a policy is recorded as such. */
export const POLICY_UNSUPPORTED_REASONS = Object.freeze({
  FORMAT_NOT_INTERPRETED: "policy-format-not-interpreted",
});

/** The unsupported vocabulary as a list, for validation. */
export const POLICY_UNSUPPORTED_REASON_VALUES = Object.freeze(
  Object.values(POLICY_UNSUPPORTED_REASONS),
);

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Reduce a candidate detail to a bounded, inert token.
 *
 * A failure `detail` names the offending key so a repository author can find it, and that
 * string is repository-authored text. Only identifier characters survive, at most
 * `POLICY_LIMITS.maxDetailLength` of them; anything else becomes `null`, which is the same
 * answer the field gives when there is nothing to name. So no hostile key can travel through
 * this layer as free text, and no value is ever carried at all.
 *
 * @param {unknown} value
 * @returns {string|null}
 */
export function boundedPolicyToken(value) {
  if (typeof value !== "string") return null;
  const sanitized = value.replace(/[^A-Za-z0-9_.-]/g, "");
  if (sanitized === "" || sanitized.length > POLICY_LIMITS.maxDetailLength) {
    return sanitized === "" ? null : sanitized.slice(0, POLICY_LIMITS.maxDetailLength);
  }
  return sanitized;
}

/** Whether a repository-relative path is the contracted policy document. */
export function isPolicyDocumentPath(path) {
  return path === POLICY_DOCUMENT_PATH;
}

/** The unread-format record for a path, or `null`. */
export function unreadPolicyFormat(path) {
  return POLICY_UNREAD_FORMATS.find((entry) => entry.path === path) ?? null;
}

/**
 * Parse and validate a policy document's text.
 *
 * The return contract mirrors every other acquisition policy in this layer: `ok: true` with the
 * document, or `ok: false` with a closed `reason` and a bounded `detail`. The document it returns
 * is **rebuilt**, never the parsed value itself: domains appear in `POLICY_DOMAINS` order, keys
 * in schema order, and nothing that is not in the schema appears at all. A caller therefore
 * cannot receive a half-validated document, and the object it does receive is safe to freeze,
 * hash and serialize.
 *
 * @param {unknown} text The file's text, as read through the Phase 8A boundary.
 * @returns {{ok: true, document: object} | {ok: false, reason: string, detail: string|null}}
 */
export function parsePolicyDocument(text) {
  if (typeof text !== "string" || text.includes("\u0000")) {
    return { ok: false, reason: POLICY_FAILURE_REASONS.NOT_TEXT, detail: null };
  }

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    // The platform's own parse message is deliberately not carried: it quotes document text,
    // and this layer records *that* the document is not JSON, never what it said.
    return { ok: false, reason: POLICY_FAILURE_REASONS.INVALID_JSON, detail: null };
  }

  if (!isPlainObject(parsed)) {
    return { ok: false, reason: POLICY_FAILURE_REASONS.NOT_AN_OBJECT, detail: null };
  }

  for (const key of Object.keys(parsed)) {
    if (POLICY_DOMAINS.includes(key)) continue;
    // Phase 23 — the two document-level fields a policy may state beside its domains. They are
    // interpreted here and resolved by the model; they are *not* domains, and nothing about them
    // reaches the compliance engine as a requirement.
    if (POLICY_DOCUMENT_METADATA_KEYS.includes(key)) continue;
    return {
      ok: false,
      reason: POLICY_FAILURE_REASONS.UNKNOWN_DOMAIN,
      detail: boundedPolicyToken(key),
    };
  }

  // The pinned version, refused rather than negotiated. A missing version means the contracted one:
  // the schema's own default, so a document need not restate the only version this build reads.
  if (Object.hasOwn(parsed, "version")) {
    if (parsed.version !== POLICY_DOCUMENT_VERSION) {
      return {
        ok: false,
        reason: POLICY_FAILURE_REASONS.UNSUPPORTED_VERSION,
        detail: boundedPolicyToken(parsed.version),
      };
    }
  }

  // A declared preset is a name, and only a name. Whether the registry holds it is a *resolution*
  // question the model answers: the acquisition layer knows no preset vocabulary, and teaching it
  // one would put the closed list in two places.
  if (Object.hasOwn(parsed, "preset")) {
    const preset = parsed.preset;
    if (
      typeof preset !== "string" ||
      preset === "" ||
      preset.length > POLICY_LIMITS.maxPresetNameLength
    ) {
      return {
        ok: false,
        reason: POLICY_FAILURE_REASONS.WRONG_TYPE,
        detail: boundedPolicyToken("preset"),
      };
    }
  }

  // The document is rebuilt in canonical order: the version when it was stated, the preset when one
  // was named, then the domains in declared order. Two spellings of one policy therefore serialize
  // identically, so every downstream id depends on the declaration and not on how a file was typed.
  const document = {};
  if (Object.hasOwn(parsed, "version")) document.version = POLICY_DOCUMENT_VERSION;
  if (Object.hasOwn(parsed, "preset")) document.preset = parsed.preset;
  for (const domain of POLICY_DOMAINS) {
    if (!Object.hasOwn(parsed, domain)) continue;
    const stated = parsed[domain];
    if (!isPlainObject(stated)) {
      return {
        ok: false,
        reason: POLICY_FAILURE_REASONS.WRONG_TYPE,
        detail: boundedPolicyToken(domain),
      };
    }

    const schema = POLICY_SCHEMA[domain];
    for (const key of Object.keys(stated)) {
      if (!Object.hasOwn(schema, key)) {
        return {
          ok: false,
          reason: POLICY_FAILURE_REASONS.UNKNOWN_KEY,
          detail: boundedPolicyToken(`${domain}.${key}`),
        };
      }
    }

    const settings = {};
    for (const key of POLICY_KEYS_BY_DOMAIN[domain]) {
      if (!Object.hasOwn(stated, key)) continue;
      const value = stated[key];
      const expected = schema[key];
      if (expected === "boolean") {
        if (typeof value !== "boolean") {
          return {
            ok: false,
            reason: POLICY_FAILURE_REASONS.WRONG_TYPE,
            detail: boundedPolicyToken(`${domain}.${key}`),
          };
        }
        settings[key] = value;
        continue;
      }
      // The one non-boolean setting. A non-integer, a negative value and a value beyond the
      // declared bound are three ways of stating a requirement this build cannot evaluate, so
      // all three refuse rather than clamp.
      if (!Number.isInteger(value) || value < 0 || value > POLICY_LIMITS.maxReleaseWorkflows) {
        return {
          ok: false,
          reason: Number.isInteger(value)
            ? POLICY_FAILURE_REASONS.OUT_OF_RANGE
            : POLICY_FAILURE_REASONS.WRONG_TYPE,
          detail: boundedPolicyToken(`${domain}.${key}`),
        };
      }
      settings[key] = value;
    }

    document[domain] = settings;
  }

  return { ok: true, document };
}

/**
 * Count the settings a document states.
 *
 * Used by the model to report how much of the policy it is acting on, without carrying the
 * values into any count that could read as a score.
 *
 * @param {object|null} document
 * @returns {number}
 */
export function policySettingCount(document) {
  if (!isPlainObject(document)) return 0;
  let total = 0;
  for (const domain of POLICY_DOMAINS) {
    const settings = document[domain];
    if (isPlainObject(settings)) total += Object.keys(settings).length;
  }
  return total;
}
