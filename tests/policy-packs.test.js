/**
 * Code Guardian — Policy Pack Contract Tests (Phase 24)
 *
 * Four fixture styles, the same four the Phase 23 suite uses and for the same reasons:
 *
 *   - **the pack layer directly**, because it is a leaf: a pack is an object this process built, so
 *     its contract can be checked without a repository, a file, a network, a clock or a process;
 *   - **real repositories**, written to a temporary directory and scanned through the accepted Phase
 *     8A boundary, the Phase 8C scanner and the Phase 8D model builder, so a reference in a file on
 *     disk becomes an identity, an effective policy and a provenance by the accepted path alone;
 *   - **tampering inside the model's own policy area**, because the point of the contract is that a
 *     hand-edited pack identity is a validation failure rather than an answer;
 *   - **the accepted rule engine**, because the audit must still be an ordinary informational rule.
 *
 * The suite's central claims are the phase's central requirements: pack identity is closed and
 * deterministic, resolution refuses far more than it accepts, a bare Phase 23 preset name keeps
 * meaning exactly what it meant, no reference ever falls back to another pack, every resolved value
 * can be traced to a pack and a version, and no pack can execute anything.
 *
 * No test starts a container, sends a request, spawns a process, contacts a network, installs a
 * package or writes to the repository under test.
 *
 * Run with: node --test tests/policy-packs.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ValidationError } from "../src/core/index.js";

import {
  BUILT_IN_PACK,
  BUILT_IN_PACKS,
  BUILT_IN_PACK_NAME,
  BUILT_IN_PACK_PURPOSE,
  BUILT_IN_PACK_REFERENCE,
  BUILT_IN_PACK_TITLE,
  BUILT_IN_PACK_VERSION,
  BUILT_IN_PRESETS,
  DEFAULT_PACK_REGISTRY,
  POLICY_PRESET_DEFINITION_FIELDS,
  POLICY_PACK_ERROR_CODE,
  POLICY_PACK_ERROR_KINDS,
  POLICY_PACK_FIELDS,
  POLICY_PACK_LIMITS,
  POLICY_PACK_ORIGINS,
  POLICY_PACK_ORIGIN_VALUES,
  POLICY_PACK_REFERENCE_SEPARATOR,
  POLICY_PACK_PRESET_SEPARATOR,
  POLICY_PACK_VERSION,
  POLICY_PRESET_LIMITS,
  POLICY_PRESET_VERSION,
  POLICY_RESOLUTION_FAILURES,
  POLICY_RESOLUTION_FAILURE_VALUES,
  PolicyPackError,
  builtInPackIssues,
  createPolicyPackRegistry,
  createPresetRegistry,
  freezePack,
  isPackName,
  isPackReference,
  isPackVersion,
  isPresetName,
  isPresetSource,
  packDefinitionIssues,
  packPolicyIssues,
  packPresetReference,
  packReference,
  parsePresetReference,
  presetDefinitionIssues,
  presetSource,
  resolvePackPolicyDocument,
  resolvePackPreset,
  resolvePolicyDocument,
} from "../src/policy/index.js";

import {
  POLICY_DOCUMENT_PATH,
  POLICY_DOCUMENT_VERSION,
  POLICY_SOURCE_STATUSES,
  parsePolicyDocument,
  scanRepository,
} from "../src/repository/scanner/index.js";

import {
  POLICY_DOMAINS,
  POLICY_STATES,
  POLICY_UNKNOWN_REASONS,
  buildRepositoryModel,
  createPolicyPackResult,
  createPolicyProvenanceResult,
  createPolicyResult,
  createRepositoryQuery,
  validatePolicyPackResult,
  validatePolicyProvenanceResult,
  validatePolicyResult,
  validateRepositoryModelGraph,
} from "../src/repository/model/index.js";

import {
  buildAnalysisContext,
  createAnalyzerEngine,
  createAnalyzerRegistry,
} from "../src/analysis/index.js";

import { createRuleEngine } from "../src/rules/index.js";

import {
  POLICY_RULE_IDS,
  POLICY_RULE_SEVERITY,
  activePack,
  activePreset,
  createPolicyAnalyzer,
  createPolicyRuleRegistry,
  policyRules,
} from "../src/rules/policy/index.js";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const TMP = mkdtempSync(join(tmpdir(), "cg-packs-"));
after(() => rmSync(TMP, { recursive: true, force: true }));

let repositories = 0;

/** Write a repository and scan it end to end. */
async function scanOf(files) {
  const root = join(TMP, `repo-${repositories}`);
  repositories += 1;
  mkdirSync(root, { recursive: true });
  for (const [relative, content] of Object.entries(files)) {
    const full = join(root, relative);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
  const scan = await scanRepository(root);
  const model = buildRepositoryModel(scan);
  return {
    root,
    scan,
    model,
    policy: model.policy,
    report: model.compliance.report,
    query: createRepositoryQuery(model),
    context: buildAnalysisContext({ repository: model }),
  };
}

/** A minimal `package.json`. */
const pkg = (fields = {}) => JSON.stringify({ name: "demo", version: "1.0.0", ...fields }, null, 2);

/** A repository-relative policy document. */
const policyFile = (policy) => ({ [POLICY_DOCUMENT_PATH]: JSON.stringify(policy, null, 2) });

/** The document a built-in preset resolves to, as a plain JSON value. */
const documentOf = (name) => JSON.parse(JSON.stringify(BUILT_IN_PRESETS.find((p) => p.name === name).document));

/** A preset definition a fixture can register, complete and schema-valid. */
const presetOf = (name, overrides = {}) => ({
  name,
  purpose: `A fixture preset named ${name}.`,
  document: { ...documentOf(name), ...overrides },
});

/** A pack definition a fixture can register. */
const packOf = (overrides = {}) => ({
  name: "company-core",
  version: "1",
  origin: POLICY_PACK_ORIGINS.BUILT_IN,
  title: "Company core policies",
  purpose: "A pack built by a fixture to exercise the contract.",
  presets: [presetOf("web-production")],
  ...overrides,
});

/**
 * A pack that declares the *same* preset name as the built-in pack, with a different requirement.
 *
 * This is the fixture the whole phase is about: two packs may each declare `web-production`, and a
 * bare name must still mean the built-in one.
 */
const businessPack = (overrides = {}) =>
  packOf({
    name: "business-core",
    title: "Business core policies",
    presets: [presetOf("web-production", { ci: { requireTestsForRelease: true, requireLintForRelease: true, maxReleaseWorkflows: 7 } })],
    ...overrides,
  });

/** A registry holding the built-in pack and the business pack. */
const twoPackRegistry = () => createPolicyPackRegistry({ packs: [BUILT_IN_PACK, businessPack()] });

/** Every problem the graph contract reports, or `null` when the model is valid. */
function issuesOfValidate(model) {
  try {
    validateRepositoryModelGraph(model);
    return null;
  } catch (error) {
    if (error instanceof ValidationError) return error.details?.issues ?? [];
    throw error;
  }
}

const clone = (value) => JSON.parse(JSON.stringify(value));

/** Every `domain.key` an effective document states, sorted. */
const keyIdsOf = (document) =>
  Object.keys(document)
    .flatMap((domain) => Object.keys(document[domain]).map((key) => `${domain}.${key}`))
    .sort();

/** Deep-walk a value, calling `visit` on every node. */
function walk(value, visit) {
  visit(value);
  if (value === null || typeof value !== "object") return;
  for (const key of Object.keys(value)) walk(value[key], visit);
}

// ─── Pack schema ─────────────────────────────────────────────────────────────

describe("policy pack schema", () => {
  it("accepts the built-in pack and declares it complete", () => {
    assert.deepEqual(builtInPackIssues(), []);
    assert.deepEqual(packDefinitionIssues(BUILT_IN_PACK), []);
    assert.deepEqual(
      BUILT_IN_PACKS.map((pack) => pack.reference),
      [BUILT_IN_PACK_REFERENCE],
    );
    assert.equal(BUILT_IN_PACK.name, BUILT_IN_PACK_NAME);
    assert.equal(BUILT_IN_PACK.version, BUILT_IN_PACK_VERSION);
    assert.equal(BUILT_IN_PACK.origin, POLICY_PACK_ORIGINS.BUILT_IN);
    assert.equal(BUILT_IN_PACK.title, BUILT_IN_PACK_TITLE);
    assert.equal(BUILT_IN_PACK.purpose, BUILT_IN_PACK_PURPOSE);
    assert.deepEqual(POLICY_PACK_ORIGIN_VALUES, ["built-in"]);
    assert.equal(POLICY_PACK_VERSION, "1");
    // The built-in identity is pinned literally: it is the name a repository may write in a policy
    // document, so it is a contract rather than whatever the constant happens to hold.
    assert.equal(BUILT_IN_PACK_NAME, "code-guardian-core");
    assert.equal(BUILT_IN_PACK_VERSION, "1");
    assert.equal(BUILT_IN_PACK_REFERENCE, "code-guardian-core@1");
    assert.equal(POLICY_PACK_ORIGINS.BUILT_IN, "built-in");
  });

  it("states the pack contract as a closed schema", () => {
    // The field list is a contract, not documentation: a pack stating anything else is refused.
    assert.deepEqual(POLICY_PACK_FIELDS, ["name", "version", "origin", "title", "purpose", "presets"]);
    assert.deepEqual(POLICY_PRESET_DEFINITION_FIELDS, ["name", "purpose", "document"]);
    assert.equal(POLICY_PACK_ERROR_CODE, "POLICY_PACK_ERROR");
    assert.equal(POLICY_PACK_ERROR_KINDS.DUPLICATE_PACK, "duplicate-pack");
    assert.equal(POLICY_PACK_ERROR_KINDS.INVALID_PACK, "invalid-pack");
    // Every bound is pinned literally, because it is the bound a caller validates against: a limit
    // raised quietly would accept a pack this build says it does not hold.
    assert.deepEqual(POLICY_PACK_LIMITS, {
      maxPacks: 32,
      maxVersionsPerPack: 16,
      maxPresetsPerPack: POLICY_PRESET_LIMITS.maxPresets,
      maxPackNameLength: 32,
      maxPackVersionLength: 16,
      maxTitleLength: 80,
      maxPurposeLength: POLICY_PRESET_LIMITS.maxPurposeLength,
      maxDetailLength: 48,
    });
    assert.equal(Object.isFrozen(POLICY_PACK_LIMITS), true);
    assert.equal(POLICY_PACK_REFERENCE_SEPARATOR, "@");
    assert.equal(POLICY_PACK_PRESET_SEPARATOR, ":");
    assert.equal(packReference("company-core", "1"), "company-core@1");
    assert.equal(packPresetReference("company-core", "1", "web-production"), "company-core@1:web-production");
    assert.equal(packPresetReference(BUILT_IN_PACK_NAME, BUILT_IN_PACK_VERSION, "web-production"), BUILT_IN_PACK_REFERENCE + ":web-production");
  });

  it("carries the built-in presets unchanged, as complete documents", () => {
    // Phase 24 must not restate a single requirement: the pack wraps the Phase 23 definitions, so
    // there is nothing here that could disagree with them.
    assert.deepEqual(BUILT_IN_PACK.presets, [...BUILT_IN_PRESETS]);
    for (const preset of BUILT_IN_PACK.presets) {
      assert.deepEqual(presetDefinitionIssues(preset), [], preset.name);
    }
  });

  it("refuses a pack whose name, version or origin is outside the vocabulary", () => {
    for (const name of [undefined, null, "", 7, "Company-Core", "-core", "core_2", "__proto__", "hasOwnProperty", "a".repeat(POLICY_PACK_LIMITS.maxPackNameLength + 1)]) {
      assert.equal(packDefinitionIssues(packOf({ name })).length > 0, true, String(name));
    }
    for (const version of [undefined, null, "", 1, "latest", "1.0.0-beta", "*", "1..2", "^1", "1".repeat(POLICY_PACK_LIMITS.maxPackVersionLength + 1)]) {
      assert.equal(packDefinitionIssues(packOf({ version })).length > 0, true, String(version));
    }
    assert.equal(packDefinitionIssues(packOf({ origin: "vendor" })).length > 0, true);
    assert.equal(packDefinitionIssues(packOf({ origin: undefined })).length > 0, true);
    assert.equal(packDefinitionIssues(packOf({ title: "" })).length > 0, true);
    assert.equal(packDefinitionIssues(packOf({ title: "t".repeat(POLICY_PACK_LIMITS.maxTitleLength + 1) })).length > 0, true);
    assert.equal(packDefinitionIssues(packOf({ purpose: "p".repeat(POLICY_PACK_LIMITS.maxPurposeLength + 1) })).length > 0, true);
    assert.equal(packDefinitionIssues(null).length > 0, true);
    assert.equal(packDefinitionIssues([]).length > 0, true);
    assert.equal(packDefinitionIssues("pack").length > 0, true);
  });

  it("refuses a pack that states an undeclared field", () => {
    const withExtra = packOf({ extends: "./other.json" });
    const issues = packDefinitionIssues(withExtra);
    assert.equal(issues.some((issue) => issue.includes("extends")), true);
    // The declaration is closed in both directions: every declared field is required too.
    for (const field of POLICY_PACK_FIELDS) {
      const missing = packOf();
      delete missing[field];
      assert.equal(
        packDefinitionIssues(missing).some((issue) => issue.includes(`.${field}: is required`)),
        true,
        field,
      );
    }
  });

  it("refuses a pack whose reference disagrees with its own name and version", () => {
    assert.equal(packDefinitionIssues({ ...packOf(), reference: "other@9" }).length > 0, true);
    assert.deepEqual(packDefinitionIssues({ ...packOf(), reference: packReference("company-core", "1") }), []);
  });

  it("refuses a pack whose presets are malformed, incomplete or duplicated", () => {
    assert.equal(packDefinitionIssues(packOf({ presets: [] })).length > 0, true);
    assert.equal(packDefinitionIssues(packOf({ presets: "web-production" })).length > 0, true);
    assert.equal(packDefinitionIssues(packOf({ presets: [() => {}] })).length > 0, true);
    assert.equal(packDefinitionIssues(packOf({ presets: [null] })).length > 0, true);
    // An incomplete document: every built-in preset must state every declared key.
    const partial = presetOf("web-production");
    delete partial.document.ci.requireLintForRelease;
    assert.equal(packDefinitionIssues(packOf({ presets: [partial] })).length > 0, true);
    // A value of the wrong type.
    const wrongType = presetOf("web-production");
    wrongType.document.container.requireHealthcheck = "yes";
    assert.equal(packDefinitionIssues(packOf({ presets: [wrongType] })).length > 0, true);
    // Two presets under one name would make `get` order-dependent.
    const duplicated = packOf({ presets: [presetOf("web-production"), presetOf("web-production")] });
    assert.equal(
      packDefinitionIssues(duplicated).some((issue) => issue.includes("declared twice")),
      true,
    );
    // More presets than the contract holds. The names are distinct on purpose: a list of one name
    // repeated would be refused for the duplication and the bound would never be the reason.
    assert.equal(
      packDefinitionIssues(
        packOf({
          presets: Array.from({ length: POLICY_PACK_LIMITS.maxPresetsPerPack + 1 }, (_, index) => ({
            ...presetOf("minimal"),
            name: `preset-${index}`,
          })),
        }),
      ).length > 0,
      true,
    );
  });

  it("refuses an unknown preset key and an unknown domain inside a preset", () => {
    const unknownKey = presetOf("web-production");
    unknownKey.document.container.somethingElse = true;
    assert.equal(presetDefinitionIssues(unknownKey).length > 0, true);

    const unknownDomain = presetOf("web-production");
    unknownDomain.document.plugins = {};
    assert.equal(presetDefinitionIssues(unknownDomain).length > 0, true);

    // A preset is not a place to smuggle metadata either: inside a pack its fields are closed to
    // `name`, `purpose` and `document`, so an extra field is refused with the pack that carries it.
    const smuggled = packOf({ presets: [{ ...presetOf("minimal"), version: "1" }] });
    assert.equal(
      packDefinitionIssues(smuggled).some((issue) => issue.includes("is not a declared preset field")),
      true,
    );
  });
});

// ─── Registry ────────────────────────────────────────────────────────────────

describe("policy pack registry", () => {
  it("registers a valid pack and answers for exactly its reference", () => {
    const registry = createPolicyPackRegistry({ packs: [BUILT_IN_PACK, businessPack()] });
    assert.equal(registry.size, 2);
    assert.equal(registry.has("business-core", "1"), true);
    assert.equal(registry.has("business-core", "2"), false);
    assert.equal(registry.has("business-core"), false);
    assert.equal(registry.get("business-core", "1").reference, "business-core@1");
    assert.deepEqual(registry.get("business-core", "1").presets, ["web-production"]);
    // The preset names a pack record carries are sorted, and the built-in pack's declared order is
    // not sorted — so the two differ and this is a real check rather than an accident of order.
    const declaredOrder = BUILT_IN_PRESETS.map((preset) => preset.name);
    const sortedOrder = [...declaredOrder].sort();
    assert.notDeepEqual(declaredOrder, sortedOrder);
    assert.deepEqual(
      registry.get(BUILT_IN_PACK_NAME, BUILT_IN_PACK_VERSION).presets,
      sortedOrder,
    );
    assert.equal(registry.get("business-core", "2"), null);
    assert.equal(registry.get("nope-core", "1"), null);
    assert.equal(registry.presetRegistry("business-core", "1").has("web-production"), true);
    assert.equal(registry.presetRegistry("business-core", "2"), null);
    assert.equal(registry.isReference("business-core@1"), true);
    assert.equal(registry.isReference("business-core"), false);
  });

  it("orders names, versions and references deterministically", () => {
    const forward = createPolicyPackRegistry({ packs: [BUILT_IN_PACK, businessPack()] });
    const reversed = createPolicyPackRegistry({ packs: [businessPack(), BUILT_IN_PACK] });
    assert.deepEqual(forward.names, ["business-core", "code-guardian-core"]);
    assert.deepEqual(reversed.names, forward.names);
    assert.deepEqual(reversed.references, forward.references);
    assert.deepEqual(
      forward.list().map((pack) => pack.reference),
      ["business-core@1", "code-guardian-core@1"],
    );
    // Two versions of one pack sort by version, whatever order they were registered in.
    const versions = createPolicyPackRegistry({
      packs: [packOf({ version: "2" }), packOf({ version: "1" })],
    });
    assert.deepEqual(versions.versions("company-core"), ["1", "2"]);
    assert.deepEqual(versions.names, ["company-core"]);
  });

  it("refuses a duplicate pack and a duplicate version, as whole registries", () => {
    assert.throws(
      () => createPolicyPackRegistry({ packs: [BUILT_IN_PACK, BUILT_IN_PACK] }),
      (error) => error instanceof PolicyPackError && error.kind === POLICY_PACK_ERROR_KINDS.DUPLICATE_PACK,
    );
    // Two *versions* of one name are two references, and both are registrable — a duplicate is one
    // reference twice, never one name twice.
    const both = createPolicyPackRegistry({ packs: [packOf({ version: "1" }), packOf({ version: "2" })] });
    assert.equal(both.size, 2);
    assert.throws(
      () => createPolicyPackRegistry({ packs: [packOf({ version: "1" }), packOf({ version: "1" })] }),
      (error) => error.kind === POLICY_PACK_ERROR_KINDS.DUPLICATE_PACK,
    );
  });

  it("refuses a malformed pack as a whole, and never registers part of one", () => {
    assert.throws(
      () => createPolicyPackRegistry({ packs: [packOf({ presets: [] })] }),
      (error) => error instanceof PolicyPackError && error.kind === POLICY_PACK_ERROR_KINDS.INVALID_PACK,
    );
    assert.throws(() => createPolicyPackRegistry({ packs: "packs" }), PolicyPackError);
    // Distinct names, so the count is the reason and not a duplicate reference.
    assert.throws(
      () =>
        createPolicyPackRegistry({
          packs: Array.from({ length: POLICY_PACK_LIMITS.maxPacks + 1 }, (_, index) =>
            packOf({ name: `company-core-${index}` }),
          ),
        }),
      PolicyPackError,
    );
    assert.throws(
      () =>
        createPolicyPackRegistry({
          packs: [BUILT_IN_PACK, packOf({ presets: [presetOf("web-production"), presetOf("web-production")] })],
        }),
      PolicyPackError,
    );
    // The failure names the pack it refused, so a caller can act on it.
    try {
      createPolicyPackRegistry({ packs: [packOf({ origin: "vendor" })] });
      assert.fail("must refuse a pack with an unknown origin");
    } catch (error) {
      assert.equal(error.detail, "company-core");
      assert.equal(error.code, "POLICY_PACK_ERROR");
    }
  });

  it("refuses more versions of one name than the contract holds", () => {
    assert.throws(
      () =>
        createPolicyPackRegistry({
          packs: Array.from({ length: POLICY_PACK_LIMITS.maxVersionsPerPack + 1 }, (_, index) =>
            packOf({ version: String(index + 1) }),
          ),
        }),
      PolicyPackError,
    );
  });

  it("is deeply immutable: no registry, pack, preset or list can be changed", () => {
    const registry = twoPackRegistry();
    assert.equal(Object.isFrozen(registry), true);
    assert.equal(Object.isFrozen(registry.names), true);
    assert.equal(Object.isFrozen(registry.references), true);
    assert.equal(Object.isFrozen(registry.versions("business-core")), true);
    assert.equal(Object.isFrozen(registry.get("business-core", "1")), true);
    assert.equal(Object.isFrozen(registry.get("business-core", "1").presets), true);
    assert.equal(Object.isFrozen(registry.describe("business-core", "1")), true);
    assert.equal(Object.isFrozen(registry.list()), true);
    assert.equal(Object.isFrozen(registry.presetRegistry("business-core", "1")), true);
    assert.equal(
      Object.isFrozen(registry.presetRegistry("business-core", "1").get("web-production").document.container),
      true,
    );

    for (const attempt of [
      () => {
        registry.size = 99;
      },
      () => {
        registry.names.push("forged");
      },
      () => {
        registry.references.length = 0;
      },
      () => {
        registry.get("business-core", "1").name = "forged";
      },
      () => {
        registry.get("business-core", "1").presets.push("forged");
      },
      () => {
        registry.presetRegistry("business-core", "1").get("web-production").document.container.requireHealthcheck = false;
      },
    ]) {
      assert.throws(attempt, TypeError);
    }
    // The registry handle exposes no mutation operation at all.
    for (const forbidden of ["add", "set", "register", "delete", "remove", "clear", "push"]) {
      assert.equal(typeof registry[forbidden], "undefined", forbidden);
    }
  });

  it("copies the pack it was handed, so a later mutation cannot reach it", () => {
    const definition = packOf();
    const registry = createPolicyPackRegistry({ packs: [definition] });
    const before = resolvePackPolicyDocument({ document: { preset: "company-core@1:web-production" }, packs: registry });
    // The caller's object is theirs, and mutating it after registration changes nothing: the registry
    // validated and registered a copy.
    definition.presets.push(presetOf("minimal"));
    definition.presets[0].document.container.requireHealthcheck = false;
    definition.presets[0].document.ci.maxReleaseWorkflows = 99;
    definition.name = "forged-core";
    assert.equal(registry.get("company-core", "1").name, "company-core");
    assert.equal(registry.get("forged-core", "1"), null);
    assert.deepEqual(registry.get("company-core", "1").presets, ["web-production"]);
    assert.equal(registry.presetRegistry("company-core", "1").has("minimal"), false);
    assert.equal(
      registry.presetRegistry("company-core", "1").get("web-production").document.container.requireHealthcheck,
      true,
    );
    const after = resolvePackPolicyDocument({ document: { preset: "company-core@1:web-production" }, packs: registry });
    assert.deepEqual(after.effective, before.effective);
    assert.equal(after.effective.container.requireHealthcheck, true);
    assert.equal(after.effective.ci.maxReleaseWorkflows, 5);
  });

  it("holds the registered pack frozen, whatever the caller does with its own copy", () => {
    const registry = twoPackRegistry();
    assert.equal(Object.isFrozen(registry.get("business-core", "1")), true);
    assert.equal(
      Object.isFrozen(registry.presetRegistry("business-core", "1").get("web-production").document.ci),
      true,
    );
    assert.throws(() => {
      registry.presetRegistry("business-core", "1").get("web-production").document.ci.maxReleaseWorkflows = 99;
    }, TypeError);
  });

  it("copies every field once, so a getter cannot change an answer", () => {
    // A pack whose `title` is read twice would be non-deterministic if the layer kept the caller's
    // object. It does not: the registry copies each field into its own frozen record.
    let reads = 0;
    const definition = packOf();
    Object.defineProperty(definition, "title", {
      enumerable: true,
      configurable: true,
      get() {
        reads += 1;
        return reads === 1 ? "first title" : "second title";
      },
    });
    const registry = createPolicyPackRegistry({ packs: [definition] });
    assert.equal(registry.describe("company-core", "1").title, "first title");
    assert.equal(registry.describe("company-core", "1").title, "first title");
    const first = resolvePackPolicyDocument({ document: { preset: "company-core@1:web-production" }, packs: registry });
    const second = resolvePackPolicyDocument({ document: { preset: "company-core@1:web-production" }, packs: registry });
    assert.deepEqual(first.effective, second.effective);
    assert.deepEqual(first.provenance, second.provenance);
  });

  it("holds no function anywhere: a pack is data", () => {
    const registry = twoPackRegistry();
    walk(
      {
        registry: registry.list(),
        pack: registry.get("business-core", "1"),
        document: registry.presetRegistry("business-core", "1").get("web-production").document,
      },
      (value) => {
        assert.notEqual(typeof value, "function");
      },
    );
    // A pack survives a JSON round trip unchanged, which a value carrying behaviour could not.
    assert.deepEqual(JSON.parse(JSON.stringify(BUILT_IN_PACK)), clone(BUILT_IN_PACK));
    assert.equal(typeof freezePack, "function");
  });
});

// ─── Reference grammar ───────────────────────────────────────────────────────

describe("policy reference grammar", () => {
  it("reads a bare preset name as the built-in pack, pinned by this build", () => {
    for (const name of ["minimal", "web-production", "backend-service", "library", "strict"]) {
      const parsed = parsePresetReference(name);
      assert.deepEqual(parsed, { ok: true, presetName: name, packName: null, packVersion: null, explicit: false }, name);
    }
  });

  it("reads an explicitly qualified pack, with and without a pinned version", () => {
    assert.deepEqual(parsePresetReference("company-core@1:web-production"), {
      ok: true,
      presetName: "web-production",
      packName: "company-core",
      packVersion: "1",
      explicit: true,
    });
    assert.deepEqual(parsePresetReference("company-core:web-production"), {
      ok: true,
      presetName: "web-production",
      packName: "company-core",
      packVersion: null,
      explicit: true,
    });
    assert.deepEqual(parsePresetReference(`${BUILT_IN_PACK_NAME}@1:strict`), {
      ok: true,
      presetName: "strict",
      packName: BUILT_IN_PACK_NAME,
      packVersion: "1",
      explicit: true,
    });
  });

  it("refuses a malformed pack reference without guessing at one", () => {
    const malformed = [
      "company-core@1:",
      ":web-production",
      "company-core@:web-production",
      "company-core@1:web-production:extra",
      "company-core@1@2:web-production",
      "Company-Core@1:web-production",
      "company-core@latest:web-production",
      "company-core@1:web production",
      "company-core@1:Web-Production",
      "company-core@1:minimal:x",
      "a@1:" + "p".repeat(120),
      "company-core@1" + "0".repeat(200),
      "@1:web-production",
    ];
    for (const reference of malformed) {
      const parsed = parsePresetReference(reference);
      assert.equal(parsed.ok, false, reference);
      assert.equal(parsed.reason, POLICY_RESOLUTION_FAILURES.PACK_REFERENCE_NOT_ESTABLISHED, reference);
      assert.equal(typeof parsed.detail === "string", true, reference);
      assert.equal(parsed.detail.length <= POLICY_PACK_LIMITS.maxDetailLength, true, reference);
    }
  });

  it("treats a lone pack name or pack reference as an unknown preset selection", () => {
    // A pack name without a preset selects nothing, so it is read as the preset name it looks like —
    // and refused, because no preset is called that.
    const lone = parsePresetReference(BUILT_IN_PACK_NAME);
    assert.equal(lone.ok, true);
    assert.equal(lone.explicit, false);
    // A pack *reference* with no preset is a pack selection that selects no policy.
    const bare = parsePresetReference(`${BUILT_IN_PACK_NAME}@1`);
    assert.equal(bare.ok, false);
    assert.equal(bare.reason, POLICY_RESOLUTION_FAILURES.PACK_REFERENCE_NOT_ESTABLISHED);
  });

  it("refuses a reference that is not a string, or is empty", () => {
    for (const value of [undefined, null, 7, true, {}, [], () => {}, ""]) {
      const parsed = parsePresetReference(value);
      assert.equal(parsed.ok, false);
      assert.equal(parsed.reason, POLICY_RESOLUTION_FAILURES.PRESET_NOT_ESTABLISHED);
      assert.equal(parsed.detail, null);
    }
  });

  it("refuses a bare name that is not a well-formed preset name", () => {
    // A single token is read as a preset name, so it must *be* one — whatever else it might be, it
    // is not a pack reference the repository qualified.
    for (const value of ["Web Production", "web production", "-leading", "Plan", "plan!", "plan/name", "p".repeat(200)]) {
      const parsed = parsePresetReference(value);
      assert.equal(parsed.ok, false, value);
      assert.equal(parsed.reason, POLICY_RESOLUTION_FAILURES.PRESET_NOT_ESTABLISHED, value);
      assert.equal(typeof parsed.detail === "string", true, value);
      assert.equal(parsed.detail.length <= POLICY_PACK_LIMITS.maxDetailLength, true, value);
    }
  });

  it("bounds every part of an identity", () => {
    assert.equal(isPackName("code-guardian-core"), true);
    assert.equal(isPackName("code_guardian"), false);
    assert.equal(isPackName("a".repeat(POLICY_PACK_LIMITS.maxPackNameLength + 1)), false);
    assert.equal(isPackVersion("1"), true);
    assert.equal(isPackVersion("1.2.3"), true);
    assert.equal(isPackVersion("1."), false);
    assert.equal(isPackVersion("01"), true);
    assert.equal(isPackReference("code-guardian-core@1"), true);
    assert.equal(isPackReference("code-guardian-core@"), false);
    assert.equal(isPackReference("code-guardian-core"), false);
    assert.equal(isPackReference("a".repeat(POLICY_PACK_LIMITS.maxPackNameLength + 1) + "@1"), false);
    assert.equal(
      isPackReference(`code-guardian-core@${"1".repeat(POLICY_PACK_LIMITS.maxPackVersionLength + 1)}`),
      false,
    );
    assert.equal(isPackReference(7), false);
    assert.equal(isPresetName("web-production"), true);
  });

  it("names a closed resolution vocabulary", () => {
    assert.ok(POLICY_RESOLUTION_FAILURE_VALUES.length >= 7);
    for (const value of [
      "preset-not-established",
      "version-not-supported",
      "document-not-interpreted",
      "pack-reference-not-established",
      "pack-not-established",
      "pack-version-not-established",
      "pack-preset-not-established",
    ]) {
      assert.equal(POLICY_RESOLUTION_FAILURE_VALUES.includes(value), true, value);
    }
  });
});

// ─── Resolution ──────────────────────────────────────────────────────────────

describe("policy pack resolution", () => {
  it("resolves every built-in preset through the built-in pack", () => {
    for (const preset of BUILT_IN_PRESETS) {
      const selected = resolvePackPreset({ reference: preset.name });
      assert.equal(selected.ok, true, preset.name);
      assert.equal(selected.pack.reference, BUILT_IN_PACK_REFERENCE);
      assert.equal(selected.explicit, false);
      assert.equal(selected.presetName, preset.name);
      assert.equal(selected.reference, `${BUILT_IN_PACK_REFERENCE}:${preset.name}`);
      const resolution = resolvePackPolicyDocument({ document: { preset: preset.name } });
      assert.deepEqual(resolution.effective, clone(preset.document));
      assert.deepEqual(resolution.pack, {
        name: BUILT_IN_PACK_NAME,
        version: BUILT_IN_PACK_VERSION,
        origin: POLICY_PACK_ORIGINS.BUILT_IN,
        reference: BUILT_IN_PACK_REFERENCE,
        explicit: false,
        preset: preset.name,
      });
    }
  });

  it("preserves the Phase 23 short-name behavior exactly", () => {
    // The same input, resolved through the Phase 23 engine and through the pack layer: the effective
    // document, the declared document and the per-key sources are identical.
    for (const document of [
      { version: "1", preset: "web-production" },
      { preset: "strict", ci: { maxReleaseWorkflows: 4 } },
      { preset: "library", api: { requireResolvedMiddleware: true } },
    ]) {
      const legacy = resolvePolicyDocument({ document });
      const packed = resolvePackPolicyDocument({ document });
      assert.equal(legacy.ok, true, JSON.stringify(document));
      assert.equal(packed.ok, true, JSON.stringify(document));
      assert.deepEqual(packed.effective, legacy.effective);
      assert.deepEqual(packed.declared, legacy.declared);
      assert.deepEqual(packed.preset, legacy.preset);
      assert.deepEqual(packed.provenance.sources, legacy.provenance.sources);
      assert.deepEqual(packed.provenance.inherited, legacy.provenance.inherited);
      assert.deepEqual(packed.provenance.overridden, legacy.provenance.overridden);
      // The only difference is the identity the pack layer adds.
      assert.equal(packed.provenance.pack, BUILT_IN_PACK_REFERENCE);
      assert.equal(legacy.provenance.pack, undefined);
    }
  });

  it("resolves a repository that names no preset into exactly what it declared", () => {
    const resolution = resolvePackPolicyDocument({
      document: { version: "1", container: { requireHealthcheck: true } },
    });
    assert.equal(resolution.ok, true);
    assert.deepEqual(resolution.effective, { container: { requireHealthcheck: true } });
    assert.equal(resolution.preset, null);
    assert.equal(resolution.pack, null);
    assert.equal(resolution.provenance.pack, null);
    assert.equal(resolution.provenance.preset, null);
    assert.deepEqual(resolution.provenance.inherited, []);
    assert.deepEqual(resolution.provenance.sources, { "container.requireHealthcheck": "user" });
  });

  it("resolves a pack-qualified reference, and keeps the declaration as it was written", () => {
    const packs = twoPackRegistry();
    const reference = "business-core@1:web-production";
    const resolution = resolvePackPolicyDocument({ document: { preset: reference }, packs });
    assert.equal(resolution.ok, true);
    assert.equal(resolution.pack.name, "business-core");
    assert.equal(resolution.pack.version, "1");
    assert.equal(resolution.pack.explicit, true);
    assert.equal(resolution.pack.preset, "web-production");
    assert.equal(resolution.effective.ci.maxReleaseWorkflows, 7);
    // The declaration is what the repository wrote, not this build's normalization of it.
    assert.deepEqual(resolution.declared, { version: "1", preset: reference });
    assert.equal(resolution.provenance.pack, "business-core@1");
    assert.equal(resolution.provenance.preset, "web-production");
    assert.equal(resolution.provenance.sources["ci.maxReleaseWorkflows"], presetSource("web-production"));
  });

  it("resolves a repository override on top of a pack-qualified preset", () => {
    const packs = twoPackRegistry();
    const resolution = resolvePackPolicyDocument({
      document: {
        preset: "business-core@1:web-production",
        ci: { maxReleaseWorkflows: 2 },
      },
      packs,
    });
    assert.equal(resolution.effective.ci.maxReleaseWorkflows, 2);
    assert.equal(resolution.provenance.sources["ci.maxReleaseWorkflows"], "user");
    assert.deepEqual(resolution.provenance.overridden, ["ci.maxReleaseWorkflows"]);
    assert.equal(resolution.provenance.inherited.includes("ci.requireTestsForRelease"), true);
  });

  it("resolves a pack named without a version only when that is unambiguous", () => {
    const single = twoPackRegistry();
    const resolved = resolvePackPolicyDocument({ document: { preset: "business-core:web-production" }, packs: single });
    assert.equal(resolved.ok, true);
    assert.equal(resolved.pack.version, "1");

    const twoVersions = createPolicyPackRegistry({ packs: [packOf({ version: "1" }), packOf({ version: "2" })] });
    const ambiguous = resolvePackPolicyDocument({ document: { preset: "company-core:web-production" }, packs: twoVersions });
    assert.equal(ambiguous.ok, false);
    assert.equal(ambiguous.reason, POLICY_RESOLUTION_FAILURES.PACK_VERSION_NOT_ESTABLISHED);
    // Naming the version resolves it, and names exactly that one.
    const pinned = resolvePackPolicyDocument({ document: { preset: "company-core@2:web-production" }, packs: twoVersions });
    assert.equal(pinned.ok, true);
    assert.equal(pinned.pack.version, "2");
  });

  it("refuses an unknown pack, an unknown version and an unknown preset in it", () => {
    const packs = twoPackRegistry();
    const unknownPack = resolvePackPolicyDocument({ document: { preset: "nope-core@1:web-production" }, packs });
    assert.equal(unknownPack.ok, false);
    assert.equal(unknownPack.reason, POLICY_RESOLUTION_FAILURES.PACK_NOT_ESTABLISHED);
    assert.equal(unknownPack.detail, "nope-core@1:web-production");

    const unknownVersion = resolvePackPolicyDocument({ document: { preset: "business-core@9:web-production" }, packs });
    assert.equal(unknownVersion.ok, false);
    assert.equal(unknownVersion.reason, POLICY_RESOLUTION_FAILURES.PACK_VERSION_NOT_ESTABLISHED);

    const unknownPreset = resolvePackPolicyDocument({ document: { preset: "business-core@1:nope" }, packs });
    assert.equal(unknownPreset.ok, false);
    assert.equal(unknownPreset.reason, POLICY_RESOLUTION_FAILURES.PACK_PRESET_NOT_ESTABLISHED);
    // A qualified reference reports the reference the repository wrote, so the author can see which
    // pack was asked and which preset it does not declare.
    assert.equal(unknownPreset.detail, "business-core@1:nope");
  });

  it("never falls back to another pack, in either direction", () => {
    const packs = twoPackRegistry();
    // The built-in pack declares `minimal`; the business pack does not. Asking the business pack for
    // it must refuse rather than quietly reaching the built-in one.
    const missing = resolvePackPolicyDocument({ document: { preset: "business-core@1:minimal" }, packs });
    assert.equal(missing.ok, false);
    assert.equal(missing.reason, POLICY_RESOLUTION_FAILURES.PACK_PRESET_NOT_ESTABLISHED);

    // And the other direction: a preset only a *different* pack declares is not reachable from a bare
    // name, because a bare name is this build's pack and nothing else.
    const businessOnly = {
      ...presetOf("web-production"),
      name: "business-only",
    };
    const custom = createPolicyPackRegistry({
      packs: [BUILT_IN_PACK, packOf({ name: "business-core", presets: [businessOnly] })],
    });
    const other = resolvePackPolicyDocument({ document: { preset: "business-only" }, packs: custom });
    assert.equal(other.ok, false);
    assert.equal(other.reason, POLICY_RESOLUTION_FAILURES.PRESET_NOT_ESTABLISHED);
    // The pack that declares it answers for it, and only when it is named.
    assert.equal(
      resolvePackPolicyDocument({ document: { preset: "business-core@1:business-only" }, packs: custom }).ok,
      true,
    );

    // A bare name is *this build's* pack even when another pack declares the same name.
    const bare = resolvePackPolicyDocument({ document: { preset: "web-production", ci: { maxReleaseWorkflows: 5 } }, packs });
    assert.equal(bare.ok, true);
    assert.equal(bare.pack.name, BUILT_IN_PACK_NAME);
    assert.equal(bare.effective.ci.maxReleaseWorkflows, 5);
    const qualified = resolvePackPolicyDocument({ document: { preset: "business-core@1:web-production" }, packs });
    assert.equal(qualified.effective.ci.maxReleaseWorkflows, 7);
  });

  it("refuses an unknown preset with the reading Phase 23 published, pack and all", () => {
    const bare = resolvePackPolicyDocument({ document: { preset: "nope" } });
    assert.equal(bare.ok, false);
    assert.equal(bare.reason, POLICY_RESOLUTION_FAILURES.PRESET_NOT_ESTABLISHED);
    assert.equal(bare.detail, "nope");

    // A registry that does not hold the built-in pack cannot answer a bare name at all — it is not a
    // reason to look in whichever pack happens to be registered.
    const other = createPolicyPackRegistry({ packs: [businessPack()] });
    const impossible = resolvePackPolicyDocument({ document: { preset: "web-production" }, packs: other });
    assert.equal(impossible.ok, false);
    assert.equal(impossible.reason, POLICY_RESOLUTION_FAILURES.PRESET_NOT_ESTABLISHED);
  });

  it("refuses a document pinning another version, or that is not a document", () => {
    for (const document of [null, 7, [], "policy", () => {}]) {
      const resolution = resolvePackPolicyDocument({ document });
      assert.equal(resolution.ok, false);
      assert.equal(resolution.reason, POLICY_RESOLUTION_FAILURES.DOCUMENT_NOT_INTERPRETED);
    }
    const versioned = resolvePackPolicyDocument({ document: { version: "2", preset: "minimal" } });
    assert.equal(versioned.ok, false);
    assert.equal(versioned.reason, POLICY_RESOLUTION_FAILURES.VERSION_NOT_SUPPORTED);
    assert.equal(versioned.detail, "2");
  });

  it("resolves deterministically, whatever order the document was typed in", () => {
    const packs = twoPackRegistry();
    const one = resolvePackPolicyDocument({
      document: { preset: "business-core@1:web-production", api: { requireResolvedMiddleware: false } },
      packs,
    });
    const two = resolvePackPolicyDocument({
      document: { api: { requireResolvedMiddleware: false }, preset: "business-core@1:web-production" },
      packs,
    });
    assert.deepEqual(one.effective, two.effective);
    assert.deepEqual(one.provenance, two.provenance);
    assert.deepEqual(one.declared, two.declared);
    assert.deepEqual(one.pack, two.pack);
    assert.equal(JSON.stringify(one.effective), JSON.stringify(two.effective));
  });

  it("freezes every value it returns", () => {
    const resolution = resolvePackPolicyDocument({ document: { preset: "strict" } });
    assert.equal(Object.isFrozen(resolution), true);
    assert.equal(Object.isFrozen(resolution.effective), true);
    assert.equal(Object.isFrozen(resolution.effective.ci), true);
    assert.equal(Object.isFrozen(resolution.declared), true);
    assert.equal(Object.isFrozen(resolution.pack), true);
    assert.equal(Object.isFrozen(resolution.provenance), true);
    assert.equal(Object.isFrozen(resolution.provenance.sources), true);
    assert.equal(Object.isFrozen(resolution.provenance.inherited), true);
    assert.equal(Object.isFrozen(resolution.provenance.overridden), true);
    assert.throws(() => {
      resolution.provenance.sources["ci.requireLintForRelease"] = "user";
    }, TypeError);
    assert.throws(() => {
      resolution.pack.explicit = true;
    }, TypeError);
  });

  it("re-resolving a published pack resolution reproduces it, or reports what differs", () => {
    const resolution = resolvePackPolicyDocument({ document: { preset: "web-production", ci: { maxReleaseWorkflows: 3 } } });
    assert.deepEqual(
      packPolicyIssues({
        declared: resolution.declared,
        effective: resolution.effective,
        provenance: resolution.provenance,
        pack: resolution.pack,
      }),
      [],
    );
    assert.equal(
      packPolicyIssues({
        declared: resolution.declared,
        effective: resolution.effective,
        provenance: resolution.provenance,
        pack: { ...resolution.pack, reference: "other@9" },
      }).some((issue) => issue.startsWith("pack:")),
      true,
    );
    assert.equal(
      packPolicyIssues({
        declared: resolution.declared,
        effective: resolution.effective,
        provenance: resolution.provenance,
        pack: { ...resolution.pack, explicit: true },
      }).some((issue) => issue.startsWith("pack:")),
      true,
    );
    assert.equal(
      packPolicyIssues({
        declared: resolution.declared,
        effective: resolution.effective,
        provenance: resolution.provenance,
        pack: null,
      }).some((issue) => issue.startsWith("pack:")),
      true,
    );
    assert.equal(
      packPolicyIssues({
        declared: { preset: "nope" },
        effective: resolution.effective,
        provenance: resolution.provenance,
        pack: resolution.pack,
      }).some((issue) => issue.startsWith("declared:")),
      true,
    );
  });

  it("keeps every effective value traceable to a pack, a version and a preset", () => {
    const packs = twoPackRegistry();
    const resolution = resolvePackPolicyDocument({
      document: { preset: "business-core@1:web-production", api: { requireResolvedMiddleware: false } },
      packs,
    });
    // One pack governs one document, so the pack answers for every inherited key.
    assert.equal(resolution.provenance.pack, "business-core@1");
    assert.equal(resolution.pack.reference, resolution.provenance.pack);
    assert.equal(resolution.provenance.preset, "web-production");
    for (const id of resolution.provenance.inherited) {
      assert.equal(isPresetSource(resolution.provenance.sources[id]), true, id);
      assert.equal(resolution.provenance.sources[id], presetSource("web-production"), id);
    }
    // A name is unique only inside a pack, so the identity needs all three parts.
    assert.equal(
      `${resolution.provenance.pack}${POLICY_PACK_PRESET_SEPARATOR}${resolution.provenance.preset}`,
      resolvePackPreset({ reference: "business-core@1:web-production", packs }).reference,
    );
  });
});

// ─── Model integration ───────────────────────────────────────────────────────

describe("model: policy pack integration", () => {
  it("resolves a pack-qualified document end to end", async () => {
    const reference = `${BUILT_IN_PACK_NAME}@${BUILT_IN_PACK_VERSION}:web-production`;
    const { scan, model, policy, query } = await scanOf({
      ...policyFile({ preset: reference }),
      "package.json": pkg(),
    });
    // 1. acquisition — the reference is a bounded string and nothing more.
    assert.equal(scan.policy.status, POLICY_SOURCE_STATUSES.PARSED);
    assert.equal(scan.policy.document.preset, reference);
    // 2. model — the effective document is the preset's, and what was declared is still readable.
    assert.equal(policy.state, POLICY_STATES.ESTABLISHED);
    assert.deepEqual(policy.declared, { version: "1", preset: reference });
    assert.deepEqual(policy.document, documentOf("web-production"));
    assert.deepEqual(policy.preset, { name: "web-production", version: "1", origin: "built-in" });
    assert.deepEqual(policy.pack, {
      name: BUILT_IN_PACK_NAME,
      version: BUILT_IN_PACK_VERSION,
      origin: "built-in",
      reference: BUILT_IN_PACK_REFERENCE,
      explicit: true,
      preset: "web-production",
    });
    assert.equal(policy.provenance.pack, BUILT_IN_PACK_REFERENCE);
    // 3. the whole model still satisfies its own contract.
    assert.equal(validateRepositoryModelGraph(model), model);
    assert.equal(query.policyPack().explicit, true);
  });

  it("reads a bare preset name as this build's own pack, implicitly", async () => {
    const { policy, query } = await scanOf({ ...policyFile({ preset: "backend-service" }), "package.json": pkg() });
    assert.deepEqual(policy.pack, {
      name: BUILT_IN_PACK_NAME,
      version: BUILT_IN_PACK_VERSION,
      origin: "built-in",
      reference: BUILT_IN_PACK_REFERENCE,
      explicit: false,
      preset: "backend-service",
    });
    // The declaration is the bare name the repository wrote.
    assert.equal(policy.declared.preset, "backend-service");
    assert.equal(query.policyPack().explicit, false);
    assert.equal(query.policyPack().preset, "backend-service");
  });

  it("carries no pack at all for a policy that names none", async () => {
    const { policy, query } = await scanOf({
      ...policyFile({ container: { requireHealthcheck: true } }),
      "package.json": pkg(),
    });
    assert.equal(policy.pack, null);
    assert.equal(policy.provenance.pack, null);
    assert.deepEqual(query.policyPack(), {
      active: false,
      name: null,
      version: null,
      origin: null,
      reference: null,
      explicit: false,
      preset: null,
    });
    assert.equal(query.policyProvenance().pack, null);
  });

  it("names the reason when a pack reference cannot be established", async () => {
    const cases = [
      [{ preset: "nope-core@1:web-production" }, POLICY_UNKNOWN_REASONS.PACK_NOT_ESTABLISHED],
      [{ preset: "code-guardian-core@9:web-production" }, POLICY_UNKNOWN_REASONS.PACK_VERSION_NOT_ESTABLISHED],
      [{ preset: "code-guardian-core@1:nope" }, POLICY_UNKNOWN_REASONS.PACK_PRESET_NOT_ESTABLISHED],
      [{ preset: "code-guardian-core@1:" }, POLICY_UNKNOWN_REASONS.PACK_REFERENCE_NOT_ESTABLISHED],
      [{ preset: "nope" }, POLICY_UNKNOWN_REASONS.PRESET_NOT_ESTABLISHED],
    ];
    for (const [document, reason] of cases) {
      const { policy, report, query } = await scanOf({ ...policyFile(document), "package.json": pkg() });
      assert.equal(policy.state, POLICY_STATES.UNKNOWN, JSON.stringify(document));
      assert.equal(policy.established, false);
      assert.equal(policy.document, null);
      assert.equal(policy.declared, null);
      assert.equal(policy.preset, null);
      assert.equal(policy.pack, null);
      assert.equal(policy.provenance, null);
      assert.equal(policy.coverage.reason, reason, JSON.stringify(document));
      assert.equal(policy.coverage.detail.length <= 48, true);
      // Never a partly-applied policy, and never a compliance answer over one.
      assert.equal(report.coverage.policyEstablished, false);
      assert.equal(query.policyPack().active, false);
      assert.equal(query.effectivePolicy(), null);
      assert.equal(query.policyProvenance(), null);
    }
  });

  it("rejects a hand-edited pack identity, effective policy or provenance", async () => {
    const { model } = await scanOf({ ...policyFile({ preset: "minimal" }), "package.json": pkg() });
    assert.equal(issuesOfValidate(model), null);

    // A pack named that never supplied the preset.
    const forgedName = clone(model);
    forgedName.policy.pack.name = "other-pack";
    assert.equal(issuesOfValidate(forgedName).some((issue) => issue.startsWith("policy.pack")), true);

    // A pack version that is not pinned.
    const forgedVersion = clone(model);
    forgedVersion.policy.pack.version = "latest";
    assert.equal(issuesOfValidate(forgedVersion).some((issue) => issue.startsWith("policy.pack")), true);

    // A reference that contradicts the pack's own identity.
    const forgedReference = clone(model);
    forgedReference.policy.pack.reference = "code-guardian-core@2";
    assert.equal(issuesOfValidate(forgedReference).some((issue) => issue.startsWith("policy.pack")), true);

    // Claiming the repository pinned a pack it named bare.
    const forgedExplicit = clone(model);
    forgedExplicit.policy.pack.explicit = true;
    assert.equal(issuesOfValidate(forgedExplicit).some((issue) => issue.startsWith("policy.pack")), true);

    // A pack that supplied a different preset than the rest of the model reports. The declaration is
    // patched to agree with the pack, so the disagreement really is between the pack and the applied
    // preset — and the contract names that field rather than reporting a general mismatch.
    const forgedPreset = clone(model);
    forgedPreset.policy.pack.preset = "strict";
    forgedPreset.policy.declared.preset = "code-guardian-core@1:strict";
    forgedPreset.policy.pack.explicit = true;
    assert.equal(
      issuesOfValidate(forgedPreset).includes("policy.pack.preset: must name the preset the pack supplied"),
      true,
    );

    // The pack dropped while the preset it supplied stays: the two are one fact.
    const forgedDrop = clone(model);
    forgedDrop.policy.pack = null;
    assert.equal(issuesOfValidate(forgedDrop).some((issue) => issue.startsWith("policy.pack")), true);

    // A pack invented for a policy that named none: a repository that resolved no preset has no pack
    // to name, and the model cannot be made to say it had one.
    const noPreset = await scanOf({
      ...policyFile({ container: { requireHealthcheck: true } }),
      "package.json": pkg(),
    });
    const forgedAdded = clone(noPreset.model);
    forgedAdded.policy.pack = {
      name: BUILT_IN_PACK_NAME,
      version: BUILT_IN_PACK_VERSION,
      origin: "built-in",
      reference: BUILT_IN_PACK_REFERENCE,
      explicit: false,
      preset: "minimal",
    };
    forgedAdded.policy.provenance.pack = BUILT_IN_PACK_REFERENCE;
    assert.equal(
      issuesOfValidate(forgedAdded).some((issue) => issue.startsWith("policy.pack")),
      true,
    );

    // A provenance whose pack was dropped entirely.
    const forgedProvenance = clone(model);
    delete forgedProvenance.policy.provenance.pack;
    assert.equal(
      issuesOfValidate(forgedProvenance).some((issue) => issue.includes("provenance")),
      true,
    );

    // A provenance naming a different pack than the rest of the model: the two are one fact, and the
    // contract names the field rather than reporting the derived mismatch underneath it.
    const forgedProvenancePack = clone(model);
    forgedProvenancePack.policy.provenance.pack = "other-pack@1";
    assert.equal(
      issuesOfValidate(forgedProvenancePack).includes("policy.provenance.pack: must name the pack the resolution used"),
      true,
    );
  });
});

// ─── Query ───────────────────────────────────────────────────────────────────

describe("policy pack query API", () => {
  it("returns a frozen pack answer with no mutable reference", async () => {
    const { query } = await scanOf({ ...policyFile({ preset: "strict" }), "package.json": pkg() });
    const answer = query.policyPack();
    assert.equal(Object.isFrozen(answer), true);
    assert.deepEqual(answer, {
      active: true,
      name: BUILT_IN_PACK_NAME,
      version: BUILT_IN_PACK_VERSION,
      origin: "built-in",
      reference: BUILT_IN_PACK_REFERENCE,
      explicit: false,
      preset: "strict",
    });
    assert.throws(() => {
      answer.name = "forged";
    }, TypeError);
    // The provenance answer carries the same identity, one level down.
    assert.equal(query.policyProvenance().pack, BUILT_IN_PACK_REFERENCE);
    assert.equal(query.policy().pack.reference, BUILT_IN_PACK_REFERENCE);
  });

  it("is null, not empty, for a model that carries no policy at all", async () => {
    const { model } = await scanOf({ "package.json": pkg() });
    const query = createRepositoryQuery({ ...clone(model), policy: {} });
    assert.equal(query.policyPack(), null);
    assert.equal(query.policyPreset(), null);
    assert.equal(query.policyProvenance(), null);
    assert.equal(query.policy(), null);
  });

  it("refuses a pack answer that contradicts itself", () => {
    const cases = [
      { active: true, name: null, version: null, origin: null, reference: null, explicit: false, preset: null },
      { active: false, name: BUILT_IN_PACK_NAME, version: "1", origin: "built-in", reference: BUILT_IN_PACK_REFERENCE, explicit: false, preset: "strict" },
      // Nothing here contradicts anything except the activity flag, so `active` agreeing with the name
      // is the only thing that can refuse this answer.
      { active: false, name: BUILT_IN_PACK_NAME, version: null, origin: null, reference: null, explicit: false, preset: null },
      { active: true, name: null, version: "1", origin: "built-in", reference: BUILT_IN_PACK_REFERENCE, explicit: true, preset: "strict" },
      { active: true, name: BUILT_IN_PACK_NAME, version: "1", origin: "built-in", reference: "other@1", explicit: false, preset: "strict" },
      { active: true, name: BUILT_IN_PACK_NAME, version: "1", origin: "vendor", reference: BUILT_IN_PACK_REFERENCE, explicit: false, preset: "strict" },
      { active: true, name: BUILT_IN_PACK_NAME, version: "1", origin: "built-in", reference: BUILT_IN_PACK_REFERENCE, explicit: false, preset: "Web Production" },
      { active: true, name: BUILT_IN_PACK_NAME, version: "1", origin: "built-in", reference: BUILT_IN_PACK_REFERENCE, explicit: "yes", preset: "strict" },
      { active: false, name: null, version: null, origin: null, reference: null, explicit: true, preset: null },
    ];
    for (const answer of cases) {
      // The raw value reaches the validator: the builder coerces, the validator refuses.
      const draft = { ...createPolicyPackResult(answer), ...answer };
      assert.throws(() => validatePolicyPackResult(draft), ValidationError, JSON.stringify(answer));
    }
    assert.equal(
      validatePolicyPackResult(
        createPolicyPackResult({
          active: true,
          name: BUILT_IN_PACK_NAME,
          version: "1",
          origin: "built-in",
          reference: BUILT_IN_PACK_REFERENCE,
          explicit: true,
          preset: "strict",
        }),
      ).active,
      true,
    );
  });

  it("pins the reading vocabulary a pack failure is published under", () => {
    // The four reasons are the only vocabulary a repository author sees when a pack reference cannot
    // be established, so they are pinned literally rather than compared against themselves.
    assert.equal(POLICY_UNKNOWN_REASONS.PACK_REFERENCE_NOT_ESTABLISHED, "policy-pack-reference-not-established");
    assert.equal(POLICY_UNKNOWN_REASONS.PACK_NOT_ESTABLISHED, "policy-pack-not-established");
    assert.equal(POLICY_UNKNOWN_REASONS.PACK_VERSION_NOT_ESTABLISHED, "policy-pack-version-not-established");
    assert.equal(POLICY_UNKNOWN_REASONS.PACK_PRESET_NOT_ESTABLISHED, "policy-pack-preset-not-established");
    assert.equal(POLICY_UNKNOWN_REASONS.PRESET_NOT_ESTABLISHED, "policy-preset-not-established");
  });

  it("refuses a provenance or a policy result whose pack disagrees with itself", async () => {
    const { model } = await scanOf({ ...policyFile({ preset: "minimal" }), "package.json": pkg() });
    const area = clone(model).policy;
    // The baseline is a well-formed result, so every case below can only fail for the pack relation.
    assert.deepEqual(createPolicyResult({ ...area }).pack, area.pack);
    assert.equal(validatePolicyResult(createPolicyResult({ ...area })).pack.reference, BUILT_IN_PACK_REFERENCE);

    for (const patch of [
      // A pack with no preset behind it, and a preset with no pack: one fact read twice.
      { pack: null, provenance: { ...area.provenance, pack: null } },
      { pack: null },
      { provenance: { ...area.provenance, pack: "other-pack@1" } },
      { provenance: { ...area.provenance, pack: "code-guardian-core" } },
      { pack: { ...area.pack, reference: "code-guardian-core@2" } },
    ]) {
      assert.throws(
        () => validatePolicyResult(createPolicyResult({ ...area, ...patch })),
        ValidationError,
        JSON.stringify(patch),
      );
    }
    assert.equal(validatePolicyResult(createPolicyResult({ ...area })).pack.reference, BUILT_IN_PACK_REFERENCE);
  });

  it("refuses a provenance whose pack disagrees with its own preset", () => {
    // A provenance that names a preset but no pack, and one that names a pack but no preset: one
    // fact read twice, so either half alone is a contradiction.
    for (const answer of [
      { version: "1", preset: "strict", pack: null, sources: { "ci.maxReleaseWorkflows": presetSource("strict") }, inherited: ["ci.maxReleaseWorkflows"], overridden: [] },
      { version: "1", preset: null, pack: BUILT_IN_PACK_REFERENCE, sources: {}, inherited: [], overridden: [] },
      { version: "1", preset: "strict", pack: "code-guardian-core", sources: {}, inherited: [], overridden: [] },
    ]) {
      assert.throws(
        () => validatePolicyProvenanceResult(createPolicyProvenanceResult(answer)),
        ValidationError,
        JSON.stringify(answer),
      );
    }

  });
});

// ─── Compatibility ───────────────────────────────────────────────────────────

describe("phase 22 and 23 compatibility", () => {
  it("reads a Phase 22 document — no preset — exactly as Phase 22 did", async () => {
    const declared = {
      environment: { requireTemplate: true, allowMultipleTemplates: false },
      container: { requireHealthcheck: true },
      ci: { requireTestsForRelease: true, requireLintForRelease: false, maxReleaseWorkflows: 3 },
      api: { requireResolvedMiddleware: true },
      dependencies: { requireLockfile: true, allowMultipleManagers: false },
      architecture: { requireConnectedEntrypoints: true },
    };
    const { policy } = await scanOf({ ...policyFile(declared), "package.json": pkg() });
    // The effective document *is* the declaration: no preset, so nothing was merged in.
    assert.deepEqual(policy.document, declared);
    assert.equal(policy.state, POLICY_STATES.ESTABLISHED);
    assert.equal(policy.preset, null);
    assert.equal(policy.pack, null);
    assert.equal(policy.provenance.preset, null);
    assert.equal(policy.provenance.pack, null);
    assert.deepEqual(policy.coverage.domains, POLICY_DOMAINS);
    for (const id of keyIdsOf(policy.document)) {
      assert.equal(policy.provenance.sources[id], "user", id);
    }
    assert.deepEqual(policy.provenance.overridden, []);
    assert.deepEqual(policy.provenance.inherited, []);
  });

  it("reads a Phase 23 document — a bare preset name — exactly as Phase 23 did", async () => {
    for (const name of BUILT_IN_PRESETS.map((preset) => preset.name)) {
      const { policy } = await scanOf({ ...policyFile({ preset: name }), "package.json": pkg() });
      assert.deepEqual(policy.document, documentOf(name), name);
      assert.deepEqual(policy.preset, { name, version: POLICY_PRESET_VERSION, origin: "built-in" }, name);
      assert.deepEqual(policy.declared, { version: POLICY_DOCUMENT_VERSION, preset: name }, name);
      assert.deepEqual(policy.provenance.inherited, keyIdsOf(policy.document), name);
      for (const id of policy.provenance.inherited) {
        assert.equal(policy.provenance.sources[id], presetSource(name), id);
      }
      // The one thing Phase 24 adds is the identity beside it.
      assert.equal(policy.pack.reference, BUILT_IN_PACK_REFERENCE, name);
      assert.equal(policy.pack.name, BUILT_IN_PACK_NAME, name);
    }
  });

  it("does not require a repository to rewrite its document", async () => {
    // The same policy, written the Phase 23 way and the Phase 24 way, resolves to one effective
    // document; only the identity of the selection differs.
    const legacy = await scanOf({ ...policyFile({ preset: "web-production" }), "package.json": pkg() });
    const explicit = await scanOf({
      ...policyFile({ preset: `${BUILT_IN_PACK_NAME}@${BUILT_IN_PACK_VERSION}:web-production` }),
      "package.json": pkg(),
    });
    assert.deepEqual(explicit.policy.document, legacy.policy.document);
    assert.deepEqual(explicit.policy.provenance.sources, legacy.policy.provenance.sources);
    assert.deepEqual(explicit.policy.provenance.inherited, legacy.policy.provenance.inherited);
    assert.deepEqual(explicit.policy.preset, legacy.policy.preset);
    assert.equal(explicit.policy.pack.explicit, true);
    assert.equal(legacy.policy.pack.explicit, false);
    assert.equal(validateRepositoryModelGraph(explicit.model), explicit.model);
  });

  it("keeps the acquisition layer's reading of a preset field unchanged", () => {
    // The field is a bounded string, and the pack grammar is not the acquisition layer's business:
    // a Phase 23 document parses to exactly what it parsed to.
    const document = parsePolicyDocument(JSON.stringify({ version: "1", preset: "web-production" }));
    assert.equal(document.ok, true);
    assert.deepEqual(document.document, { version: "1", preset: "web-production" });
    const qualified = parsePolicyDocument(
      JSON.stringify({ preset: `${BUILT_IN_PACK_NAME}@1:web-production` }),
    );
    assert.equal(qualified.ok, true);
    assert.equal(qualified.document.preset, `${BUILT_IN_PACK_NAME}@1:web-production`);
    // Still refused when it is not a string, or absent.
    assert.equal(parsePolicyDocument(JSON.stringify({ preset: 7 })).ok, false);
    assert.equal(parsePolicyDocument(JSON.stringify({ preset: "" })).ok, false);
    assert.equal(parsePolicyDocument(JSON.stringify({ preset: "p".repeat(200) })).ok, false);
    assert.equal(parsePolicyDocument(JSON.stringify({ pack: "code-guardian-core" })).ok, false);
  });

  it("keeps a caller's own preset registry working, unchanged", () => {
    // The Phase 23 preset registry is still the merge engine's input, and a caller that builds one
    // still gets the Phase 23 answers.
    const registry = createPresetRegistry({ presets: [...BUILT_IN_PRESETS] });
    const resolution = resolvePolicyDocument({ document: { preset: "strict" }, registry });
    assert.equal(resolution.ok, true);
    assert.equal(resolution.preset.name, "strict");
    assert.equal(resolution.provenance.sources["ci.maxReleaseWorkflows"], presetSource("strict"));
  });
});

// ─── Security ────────────────────────────────────────────────────────────────

describe("policy pack security", () => {
  it("refuses a pack carrying prototype-pollution keys, and pollutes nothing", () => {
    const polluted = '{"name":"company-core","version":"1","origin":"built-in","title":"t","purpose":"p","presets":[],"__proto__":{"polluted":true}}';
    const parsed = JSON.parse(polluted);
    assert.equal(Object.hasOwn(parsed, "__proto__"), true);
    const issues = packDefinitionIssues(parsed);
    assert.equal(issues.length > 0, true);
    assert.throws(() => createPolicyPackRegistry({ packs: [parsed] }), PolicyPackError);
    assert.equal({}.polluted, undefined);
    assert.equal(Object.prototype.polluted, undefined);

    // The same key inside a preset document.
    const preset = '{"name":"web-production","purpose":"p","document":{"__proto__":{"polluted":true}}}';
    assert.equal(presetDefinitionIssues(JSON.parse(preset)).length > 0, true);
    assert.equal(Object.prototype.polluted, undefined);

    // And inside a preset's settings.
    const settings = '{"name":"web-production","purpose":"p","document":{"container":{"__proto__":true}}}';
    assert.equal(presetDefinitionIssues(JSON.parse(settings)).length > 0, true);
    assert.equal(Object.prototype.polluted, undefined);
  });

  it("refuses a prototype-shaped pack name, and handles the ones the grammar allows safely", () => {
    // `_`, uppercase and a leading digit are outside the name grammar, so the classic pollution keys
    // cannot be a pack name at all.
    for (const name of ["__proto__", "hasOwnProperty", "toString", "constructor__"]) {
      assert.equal(isPackName(name), false, name);
      assert.equal(packDefinitionIssues(packOf({ name })).length > 0, true, name);
      const refused = resolvePackPolicyDocument({ document: { preset: `${name}@1:web-production` } });
      assert.equal(refused.ok, false, name);
      assert.equal(refused.reason, POLICY_RESOLUTION_FAILURES.PACK_REFERENCE_NOT_ESTABLISHED, name);
    }
    // A name that *is* a well-formed identifier, even one that shadows a prototype member, is safe:
    // this layer keys by name in a Map and reads fields as fixed properties, so nothing is looked up
    // through the name.
    const registry = createPolicyPackRegistry({
      packs: [packOf({ name: "constructor" }), packOf({ name: "prototype" })],
    });
    for (const name of ["constructor", "prototype"]) {
      assert.equal(registry.has(name, "1"), true, name);
      assert.equal(registry.get(name, "1").name, name);
      assert.equal(registry.describe(name, "1").name, name);
      const resolved = resolvePackPolicyDocument({
        document: { preset: `${name}@1:web-production` },
        packs: registry,
      });
      assert.equal(resolved.ok, true, name);
      assert.equal(resolved.effective.container.requireHealthcheck, true, name);
    }
    assert.equal(Object.prototype.polluted, undefined);
    assert.equal({}.polluted, undefined);
  });

  it("refuses a pack whose fields are functions, getters or arbitrary objects", () => {
    // A function-valued field is not data, and a pack is data.
    assert.equal(packDefinitionIssues(packOf({ origin: () => "built-in" })).length > 0, true);
    assert.equal(packDefinitionIssues(packOf({ presets: () => [] })).length > 0, true);
    assert.equal(packDefinitionIssues(packOf({ purpose: { toString: () => "p" } })).length > 0, true);
    // A preset document whose value is a function is refused by the type check.
    const fn = presetOf("web-production");
    fn.document.container.requireHealthcheck = () => true;
    assert.equal(packDefinitionIssues(packOf({ presets: [fn] })).length > 0, true);
  });

  it("refuses an oversized name, an unsupported version and an ambiguous reference", () => {
    const long = "a".repeat(POLICY_PACK_LIMITS.maxPackNameLength + 1);
    assert.equal(packDefinitionIssues(packOf({ name: long })).length > 0, true);
    assert.equal(resolvePackPolicyDocument({ document: { preset: `${long}@1:web-production` } }).ok, false);
    assert.equal(resolvePackPolicyDocument({ document: { preset: "code-guardian-core@1:strict", version: "1" } }).ok, true);
    assert.equal(
      resolvePackPolicyDocument({ document: { preset: "code-guardian-core:strict" } }).ok,
      true,
    );
    // A reference that could be read two ways is refused rather than interpreted.
    for (const ambiguous of ["code-guardian-core@1@2:strict", "code-guardian-core:a:b", "code-guardian-core:1:strict"]) {
      const parsed = parsePresetReference(ambiguous);
      assert.equal(parsed.ok, false, ambiguous);
    }
  });

  it("ignores a registry that is not one, rather than trusting it", () => {
    for (const packs of [null, 7, {}, [], "registry", { resolveVersion: 7 }]) {
      // A registry with no `resolveVersion` is not a registry: the resolution refuses rather than
      // reading whatever shape was handed to it.
      const qualified = resolvePackPolicyDocument({ document: { preset: "business-core@1:web-production" }, packs });
      assert.equal(qualified.ok, false, JSON.stringify(packs ?? null));
      assert.equal(qualified.reason, POLICY_RESOLUTION_FAILURES.PACK_NOT_ESTABLISHED);
      // A bare preset name is still reported as the preset selection it is, in the reading Phase 23
      // published: the repository named no pack, so no pack enters the answer.
      const bare = resolvePackPolicyDocument({ document: { preset: "web-production" }, packs });
      assert.equal(bare.ok, false, JSON.stringify(packs ?? null));
      assert.equal(bare.reason, POLICY_RESOLUTION_FAILURES.PRESET_NOT_ESTABLISHED);
    }
    // A pack that declares a preset it will not hand back is refused too: the layer checks the pack
    // holds the preset *and* trusts the merge to find it, so a registry that contradicts itself
    // produces a refusal rather than a half-built resolution.
    const lying = {
      resolveVersion: () => ({ ok: true, version: "1" }),
      presetRegistry: () => ({ has: () => true, get: () => null }),
      get: () => ({
        name: "lying",
        version: "1",
        origin: "built-in",
        reference: "lying@1",
        presets: ["web-production"],
      }),
    };
    const inconsistent = resolvePackPolicyDocument({
      document: { preset: "lying@1:web-production" },
      packs: lying,
    });
    assert.equal(inconsistent.ok, false);
    assert.equal(inconsistent.reason, POLICY_RESOLUTION_FAILURES.PRESET_NOT_ESTABLISHED);

    // A policy that names no preset needs no registry at all, so it still resolves.
    assert.equal(resolvePackPolicyDocument({ document: { container: {} }, packs: null }).ok, true);
  });

  it("cannot be made to apply a pack by mutating one after registration", () => {
    const definition = packOf();
    const registry = createPolicyPackRegistry({ packs: [definition] });
    const before = resolvePackPolicyDocument({ document: { preset: "company-core@1:web-production" }, packs: registry });
    // The caller's own object is not frozen — it belongs to the caller — but it is no longer reachable
    // from the registry, so changing it cannot change a policy.
    definition.presets[0].document.ci.maxReleaseWorkflows = 99;
    const after = resolvePackPolicyDocument({ document: { preset: "company-core@1:web-production" }, packs: registry });
    assert.deepEqual(after.effective, before.effective);
    assert.equal(after.effective.ci.maxReleaseWorkflows, 5);
    assert.equal(Object.isFrozen(registry.get("company-core", "1")), true);
  });

  it("treats a hostile reference as a bounded token, never as text", () => {
    const hostile = [
      "code-guardian-core@1:web-production\n<script>",
      "../../etc/passwd:web-production",
      "company-core@1:web-production\u0000",
      "company-core@1:" + "\u001b[31mred",
      "javascript:alert(1)",
    ];
    for (const reference of hostile) {
      const resolution = resolvePackPolicyDocument({ document: { preset: reference } });
      assert.equal(resolution.ok, false, reference);
      assert.equal(typeof resolution.detail === "string", true, reference);
      assert.equal(resolution.detail.length <= POLICY_PACK_LIMITS.maxDetailLength, true, reference);
      assert.equal(/[\u0000-\u001f\u007f]/.test(resolution.detail), false, reference);
    }
  });

  it("keeps a pack definition that declares an executable preset out of the registry", () => {
    // A preset definition carrying a `document` that is a function, an array or a nested function is
    // refused as a whole, so no pack can smuggle behaviour into a resolved policy.
    for (const document of [() => ({}), [], "document", { container: () => ({}) }]) {
      const preset = { name: "web-production", purpose: "p", document };
      assert.equal(presetDefinitionIssues(preset).length > 0, true, typeof document);
      assert.throws(() => createPolicyPackRegistry({ packs: [packOf({ presets: [preset] })] }), PolicyPackError);
    }
  });
});

// ─── Rule ────────────────────────────────────────────────────────────────────

describe("policy audit rule: pack identity", () => {
  it("still ships exactly one informational rule", () => {
    assert.equal(policyRules.length, 1);
    assert.deepEqual(policyRules.map((rule) => rule.id), [POLICY_RULE_IDS.PRESET_AUDIT]);
    assert.equal(policyRules[0].severity, POLICY_RULE_SEVERITY);
    assert.equal(POLICY_RULE_SEVERITY, "info");
    assert.deepEqual(policyRules[0].remediation, {});
  });

  it("reports the pack, its pinned version and whether the repository named it", async () => {
    const implicit = await scanOf({ ...policyFile({ preset: "web-production" }), "package.json": pkg() });
    const engine = createRuleEngine({ registry: createPolicyRuleRegistry({ rules: policyRules }) });
    const run = await engine.runAll(implicit.context);
    const finding = run.findings[0];
    assert.equal(finding.metadata.pack, BUILT_IN_PACK_NAME);
    assert.equal(finding.metadata.packVersion, BUILT_IN_PACK_VERSION);
    assert.equal(finding.metadata.packOrigin, "built-in");
    assert.equal(finding.metadata.packReference, BUILT_IN_PACK_REFERENCE);
    assert.equal(finding.metadata.packActive, true);
    assert.equal(finding.metadata.packExplicit, false);
    assert.equal(finding.metadata.packPreset, "web-production");
    assert.equal(finding.metadata.preset, "web-production");
    assert.equal(Object.isFrozen(run.findings), true);
    // The description names the pack, and how it was selected.
    assert.equal(finding.description.includes(BUILT_IN_PACK_REFERENCE), true);
    assert.equal(finding.description.includes("this build's own pack"), true);
  });

  it("distinguishes a repository that pinned the pack from one that did not", async () => {
    const pinned = await scanOf({
      ...policyFile({ preset: `${BUILT_IN_PACK_NAME}@${BUILT_IN_PACK_VERSION}:strict` }),
      "package.json": pkg(),
    });
    const engine = createRuleEngine({ registry: createPolicyRuleRegistry({ rules: policyRules }) });
    const run = await engine.runAll(pinned.context);
    const finding = run.findings[0];
    assert.equal(finding.metadata.packExplicit, true);
    assert.equal(finding.metadata.packReference, BUILT_IN_PACK_REFERENCE);
    assert.equal(finding.description.includes("the pack this repository pinned"), true);
    // Still informational: no violation, no score, no recommendation anywhere.
    assert.equal(finding.severity, "info");
    const text = `${finding.title} ${finding.description}`.toLowerCase();
    for (const forbidden of ["grade", "percent", "compliance score", "recommend the", "should use", "must fix", "remediate"]) {
      assert.equal(text.includes(forbidden), false, forbidden);
    }
  });

  it("abstains when no pack governs the policy, and when the reading established nothing", async () => {
    const engine = createRuleEngine({ registry: createPolicyRuleRegistry({ rules: policyRules }) });
    const none = await scanOf({ ...policyFile({ container: { requireHealthcheck: true } }), "package.json": pkg() });
    const first = await engine.runAll(none.context);
    assert.deepEqual(first.findings, []);
    assert.equal(first.rules[0].status, "unknown");
    assert.equal(first.rules[0].metadata.pack, null);
    assert.equal(first.rules[0].metadata.packActive, false);

    const unestablished = await scanOf({ ...policyFile({ preset: "nope-core@1:web-production" }), "package.json": pkg() });
    const second = await engine.runAll(unestablished.context);
    assert.deepEqual(second.findings, []);
    assert.equal(second.rules[0].status, "unknown");
    assert.equal(second.rules[0].metadata.packActive, false);
  });

  it("reads the pack answer through its own signal readers and the accepted framework", async () => {
    const { query, context } = await scanOf({ ...policyFile({ preset: "library" }), "package.json": pkg() });
    assert.deepEqual(activePack(query), query.policyPack());
    assert.deepEqual(activePreset(query), query.policyPreset());
    const engine = createAnalyzerEngine({ registry: createAnalyzerRegistry([createPolicyAnalyzer()]) });
    const result = await engine.runAll(context);
    assert.equal(result.analyzers.length, 1);
    assert.equal(result.findings.length, 1);
    assert.equal(typeof result.findings[0].fingerprint, "string");
    assert.equal(result.findings[0].metadata.packReference, BUILT_IN_PACK_REFERENCE);
  });

  it("derives the finding's identity from the policy definition, not from the word", async () => {
    const { model, context } = await scanOf({ ...policyFile({ preset: "web-production" }), "package.json": pkg() });
    const engine = createRuleEngine({ registry: createPolicyRuleRegistry({ rules: policyRules }) });
    const run = await engine.runAll(context);
    const key = run.findings[0].metadata.fingerprintKey;
    assert.equal(typeof key, "string");
    assert.equal(key.startsWith("policy:preset:"), true);
    assert.equal(key.length > "policy:preset:".length, true);

    // Identity is derived from the policy definition — the pack and its version, then the preset — so
    // two packs declaring one preset name cannot collide. The pack is the only thing that changes
    // here, and the identity follows it.
    const otherPack = clone(model);
    otherPack.policy.pack = {
      name: "other-pack",
      version: "2",
      origin: "built-in",
      reference: "other-pack@2",
      explicit: false,
      preset: "web-production",
    };
    otherPack.policy.provenance.pack = "other-pack@2";
    const otherContext = buildAnalysisContext({ repository: otherPack });
    const otherRun = await engine.runAll(otherContext);
    assert.equal(otherRun.findings[0].metadata.preset, run.findings[0].metadata.preset);
    assert.notEqual(otherRun.findings[0].metadata.fingerprintKey, key);
    assert.equal(otherRun.findings[0].metadata.packReference, "other-pack@2");
    // The same command twice produces the same fingerprint — nothing here reads a clock or randomness.
    const again = await engine.runAll(context);
    assert.deepEqual(
      again.findings.map((finding) => finding.fingerprint),
      run.findings.map((finding) => finding.fingerprint),
    );
  });
});

// ─── Architectural boundary ──────────────────────────────────────────────────

describe("policy pack layer: architectural boundary", () => {
  const POLICY_DIR = join(process.cwd(), "src", "policy");
  const FORBIDDEN = [
    "node:fs",
    "node:path",
    "node:process",
    "node:os",
    "node:url",
    "child_process",
    "node:child_process",
    "node:net",
    "node:http",
    "node:https",
    "node:dns",
    "node:worker_threads",
    "node:module",
    "node:vm",
    "tools.js",
    "tool-registry",
    "http-server",
    "stdio-server",
    "../repository",
    "../../repository",
    "../analysis",
  ];

  const sourcesOf = (dir) =>
    readdirSync(dir, { withFileTypes: true })
      .filter((entry) => entry.name.endsWith(".js"))
      .map((entry) => ({ name: entry.name, text: readFileSync(join(dir, entry.name), "utf8") }));

  it("adds three pack modules and one built-in pack, with no other file", () => {
    const sources = sourcesOf(POLICY_DIR);
    assert.equal(sources.length, 10);
    assert.deepEqual(
      sources.map((entry) => entry.name).sort(),
      [
        "contracts.js",
        "errors.js",
        "index.js",
        "pack-registry.js",
        "pack-resolution.js",
        "pack-validation.js",
        "packs.js",
        "presets.js",
        "registry.js",
        "resolver.js",
      ],
    );
  });

  it("keeps the whole layer a leaf: it imports only its own siblings", () => {
    for (const { name, text } of sourcesOf(POLICY_DIR)) {
      for (const match of text.matchAll(/from\s+"([^"]+)"/g)) {
        assert.equal(match[1].startsWith("./"), true, `${name} imports "${match[1]}"`);
      }
      assert.equal(/import\s*\(/.test(text), false, `${name} uses a dynamic import`);
      assert.equal(/\brequire\s*\(/.test(text), false, `${name} uses require`);
      for (const forbidden of FORBIDDEN) {
        assert.equal(text.includes(`"${forbidden}"`), false, `${name} references "${forbidden}"`);
      }
      // No clock, no randomness, no environment, no evaluation, no process, no network.
      assert.equal(/\bnew Date\b/.test(text), false, `${name} must not construct a Date`);
      assert.equal(/\bDate\.now\b/.test(text), false, `${name} must not read the clock`);
      assert.equal(/\bperformance\.now\b/.test(text), false, `${name} must not read a timer`);
      assert.equal(/\bMath\.random\b/.test(text), false, `${name} must not use randomness`);
      assert.equal(/\bprocess\.env\b/.test(text), false, `${name} must not read the environment`);
      assert.equal(/\beval\s*\(/.test(text), false, `${name} must not evaluate`);
      assert.equal(/\bnew Function\b/.test(text), false, `${name} must not build a function`);
      assert.equal(/\bfetch\s*\(/.test(text), false, `${name} must not fetch`);
      assert.equal(/\bXMLHttpRequest\b/.test(text), false, `${name} must not open a request`);
    }
  });

  it("keeps the pack layer below the preset layer, never above it", () => {
    // The pack layer may import the preset layer; the preset layer must not import the pack layer,
    // or a preset would depend on where it is distributed from.
    for (const name of ["presets.js", "registry.js", "resolver.js"]) {
      const text = readFileSync(join(POLICY_DIR, name), "utf8");
      for (const imported of ["packs.js", "pack-registry.js", "pack-validation.js", "pack-resolution.js"]) {
        assert.equal(text.includes(`"./${imported}"`), false, `${name} must not import ${imported}`);
      }
    }
    // And the built-in pack is built from the presets, so there is one copy of every requirement.
    const packsText = readFileSync(join(POLICY_DIR, "packs.js"), "utf8");
    assert.equal(packsText.includes('from "./presets.js"'), true);
    assert.equal(packsText.includes("requireHealthcheck"), false);
    assert.equal(packsText.includes("maxReleaseWorkflows"), false);
  });

  it("keeps the policy rule pack off every registry and acquisition boundary", () => {
    const PACK_DIR = join(process.cwd(), "src", "rules", "policy");
    const sources = sourcesOf(PACK_DIR).concat(
      sourcesOf(join(PACK_DIR, "rules")).map((entry) => ({ name: `rules/${entry.name}`, text: entry.text })),
    );
    for (const { name, text } of sources) {
      assert.equal(text.includes("../../policy/index.js"), false, `${name} must not import the pack layer`);
      for (const forbidden of ["node:fs", "node:path", "child_process", "node:net", "node:http", "tools.js"]) {
        assert.equal(text.includes(`"${forbidden}"`), false, `${name} references "${forbidden}"`);
      }
      assert.equal(/\bMath\.random\b/.test(text), false, `${name} must not use randomness`);
      assert.equal(/\bprocess\.env\b/.test(text), false, `${name} must not read the environment`);
    }
  });

  it("holds no credential, URL or path a pack could be loaded from", () => {
    // The layer holds no way to fetch a pack, and no string that names one outside its own grammar.
    for (const { name, text } of sourcesOf(POLICY_DIR)) {
      assert.equal(/https?:\/\//.test(text), false, `${name} mentions a URL`);
      assert.equal(/[A-Za-z]:\\\\/.test(text), false, `${name} mentions an absolute path`);
      assert.equal(/\b(api[_-]?key|secret|password|credential)\b/i.test(text), false, `${name} mentions a credential`);
      assert.equal(/\bregistry\.npmjs\b/.test(text), false, `${name} mentions a package registry`);
    }
  });
});

// ─── Determinism across the whole layer ──────────────────────────────────────

describe("policy pack determinism", () => {
  it("builds the same registry and the same answers from the same definitions", () => {
    const first = createPolicyPackRegistry({ packs: [BUILT_IN_PACK, businessPack()] });
    const second = createPolicyPackRegistry({ packs: [businessPack(), BUILT_IN_PACK] });
    assert.deepEqual(second.list(), first.list());
    assert.deepEqual(second.references, first.references);
    const document = { preset: "business-core@1:web-production", ci: { maxReleaseWorkflows: 6 } };
    const a = resolvePackPolicyDocument({ document, packs: first });
    const b = resolvePackPolicyDocument({ document, packs: second });
    assert.equal(JSON.stringify(a), JSON.stringify(b));
  });

  it("publishes the built-in pack's identity as constants a consumer can pin", () => {
    assert.equal(DEFAULT_PACK_REGISTRY.size, 1);
    assert.deepEqual(DEFAULT_PACK_REGISTRY.names, [BUILT_IN_PACK_NAME]);
    assert.deepEqual(DEFAULT_PACK_REGISTRY.versions(BUILT_IN_PACK_NAME), [BUILT_IN_PACK_VERSION]);
    assert.equal(DEFAULT_PACK_REGISTRY.list()[0].reference, BUILT_IN_PACK_REFERENCE);
    assert.deepEqual(DEFAULT_PACK_REGISTRY.list()[0].presets, BUILT_IN_PRESETS.map((preset) => preset.name).sort());
    assert.equal(packPresetReference(BUILT_IN_PACK_NAME, BUILT_IN_PACK_VERSION, "minimal"), `${BUILT_IN_PACK_REFERENCE}:minimal`);
    assert.equal(Object.isFrozen(DEFAULT_PACK_REGISTRY.list()[0]), true);
  });

  it("names one pack and one version per reference it answers for", () => {
    // Nothing in the layer resolves a name to "a" pack: every answer is the reference it was asked
    // for, and every reference answers for exactly one pack.
    const registry = twoPackRegistry();
    for (const reference of registry.references) {
      const separator = reference.lastIndexOf(POLICY_PACK_REFERENCE_SEPARATOR);
      const name = reference.slice(0, separator);
      const version = reference.slice(separator + 1);
      assert.equal(registry.get(name, version).reference, reference);
      assert.equal(registry.has(name, version), true);
      assert.equal(registry.versions(name).includes(version), true);
    }
    assert.equal(registry.versions("nope-core").length, 0);
  });
});
