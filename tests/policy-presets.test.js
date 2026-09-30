/**
 * Code Guardian — Policy Presets & Rule Packs Tests (Phase 23)
 *
 * Four fixture styles, chosen deliberately:
 *
 *   - **the registry and the resolver directly**, because the preset layer is a leaf: it reads no
 *     file, no network and no clock, so its contract can be checked without a repository at all;
 *   - **real repositories** written to a temporary directory and scanned through the accepted
 *     Phase 8A boundary, the Phase 8C scanner and the Phase 8D model builder, so `{"preset":
 *     "web-production"}` in a file on disk becomes a policy, an effective document, a provenance and
 *     a compliance report by the accepted path and by nothing else;
 *   - **tampering inside the model's own policy area**, because the point of the contract is that a
 *     hand-edited provenance is a validation failure instead of an answer;
 *   - **the accepted engines**, because the pack must be an ordinary analyzer over the accepted
 *     framework and nothing else.
 *
 * The suite's central claims are the phase's central requirements: a preset is an immutable
 * in-memory document, resolution is deterministic and refuses the *whole* document when the preset
 * is unknown, every effective value keeps a source, the query API hands out frozen answers, and the
 * one rule the pack ships is informational — it never violates, never scores and never recommends.
 *
 * No test starts a container, sends a request, spawns a process, contacts a network, installs a
 * package or writes to the repository under test.
 *
 * Run with: node --test tests/policy-presets.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ValidationError } from "../src/core/index.js";

import {
  BUILT_IN_PRESETS,
  DEFAULT_PRESET_REGISTRY,
  POLICY_PRESET_DOMAINS,
  POLICY_PRESET_ERROR_KINDS,
  POLICY_PRESET_KEY_IDS,
  POLICY_PRESET_KEYS,
  POLICY_PRESET_ORIGIN,
  POLICY_PRESET_SCHEMA,
  POLICY_PRESET_SOURCES,
  POLICY_PRESET_VERSION,
  POLICY_RESOLUTION_FAILURES,
  PRESET_NAMES,
  PRESET_SOURCE_PREFIX,
  PolicyPresetError,
  boundedPresetName,
  builtInPresetIssues,
  createPresetRegistry,
  effectivePolicyIssues,
  isBuiltInPresetName,
  isPresetName,
  isPresetSource,
  isUserSource,
  presetDefinitionIssues,
  presetSource,
  presetSourceName,
  resolvePolicyDocument,
} from "../src/policy/index.js";

import {
  POLICY_DOCUMENT_PATH,
  POLICY_DOCUMENT_VERSION,
  POLICY_FAILURE_REASONS,
  POLICY_SOURCE_STATUSES,
  parsePolicyDocument,
  scanRepository,
} from "../src/repository/scanner/index.js";

import {
  POLICY_DOCUMENT_KEYS,
  POLICY_DOCUMENT_SCHEMA,
  POLICY_DOMAINS,
  POLICY_STATES,
  POLICY_UNKNOWN_REASONS,
  buildRepositoryModel,
  createPolicyPresetResult,
  createRepositoryQuery,
  validatePolicyPresetResult,
  validateRepositoryModelGraph,
} from "../src/repository/model/index.js";

import {
  buildAnalysisContext,
  createAnalyzerEngine,
  createAnalyzerRegistry,
} from "../src/analysis/index.js";

import {
  APPLICABILITY_COVERAGE,
  MAX_IDENTIFIER_LENGTH,
  RULE_OUTCOME_STATUSES,
  createRuleEngine,
} from "../src/rules/index.js";

import {
  MAX_POLICY_FINDINGS,
  POLICY_ABSTENTION_REASONS,
  POLICY_ABSTENTION_WORDING,
  POLICY_ANALYZER_ID,
  POLICY_ANALYZER_NAME,
  POLICY_ANALYZER_SCOPE,
  POLICY_BASIS,
  POLICY_CATEGORY,
  POLICY_CONFIDENCE,
  POLICY_DESCRIBED_STATES,
  POLICY_RULE_ID_PREFIX,
  POLICY_RULE_IDS,
  POLICY_RULE_PACK_VERSION,
  POLICY_RULE_SEVERITY,
  POLICY_SEVERITY_VALUES,
  POLICY_STATE_WORDING,
  activePreset,
  createPolicyAnalyzer,
  createPolicyRuleRegistry,
  effectivePolicy as effectivePolicySignal,
  policyArea,
  policyAuditRules,
  policyProvenance as policyProvenanceSignal,
  policyRules,
  policyRuleSetIssues,
} from "../src/rules/policy/index.js";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const HERE = dirname(fileURLToPath(import.meta.url));
const TMP = mkdtempSync(join(tmpdir(), "cg-presets-"));
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
const pkg = (fields = {}) =>
  JSON.stringify({ name: "demo", version: "1.0.0", ...fields }, null, 2);

/** A repository-relative policy document. */
const policyFile = (policy) => ({ [POLICY_DOCUMENT_PATH]: JSON.stringify(policy, null, 2) });

/** A GitHub Actions workflow body. Deliberately minimal: no workflow body is ever read. */
const workflow = (name) => `name: ${name}\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n`;

/** The document a preset resolves to, as a plain JSON value. */
const documentOf = (name) =>
  JSON.parse(JSON.stringify(BUILT_IN_PRESETS.find((preset) => preset.name === name).document));

/** Every `domain.key` an effective document states, sorted. */
const keyIdsOf = (document) =>
  Object.keys(document)
    .flatMap((domain) => Object.keys(document[domain]).map((key) => `${domain}.${key}`))
    .sort();

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

// ─── Registry ────────────────────────────────────────────────────────────────

describe("preset registry", () => {
  it("ships exactly the five built-in presets, each a complete policy document", () => {
    assert.deepEqual(PRESET_NAMES, [
      "minimal",
      "web-production",
      "backend-service",
      "library",
      "strict",
    ]);
    assert.deepEqual(builtInPresetIssues(), []);
    assert.equal(Object.isFrozen(BUILT_IN_PRESETS), true);
    assert.equal(Object.isFrozen(PRESET_NAMES), true);
    for (const preset of BUILT_IN_PRESETS) {
      assert.equal(isBuiltInPresetName(preset.name), true, preset.name);
      assert.deepEqual(presetDefinitionIssues(preset), [], preset.name);
      // Complete: every domain, every key of every domain, in schema order.
      assert.deepEqual(Object.keys(preset.document), POLICY_PRESET_DOMAINS, preset.name);
      for (const domain of POLICY_PRESET_DOMAINS) {
        assert.deepEqual(Object.keys(preset.document[domain]), POLICY_PRESET_KEYS[domain], preset.name);
      }
      assert.equal(isPresetName(preset.name), true, preset.name);
    }
  });

  it("states the built-in presets the mission declares, key by key", () => {
    const minimal = documentOf("minimal");
    assert.deepEqual(minimal, {
      environment: { requireTemplate: false, allowMultipleTemplates: true },
      container: { requireHealthcheck: false },
      ci: { requireTestsForRelease: false, requireLintForRelease: false, maxReleaseWorkflows: 5 },
      api: { requireResolvedMiddleware: false },
      dependencies: { requireLockfile: false, allowMultipleManagers: true },
      architecture: { requireConnectedEntrypoints: false },
    });

    const web = documentOf("web-production");
    for (const [domain, key] of [
      ["container", "requireHealthcheck"],
      ["ci", "requireTestsForRelease"],
      ["ci", "requireLintForRelease"],
      ["api", "requireResolvedMiddleware"],
      ["dependencies", "requireLockfile"],
      ["architecture", "requireConnectedEntrypoints"],
    ]) {
      assert.equal(web[domain][key], true, `${domain}.${key}`);
    }

    // `backend-service` is `web-production` with a narrower release path, and nothing else differs.
    const backend = documentOf("backend-service");
    assert.equal(backend.ci.maxReleaseWorkflows, 2);
    assert.equal(web.ci.maxReleaseWorkflows, 5);
    assert.deepEqual(
      { ...backend.ci, maxReleaseWorkflows: null },
      { ...web.ci, maxReleaseWorkflows: null },
    );

    // `library` requires no container and no middleware, and requires a lockfile and a CI gate.
    const library = documentOf("library");
    assert.equal(library.container.requireHealthcheck, false);
    assert.equal(library.api.requireResolvedMiddleware, false);
    assert.equal(library.dependencies.requireLockfile, true);
    assert.equal(library.ci.requireTestsForRelease, true);
    assert.equal(library.ci.requireLintForRelease, true);

    // `strict` requires everything, and permits one release workflow. The two "forbid" keys read the
    // other way round — `allowMultipleTemplates: false` and `allowMultipleManagers: false` are
    // requirements, and stating them as `true` would mean the opposite.
    const strict = documentOf("strict");
    for (const id of [
      "environment.requireTemplate",
      "container.requireHealthcheck",
      "ci.requireTestsForRelease",
      "ci.requireLintForRelease",
      "api.requireResolvedMiddleware",
      "dependencies.requireLockfile",
      "architecture.requireConnectedEntrypoints",
    ]) {
      const [domain, key] = id.split(".");
      assert.equal(strict[domain][key], true, id);
    }
    assert.equal(strict.environment.allowMultipleTemplates, false);
    assert.equal(strict.dependencies.allowMultipleManagers, false);
    assert.equal(strict.ci.maxReleaseWorkflows, 1);
  });

  it("orders its names deterministically, whatever order it was built from", () => {
    const forward = createPresetRegistry({ presets: BUILT_IN_PRESETS });
    const reversed = createPresetRegistry({ presets: [...BUILT_IN_PRESETS].reverse() });
    const shuffled = createPresetRegistry({
      presets: [BUILT_IN_PRESETS[3], BUILT_IN_PRESETS[0], BUILT_IN_PRESETS[4], BUILT_IN_PRESETS[2], BUILT_IN_PRESETS[1]],
    });
    assert.deepEqual(forward.names, [...forward.names].sort());
    assert.deepEqual(forward.names, reversed.names);
    assert.deepEqual(forward.names, shuffled.names);
    assert.deepEqual(forward.names, DEFAULT_PRESET_REGISTRY.names);
    assert.equal(forward.size, PRESET_NAMES.length);
    for (const name of forward.names) {
      assert.deepEqual(forward.get(name).document, reversed.get(name).document, name);
    }
  });

  it("is deeply immutable, and cannot be mutated into answering differently", () => {
    const registry = createPresetRegistry();
    assert.equal(Object.isFrozen(registry), true);
    assert.equal(Object.isFrozen(registry.names), true);
    for (const name of registry.names) {
      const preset = registry.get(name);
      assert.equal(Object.isFrozen(preset), true, name);
      assert.equal(Object.isFrozen(preset.document), true, name);
      for (const domain of POLICY_PRESET_DOMAINS) {
        assert.equal(Object.isFrozen(preset.document[domain]), true, `${name}.${domain}`);
      }
    }
    assert.throws(() => {
      registry.names.push("forged");
    }, TypeError);
    assert.throws(() => {
      registry.get("strict").document.ci.maxReleaseWorkflows = 99;
    }, TypeError);
    // The mutation attempt left no trace: the next resolution is unchanged.
    assert.equal(resolvePolicyDocument({ document: { preset: "strict" } }).effective.ci.maxReleaseWorkflows, 1);
    assert.equal(registry.names.includes("forged"), false);
  });

  it("answers an unknown preset with null, never an error", () => {
    const registry = createPresetRegistry();
    assert.equal(registry.has("nope"), false);
    assert.equal(registry.get("nope"), null);
    assert.equal(registry.get(7), null);
    assert.equal(registry.get(undefined), null);
    assert.equal(registry.describe("nope"), null);
    assert.equal(registry.describe("minimal").purpose.length > 0, true);
  });

  it("refuses a duplicate name and a malformed definition", () => {
    assert.throws(
      () => createPresetRegistry({ presets: [BUILT_IN_PRESETS[0], BUILT_IN_PRESETS[0]] }),
      (error) => {
        assert.equal(error instanceof PolicyPresetError, true);
        assert.equal(error.kind, POLICY_PRESET_ERROR_KINDS.DUPLICATE_PRESET);
        assert.equal(error.detail, "minimal");
        return true;
      },
    );
    // A preset missing one key is refused: a partial preset would resolve to a policy whose key has
    // no source at all, which is exactly what "never lose provenance" forbids.
    const partial = {
      name: "partial",
      purpose: "A test preset that states eight of ten keys.",
      document: { ...documentOf("minimal"), ci: { requireTestsForRelease: false } },
    };
    assert.equal(presetDefinitionIssues(partial).length > 0, true);
    assert.throws(
      () => createPresetRegistry({ presets: [partial] }),
      (error) => error instanceof PolicyPresetError && error.kind === POLICY_PRESET_ERROR_KINDS.INVALID_PRESET,
    );
    assert.throws(() => createPresetRegistry({ presets: "nope" }), PolicyPresetError);
  });

  it("allows a caller to register a well-formed extra preset", () => {
    const extra = {
      name: "company-web",
      purpose: "A caller-supplied preset that satisfies the closed schema.",
      document: documentOf("web-production"),
    };
    const registry = createPresetRegistry({ presets: [...BUILT_IN_PRESETS, extra] });
    assert.equal(registry.has("company-web"), true);
    const resolution = resolvePolicyDocument({ document: { preset: "company-web" }, registry });
    assert.equal(resolution.ok, true);
    assert.equal(resolution.preset.name, "company-web");
    assert.equal(resolution.preset.origin, POLICY_PRESET_ORIGIN);
  });

  it("states its own vocabulary exactly as the model and the scanner do", () => {
    // The preset layer restates the schema rather than importing it, so the three lists are pinned
    // here: a rename in any of them fails the suite instead of silently retiring a preset key.
    assert.deepEqual(POLICY_PRESET_DOMAINS, POLICY_DOMAINS);
    assert.deepEqual(POLICY_PRESET_DOMAINS, Object.keys(POLICY_PRESET_SCHEMA));
    assert.deepEqual(POLICY_DOCUMENT_SCHEMA, POLICY_PRESET_SCHEMA);
    for (const domain of POLICY_PRESET_DOMAINS) {
      assert.deepEqual(POLICY_PRESET_KEYS[domain], Object.keys(POLICY_PRESET_SCHEMA[domain]));
      assert.deepEqual(POLICY_DOCUMENT_KEYS[domain], POLICY_PRESET_KEYS[domain]);
    }
    assert.deepEqual(
      POLICY_PRESET_KEY_IDS,
      POLICY_PRESET_DOMAINS.flatMap((domain) => POLICY_PRESET_KEYS[domain].map((key) => `${domain}.${key}`)),
    );
    assert.equal(POLICY_PRESET_VERSION, POLICY_DOCUMENT_VERSION);
  });

  it("names and reads sources through a closed two-token vocabulary", () => {
    // The token format is pinned literally: a provenance token travels into a compliance item's
    // source, so `preset:<name>` is a contract and not merely whatever the prefix happens to be.
    assert.equal(PRESET_SOURCE_PREFIX, "preset:");
    assert.equal(presetSource("strict"), "preset:strict");
    assert.equal(presetSource("strict"), `${PRESET_SOURCE_PREFIX}strict`);
    assert.equal(isPresetSource(presetSource("strict")), true);
    assert.equal(isPresetSource(POLICY_PRESET_SOURCES.USER), false);
    assert.equal(isUserSource(POLICY_PRESET_SOURCES.USER), true);
    assert.equal(presetSourceName(presetSource("strict")), "strict");
    assert.equal(presetSourceName(POLICY_PRESET_SOURCES.USER), null);
    assert.equal(boundedPresetName("web-production"), "web-production");
    assert.equal(boundedPresetName("bad name/../x"), "badname..x");
    assert.equal(boundedPresetName(7), null);
  });
});

// ─── Resolution ──────────────────────────────────────────────────────────────

describe("preset resolution", () => {
  it("resolves a document that names only a preset into the preset's own policy", () => {
    const resolution = resolvePolicyDocument({ document: { preset: "web-production" } });
    assert.equal(resolution.ok, true);
    assert.deepEqual(resolution.effective, documentOf("web-production"));
    assert.equal(resolution.preset.name, "web-production");
    assert.equal(resolution.preset.version, POLICY_PRESET_VERSION);
    // The declared document is what was written, canonicalised: the pinned version, the named
    // preset, and the domains the repository itself stated (none).
    assert.deepEqual(resolution.declared, { version: "1", preset: "web-production" });
    assert.deepEqual(resolution.provenance.inherited, keyIdsOf(documentOf("web-production")));
    assert.deepEqual(resolution.provenance.overridden, []);
  });

  it("lets a repository value override the preset it inherited", () => {
    const resolution = resolvePolicyDocument({
      document: { preset: "minimal", container: { requireHealthcheck: true } },
    });
    assert.equal(resolution.ok, true);
    assert.equal(resolution.effective.container.requireHealthcheck, true);
    assert.equal(resolution.effective.ci.maxReleaseWorkflows, 5);
    assert.equal(resolution.provenance.sources["container.requireHealthcheck"], POLICY_PRESET_SOURCES.USER);
    assert.equal(resolution.provenance.sources["ci.maxReleaseWorkflows"], presetSource("minimal"));
    assert.deepEqual(resolution.provenance.overridden, ["container.requireHealthcheck"]);
    assert.equal(resolution.provenance.inherited.includes("container.requireHealthcheck"), false);
    assert.equal(resolution.provenance.inherited.length, 9);
  });

  it("applies an override nested inside a domain, leaving its siblings inherited", () => {
    const resolution = resolvePolicyDocument({
      document: { preset: "backend-service", ci: { maxReleaseWorkflows: 2 } },
    });
    assert.equal(resolution.ok, true);
    assert.deepEqual(resolution.effective.ci, {
      requireTestsForRelease: true,
      requireLintForRelease: true,
      maxReleaseWorkflows: 2,
    });
    assert.deepEqual(resolution.provenance.overridden, ["ci.maxReleaseWorkflows"]);
    assert.equal(resolution.provenance.inherited.includes("ci.requireTestsForRelease"), true);
    // A value restated with the value the preset already states is still user-stated: provenance
    // records who stated it, not whether it changed anything.
    assert.equal(resolution.provenance.sources["ci.maxReleaseWorkflows"], "user");
    assert.equal(resolution.effective.ci.maxReleaseWorkflows, documentOf("backend-service").ci.maxReleaseWorkflows);
  });

  it("refuses the entire document when the preset is unknown", () => {
    const resolution = resolvePolicyDocument({
      document: { preset: "does-not-exist", container: { requireHealthcheck: true } },
    });
    assert.equal(resolution.ok, false);
    assert.equal(resolution.reason, POLICY_RESOLUTION_FAILURES.PRESET_NOT_ESTABLISHED);
    assert.equal(resolution.detail, "does-not-exist");
    assert.equal(Object.hasOwn(resolution, "effective"), false);
    // Not "the repository's own values applied and the preset dropped": nothing is resolved at all.
    assert.equal(Object.hasOwn(resolution, "declared"), false);
  });

  it("resolves a document that names no preset into exactly what it declared", () => {
    const declared = { version: "1", ci: { requireTestsForRelease: true }, container: { requireHealthcheck: false } };
    const resolution = resolvePolicyDocument({ document: declared });
    assert.equal(resolution.ok, true);
    assert.deepEqual(resolution.effective, {
      container: { requireHealthcheck: false },
      ci: { requireTestsForRelease: true },
    });
    assert.equal(resolution.preset, null);
    assert.equal(resolution.provenance.preset, null);
    assert.deepEqual(resolution.provenance.inherited, []);
    assert.deepEqual(resolution.provenance.overridden, []);
    for (const token of Object.values(resolution.provenance.sources)) {
      assert.equal(token, POLICY_PRESET_SOURCES.USER);
    }
  });

  it("resolves deterministically, whatever order the document was typed in", () => {
    const first = resolvePolicyDocument({
      document: { preset: "strict", api: { requireResolvedMiddleware: false } },
    });
    const second = resolvePolicyDocument({
      document: { preset: "strict", api: { requireResolvedMiddleware: false } },
    });
    assert.equal(JSON.stringify(first), JSON.stringify(second));
    // The canonical rebuild means key order in the input cannot change the output.
    const reordered = resolvePolicyDocument({
      document: { api: { requireResolvedMiddleware: false }, preset: "strict" },
    });
    assert.equal(JSON.stringify(reordered.effective), JSON.stringify(first.effective));
    assert.equal(JSON.stringify(reordered.provenance), JSON.stringify(first.provenance));
    assert.equal(JSON.stringify(reordered.declared), JSON.stringify(first.declared));
  });

  it("refuses a document that pins another version or is not a document", () => {
    const versioned = resolvePolicyDocument({ document: { version: "2", preset: "minimal" } });
    assert.equal(versioned.ok, false);
    assert.equal(versioned.reason, POLICY_RESOLUTION_FAILURES.VERSION_NOT_SUPPORTED);
    assert.equal(resolvePolicyDocument({ document: null }).reason, POLICY_RESOLUTION_FAILURES.DOCUMENT_NOT_INTERPRETED);
    assert.equal(resolvePolicyDocument({}).reason, POLICY_RESOLUTION_FAILURES.DOCUMENT_NOT_INTERPRETED);
    assert.equal(resolvePolicyDocument({ document: { preset: 7 } }).ok, false);
  });

  it("freezes every value it returns", () => {
    const resolution = resolvePolicyDocument({ document: { preset: "library" } });
    assert.equal(Object.isFrozen(resolution), true);
    assert.equal(Object.isFrozen(resolution.effective), true);
    assert.equal(Object.isFrozen(resolution.effective.dependencies), true);
    assert.equal(Object.isFrozen(resolution.declared), true);
    assert.equal(Object.isFrozen(resolution.preset), true);
    assert.equal(Object.isFrozen(resolution.provenance), true);
    assert.equal(Object.isFrozen(resolution.provenance.sources), true);
    assert.equal(Object.isFrozen(resolution.provenance.inherited), true);
  });

  it("re-resolving a published effective policy reproduces it, or reports what differs", () => {
    const resolution = resolvePolicyDocument({ document: { preset: "strict" } });
    assert.deepEqual(
      effectivePolicyIssues({
        declared: resolution.declared,
        effective: resolution.effective,
        provenance: resolution.provenance,
      }),
      [],
    );
    const tampered = clone(resolution.provenance);
    tampered.sources["ci.maxReleaseWorkflows"] = "user";
    const issues = effectivePolicyIssues({
      declared: resolution.declared,
      effective: resolution.effective,
      provenance: tampered,
    });
    assert.equal(issues.length > 0, true);
  });

  it("parses the two document-level fields the acquisition layer now accepts", () => {
    const parsed = parsePolicyDocument('{"version":"1","preset":"minimal","ci":{"maxReleaseWorkflows":2}}');
    assert.equal(parsed.ok, true);
    assert.deepEqual(parsed.document, {
      version: "1",
      preset: "minimal",
      ci: { maxReleaseWorkflows: 2 },
    });
    assert.equal(parsePolicyDocument('{"preset":"minimal"}').document.preset, "minimal");

    const version = parsePolicyDocument('{"version":"2"}');
    assert.equal(version.ok, false);
    assert.equal(version.reason, POLICY_FAILURE_REASONS.UNSUPPORTED_VERSION);
    const presetType = parsePolicyDocument('{"preset":7}');
    assert.equal(presetType.ok, false);
    assert.equal(presetType.reason, POLICY_FAILURE_REASONS.WRONG_TYPE);
    const presetEmpty = parsePolicyDocument('{"preset":""}');
    assert.equal(presetEmpty.ok, false);
    // A field this build does not declare is still refused.
    assert.equal(parsePolicyDocument('{"extends":"./base.json"}').reason, POLICY_FAILURE_REASONS.UNKNOWN_DOMAIN);
  });
});

// ─── Provenance ──────────────────────────────────────────────────────────────

describe("effective policy provenance", () => {
  it("names the preset as the source of every inherited value", () => {
    const resolution = resolvePolicyDocument({ document: { preset: "web-production" } });
    assert.equal(resolution.provenance.preset, "web-production");
    assert.equal(Object.keys(resolution.provenance.sources).length, POLICY_PRESET_KEY_IDS.length);
    for (const id of POLICY_PRESET_KEY_IDS) {
      assert.equal(resolution.provenance.sources[id], presetSource("web-production"), id);
    }
  });

  it("names the repository as the source of every overridden value", () => {
    const resolution = resolvePolicyDocument({
      document: { preset: "strict", ci: { maxReleaseWorkflows: 4 }, architecture: { requireConnectedEntrypoints: false } },
    });
    assert.deepEqual(resolution.provenance.overridden, [
      "architecture.requireConnectedEntrypoints",
      "ci.maxReleaseWorkflows",
    ]);
    assert.equal(resolution.provenance.sources["ci.maxReleaseWorkflows"], "user");
    assert.equal(resolution.provenance.sources["architecture.requireConnectedEntrypoints"], "user");
    assert.equal(resolution.provenance.sources["container.requireHealthcheck"], presetSource("strict"));
    assert.equal(resolution.effective.ci.maxReleaseWorkflows, 4);
    assert.equal(resolution.effective.architecture.requireConnectedEntrypoints, false);
  });

  it("keeps the two sources apart across different domains in one document", () => {
    const resolution = resolvePolicyDocument({
      document: {
        preset: "library",
        environment: { requireTemplate: true, allowMultipleTemplates: false },
        api: { requireResolvedMiddleware: true },
      },
    });
    const bySource = {};
    for (const [id, token] of Object.entries(resolution.provenance.sources)) {
      bySource[token] = [...(bySource[token] ?? []), id];
    }
    assert.deepEqual(bySource["user"], [
      "api.requireResolvedMiddleware",
      "environment.allowMultipleTemplates",
      "environment.requireTemplate",
    ]);
    assert.equal(bySource[presetSource("library")].length, POLICY_PRESET_KEY_IDS.length - 3);
  });

  it("leaves no effective value without a source", () => {
    for (const preset of PRESET_NAMES) {
      const resolution = resolvePolicyDocument({ document: { preset } });
      assert.deepEqual(Object.keys(resolution.provenance.sources), keyIdsOf(resolution.effective), preset);
      assert.deepEqual(
        [...resolution.provenance.inherited, ...resolution.provenance.overridden].sort(),
        keyIdsOf(resolution.effective),
        preset,
      );
      for (const token of Object.values(resolution.provenance.sources)) {
        assert.equal(token === "user" || isPresetSource(token), true, preset);
      }
    }
    // And the same holds for a document with no preset at all.
    const bare = resolvePolicyDocument({ document: { container: { requireHealthcheck: true } } });
    assert.deepEqual(Object.keys(bare.provenance.sources), ["container.requireHealthcheck"]);
  });
});

// ─── Model integration ───────────────────────────────────────────────────────

describe("model: policy preset integration", () => {
  it("resolves a preset-only document into an effective policy, end to end", async () => {
    const { scan, model, policy, query } = await scanOf({
      ...policyFile({ preset: "web-production" }),
      "package.json": pkg(),
    });
    // 1. acquisition — what was written, plus the preset name.
    assert.equal(scan.policy.status, POLICY_SOURCE_STATUSES.PARSED);
    assert.equal(scan.policy.document.preset, "web-production");
    // 2. model — the effective document is the preset, and what was declared is still readable.
    assert.equal(policy.state, POLICY_STATES.ESTABLISHED);
    assert.deepEqual(policy.declared, { version: "1", preset: "web-production" });
    assert.deepEqual(policy.document, documentOf("web-production"));
    assert.deepEqual(policy.preset, { name: "web-production", version: "1", origin: "built-in" });
    assert.equal(policy.provenance.preset, "web-production");
    // 3. coverage counts describe the policy the model actually acts on.
    assert.deepEqual(policy.coverage.domains, POLICY_DOMAINS);
    assert.equal(policy.coverage.settings, POLICY_PRESET_KEY_IDS.length);
    // 4. the whole model still satisfies its own contract.
    assert.equal(validateRepositoryModelGraph(model), model);
    assert.equal(query.policy().preset.name, "web-production");
  });

  it("measures the preset's requirements even though the file declared none of them", async () => {
    const { report } = await scanOf({ ...policyFile({ preset: "web-production" }), "package.json": pkg() });
    // The compliance engine is unchanged and unaware: it simply receives a document that states ten
    // requirements instead of none.
    for (const section of report.sections) {
      assert.equal(section.policyDeclared, true, section.name);
      assert.deepEqual(section.policyKeys, POLICY_DOCUMENT_KEYS[section.name], section.name);
    }
    assert.equal(report.coverage.policySettings, POLICY_PRESET_KEY_IDS.length);
  });

  it("keeps provenance per key when the repository overrides the preset", async () => {
    const { policy, query } = await scanOf({
      ...policyFile({ preset: "strict", ci: { maxReleaseWorkflows: 9 } }),
      "package.json": pkg(),
    });
    assert.equal(policy.document.ci.maxReleaseWorkflows, 9);
    assert.equal(policy.provenance.sources["ci.maxReleaseWorkflows"], POLICY_PRESET_SOURCES.USER);
    assert.equal(policy.provenance.sources["ci.requireLintForRelease"], presetSource("strict"));
    assert.deepEqual(query.policyProvenance().overridden, ["ci.maxReleaseWorkflows"]);
  });

  it("refuses an unknown preset as a reading that established nothing", async () => {
    const { policy, report, query } = await scanOf({
      ...policyFile({ preset: "nope", container: { requireHealthcheck: true } }),
      "package.json": pkg(),
    });
    // Never a partly-applied policy: the whole document establishes nothing.
    assert.equal(policy.state, POLICY_STATES.UNKNOWN);
    assert.equal(policy.established, false);
    assert.equal(policy.document, null);
    assert.equal(policy.declared, null);
    assert.equal(policy.preset, null);
    assert.equal(policy.provenance, null);
    assert.equal(policy.coverage.reason, POLICY_UNKNOWN_REASONS.PRESET_NOT_ESTABLISHED);
    assert.equal(policy.coverage.detail, "nope");
    // And nothing downstream pretends otherwise.
    assert.equal(report.coverage.policyEstablished, false);
    assert.equal(query.effectivePolicy(), null);
    assert.equal(query.policyProvenance(), null);
    assert.equal(query.policyPreset().active, false);
  });

  it("leaves a policy that names no preset exactly as Phase 22 read it", async () => {
    const { policy } = await scanOf({
      ...policyFile({ container: { requireHealthcheck: true } }),
      "package.json": pkg(),
    });
    assert.equal(policy.state, POLICY_STATES.ESTABLISHED);
    assert.deepEqual(policy.document, { container: { requireHealthcheck: true } });
    assert.equal(policy.preset, null);
    assert.equal(policy.provenance.preset, null);
    assert.equal(policy.declared.version, POLICY_DOCUMENT_VERSION);
    assert.equal(policy.provenance.sources["container.requireHealthcheck"], "user");
  });

  it("rejects a hand-edited effective policy or provenance", async () => {
    const { model } = await scanOf({ ...policyFile({ preset: "minimal" }), "package.json": pkg() });
    assert.equal(issuesOfValidate(model), null);

    // A provenance that claims a preset supplied a value the preset does not state. The contract
    // re-resolves the declared document, so a published provenance that is not the resolved one is a
    // validation failure rather than an answer.
    const forgedProvenance = clone(model);
    forgedProvenance.policy.provenance.sources["ci.maxReleaseWorkflows"] = "user";
    assert.equal(
      issuesOfValidate(forgedProvenance).some((issue) => issue.includes("provenance")),
      true,
    );

    // An effective document that is not what the declared one resolves to.
    const forgedEffective = clone(model);
    forgedEffective.policy.document.ci.maxReleaseWorkflows = 99;
    const issues = issuesOfValidate(forgedEffective);
    assert.equal(issues.some((issue) => issue.includes("effective:")), true);
    // The compliance report can no longer cite a declaration that supports it either.
    assert.equal(issues.length > 0, true);

    // A preset record naming nothing.
    const forgedPreset = clone(model);
    forgedPreset.policy.preset = null;
    assert.equal(
      issuesOfValidate(forgedPreset).some((issue) => issue.startsWith("policy.preset")),
      true,
    );

    // A declared document that vanished while the effective one stayed: the two must be carried
    // together or not at all.
    const forgedDeclaredPresence = clone(model);
    forgedDeclaredPresence.policy.declared = null;
    assert.equal(
      issuesOfValidate(forgedDeclaredPresence).some((issue) => issue.startsWith("policy.declared")),
      true,
    );

    // A preset record naming a different preset than the provenance records: the two are one fact
    // read twice, so a model that disagrees with itself is a validation failure.
    const forgedPresetName = clone(model);
    forgedPresetName.policy.preset.name = "strict";
    assert.equal(
      issuesOfValidate(forgedPresetName).some((issue) => issue.startsWith("policy.preset")),
      true,
    );

    // A declared document whose metadata is not first.
    const forgedDeclared = clone(model);
    forgedDeclared.policy.declared = {
      environment: forgedDeclared.policy.declared.environment,
      version: "1",
      preset: "minimal",
    };
    assert.equal(
      issuesOfValidate(forgedDeclared).some((issue) => issue.startsWith("policy.declared")),
      true,
    );
  });
});

// ─── Query ───────────────────────────────────────────────────────────────────

describe("policy preset query API", () => {
  it("returns frozen answers and no mutable reference", async () => {
    const { query } = await scanOf({ ...policyFile({ preset: "strict" }), "package.json": pkg() });

    const effective = query.effectivePolicy();
    assert.equal(Object.isFrozen(effective), true);
    assert.equal(Object.isFrozen(effective.document), true);
    assert.equal(Object.isFrozen(effective.document.ci), true);
    assert.equal(Object.isFrozen(effective.domains), true);
    assert.deepEqual(effective.domains, POLICY_DOMAINS);
    assert.equal(effective.settings, POLICY_PRESET_KEY_IDS.length);

    const provenance = query.policyProvenance();
    assert.equal(Object.isFrozen(provenance), true);
    assert.equal(Object.isFrozen(provenance.sources), true);
    assert.equal(Object.isFrozen(provenance.inherited), true);
    assert.equal(Object.isFrozen(provenance.overridden), true);

    const preset = query.policyPreset();
    assert.equal(Object.isFrozen(preset), true);
    assert.throws(() => {
      preset.name = "forged";
    }, TypeError);
    assert.throws(() => {
      provenance.sources["ci.maxReleaseWorkflows"] = "user";
    }, TypeError);
  });

  it("looks the active preset up, and reports an inactive answer when none governs", async () => {
    const active = await scanOf({ ...policyFile({ preset: "backend-service" }), "package.json": pkg() });
    assert.deepEqual(active.query.policyPreset(), {
      name: "backend-service",
      version: "1",
      origin: "built-in",
      active: true,
    });

    const none = await scanOf({ ...policyFile({ ci: { maxReleaseWorkflows: 1 } }), "package.json": pkg() });
    assert.deepEqual(none.query.policyPreset(), { name: null, version: null, origin: null, active: false });
    assert.equal(none.query.effectivePolicy().preset, null);
    assert.equal(none.query.policyProvenance().preset, null);
    assert.equal(none.query.policyProvenance().inherited.length, 0);
  });

  it("is null, not empty, for a model that carries no policy at all", async () => {
    const { model } = await scanOf({ "package.json": pkg() });
    const bare = { ...clone(model), policy: {} };
    const query = createRepositoryQuery(bare);
    assert.equal(query.policy(), null);
    assert.equal(query.policyPreset(), null);
    assert.equal(query.effectivePolicy(), null);
    assert.equal(query.policyProvenance(), null);
  });

  it("refuses a preset answer whose activity disagrees with the preset it names", () => {
    const cases = [
      { name: "strict", version: "1", origin: "built-in", active: false },
      { name: null, version: null, origin: null, active: true },
      { name: "strict", version: "1", origin: null, active: true },
      { name: "strict", version: "2", origin: "built-in", active: true },
    ];
    for (const answer of cases) {
      assert.throws(
        () => validatePolicyPresetResult(createPolicyPresetResult(answer)),
        ValidationError,
        JSON.stringify(answer),
      );
    }
    // The well-formed answers the query API actually produces pass.
    assert.equal(
      validatePolicyPresetResult(
        createPolicyPresetResult({ name: "strict", version: "1", origin: "built-in", active: true }),
      ).active,
      true,
    );
  });

  it("hands out the provenance the resolver produced, not a second opinion", async () => {
    const { model, query } = await scanOf({
      ...policyFile({ preset: "library", api: { requireResolvedMiddleware: true } }),
      "package.json": pkg(),
    });
    const resolved = resolvePolicyDocument({ document: { version: "1", preset: "library", api: { requireResolvedMiddleware: true } } });
    assert.deepEqual(query.policyProvenance().sources, resolved.provenance.sources);
    assert.deepEqual(query.effectivePolicy().document, resolved.effective);
    assert.deepEqual(query.effectivePolicy().document, model.policy.document);
  });
});

// ─── Rule ────────────────────────────────────────────────────────────────────

describe("policy preset audit rule", () => {
  it("ships exactly one informational rule, in the declared namespace", () => {
    assert.equal(policyRules.length, 1);
    assert.deepEqual(policyRules.map((rule) => rule.id), Object.values(POLICY_RULE_IDS));
    assert.equal(policyAuditRules.length, policyRules.length);
    const rule = policyRules[0];
    assert.equal(rule.id, "policy.preset.audit");
    assert.equal(rule.id.startsWith(POLICY_RULE_ID_PREFIX), true);
    assert.equal(rule.severity, POLICY_RULE_SEVERITY);
    assert.equal(POLICY_RULE_SEVERITY, "info");
    assert.deepEqual(POLICY_SEVERITY_VALUES, ["info"]);
    assert.equal(rule.category, POLICY_CATEGORY);
    assert.equal(rule.metadata.basis, POLICY_BASIS);
    assert.equal(rule.version, "1.0.0");
    assert.equal(POLICY_RULE_PACK_VERSION, "1.0.0");
    // Informational: no remediation at all, and no severity above info exists in the pack.
    assert.deepEqual(rule.remediation, {});
    assert.equal(["high", "critical", "medium", "low"].includes(rule.severity), false);
    assert.equal(POLICY_CONFIDENCE.RESOLVED_PRESET > 0, true);
    assert.equal(MAX_POLICY_FINDINGS, 1);
  });

  it("describes every abstention reason and policy state it can produce", () => {
    assert.deepEqual(
      [...POLICY_DESCRIBED_STATES].sort(),
      Object.values(POLICY_STATES).sort(),
    );
    for (const value of Object.values(POLICY_ABSTENTION_REASONS)) {
      assert.equal(typeof POLICY_ABSTENTION_WORDING[value], "string", value);
    }
    assert.equal(Object.keys(POLICY_ABSTENTION_WORDING).length, Object.keys(POLICY_ABSTENTION_REASONS).length);
    assert.deepEqual(
      POLICY_DESCRIBED_STATES.map((state) => POLICY_STATE_WORDING[state]).filter(Boolean).length,
      POLICY_DESCRIBED_STATES.length,
    );
  });

  it("refuses a rule set that drops, duplicates or renames the declared rule", () => {
    assert.deepEqual(policyRuleSetIssues(policyRules), []);
    assert.equal(policyRuleSetIssues([]).length, 1);
    assert.equal(policyRuleSetIssues([...policyRules, policyRules[0]]).length, 1);
    assert.equal(policyRuleSetIssues([{ id: "compliance.ci" }]).length > 0, true);
    assert.equal(policyRuleSetIssues("rules").length, 1);
    assert.throws(() => createPolicyRuleRegistry({ rules: [] }));
    assert.equal(typeof createPolicyRuleRegistry({ rules: policyRules }).select, "function");
  });

  it("reports the preset, the inherited keys and the overridden keys", async () => {
    const { model, context } = await scanOf({
      ...policyFile({ preset: "web-production", ci: { maxReleaseWorkflows: 3 } }),
      "package.json": pkg(),
    });
    const engine = createRuleEngine({ registry: createPolicyRuleRegistry({ rules: policyRules }) });
    const run = await engine.runAll(context);
    assert.equal(run.findings.length, 1);
    const finding = run.findings[0];
    assert.equal(finding.ruleId, "policy.preset.audit");
    assert.equal(finding.severity, "info");
    assert.equal(finding.title.includes("web-production"), true);
    assert.equal(finding.title.length <= MAX_IDENTIFIER_LENGTH, true);
    // The audit cites the declaration that made the preset active.
    assert.deepEqual(finding.evidence, [...model.policy.coverage.evidenceIds]);
    assert.equal(finding.metadata.preset, "web-production");
    assert.equal(finding.metadata.presetActive, true);
    assert.deepEqual(finding.metadata.overriddenKeys, ["ci.maxReleaseWorkflows"]);
    assert.equal(finding.metadata.inheritedKeys.includes("container.requireHealthcheck"), true);
    assert.equal(finding.metadata.inheritedKeys.includes("ci.maxReleaseWorkflows"), false);
    assert.equal(
      finding.metadata.inheritedKeys.length + finding.metadata.overriddenKeys.length,
      POLICY_PRESET_KEY_IDS.length,
    );
    assert.equal(typeof finding.metadata.fingerprintKey, "string");
  });

  it("is informational only: never a violation, never a score, never a recommendation", async () => {
    const { context } = await scanOf({ ...policyFile({ preset: "strict" }), "package.json": pkg() });
    const engine = createRuleEngine({ registry: createPolicyRuleRegistry({ rules: policyRules }) });
    const run = await engine.runAll(context);
    assert.equal(run.findings.length, 1);
    for (const finding of run.findings) {
      assert.equal(finding.severity, "info");
      assert.equal(["low", "medium", "high", "critical"].includes(finding.severity), false);
      assert.deepEqual(finding.remediation, {});
      assert.equal(POLICY_SEVERITY_VALUES.includes(finding.severity), true);
      const text = `${finding.title} ${finding.description}`.toLowerCase();
      // The description may *deny* scoring; what it must never do is offer one.
      for (const forbidden of ["grade", "percent", "recommend the", "should use", "compliance score"]) {
        assert.equal(text.includes(forbidden), false, forbidden);
      }
    }
    // The engine's run status names "this rule produced findings" — the pack's own claim is the
    // finding, and its severity vocabulary is exactly {info}.
    assert.deepEqual(POLICY_SEVERITY_VALUES, ["info"]);
    assert.equal(run.rules.length, 1);
  });

  it("lists every inherited key for a preset the repository does not override", async () => {
    const { context } = await scanOf({ ...policyFile({ preset: "minimal" }), "package.json": pkg() });
    const engine = createRuleEngine({ registry: createPolicyRuleRegistry({ rules: policyRules }) });
    const run = await engine.runAll(context);
    const finding = run.findings[0];
    assert.deepEqual(finding.metadata.overriddenKeys, []);
    assert.deepEqual(finding.metadata.inheritedKeys, [...POLICY_PRESET_KEY_IDS].sort());
    assert.equal(
      Object.values(finding.metadata.sources).every((token) => isPresetSource(token)),
      true,
    );
  });

  it("reports no findings when no preset governs the repository", async () => {
    // No policy at all.
    const noPolicy = await scanOf({ "package.json": pkg() });
    const engine = createRuleEngine({ registry: createPolicyRuleRegistry({ rules: policyRules }) });
    const run = await engine.runAll(noPolicy.context);
    assert.deepEqual(run.findings, []);
    assert.equal(run.rules[0].status, RULE_OUTCOME_STATUSES.UNKNOWN);
    assert.equal(run.rules[0].applicability.coverage, APPLICABILITY_COVERAGE.UNKNOWN);
    assert.equal(run.rules[0].applicability.reason, POLICY_ABSTENTION_WORDING["preset-not-active"]);

    // A policy that names no preset.
    const namedNone = await scanOf({
      ...policyFile({ container: { requireHealthcheck: true } }),
      "package.json": pkg(),
    });
    const second = await engine.runAll(namedNone.context);
    assert.deepEqual(second.findings, []);
    assert.equal(second.rules[0].status, RULE_OUTCOME_STATUSES.UNKNOWN);
    assert.equal(second.rules[0].applicability.reason, POLICY_ABSTENTION_WORDING["preset-not-active"]);

    // A policy whose reading established nothing.
    const unknownPreset = await scanOf({
      ...policyFile({ preset: "nope" }),
      "package.json": pkg(),
    });
    const third = await engine.runAll(unknownPreset.context);
    assert.deepEqual(third.findings, []);
    assert.equal(third.rules[0].applicability.reason, POLICY_ABSTENTION_WORDING["policy-not-established"]);
  });

  it("abstains, with its own reason, when this model carries no policy area", async () => {
    const { model } = await scanOf({ ...policyFile({ preset: "minimal" }), "package.json": pkg() });
    const bare = { ...clone(model), policy: {} };
    const context = buildAnalysisContext({ repository: bare });
    const engine = createRuleEngine({ registry: createPolicyRuleRegistry({ rules: policyRules }) });
    const run = await engine.runAll(context);
    assert.deepEqual(run.findings, []);
    assert.equal(run.rules[0].applicability.reason, POLICY_ABSTENTION_WORDING["no-policy-area"]);
  });

  it("reads the preset answer through its own signal readers", async () => {
    const { context } = await scanOf({
      ...policyFile({ preset: "backend-service", api: { requireResolvedMiddleware: false } }),
      "package.json": pkg(),
    });
    const query = context.repository ? createRepositoryQuery(context.repository) : null;
    assert.equal(policyArea(query).state, POLICY_STATES.ESTABLISHED);
    assert.equal(activePreset(query).name, "backend-service");
    assert.equal(effectivePolicySignal(query).preset, "backend-service");
    assert.deepEqual(policyProvenanceSignal(query).overridden, ["api.requireResolvedMiddleware"]);
  });

  it("runs as an ordinary analyzer over the accepted framework", async () => {
    const { context } = await scanOf({ ...policyFile({ preset: "library" }), "package.json": pkg() });
    const analyzers = createAnalyzerEngine({
      registry: createAnalyzerRegistry([createPolicyAnalyzer()]),
    });
    const result = await analyzers.runAll(context);
    assert.equal(result.findings.length, 1);
    const finding = result.findings[0];
    assert.equal(finding.ruleId, "policy.preset.audit");
    assert.equal(finding.severity, "info");
    assert.equal(finding.metadata.preset, "library");
    assert.equal(typeof finding.fingerprint, "string");

    const again = await analyzers.runAll(context);
    assert.deepEqual(
      again.findings.map((entry) => entry.fingerprint),
      result.findings.map((entry) => entry.fingerprint),
    );
    assert.equal(createPolicyAnalyzer().id, POLICY_ANALYZER_ID);
    assert.equal(createPolicyAnalyzer().name, POLICY_ANALYZER_NAME);
    assert.equal(createPolicyAnalyzer().scope, POLICY_ANALYZER_SCOPE);
  });
});

// ─── Architectural boundary ──────────────────────────────────────────────────

describe("preset layer: architectural boundary", () => {
  const POLICY_DIR = join(process.cwd(), "src", "policy");
  const PACK_DIR = join(process.cwd(), "src", "rules", "policy");
  const FORBIDDEN = [
    "node:fs",
    "node:path",
    "node:process",
    "child_process",
    "node:child_process",
    "node:net",
    "node:http",
    "node:https",
    "node:dns",
    "node:worker_threads",
    "tools.js",
    "tool-registry",
    "http-server",
    "stdio-server",
    "../repository",
    "../../repository/scanner",
  ];

  const sourcesOf = (dir) =>
    readdirSync(dir, { withFileTypes: true })
      .filter((entry) => entry.name.endsWith(".js"))
      .map((entry) => ({ name: entry.name, text: readFileSync(join(dir, entry.name), "utf8") }));

  it("makes the preset layer a leaf: it imports only its own siblings", () => {
    const sources = sourcesOf(POLICY_DIR);
    assert.equal(sources.length, 6);
    assert.deepEqual(
      sources.map((entry) => entry.name).sort(),
      ["contracts.js", "errors.js", "index.js", "presets.js", "registry.js", "resolver.js"],
    );
    for (const { name, text } of sources) {
      for (const match of text.matchAll(/from\s+"([^"]+)"/g)) {
        assert.equal(match[1].startsWith("./"), true, `${name} imports "${match[1]}"`);
      }
      assert.equal(/import\s*\(/.test(text), false, `${name} uses a dynamic import`);
      for (const forbidden of FORBIDDEN) {
        assert.equal(text.includes(`"${forbidden}"`), false, `${name} references "${forbidden}"`);
      }
      assert.equal(/\bnew Date\b/.test(text), false, `${name} must not construct a Date`);
      assert.equal(/\bDate\.now\b/.test(text), false, `${name} must not read the clock`);
      assert.equal(/\bMath\.random\b/.test(text), false, `${name} must not use randomness`);
      assert.equal(/\bprocess\.env\b/.test(text), false, `${name} must not read the environment`);
      assert.equal(/\beval\s*\(/.test(text), false, `${name} must not evaluate`);
    }
  });

  it("keeps the rule pack off every acquisition, preset and transport boundary", () => {
    const sources = sourcesOf(PACK_DIR);
    const nested = sourcesOf(join(PACK_DIR, "rules")).map((entry) => ({
      name: `rules/${entry.name}`,
      text: entry.text,
    }));
    assert.ok(sources.length + nested.length >= 6);
    for (const { name, text } of [...sources, ...nested]) {
      assert.equal(
        text.includes("../../policy/index.js") || text.includes("../policy/index.js"),
        false,
        `${name} must not import the preset layer directly`,
      );
      for (const forbidden of FORBIDDEN) {
        assert.equal(text.includes(`"${forbidden}"`), false, `${name} references "${forbidden}"`);
      }
      assert.equal(/\bnew Date\b/.test(text), false, `${name} must not construct a Date`);
      assert.equal(/\bMath\.random\b/.test(text), false, `${name} must not use randomness`);
      assert.equal(/\bprocess\.env\b/.test(text), false, `${name} must not read the environment`);
    }
  });
});
