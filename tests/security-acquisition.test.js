/**
 * Code Guardian — Phase 12 Correction Tests
 *
 * Focused tests for the three recorded Phase 12 gaps:
 *
 *   1. symlink escape detection      (filesystem `readLink` → scanner target
 *                                     classification → model → security rule)
 *   2. content-level secret detection (bounded inspection → evidence → rule)
 *   3. `.dockerignore` build context  (the container rule's context model)
 *
 * The suite follows the accepted suites' conventions: real repositories in an
 * OS-temp directory are scanned for the acquisition-level tests, and hand-built
 * `ScanResult`s are used where a case cannot be produced portably (a symlink the
 * platform refuses to create, a legacy scan with no content section, a budget that
 * would need a 300 MB fixture). Nothing here spawns a process or touches the
 * network, and no fixture ever contains a real credential.
 *
 * Run with: node --test tests/security-acquisition.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";

import { ValidationError } from "../src/core/index.js";

import {
  CONTENT_INSPECTION_LIMITS,
  CONTENT_PATTERN_IDS,
  MAX_SYMLINK_CHAIN,
  SYMLINK_TARGET_KINDS,
  createScanResult,
  resolveSymlinkChain,
  scanRepository,
  validateScanResult,
} from "../src/repository/scanner/index.js";
import {
  CONTENT_STATUSES,
  SYMLINK_TARGET_REASONS,
  buildRepositoryModel,
  getEvidence,
} from "../src/repository/model/index.js";
import {
  buildAnalysisContext,
  createAnalyzerEngine,
  createAnalyzerRegistry,
} from "../src/analysis/index.js";

import {
  CONTENT_PATTERNS,
  FINDING_BASES,
  RULE_OUTCOME_STATUSES,
  SECURITY_CONFIDENCE,
  SECURITY_RULE_IDS,
  createRuleEngine,
  createSecurityAnalyzer,
  createSecurityRuleRegistry,
  securityRules,
} from "../src/rules/index.js";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const TMP_ROOT = join(tmpdir(), `cg-corrections-${process.pid}-${Date.now()}`);
let counter = 0;

/** Create a disposable repository fixture. */
function makeRepo(files = {}, dirs = []) {
  const root = join(TMP_ROOT, `repo-${counter++}`);
  mkdirSync(root, { recursive: true });
  for (const dir of dirs) mkdirSync(join(root, dir), { recursive: true });
  for (const [relative, content] of Object.entries(files)) {
    const full = join(root, relative);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
  return root;
}

const SYMLINKS_AVAILABLE = (() => {
  const probe = mkdtempSync(join(tmpdir(), "cg-corrections-symlink-probe-"));
  try {
    symlinkSync(probe, join(probe, "link"), "dir");
    return true;
  } catch {
    return false;
  } finally {
    rmSync(probe, { recursive: true, force: true });
  }
})();
const SYMLINK_SKIP = SYMLINKS_AVAILABLE
  ? false
  : "symlinks are unavailable on this platform/account";

after(() => {
  rmSync(TMP_ROOT, { recursive: true, force: true });
});

/** A token-shaped string the tests prove never leaves the acquisition layers. */
const NPM_TOKEN = "npm_TOKEN_do_NOT_leak_4f9a2c";
const TFVARS_PASSWORD = "db_PASSWORD_do_NOT_leak_17bd";
const PEM_BODY = "MIIEowIBAAKCAQEA_do_NOT_leak_9c1f";

const symlinkFor = (scan, path) => scan.symlinks.find((entry) => entry.path === path);
const candidateFor = (scan, path) =>
  scan.content.candidates.find((entry) => entry.path === path);

async function modelOf(root) {
  return buildRepositoryModel(await scanRepository(root));
}

const contextOf = (model) => buildAnalysisContext({ repository: model });

async function runRules(model, { rules = securityRules, failFast = false } = {}) {
  const engine = createRuleEngine({ registry: createSecurityRuleRegistry({ rules }), failFast });
  return engine.runAll(contextOf(model));
}

async function runAnalyzer(model) {
  const engine = createAnalyzerEngine({
    registry: createAnalyzerRegistry([createSecurityAnalyzer()]),
  });
  return engine.runAll(contextOf(model));
}

const statusOf = (run, ruleId) =>
  run.rules.find((entry) => entry.rule.id === ruleId)?.status;
const resultOf = (run, ruleId) =>
  run.rules.find((entry) => entry.rule.id === ruleId);

/** Every path-shaped string a serialized artifact contains. */
function absolutePathsIn(value) {
  const found = [];
  const walk = (node) => {
    if (typeof node === "string") {
      if (isAbsolute(node)) found.push(node);
      return;
    }
    if (node === null || typeof node !== "object") return;
    for (const child of Array.isArray(node) ? node : Object.values(node)) walk(child);
  };
  walk(value);
  return found;
}

// ─── 1. Symlink targets: filesystem classification ───────────────────────────

describe("correction 1: symlink target classification", () => {
  it("resolves a chain without filesystem access", () => {
    const oneHop = new Map([
      ["a", { kind: SYMLINK_TARGET_KINDS.INSIDE, path: "b", reason: null }],
      ["b", { kind: SYMLINK_TARGET_KINDS.INSIDE, path: "c", reason: null }],
      ["c", { kind: SYMLINK_TARGET_KINDS.INSIDE, path: "src/file.ts", reason: null }],
      ["escape", { kind: SYMLINK_TARGET_KINDS.INSIDE, path: "out", reason: null }],
      ["out", { kind: SYMLINK_TARGET_KINDS.OUTSIDE, path: null, reason: null }],
    ]);

    assert.deepEqual(resolveSymlinkChain("a", oneHop), {
      kind: SYMLINK_TARGET_KINDS.INSIDE,
      path: "src/file.ts",
      reason: null,
    });
    // A chain that ends outside is an escape, even though the first hop is inside.
    assert.equal(resolveSymlinkChain("escape", oneHop).kind, SYMLINK_TARGET_KINDS.OUTSIDE);
  });

  it("reports a cycle and an over-long chain as unknown, never as safe", () => {
    const cyclic = new Map([
      ["a", { kind: SYMLINK_TARGET_KINDS.INSIDE, path: "b", reason: null }],
      ["b", { kind: SYMLINK_TARGET_KINDS.INSIDE, path: "a", reason: null }],
    ]);
    assert.deepEqual(resolveSymlinkChain("a", cyclic), {
      kind: SYMLINK_TARGET_KINDS.UNKNOWN,
      path: null,
      reason: SYMLINK_TARGET_REASONS.CYCLE,
    });

    const long = new Map();
    for (let index = 0; index < MAX_SYMLINK_CHAIN + 4; index += 1) {
      long.set(`l${index}`, {
        kind: SYMLINK_TARGET_KINDS.INSIDE,
        path: `l${index + 1}`,
        reason: null,
      });
    }
    long.set(`l${MAX_SYMLINK_CHAIN + 4}`, {
      kind: SYMLINK_TARGET_KINDS.INSIDE,
      path: "real/file.ts",
      reason: null,
    });
    assert.equal(
      resolveSymlinkChain("l0", long).reason,
      SYMLINK_TARGET_REASONS.DEPTH_EXCEEDED,
    );
  });

  it("treats a link with no recorded target as unknown, not inside", () => {
    assert.deepEqual(resolveSymlinkChain("a", new Map()), {
      kind: SYMLINK_TARGET_KINDS.UNKNOWN,
      path: null,
      reason: SYMLINK_TARGET_REASONS.NOT_INSPECTED,
    });
  });

  it(
    "classifies inside, outside, chained and cyclic links from a real repository",
    { skip: SYMLINK_SKIP },
    async () => {
      const outside = makeRepo({ "secret.txt": "top secret" });
      const root = makeRepo({ "src/app.ts": "", "keep.txt": "" }, ["a", "b"]);
      symlinkSync(join(root, "keep.txt"), join(root, "inside-link"), "file");
      symlinkSync(join(outside, "secret.txt"), join(root, "escape-link"), "file");
      symlinkSync("../escape-link", join(root, "a", "hop"), "file");
      symlinkSync("../a/hop", join(root, "b", "back"), "file");
      symlinkSync("missing-target", join(root, "broken"), "file");

      const scan = await scanRepository(root);

      assert.deepEqual(symlinkFor(scan, "inside-link").target, {
        kind: SYMLINK_TARGET_KINDS.INSIDE,
        path: "keep.txt",
        reason: null,
      });
      assert.equal(symlinkFor(scan, "escape-link").target.kind, SYMLINK_TARGET_KINDS.OUTSIDE);
      // Both hops lead, through recorded link facts alone, to the escaping link.
      assert.equal(symlinkFor(scan, "a/hop").target.kind, SYMLINK_TARGET_KINDS.OUTSIDE);
      assert.equal(symlinkFor(scan, "b/back").target.kind, SYMLINK_TARGET_KINDS.OUTSIDE);
      // A broken link cannot escape: its target is inside the repository.
      assert.deepEqual(symlinkFor(scan, "broken").target, {
        kind: SYMLINK_TARGET_KINDS.INSIDE,
        path: "missing-target",
        reason: null,
      });

      // No host location is recorded anywhere in the symlink inventory.
      assert.deepEqual(absolutePathsIn(scan.symlinks), []);
      assert.equal(JSON.stringify(scan.symlinks).includes(outside), false);
    },
  );

  it(
    "records a cycle between two links as unknown",
    { skip: SYMLINK_SKIP },
    async () => {
      const root = makeRepo({ "keep.txt": "" }, ["a"]);
      symlinkSync("../a/one", join(root, "a", "two"), "file");
      symlinkSync("../a/two", join(root, "a", "one"), "file");

      const scan = await scanRepository(root);
      assert.equal(symlinkFor(scan, "a/one").target.reason, SYMLINK_TARGET_REASONS.CYCLE);
      assert.equal(symlinkFor(scan, "a/two").target.reason, SYMLINK_TARGET_REASONS.CYCLE);
      assert.equal(scan.scan.complete, true);
    },
  );

  it("produces identical symlink target records for the same repository", async () => {
    const root = makeRepo({ "keep.txt": "" });
    const first = await scanRepository(root);
    const second = await scanRepository(root);
    assert.deepEqual(first.symlinks, second.symlinks);
  });

  it("rejects a malformed symlink target contract", () => {
    const base = (target) => ({
      root: "/scan-root",
      scannedAt: "2026-01-01T00:00:00.000Z",
      symlinks: [{ path: "link", name: "link", depth: 1, target }],
      scan: { complete: true, truncated: false, limits: {}, errors: [] },
    });

    // An absolute path must never be recorded, even for an inside target.
    assert.throws(
      () =>
        validateScanResult(
          createScanResult(
            base({ kind: SYMLINK_TARGET_KINDS.INSIDE, path: "/etc/passwd", reason: null }),
          ),
        ),
      ValidationError,
    );
    // An outside target must carry no location at all.
    assert.throws(
      () =>
        validateScanResult(
          createScanResult(
            base({ kind: SYMLINK_TARGET_KINDS.OUTSIDE, path: "somewhere", reason: null }),
          ),
        ),
      ValidationError,
    );
    // An unknown target must say why.
    assert.throws(
      () => validateScanResult(createScanResult(base({ kind: "unknown", path: null }))),
      ValidationError,
    );
    assert.throws(
      () => validateScanResult(createScanResult(base({ kind: "elsewhere", path: null }))),
      ValidationError,
    );
    // A symlink with no target at all is valid and means "not inspected".
    assert.ok(validateScanResult(createScanResult(base(undefined))));
  });
});

// ─── 2. Content: bounded inspection ──────────────────────────────────────────

describe("correction 2: bounded content inspection", () => {
  it("detects credential-shaped content in every candidate class", async () => {
    const root = makeRepo({
      ".npmrc": `//registry.npmjs.org/:_authToken=${NPM_TOKEN}\nregistry=https://registry.npmjs.org/\n`,
      ".pypirc": "[pypi]\nusername = ci\npassword = p4ssw0rd_not_real\n",
      ".envrc": "export AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n",
      ".env": `DATABASE_PASSWORD=${TFVARS_PASSWORD}\nREGION=eu-west-1\n`,
      "prod.tfvars": 'db_password = "not-a-real-value"\nregion = "eu-west-1"\n',
      "dump.sql": "CREATE USER bob IDENTIFIED BY 'not-a-real-password';\n",
    });

    const scan = await scanRepository(root);
    assert.equal(scan.content.inspected, true);
    assert.equal(scan.content.complete, true);
    assert.equal(scan.content.truncated, false);

    assert.deepEqual(candidateFor(scan, ".npmrc").patterns, [
      CONTENT_PATTERNS.CREDENTIAL_ASSIGNMENT,
    ]);
    assert.deepEqual(candidateFor(scan, ".pypirc").patterns, [
      CONTENT_PATTERNS.CREDENTIAL_ASSIGNMENT,
    ]);
    assert.deepEqual(candidateFor(scan, ".envrc").patterns, [
      CONTENT_PATTERNS.AWS_CREDENTIAL_ASSIGNMENT,
      CONTENT_PATTERNS.CREDENTIAL_ASSIGNMENT,
    ]);
    assert.deepEqual(candidateFor(scan, ".env").patterns, [
      CONTENT_PATTERNS.CREDENTIAL_ASSIGNMENT,
    ]);
    assert.deepEqual(candidateFor(scan, "prod.tfvars").patterns, [
      CONTENT_PATTERNS.CREDENTIAL_ASSIGNMENT,
    ]);
    assert.deepEqual(candidateFor(scan, "dump.sql").patterns, [
      CONTENT_PATTERNS.SQL_PASSWORD_STATEMENT,
    ]);
    assert.equal(candidateFor(scan, ".npmrc").candidate, "npm-config");
  });

  it("reports clean content as inspected-with-no-match, not as unknown", async () => {
    const root = makeRepo({
      ".env": "REGION=eu-west-1\nLOG_LEVEL=info\n",
      ".npmrc": "registry=https://registry.npmjs.org/\n",
    });

    const scan = await scanRepository(root);
    assert.equal(scan.content.complete, true);
    for (const path of [".env", ".npmrc"]) {
      const candidate = candidateFor(scan, path);
      assert.equal(candidate.inspected, true);
      assert.equal(candidate.reason, null);
      assert.deepEqual(candidate.patterns, []);
    }
  });

  it("does not inspect a file that is not a candidate, and does not guess from a name alone", async () => {
    const root = makeRepo({
      "secrets.json": `{"password": "${TFVARS_PASSWORD}"}\n`,
      "notes.md": `password = ${TFVARS_PASSWORD}\n`,
    });

    const scan = await scanRepository(root);
    assert.deepEqual(scan.content.candidates, []);
    assert.equal(scan.content.inspected, false);
    // Nothing to inspect and nothing that stopped an inspection: the section is
    // complete over an empty candidate set, and the rules fall back to the file
    // inventory for their absence claim.
    assert.equal(scan.content.complete, true);
    assert.equal(scan.content.truncated, false);
  });

  it("reports a non-text candidate as uninspected with a reason", async () => {
    const root = makeRepo({ ".env": "ab\u0000cd" });
    const scan = await scanRepository(root);

    const candidate = candidateFor(scan, ".env");
    assert.equal(candidate.inspected, false);
    assert.equal(candidate.reason, "not-text");
    assert.deepEqual(candidate.patterns, []);
    assert.equal(scan.content.complete, false);
  });

  it("marks an oversized candidate truncated instead of claiming a clean file", async () => {
    const big = `${"a".repeat(CONTENT_INSPECTION_LIMITS.maxFileBytes)}x`;
    const root = makeRepo({ ".env": big });

    const scan = await scanRepository(root);
    const candidate = candidateFor(scan, ".env");
    assert.equal(candidate.inspected, true);
    assert.equal(candidate.truncated, true);
    assert.equal(candidate.bytesInspected, CONTENT_INSPECTION_LIMITS.maxFileBytes);
    // A partially read file is not a complete inspection.
    assert.equal(scan.content.complete, false);
    assert.equal(scan.content.truncated, true);
  });

  it("records budget exhaustion instead of dropping candidates", async () => {
    const files = {};
    const total = CONTENT_INSPECTION_LIMITS.maxFiles + 1;
    for (let index = 0; index < total; index += 1) {
      files[`.env.${String(index).padStart(2, "0")}`] = "REGION=eu-west-1\n";
    }
    const root = makeRepo(files);

    const scan = await scanRepository(root);
    assert.equal(scan.content.candidates.length, total);
    const expired = scan.content.candidates.filter(
      (candidate) => candidate.reason === "budget-exhausted",
    );
    assert.equal(expired.length, 1);
    assert.equal(expired[0].inspected, false);
    assert.equal(scan.content.complete, false);
    assert.equal(scan.content.truncated, true);
  });

  it("never puts a matched value into the scan result", async () => {
    const root = makeRepo({
      ".npmrc": `//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n`,
      ".env": `DATABASE_PASSWORD=${TFVARS_PASSWORD}\nPRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n${PEM_BODY}\n-----END RSA PRIVATE KEY-----"\n`,
    });

    const serialized = JSON.stringify(await scanRepository(root));
    for (const secret of [NPM_TOKEN, TFVARS_PASSWORD, PEM_BODY]) {
      assert.equal(serialized.includes(secret), false, `leaked ${secret}`);
    }
    // The pattern that matched is reported; the value it matched is not.
    assert.equal(serialized.includes("credential-assignment"), true);
    assert.equal(serialized.includes("private-key-block"), true);
  });

  it("keeps absolute host paths out of the content section", async () => {
    const root = makeRepo({ ".env": `DATABASE_PASSWORD=${TFVARS_PASSWORD}\n` });
    const scan = await scanRepository(root);
    assert.deepEqual(absolutePathsIn(scan.content), []);
  });

  it("produces identical content sections for the same repository", async () => {
    const root = makeRepo({ ".env": "A=1\n", ".npmrc": "registry=https://x/\n" });
    const first = await scanRepository(root);
    const second = await scanRepository(root);
    assert.deepEqual(first.content, second.content);
  });

  it("exposes a closed pattern vocabulary", () => {
    assert.deepEqual([...CONTENT_PATTERN_IDS].sort(), Object.values(CONTENT_PATTERNS).sort());
  });

  it("rejects a malformed content section", () => {
    const base = (content) => ({
      root: "/scan-root",
      scannedAt: "2026-01-01T00:00:00.000Z",
      files: [
        { path: ".env", name: ".env", isDirectory: false, extension: "", depth: 1 },
      ],
      content,
      scan: { complete: true, truncated: false, limits: {}, errors: [] },
    });
    const candidate = (extra) => ({
      path: ".env",
      candidate: "dotenv",
      inspected: true,
      reason: null,
      bytesInspected: 4,
      truncated: false,
      patterns: [],
      ...extra,
    });
    const section = (candidates, extra = {}) => ({
      inspected: true,
      complete: true,
      truncated: false,
      candidates,
      limits: {},
      ...extra,
    });

    // Completeness cannot be claimed while a candidate is unknown.
    assert.throws(
      () =>
        validateScanResult(
          createScanResult(
            base(
              section([
                candidate({ inspected: false, reason: "budget-exhausted" }),
              ]),
            ),
          ),
        ),
      ValidationError,
    );
    // An uninspected candidate must say why.
    assert.throws(
      () =>
        validateScanResult(
          createScanResult(
            base(section([candidate({ inspected: false, reason: null })], { complete: false })),
          ),
        ),
      ValidationError,
    );
    // Pattern ids must be sorted and unique.
    assert.throws(
      () =>
        validateScanResult(
          createScanResult(
            base(section([candidate({ patterns: ["b", "a"] })])),
          ),
        ),
      ValidationError,
    );
    // Candidates must be sorted by path.
    assert.throws(
      () =>
        validateScanResult(
          createScanResult(
            base({
              ...section([candidate({ path: "b" }), candidate({ path: "a" })]),
            }),
          ),
        ),
      ValidationError,
    );
    assert.ok(
      validateScanResult(createScanResult(base(section([candidate({})])))),
    );
  });
});

// ─── 3. Model projections ────────────────────────────────────────────────────

describe("corrections 1–2: model projections", () => {
  it(
    "carries the closed symlink target vocabulary onto the entity",
    { skip: SYMLINK_SKIP },
    async () => {
      const root = makeRepo({ "keep.txt": "" });
      symlinkSync(join(root, "keep.txt"), join(root, "alias"), "file");
      const model = await modelOf(root);
    const link = model.files.symlinks[0];
      assert.equal(link.followed, false);
      assert.deepEqual(link.target, { kind: "inside", path: "keep.txt", reason: null });

      // The inventory observation records the same fact, so a finding can cite it.
      const evidence = getEvidence(model, link.evidenceIds[0]);
      assert.equal(evidence.data.targetKind, "inside");
      assert.equal(evidence.data.targetPath, "keep.txt");
    },
  );

  it("turns a scan that never classified its links into unknown", () => {
    const model = buildRepositoryModel(
      createScanResult({
        root: "/scan-root",
        scannedAt: "2026-01-01T00:00:00.000Z",
        symlinks: [{ path: "link", name: "link", depth: 1 }],
        scan: { complete: true, truncated: false, limits: {}, errors: [] },
      }),
    );
    assert.deepEqual(model.files.symlinks[0].target, {
      kind: "unknown",
      path: null,
      reason: "not-inspected",
    });
  });

  it("fails closed on a symlink target that is incoherent", () => {
    const build = (target) =>
      buildRepositoryModel(
        createScanResult({
          root: "/scan-root",
          scannedAt: "2026-01-01T00:00:00.000Z",
          symlinks: [{ path: "link", name: "link", depth: 1, target }],
          scan: { complete: true, truncated: false, limits: {}, errors: [] },
        }),
      );

    assert.throws(
      () => build({ kind: "inside", path: "/etc/passwd", reason: null }),
      ValidationError,
    );
    assert.throws(() => build({ kind: "sideways", path: null, reason: null }), ValidationError);
    assert.throws(
      () => build({ kind: "outside", path: null, reason: "cycle" }),
      ValidationError,
    );
  });

  it("projects content inspections as value-free observations", async () => {
    const root = makeRepo({ ".npmrc": `//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n` });
    const model = await modelOf(root);

    const file = model.indexes.entityIdsByPath
      ? null
      : null; // (the file entity is resolved through its id below)
    const fileId = `file:.npmrc`;
    assert.ok(file === null);

    const inspections = model.evidence.filter(
      (record) => record.location.path === ".npmrc" && record.data.signal === "content-inspection",
    );
    const patterns = model.evidence.filter(
      (record) => record.location.path === ".npmrc" && record.data.signal === "content-pattern",
    );

    assert.equal(inspections.length, 1);
    assert.equal(inspections[0].data.status, CONTENT_STATUSES.INSPECTED);
    assert.equal(inspections[0].data.reason, null);
    assert.deepEqual(patterns.map((record) => record.data.pattern), [
      CONTENT_PATTERNS.CREDENTIAL_ASSIGNMENT,
    ]);

    // The file entity carries them as its own provenance, and no record contains the
    // matched text.
    const entity = model.indexes.entitiesById[fileId];
    const cited = entity.evidenceIds.map((id) => getEvidence(model, id));
    assert.equal(cited.some((record) => record.data.signal === "content-pattern"), true);
    assert.equal(JSON.stringify(model.evidence).includes(NPM_TOKEN), false);
  });

  it("keeps an uninspected candidate distinguishable from a clean one", () => {
    const scan = createScanResult({
      root: "/scan-root",
      scannedAt: "2026-01-01T00:00:00.000Z",
      files: [
        { path: ".env", name: ".env", isDirectory: false, extension: "", depth: 1 },
        { path: ".npmrc", name: ".npmrc", isDirectory: false, extension: "", depth: 1 },
      ],
      content: {
        inspected: true,
        complete: false,
        truncated: true,
        limits: {},
        candidates: [
          { path: ".env", candidate: "dotenv", inspected: true, reason: null, bytesInspected: 4, truncated: true, patterns: [] },
          { path: ".npmrc", candidate: "npm-config", inspected: false, reason: "budget-exhausted", bytesInspected: 0, truncated: false, patterns: [] },
        ],
      },
      scan: { complete: true, truncated: false, limits: {}, errors: [] },
    });
    const model = buildRepositoryModel(scan);

    const statusOfPath = (path) =>
      model.evidence.find(
        (record) => record.location.path === path && record.data.signal === "content-inspection",
      ).data;
    assert.deepEqual(statusOfPath(".env"), {
      signal: "content-inspection",
      status: CONTENT_STATUSES.PARTIAL,
      reason: null,
      bytesInspected: 4,
    });
    assert.deepEqual(statusOfPath(".npmrc"), {
      signal: "content-inspection",
      status: CONTENT_STATUSES.UNINSPECTED,
      reason: "budget-exhausted",
      bytesInspected: 0,
    });
  });

  it("refuses a content candidate that is not an observed file", () => {
    const scan = createScanResult({
      root: "/scan-root",
      scannedAt: "2026-01-01T00:00:00.000Z",
      files: [{ path: "README.md", name: "README.md", isDirectory: false, extension: ".md", depth: 1 }],
      content: {
        inspected: true,
        complete: true,
        truncated: false,
        limits: {},
        candidates: [
          { path: ".env", candidate: "dotenv", inspected: true, reason: null, bytesInspected: 4, truncated: false, patterns: [] },
        ],
      },
      scan: { complete: true, truncated: false, limits: {}, errors: [] },
    });
    assert.throws(() => buildRepositoryModel(scan), ValidationError);
  });
});

// ─── 4. Security rule: symlink escape ────────────────────────────────────────

describe("correction 1: symlink escape rule", () => {
  it(
    "reports an escaping symlink and passes when every link stays inside",
    { skip: SYMLINK_SKIP },
    async () => {
      const outside = makeRepo({ "secret.txt": "top secret" });
      const escaping = await modelOf(
        (() => {
          const root = makeRepo({ "keep.txt": "" });
          symlinkSync(join(outside, "secret.txt"), join(root, "escape"), "file");
          return root;
        })(),
      );

      const run = await runRules(escaping);
      const entry = resultOf(run, SECURITY_RULE_IDS.SYMLINK_ESCAPE);
      assert.equal(entry.status, RULE_OUTCOME_STATUSES.VIOLATION);
      assert.deepEqual(entry.findings.map((finding) => finding.metadata.path), ["escape"]);
      assert.equal(entry.findings[0].metadata.basis, FINDING_BASES.LINK);
      assert.equal(entry.findings[0].confidence, SECURITY_CONFIDENCE.OBSERVED_LINK);
      assert.ok(entry.findings[0].evidence.length > 0);
      assert.equal(entry.rule.severity, "medium");

      const inside = await modelOf(
        (() => {
          const root = makeRepo({ "keep.txt": "" });
          symlinkSync(join(root, "keep.txt"), join(root, "alias"), "file");
          return root;
        })(),
      );
      const cleanRun = await runRules(inside);
      assert.equal(
        statusOf(cleanRun, SECURITY_RULE_IDS.SYMLINK_ESCAPE),
        RULE_OUTCOME_STATUSES.PASS,
      );
      assert.equal(
        resultOf(cleanRun, SECURITY_RULE_IDS.SYMLINK_ESCAPE).metadata.inside,
        1,
      );
    },
  );

  it("declines to call an unresolved link safe", () => {
    const model = buildRepositoryModel(
      createScanResult({
        root: "/scan-root",
        scannedAt: "2026-01-01T00:00:00.000Z",
        files: [{ path: "a.txt", name: "a.txt", isDirectory: false, extension: ".txt", depth: 1 }],
        symlinks: [{ path: "link", name: "link", depth: 1 }],
        scan: { complete: true, truncated: false, limits: {}, errors: [] },
      }),
    );

    return runRules(model).then((run) => {
      const entry = resultOf(run, SECURITY_RULE_IDS.SYMLINK_ESCAPE);
      assert.equal(entry.status, RULE_OUTCOME_STATUSES.UNKNOWN);
      assert.equal(entry.findings.length, 0);
      assert.ok(entry.applicability.reason.includes("not-inspected"));
    });
  });

  it("reports what it did observe even when other links are unresolved", () => {
    const model = buildRepositoryModel(
      createScanResult({
        root: "/scan-root",
        scannedAt: "2026-01-01T00:00:00.000Z",
        files: [{ path: "a.txt", name: "a.txt", isDirectory: false, extension: ".txt", depth: 1 }],
        symlinks: [
          { path: "escape", name: "escape", depth: 1, target: { kind: "outside", path: null, reason: null } },
          { path: "unknown", name: "unknown", depth: 1 },
        ],
        scan: { complete: true, truncated: false, limits: {}, errors: [] },
      }),
    );

    return runRules(model).then((run) => {
      const entry = resultOf(run, SECURITY_RULE_IDS.SYMLINK_ESCAPE);
      assert.equal(entry.status, RULE_OUTCOME_STATUSES.VIOLATION);
      assert.deepEqual(entry.findings.map((finding) => finding.metadata.path), ["escape"]);
      // The unresolved link is recorded rather than hidden.
      assert.equal(entry.metadata.unresolved, 1);
      assert.deepEqual(entry.metadata.unresolvedReasons, ["not-inspected"]);
    });
  });

  it("turns an absence claim over an incomplete inventory into unknown", () => {
    const model = buildRepositoryModel(
      createScanResult({
        root: "/scan-root",
        scannedAt: "2026-01-01T00:00:00.000Z",
        files: [{ path: "a.txt", name: "a.txt", isDirectory: false, extension: ".txt", depth: 1 }],
        statistics: { filesScanned: 1, directoriesScanned: 0, symlinksScanned: 0, ignored: 0, unreadable: 0, truncatedBy: ["file-limit"] },
        scan: { complete: false, truncated: true, limits: {}, errors: [] },
      }),
    );

    return runRules(model).then((run) => {
      assert.equal(statusOf(run, SECURITY_RULE_IDS.SYMLINK_ESCAPE), RULE_OUTCOME_STATUSES.UNKNOWN);
    });
  });

  it(
    "never leaks the link's host target into a finding, an observation or an error",
    { skip: SYMLINK_SKIP },
    async () => {
      const outside = makeRepo({ "secret.txt": "top secret" });
      const root = makeRepo({ "keep.txt": "" });
      symlinkSync(join(outside, "secret.txt"), join(root, "escape"), "file");
      const model = await modelOf(root);
      const run = await runRules(model);

      const serialized = JSON.stringify({
        findings: run.findings,
        evidence: run.evidence,
        rules: run.rules.map((entry) => ({ metadata: entry.metadata, evidence: entry.evidence })),
        errors: run.rules.flatMap((entry) => entry.errors),
      });
      assert.equal(serialized.includes(outside), false);
      assert.equal(serialized.includes("secret.txt"), false);
      assert.deepEqual(absolutePathsIn(run.findings), []);
      assert.deepEqual(absolutePathsIn(run.evidence), []);
    },
  );

  it("produces identical findings and fingerprints for the same model", async () => {
    const model = buildRepositoryModel(
      createScanResult({
        root: "/scan-root",
        scannedAt: "2026-01-01T00:00:00.000Z",
        files: [{ path: "a.txt", name: "a.txt", isDirectory: false, extension: ".txt", depth: 1 }],
        symlinks: [
          { path: "escape", name: "escape", depth: 1, target: { kind: "outside", path: null, reason: null } },
        ],
        scan: { complete: true, truncated: false, limits: {}, errors: [] },
      }),
    );

    const first = await runAnalyzer(model);
    const second = await runAnalyzer(model);
    assert.deepEqual(
      first.findings.map((finding) => finding.fingerprint),
      second.findings.map((finding) => finding.fingerprint),
    );
    assert.equal(first.findings.some((finding) => finding.ruleId === SECURITY_RULE_IDS.SYMLINK_ESCAPE), true);
  });
});

// ─── 5. Security rules: content ──────────────────────────────────────────────

describe("correction 2: content rules", () => {
  it("reports a credential-shaped value and cites the pattern observation", async () => {
    const model = await modelOf(
      makeRepo({ ".npmrc": `//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n` }),
    );
    const run = await runRules(model);
    const entry = resultOf(run, SECURITY_RULE_IDS.CREDENTIAL_CONTENT);

    assert.equal(entry.status, RULE_OUTCOME_STATUSES.VIOLATION);
    assert.deepEqual(entry.findings.map((finding) => finding.metadata.path), [".npmrc"]);
    assert.deepEqual(entry.findings[0].metadata.patterns, [
      CONTENT_PATTERNS.CREDENTIAL_ASSIGNMENT,
    ]);
    assert.equal(entry.findings[0].metadata.basis, FINDING_BASES.CONTENT);
    assert.equal(entry.findings[0].confidence, SECURITY_CONFIDENCE.OBSERVED_CONTENT);
    // The file's inventory evidence, its content inspection, and the pattern that
    // matched — all of them the model's own records.
    assert.equal(entry.findings[0].evidence.length, 3);

    // The key-block rule stays silent about a credential assignment.
    assert.equal(
      statusOf(run, SECURITY_RULE_IDS.PRIVATE_KEY_CONTENT),
      RULE_OUTCOME_STATUSES.PASS,
    );
  });

  it("reports an inlined private-key block", async () => {
    const model = await modelOf(
      makeRepo({
        "secrets.tfvars": `tls_key = "-----BEGIN RSA PRIVATE KEY-----\n${PEM_BODY}\n-----END RSA PRIVATE KEY-----"\n`,
      }),
    );
    const run = await runRules(model);
    const entry = resultOf(run, SECURITY_RULE_IDS.PRIVATE_KEY_CONTENT);
    assert.equal(entry.status, RULE_OUTCOME_STATUSES.VIOLATION);
    assert.deepEqual(entry.findings[0].metadata.patterns, [
      CONTENT_PATTERNS.PRIVATE_KEY_BLOCK,
    ]);
  });

  it("never lets the matched value reach a finding, an observation or an error", async () => {
    const model = await modelOf(
      makeRepo({
        ".npmrc": `//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n`,
        ".env": `DATABASE_PASSWORD=${TFVARS_PASSWORD}\n`,
      }),
    );
    const run = await runRules(model);
    const analysis = await runAnalyzer(model);

    for (const artifact of [run, analysis]) {
      const serialized = JSON.stringify(artifact);
      for (const secret of [NPM_TOKEN, TFVARS_PASSWORD]) {
        assert.equal(serialized.includes(secret), false, `leaked ${secret}`);
      }
      assert.deepEqual(absolutePathsIn(artifact.findings ?? []), []);
    }
  });

  it("treats a candidate with no inspection record as unknown, not clean", async () => {
    // A scan built before content inspection existed: the candidate exists as a file
    // and the content section says nothing.
    const model = buildRepositoryModel(
      createScanResult({
        root: "/scan-root",
        scannedAt: "2026-01-01T00:00:00.000Z",
        files: [{ path: ".npmrc", name: ".npmrc", isDirectory: false, extension: "", depth: 1 }],
        scan: { complete: true, truncated: false, limits: {}, errors: [] },
      }),
    );
    const run = await runRules(model);
    const entry = resultOf(run, SECURITY_RULE_IDS.CREDENTIAL_CONTENT);
    assert.equal(entry.status, RULE_OUTCOME_STATUSES.UNKNOWN);
    assert.ok(entry.applicability.reason.includes("no-inspection-recorded"));
  });

  it("treats a partially inspected candidate as unknown", async () => {
    const big = `${"a".repeat(CONTENT_INSPECTION_LIMITS.maxFileBytes + 1)}`;
    const model = await modelOf(makeRepo({ ".env": big }));
    const run = await runRules(model);

    for (const ruleId of [
      SECURITY_RULE_IDS.CREDENTIAL_CONTENT,
      SECURITY_RULE_IDS.PRIVATE_KEY_CONTENT,
    ]) {
      const entry = resultOf(run, ruleId);
      assert.equal(entry.status, RULE_OUTCOME_STATUSES.UNKNOWN, ruleId);
      assert.ok(entry.applicability.reason.includes("partial"), ruleId);
    }
  });

  it("treats an exhausted budget and a non-text candidate as unknown", async () => {
    const files = { ".env": "ab\u0000cd" };
    for (let index = 0; index < CONTENT_INSPECTION_LIMITS.maxFiles + 1; index += 1) {
      files[`.env.${String(index).padStart(2, "0")}`] = "A=1\n";
    }
    const run = await runRules(await modelOf(makeRepo(files)));
    const entry = resultOf(run, SECURITY_RULE_IDS.CREDENTIAL_CONTENT);

    assert.equal(entry.status, RULE_OUTCOME_STATUSES.UNKNOWN);
    const reason = entry.applicability.reason;
    assert.ok(reason.includes("budget-exhausted"), reason);
    assert.ok(reason.includes("not-text"), reason);
  });

  it("passes only when every candidate was fully inspected", async () => {
    const run = await runRules(await modelOf(makeRepo({ ".npmrc": "registry=https://x/\n" })));
    assert.equal(
      statusOf(run, SECURITY_RULE_IDS.CREDENTIAL_CONTENT),
      RULE_OUTCOME_STATUSES.PASS,
    );
    assert.equal(
      statusOf(run, SECURITY_RULE_IDS.PRIVATE_KEY_CONTENT),
      RULE_OUTCOME_STATUSES.PASS,
    );
  });

  it("turns an absence claim over an incomplete inventory into unknown", async () => {
    const model = buildRepositoryModel(
      createScanResult({
        root: "/scan-root",
        scannedAt: "2026-01-01T00:00:00.000Z",
        files: [{ path: "a.txt", name: "a.txt", isDirectory: false, extension: ".txt", depth: 1 }],
        statistics: { filesScanned: 1, directoriesScanned: 0, symlinksScanned: 0, ignored: 0, unreadable: 0, truncatedBy: ["file-limit"] },
        scan: { complete: false, truncated: true, limits: {}, errors: [] },
      }),
    );
    const run = await runRules(model);
    assert.equal(
      statusOf(run, SECURITY_RULE_IDS.CREDENTIAL_CONTENT),
      RULE_OUTCOME_STATUSES.UNKNOWN,
    );
  });

  it("produces identical findings and fingerprints for the same model", async () => {
    const model = await modelOf(
      makeRepo({ ".npmrc": `//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n` }),
    );
    const first = await runAnalyzer(model);
    const second = await runAnalyzer(model);
    assert.deepEqual(
      first.findings.map((finding) => finding.fingerprint),
      second.findings.map((finding) => finding.fingerprint),
    );
    for (const finding of first.findings) {
      assert.match(finding.fingerprint, /^cg-fp1-[0-9a-f]{32}$/);
    }
  });
});

// ─── 6. Security rule: docker build context ──────────────────────────────────

describe("correction 3: docker build context", () => {
  const runContainer = async (files) => {
    const run = await runRules(await modelOf(makeRepo(files)));
    return resultOf(run, SECURITY_RULE_IDS.CONTAINER_IGNORE);
  };

  it("passes when the ignore file sits at the Dockerfile's own directory", async () => {
    const entry = await runContainer({
      "docker/Dockerfile": "FROM node:22\n",
      "docker/.dockerignore": "node_modules\n",
    });
    assert.equal(entry.status, RULE_OUTCOME_STATUSES.PASS);
  });

  it("declines when only a root ignore file exists for a nested Dockerfile", async () => {
    const entry = await runContainer({
      "docker/Dockerfile": "FROM node:22\n",
      ".dockerignore": "node_modules\n",
    });
    // Which context applies depends on the build command, which the model does not
    // record: neither "protected" nor "unprotected" is supported.
    assert.equal(entry.status, RULE_OUTCOME_STATUSES.UNKNOWN);
    assert.ok(entry.applicability.reason.includes("build context"));
    assert.ok(entry.applicability.reason.includes(".dockerignore"));
  });

  it("passes when both plausible context roots are ignored", async () => {
    const entry = await runContainer({
      "docker/Dockerfile": "FROM node:22\n",
      "docker/.dockerignore": "node_modules\n",
      ".dockerignore": "node_modules\n",
    });
    assert.equal(entry.status, RULE_OUTCOME_STATUSES.PASS);
  });

  it("reports a nested Dockerfile with no ignore file anywhere", async () => {
    const entry = await runContainer({ "docker/Dockerfile": "FROM node:22\n" });
    assert.equal(entry.status, RULE_OUTCOME_STATUSES.VIOLATION);
    assert.deepEqual(entry.findings.map((finding) => finding.metadata.path), [
      "docker/Dockerfile",
    ]);
    assert.deepEqual(entry.findings[0].metadata.contexts, ["docker"]);
    assert.equal(entry.findings[0].metadata.basis, FINDING_BASES.BUILD_CONTEXT);
  });

  it("reports a root Dockerfile with no ignore file", async () => {
    const entry = await runContainer({ Dockerfile: "FROM node:22\n" });
    assert.equal(entry.status, RULE_OUTCOME_STATUSES.VIOLATION);
    assert.deepEqual(entry.findings[0].metadata.contextRoot, ".");
  });

  it("does not treat an unrelated ignore file as the applicable one", async () => {
    const entry = await runContainer({
      "docker/Dockerfile": "FROM node:22\n",
      "other/.dockerignore": "node_modules\n",
    });
    assert.equal(entry.status, RULE_OUTCOME_STATUSES.VIOLATION);
    assert.deepEqual(entry.findings[0].metadata.contexts, ["docker"]);
  });

  it("applies the same context model to custom Dockerfile names", async () => {
    const protectedEntry = await runContainer({
      "deploy/App.dockerfile": "FROM node:22\n",
      "deploy/.dockerignore": "node_modules\n",
    });
    assert.equal(protectedEntry.status, RULE_OUTCOME_STATUSES.PASS);

    const unprotectedEntry = await runContainer({
      "Dockerfile.dev": "FROM node:22\n",
    });
    assert.equal(unprotectedEntry.status, RULE_OUTCOME_STATUSES.VIOLATION);
    assert.deepEqual(unprotectedEntry.findings[0].metadata.path, "Dockerfile.dev");
  });

  it("keeps a nested root-context ambiguity out of the clean result", async () => {
    const run = await runRules(
      await modelOf(
        makeRepo({
          "docker/Dockerfile": "FROM node:22\n",
          ".dockerignore": "node_modules\n",
        }),
      ),
    );
    assert.equal(run.complete, false);
    assert.equal(statusOf(run, SECURITY_RULE_IDS.CONTAINER_IGNORE), RULE_OUTCOME_STATUSES.UNKNOWN);
    assert.notEqual(
      statusOf(run, SECURITY_RULE_IDS.CONTAINER_IGNORE),
      RULE_OUTCOME_STATUSES.PASS,
    );
  });
});

// ─── 7. End-to-end: scan → model → analyzer ─────────────────────────────────

describe("corrections 1–3: end-to-end", () => {
  it(
    "detects all three conditions through the real pipeline and leaks nothing",
    { skip: SYMLINK_SKIP },
    async () => {
      const outside = makeRepo({ "host-secret.txt": "top secret" });
      const root = makeRepo(
        {
          ".npmrc": `//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n`,
          ".env": "REGION=eu-west-1\n",
          "docker/Dockerfile": "FROM node:22\n",
          ".dockerignore": "node_modules\n",
        },
        ["docker"],
      );
      symlinkSync(join(outside, "host-secret.txt"), join(root, "escape"), "file");

      const model = await modelOf(root);
      const analysis = await runAnalyzer(model);

      const byRule = new Map(analysis.findings.map((finding) => [finding.ruleId, finding]));
      assert.deepEqual([...byRule.keys()].sort(), [
        // `security.exposure…` sorts before `security.sensitive-content…`.
        SECURITY_RULE_IDS.SYMLINK_ESCAPE,
        SECURITY_RULE_IDS.CREDENTIAL_CONTENT,
        // The `.env` fixture is a dotenv file, so the filename rule reports it too.
        SECURITY_RULE_IDS.DOTENV,
      ]);
      for (const finding of analysis.findings) {
        assert.match(finding.fingerprint, /^cg-fp1-[0-9a-f]{32}$/);
        assert.equal(finding.id, `finding:${finding.fingerprint}`);
      }

      // The container rule declines: the root context is protected, the Dockerfile's
      // own directory is not. The analyzer reports it as unavailable, with a reason.
      const analyzer = analysis.analyzers.find((entry) => entry.analyzer.scope === "security");
      assert.equal(
        analyzer.metadata.unavailableRules.some(
          (entry) => entry.ruleId === SECURITY_RULE_IDS.CONTAINER_IGNORE,
        ),
        true,
      );

      const serialized = JSON.stringify(analysis);
      for (const leak of [NPM_TOKEN, outside, "host-secret.txt"]) {
        assert.equal(serialized.includes(leak), false, `leaked ${leak}`);
      }
      assert.deepEqual(absolutePathsIn(analysis.findings), []);

      // Two runs over the same frozen model agree completely.
      const second = await runAnalyzer(model);
      assert.deepEqual(
        analysis.findings.map((finding) => finding.fingerprint),
        second.findings.map((finding) => finding.fingerprint),
      );
    },
  );
});
