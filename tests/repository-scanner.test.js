/**
 * Code Guardian — Repository Scanner Tests (Phase 8C)
 *
 * Focused tests for `src/repository/scanner`. Fixtures are created in a unique
 * OS-temp directory (never the shared `.test-tmp`, which other suites wipe), and
 * no test spawns a process or touches the network.
 *
 * The security and limit tests are written so that weakening the corresponding
 * protection makes them fail; that was verified by mutation (see the Phase 8C
 * report).
 *
 * Run with: node --test tests/repository-scanner.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { ValidationError } from "../src/core/index.js";

import {
  DEFAULT_IGNORED_DIRECTORIES,
  DEFAULT_SCANNER_LIMITS,
  IGNORE_POLICIES,
  MAX_EVIDENCE_PER_SIGNAL,
  SCAN_RESULT_VERSION,
  SCAN_SIGNALS,
  TRUNCATION_REASONS,
  buildIgnorePolicy,
  createScanResult,
  isIgnored,
  parseGitignore,
  scanRepository,
  validateScanResult,
} from "../src/repository/scanner/index.js";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const TMP_ROOT = join(tmpdir(), `cg-scanner-${process.pid}-${Date.now()}`);
const WINDOWS = process.platform === "win32";
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
  const probe = mkdtempSync(join(tmpdir(), "cg-scanner-symlink-probe-"));
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

const filePaths = (result) => result.files.map((entry) => entry.path);
const directoryPaths = (result) => result.directories.map((entry) => entry.path);
const evidencePaths = (section) => section.evidence.map((entry) => entry.path);
const signalsFor = (section, path) =>
  section.evidence.filter((entry) => entry.path === path).map((entry) => entry.signal);

/** Everything except the timestamp, for structural determinism comparison. */
function structurally(result) {
  return JSON.stringify({ ...result, scannedAt: null });
}

// ─── Basic scanning ──────────────────────────────────────────────────────────

describe("scanner: basic scanning", () => {
  it("scans an empty repository as complete and empty", async () => {
    const root = makeRepo();
    const result = await scanRepository(root);

    assert.equal(result.version, SCAN_RESULT_VERSION);
    assert.equal(result.root, realpathSync(root));
    assert.equal(typeof result.scannedAt, "string");
    assert.deepEqual(result.files, []);
    assert.deepEqual(result.directories, []);
    assert.deepEqual(result.languages, []);
    assert.deepEqual(result.manifests, []);
    assert.equal(result.tests.detected, false);
    assert.equal(result.cicd.detected, false);
    assert.equal(result.documentation.detected, false);
    assert.equal(result.configuration.detected, false);
    assert.equal(result.git.detected, false);
    assert.equal(result.git.head, null);
    assert.equal(result.scan.complete, true);
    assert.equal(result.scan.truncated, false);
    assert.equal(result.ignore.sources[0].status, "absent");
  });

  it("inventories files and directories with depth and extension", async () => {
    const root = makeRepo(
      { "index.js": "", "src/app.ts": "", "src/util/helper.cjs": "" },
      ["docs"],
    );
    const result = await scanRepository(root);

    assert.deepEqual(filePaths(result), [
      "index.js",
      "src/app.ts",
      "src/util/helper.cjs",
    ]);
    assert.deepEqual(directoryPaths(result), ["docs", "src", "src/util"]);

    const app = result.files.find((entry) => entry.path === "src/app.ts");
    assert.deepEqual(app, {
      path: "src/app.ts",
      name: "app.ts",
      isDirectory: false,
      extension: ".ts",
      depth: 2,
    });
    const nested = result.files.find((entry) => entry.path === "src/util/helper.cjs");
    assert.equal(nested.depth, 3);
  });

  it("keeps collections deterministically ordered", async () => {
    const root = makeRepo({
      "z.js": "",
      "a.js": "",
      "m/n.js": "",
      "b.txt": "",
    });
    const result = await scanRepository(root);

    const sorted = [...filePaths(result)].sort();
    assert.deepEqual(filePaths(result), sorted);
    assert.deepEqual(filePaths(result), ["a.js", "b.txt", "m/n.js", "z.js"]);

    for (const section of [
      result.tests,
      result.cicd,
      result.documentation,
      result.configuration,
    ]) {
      const keys = section.evidence.map((entry) => `${entry.path}\u0000${entry.signal}`);
      assert.deepEqual(keys, [...keys].sort());
    }
    const languageIds = result.languages.map((entry) => entry.id);
    assert.deepEqual(languageIds, [...languageIds].sort());
  });

  it("produces structurally identical output for the same repository state", async () => {
    const root = makeRepo({
      "package.json": JSON.stringify({ name: "demo" }),
      "src/index.js": "",
      "tests/index.test.js": "",
      "README.md": "",
      ".gitignore": "generated/\n",
      "generated/out.js": "",
    });

    const first = await scanRepository(root);
    const second = await scanRepository(root);
    assert.equal(structurally(first), structurally(second));
    // Only the timestamp differs.
    assert.deepEqual({ ...first, scannedAt: null }, { ...second, scannedAt: null });
  });

  it("returns a result that satisfies its own contract", async () => {
    const root = makeRepo({ "src/index.js": "", "README.md": "" });
    const result = await scanRepository(root);
    assert.equal(validateScanResult(result), result);
  });

  it("rejects malformed scan arguments", async () => {
    await assert.rejects(() => scanRepository(), ValidationError);
    await assert.rejects(() => scanRepository(""), ValidationError);
    await assert.rejects(() => scanRepository(42), ValidationError);
    await assert.rejects(() => scanRepository(".", null), ValidationError);
    await assert.rejects(() => scanRepository(".", { unknown: 1 }), ValidationError);
    await assert.rejects(() => scanRepository(".", { maxFiles: 0 }), ValidationError);
    await assert.rejects(() => scanRepository(".", { maxDepth: -1 }), ValidationError);
    await assert.rejects(() => scanRepository(".", { maxFiles: 1.5 }), ValidationError);
    await assert.rejects(() => scanRepository(".", { maxDepth: "10" }), ValidationError);
  });

  it("reports a missing root as an incomplete scan instead of throwing", async () => {
    const missing = join(TMP_ROOT, "does-not-exist");
    const result = await scanRepository(missing);

    assert.equal(result.scan.complete, false);
    assert.equal(result.scan.errors.length, 1);
    assert.equal(result.scan.errors[0].operation, "listDirectory");
    assert.equal(result.scan.errors[0].path, ".");
    assert.deepEqual(result.files, []);
  });

  it("never modifies the scanned repository", async () => {
    const root = makeRepo({ "src/index.js": "", "package.json": "{}" });
    const before = readdirSync(root).sort();
    await scanRepository(root);
    assert.deepEqual(readdirSync(root).sort(), before);
  });
});

// ─── Scan limits ─────────────────────────────────────────────────────────────

describe("scanner: limits and completeness", () => {
  it("declares the Core scan-limit baseline by default", async () => {
    const root = makeRepo({ "a.txt": "" });
    const result = await scanRepository(root);

    assert.deepEqual(result.scan.limits, {
      maxFiles: DEFAULT_SCANNER_LIMITS.maxFiles,
      maxDepth: DEFAULT_SCANNER_LIMITS.maxDepth,
    });
    assert.equal(DEFAULT_SCANNER_LIMITS.maxFiles, 10000);
    assert.equal(DEFAULT_SCANNER_LIMITS.maxDepth, 20);
  });

  it("marks a file-limited scan truncated and never complete", async () => {
    const root = makeRepo({ "a.txt": "", "b.txt": "", "c.txt": "", "d.txt": "" });
    const result = await scanRepository(root, { maxFiles: 2 });

    assert.equal(result.files.length, 2);
    assert.equal(result.scan.truncated, true);
    assert.equal(result.scan.complete, false);
    assert.deepEqual(result.statistics.truncatedBy, [TRUNCATION_REASONS.FILE_LIMIT]);
    assert.equal(result.statistics.filesScanned, 2);
  });

  it("marks a depth-limited scan truncated and never complete", async () => {
    const root = makeRepo({ "a/b/c/deep.txt": "", "top.txt": "" });
    const result = await scanRepository(root, { maxDepth: 2 });

    assert.equal(result.scan.truncated, true);
    assert.equal(result.scan.complete, false);
    assert.deepEqual(result.statistics.truncatedBy, [TRUNCATION_REASONS.DEPTH_LIMIT]);
    assert.ok(!filePaths(result).includes("a/b/c/deep.txt"));
  });

  it("reports depth truncation conservatively at the depth boundary", async () => {
    // A directory recorded *at* `maxDepth` was not opened, so the scan reports
    // incomplete coverage even when that directory turns out to be empty. The
    // scanner never trades a false "complete" for a tidier result — this matches
    // `walk`'s own rule that declining to open a directory is truncation.
    const root = makeRepo({}, ["only-empty"]);
    const result = await scanRepository(root, { maxDepth: 1 });

    assert.deepEqual(directoryPaths(result), ["only-empty"]);
    assert.deepEqual(filePaths(result), []);
    assert.equal(result.scan.truncated, true);
    assert.equal(result.scan.complete, false);
    assert.deepEqual(result.statistics.truncatedBy, [TRUNCATION_REASONS.DEPTH_LIMIT]);
  });

  it("stays complete when the inventory fits exactly inside the limits", async () => {
    const root = makeRepo({ "a.txt": "", "b.txt": "" });
    const result = await scanRepository(root, { maxFiles: 2, maxDepth: 1 });

    assert.equal(result.scan.complete, true);
    assert.equal(result.scan.truncated, false);
    assert.deepEqual(result.statistics.truncatedBy, []);
  });

  it("never reports truncation and completeness together", async () => {
    const root = makeRepo({ "a/b/c/d/e/deep.txt": "" });
    for (const options of [
      { maxFiles: 0 + 1 },
      { maxDepth: 1 },
      { maxDepth: 2, maxFiles: 1 },
    ]) {
      const result = await scanRepository(root, options);
      assert.ok(
        !(result.scan.complete && result.scan.truncated),
        "a truncated scan must not be complete",
      );
      assert.equal(result.scan.complete, !result.scan.truncated);
    }
  });
});

// ─── Symlinks ────────────────────────────────────────────────────────────────

describe("scanner: symlink handling", () => {
  it(
    "records a symlinked file without following it",
    { skip: SYMLINK_SKIP },
    async () => {
      const outside = makeRepo({ "secret.txt": "top secret" });
      const root = makeRepo({ "real.txt": "" });
      symlinkSync(join(outside, "secret.txt"), join(root, "link.txt"), "file");

      const result = await scanRepository(root);

      assert.deepEqual(filePaths(result), ["real.txt"]);
      assert.deepEqual(result.symlinks.map((entry) => entry.path), ["link.txt"]);
      assert.equal(result.scan.complete, true, "a symlink is not an error");
      assert.ok(!structurally(result).includes(outside));
    },
  );

  it(
    "records a symlinked directory without traversing it",
    { skip: SYMLINK_SKIP },
    async () => {
      const outside = makeRepo({ "nested/secret.txt": "" });
      const root = makeRepo({ "real.txt": "" });
      symlinkSync(outside, join(root, "link-dir"), "dir");

      const result = await scanRepository(root);

      assert.deepEqual(filePaths(result), ["real.txt"]);
      assert.ok(!directoryPaths(result).includes("link-dir"));
      assert.deepEqual(result.symlinks.map((entry) => entry.path), ["link-dir"]);
      assert.ok(!structurally(result).includes("secret.txt"));
    },
  );

  it(
    "does not follow a symlink chain and stays non-recursive",
    { skip: SYMLINK_SKIP },
    async () => {
      const outside = makeRepo({ "secret.txt": "" });
      const root = makeRepo({ "a/real.txt": "" });
      symlinkSync(join(root, "b"), join(root, "a", "link-b"), "dir");
      symlinkSync(root, join(root, "a", "loop"), "dir");
      symlinkSync(outside, join(root, "b"), "dir");

      const result = await scanRepository(root);

      assert.deepEqual(filePaths(result), ["a/real.txt"]);
      const symlinkPaths = result.symlinks.map((entry) => entry.path).sort();
      assert.deepEqual(symlinkPaths, ["a/link-b", "a/loop", "b"]);
      assert.equal(result.scan.complete, true);
      assert.ok(!structurally(result).includes(outside));
    },
  );

  it(
    "never reads a manifest that is a symlink",
    { skip: SYMLINK_SKIP },
    async () => {
      const outside = makeRepo({
        "package.json": JSON.stringify({ name: "attacker-controlled" }),
      });
      const root = makeRepo({ "src/index.js": "" });
      symlinkSync(join(outside, "package.json"), join(root, "package.json"), "file");

      const result = await scanRepository(root);

      assert.deepEqual(result.manifests, [], "a symlinked manifest is not evidence");
      assert.deepEqual(result.symlinks.map((entry) => entry.path), ["package.json"]);
      assert.ok(
        !result.languages.some((language) =>
          language.evidence.some((entry) => entry.path === "package.json"),
        ),
        "a symlinked manifest contributes no language signal",
      );
      assert.ok(!structurally(result).includes("attacker-controlled"));
    },
  );

  it(
    "counts symlinks without treating them as files",
    { skip: SYMLINK_SKIP },
    async () => {
      const root = makeRepo({ "a.txt": "" });
      symlinkSync(join(root, "a.txt"), join(root, "alias.txt"), "file");

      const result = await scanRepository(root);
      assert.equal(result.statistics.symlinksScanned, 1);
      assert.equal(result.statistics.filesScanned, 1);
    },
  );
});

// ─── Language detection ──────────────────────────────────────────────────────

describe("scanner: language detection", () => {
  it("detects languages from source extensions with file evidence", async () => {
    const root = makeRepo({
      "src/index.ts": "",
      "src/util.js": "",
      "scripts/run.py": "",
      "lib/main.go": "",
      "native/core.c": "",
      "native/core.hpp": "",
    });
    const result = await scanRepository(root);

    assert.deepEqual(
      result.languages.map((entry) => entry.id),
      ["c", "cpp", "go", "javascript", "python", "typescript"],
    );

    const typescript = result.languages.find((entry) => entry.id === "typescript");
    assert.equal(typescript.fileCount, 1);
    assert.deepEqual(typescript.extensions, [".ts"]);
    assert.deepEqual(typescript.evidence, [
      { path: "src/index.ts", signal: SCAN_SIGNALS.SOURCE_EXTENSION },
    ]);
    assert.deepEqual(typescript.signals, [SCAN_SIGNALS.SOURCE_EXTENSION]);
  });

  it("detects a language from manifest evidence alone", async () => {
    const root = makeRepo({ "requirements.txt": "flask\n" });
    const result = await scanRepository(root);

    const python = result.languages.find((entry) => entry.id === "python");
    assert.ok(python, "a manifest is evidence of the project language");
    assert.equal(python.fileCount, 0, "no source file was observed");
    assert.deepEqual(python.evidence, [
      { path: "requirements.txt", signal: SCAN_SIGNALS.MANIFEST },
    ]);
    assert.deepEqual(python.extensions, []);
  });

  it("reports lockfile evidence distinctly from manifest evidence", async () => {
    const root = makeRepo({ "Cargo.toml": "", "Cargo.lock": "" });
    const result = await scanRepository(root);

    const rust = result.languages.find((entry) => entry.id === "rust");
    assert.deepEqual(rust.signals.sort(), [
      SCAN_SIGNALS.LOCKFILE,
      SCAN_SIGNALS.MANIFEST,
    ]);
  });

  it("claims no language for a directory that only looks like one", async () => {
    const root = makeRepo({ "python/notes.txt": "", "golang/readme.md": "" });
    const result = await scanRepository(root);

    assert.deepEqual(result.languages, []);
  });

  it("claims no language for extensions outside the documented table", async () => {
    const root = makeRepo({ "a.xyz": "", "b.unknownext": "" });
    const result = await scanRepository(root);
    assert.deepEqual(result.languages, []);
  });

  it("caps evidence per language and reports the truncation", async () => {
    const files = {};
    for (let index = 0; index < MAX_EVIDENCE_PER_SIGNAL + 3; index += 1) {
      files[`src/f${String(index).padStart(2, "0")}.rs`] = "";
    }
    const root = makeRepo(files);
    const result = await scanRepository(root);

    const rust = result.languages.find((entry) => entry.id === "rust");
    assert.equal(rust.fileCount, MAX_EVIDENCE_PER_SIGNAL + 3);
    assert.equal(rust.evidence.length, MAX_EVIDENCE_PER_SIGNAL);
    assert.equal(rust.evidenceTruncated, true);
  });
});

// ─── Manifest detection and parsing ──────────────────────────────────────────

describe("scanner: manifests", () => {
  it("recognizes manifests across ecosystems", async () => {
    const root = makeRepo({
      "package.json": "{}",
      "pyproject.toml": "",
      "Cargo.toml": "",
      "go.mod": "",
      "pom.xml": "",
      "Gemfile": "",
      "composer.json": "{}",
      "pubspec.yaml": "",
      "App.csproj": "",
    });
    const result = await scanRepository(root);

    assert.deepEqual(
      result.manifests.map((entry) => entry.path),
      [
        "App.csproj",
        "Cargo.toml",
        "Gemfile",
        "composer.json",
        "go.mod",
        "package.json",
        "pom.xml",
        "pubspec.yaml",
        "pyproject.toml",
      ].sort(),
    );
    assert.deepEqual(
      [...new Set(result.manifests.map((entry) => entry.ecosystem))].sort(),
      ["dart", "dotnet", "go", "java", "node", "php", "python", "ruby", "rust"],
    );
  });

  it("recognizes lockfiles as lockfile evidence", async () => {
    const root = makeRepo({
      "package-lock.json": "{}",
      "pnpm-lock.yaml": "",
      "yarn.lock": "",
      "poetry.lock": "",
      "Pipfile.lock": "{}",
    });
    const result = await scanRepository(root);

    assert.ok(result.manifests.length >= 5);
    assert.ok(result.manifests.every((entry) => entry.kind === "lockfile"));
  });

  it("recognizes a manifest nested inside a monorepo package", async () => {
    const root = makeRepo({ "packages/app/package.json": "{}" });
    const result = await scanRepository(root);

    assert.deepEqual(result.manifests, [
      {
        path: "packages/app/package.json",
        name: "package.json",
        directory: "packages/app",
        ecosystem: "node",
        kind: "manifest",
        languages: ["javascript"],
        parse: {
          status: "parsed",
          format: "json",
          bytes: 2,
          metadata: {
            name: null,
            version: null,
            type: null,
            private: null,
            workspaces: false,
            scripts: [],
            scriptsTruncated: false,
            dependencySections: [],
          },
        },
      },
    ]);
  });

  it("extracts the documented shallow package.json metadata", async () => {
    const root = makeRepo({
      "package.json": JSON.stringify({
        name: "demo",
        version: "2.1.0",
        type: "module",
        private: true,
        workspaces: ["packages/*"],
        scripts: { test: "node --test", build: "tsc" },
        dependencies: { left: "1.0.0", right: "2.0.0" },
        devDependencies: { jest: "29.0.0" },
        peerDependencies: { react: "18" },
        config: {},
      }),
    });
    const result = await scanRepository(root);

    const { metadata } = result.manifests[0].parse;
    assert.equal(metadata.name, "demo");
    assert.equal(metadata.version, "2.1.0");
    assert.equal(metadata.type, "module");
    assert.equal(metadata.private, true);
    assert.equal(metadata.workspaces, true);
    assert.deepEqual(metadata.scripts, ["build", "test"]);
    assert.equal(metadata.scriptsTruncated, false);
    // Section names and counts only — no dependency graph, no resolved versions.
    assert.deepEqual(metadata.dependencySections, [
      { section: "dependencies", count: 2 },
      { section: "devDependencies", count: 1 },
      { section: "peerDependencies", count: 1 },
    ]);
    assert.ok(!JSON.stringify(result).includes("left"));
  });

  it("records a malformed manifest without failing the scan", async () => {
    const root = makeRepo({ "package.json": "{ not json", "src/index.js": "" });
    const result = await scanRepository(root);

    assert.equal(result.manifests[0].parse.status, "failed");
    assert.equal(result.manifests[0].parse.reason, "invalid-json");
    assert.equal(result.manifests[0].parse.bytes, 10);
    assert.equal(result.scan.complete, true, "a parse failure is not a coverage failure");
    assert.deepEqual(result.scan.errors, []);
    assert.deepEqual(filePaths(result), ["package.json", "src/index.js"]);
  });

  it("records a non-object manifest value as a parse failure", async () => {
    const root = makeRepo({ "package.json": "[1, 2, 3]" });
    const result = await scanRepository(root);

    assert.equal(result.manifests[0].parse.status, "failed");
    assert.equal(result.manifests[0].parse.reason, "json-value-is-not-an-object");
  });

  it("does not read a manifest larger than the documented bound", async () => {
    const root = makeRepo({
      "package.json": JSON.stringify({ name: "big", padding: "x".repeat(300000) }),
    });
    const result = await scanRepository(root);

    assert.equal(result.manifests[0].parse.status, "not-parsed");
    assert.equal(result.manifests[0].parse.reason, "exceeds-max-manifest-bytes");
    assert.ok(result.manifests[0].parse.metadata === undefined);
  });

  it("leaves non-JSON manifests unread but documented", async () => {
    const root = makeRepo({ "pyproject.toml": "[project]\nname = 'x'\n" });
    const result = await scanRepository(root);

    assert.deepEqual(result.manifests[0].parse, {
      status: "not-parsed",
      format: "toml",
      reason: "format-not-parsed-in-phase-8c",
    });
    assert.equal(result.manifests[0].parse.bytes, undefined);
  });

  it("does not treat a directory named package.json as a manifest", async () => {
    const root = makeRepo({ "package.json/inner.txt": "" });
    const result = await scanRepository(root);

    assert.deepEqual(result.manifests, []);
  });

  it("reports no manifests when none exist", async () => {
    const root = makeRepo({ "src/index.js": "" });
    const result = await scanRepository(root);
    assert.deepEqual(result.manifests, []);
  });
});

// ─── Test detection ──────────────────────────────────────────────────────────

describe("scanner: testing signals", () => {
  it("detects test directories, files and configuration", async () => {
    const root = makeRepo({
      "tests/unit.test.js": "",
      "__tests__/app.js": "",
      "src/a.spec.ts": "",
      "service/test_service.py": "",
      "pkg/handler_test.go": "",
      "app/HomeTest.java": "",
      "spec/models/user_spec.rb": "",
      "jest.config.js": "",
      "pytest.ini": "",
    });
    const result = await scanRepository(root);

    assert.equal(result.tests.detected, true);
    assert.ok(evidencePaths(result.tests).includes("tests"));
    assert.ok(evidencePaths(result.tests).includes("__tests__"));
    assert.ok(evidencePaths(result.tests).includes("src/a.spec.ts"));
    assert.ok(evidencePaths(result.tests).includes("service/test_service.py"));
    assert.ok(evidencePaths(result.tests).includes("pkg/handler_test.go"));
    assert.ok(evidencePaths(result.tests).includes("app/HomeTest.java"));
    assert.ok(evidencePaths(result.tests).includes("spec/models/user_spec.rb"));
    assert.ok(evidencePaths(result.tests).includes("jest.config.js"));
    assert.equal(
      signalsFor(result.tests, "jest.config.js")[0],
      SCAN_SIGNALS.TEST_CONFIGURATION,
    );
    assert.ok(result.tests.frameworks.includes("jest"));
    assert.ok(result.tests.frameworks.includes("pytest"));
    assert.ok(result.tests.frameworks.includes("go-test"));
  });

  it("resists false positives from lookalike file names", async () => {
    const root = makeRepo({
      "src/test-utils.js": "",
      "src/latest.js": "",
      "src/contest.py": "",
      "src/attestation.ts": "",
      "src/spec.md": "",
      "src/mytest": "",
    });
    const result = await scanRepository(root);

    assert.equal(result.tests.detected, false);
    assert.deepEqual(result.tests.evidence, []);
  });

  it("does not treat a directory outside the conventions as a test directory", async () => {
    const root = makeRepo({ "testing-ground/notes.txt": "" });
    const result = await scanRepository(root);
    assert.equal(result.tests.detected, false);
  });

  it("caps test evidence and reports the truncation", async () => {
    const files = {};
    for (let index = 0; index < MAX_EVIDENCE_PER_SIGNAL + 2; index += 1) {
      files[`src/case${String(index).padStart(2, "0")}.test.js`] = "";
    }
    const root = makeRepo(files);
    const result = await scanRepository(root);

    assert.equal(result.tests.evidence.length, MAX_EVIDENCE_PER_SIGNAL);
    assert.equal(result.tests.evidenceTruncated, true);
  });
});

// ─── CI/CD detection ────────────────────────────────────────────────────────

describe("scanner: CI/CD signals", () => {
  it("detects multiple providers deterministically", async () => {
    const root = makeRepo({
      ".github/workflows/ci.yml": "",
      ".github/workflows/release.yaml": "",
      ".gitlab-ci.yml": "",
      ".circleci/config.yml": "",
      "Jenkinsfile": "",
      "azure-pipelines.yml": "",
      ".travis.yml": "",
      "bitbucket-pipelines.yml": "",
      ".buildkite/pipeline.yml": "",
      ".drone.yml": "",
    });
    const result = await scanRepository(root);

    assert.equal(result.cicd.detected, true);
    assert.deepEqual(result.cicd.providers, [
      "azure-pipelines",
      "bitbucket-pipelines",
      "buildkite",
      "circleci",
      "drone",
      "github-actions",
      "gitlab-ci",
      "jenkins",
      "travis-ci",
    ]);
    assert.equal(
      result.cicd.evidence.filter((entry) => entry.provider === "github-actions")
        .length,
      2,
    );
    assert.ok(!structurally(result).includes("Jenkinsfile\n"));
  });

  it("ignores workflow-shaped files outside the workflow directories", async () => {
    const root = makeRepo({ "workflows/ci.yml": "", "ci/config.yml": "" });
    const result = await scanRepository(root);
    assert.equal(result.cicd.detected, false);
  });

  it("reports no CI when none is configured", async () => {
    const root = makeRepo({ "src/index.js": "" });
    const result = await scanRepository(root);
    assert.equal(result.cicd.detected, false);
    assert.deepEqual(result.cicd.providers, []);
  });
});

// ─── Documentation and configuration ────────────────────────────────────────

describe("scanner: documentation and configuration signals", () => {
  it("detects representative documentation artifacts case-insensitively", async () => {
    const root = makeRepo({
      "readme.md": "",
      "docs/guide.md": "",
      "CHANGELOG.md": "",
      "CONTRIBUTING.md": "",
      "CODE_OF_CONDUCT.md": "",
    });
    const result = await scanRepository(root);

    assert.equal(result.documentation.detected, true);
    assert.deepEqual(evidencePaths(result.documentation), [
      "CHANGELOG.md",
      "CODE_OF_CONDUCT.md",
      "CONTRIBUTING.md",
      "docs",
      "readme.md",
    ]);
    assert.deepEqual(signalsFor(result.documentation, "readme.md"), [
      SCAN_SIGNALS.README,
    ]);
    assert.deepEqual(signalsFor(result.documentation, "docs"), [
      SCAN_SIGNALS.DOCUMENTATION_DIRECTORY,
    ]);
  });

  it("detects representative configuration artifacts", async () => {
    const root = makeRepo({
      "Dockerfile": "",
      "docker-compose.yml": "",
      ".dockerignore": "",
      ".env.example": "",
      ".eslintrc.json": "",
      ".prettierrc": "",
      ".editorconfig": "",
      ".nvmrc": "",
      ".gitattributes": "",
      "LICENSE": "",
    });
    const result = await scanRepository(root);

    assert.equal(result.configuration.detected, true);
    assert.deepEqual(signalsFor(result.configuration, "Dockerfile"), [
      SCAN_SIGNALS.DOCKERFILE,
    ]);
    assert.deepEqual(signalsFor(result.configuration, "docker-compose.yml"), [
      SCAN_SIGNALS.COMPOSE_FILE,
    ]);
    assert.deepEqual(signalsFor(result.configuration, ".env.example"), [
      SCAN_SIGNALS.ENVIRONMENT_EXAMPLE,
    ]);
    assert.deepEqual(signalsFor(result.configuration, ".eslintrc.json"), [
      SCAN_SIGNALS.LINT_CONFIGURATION,
    ]);
    assert.deepEqual(signalsFor(result.configuration, ".prettierrc"), [
      SCAN_SIGNALS.FORMAT_CONFIGURATION,
    ]);
    assert.deepEqual(signalsFor(result.configuration, ".nvmrc"), [
      SCAN_SIGNALS.VERSION_PINNING,
    ]);
    assert.deepEqual(signalsFor(result.configuration, ".gitattributes"), [
      SCAN_SIGNALS.VCS_CONFIGURATION,
    ]);
    assert.deepEqual(signalsFor(result.configuration, "LICENSE"), [
      SCAN_SIGNALS.LICENSE,
    ]);
  });

  it("detects build configuration signals", async () => {
    const root = makeRepo({
      "tsconfig.json": "",
      "jsconfig.json": "",
      "babel.config.js": "",
      "vite.config.ts": "",
      "webpack.config.js": "",
    });
    const result = await scanRepository(root);

    assert.deepEqual(evidencePaths(result.configuration), [
      "babel.config.js",
      "jsconfig.json",
      "tsconfig.json",
      "vite.config.ts",
      "webpack.config.js",
    ]);
    assert.ok(
      result.configuration.evidence.every(
        (entry) => entry.signal === SCAN_SIGNALS.BUILD_CONFIGURATION,
      ),
    );
  });

  it("caps configuration evidence and reports the truncation", async () => {
    const files = {};
    for (let index = 0; index < MAX_EVIDENCE_PER_SIGNAL + 1; index += 1) {
      files[`Dockerfile.${String(index).padStart(2, "0")}`] = "";
    }
    const root = makeRepo(files);
    const result = await scanRepository(root);

    assert.equal(result.configuration.evidence.length, MAX_EVIDENCE_PER_SIGNAL);
    assert.equal(result.configuration.evidenceTruncated, true);
    assert.ok(
      result.configuration.evidence.every(
        (entry) => entry.signal === SCAN_SIGNALS.DOCKERFILE,
      ),
    );
  });

  it("does not report a configuration signal for an unrelated file", async () => {
    const root = makeRepo({ "src/app.ts": "", "notes.txt": "" });
    const result = await scanRepository(root);
    assert.equal(result.configuration.detected, false);
    assert.equal(result.documentation.detected, false);
  });
});

// ─── Git signals ────────────────────────────────────────────────────────────

describe("scanner: git signals", () => {
  it("detects a repository and its checked-out branch without running git", async () => {
    const root = makeRepo({ "src/index.js": "" });
    mkdirSync(join(root, ".git"), { recursive: true });
    writeFileSync(join(root, ".git", "HEAD"), "ref: refs/heads/main\n");

    const result = await scanRepository(root);

    assert.equal(result.git.detected, true);
    assert.deepEqual(result.git.head, {
      kind: "branch",
      branch: "main",
      ref: "refs/heads/main",
    });
    assert.deepEqual(result.git.evidence, [
      { path: ".git", signal: SCAN_SIGNALS.GIT_DIRECTORY },
      { path: ".git/HEAD", signal: SCAN_SIGNALS.GIT_HEAD },
    ]);
    // Metadata lives in an ignored directory but is still reported; its contents
    // are not inventoried.
    assert.ok(result.ignored.some((entry) => entry.path === ".git"));
    assert.ok(!filePaths(result).some((path) => path.startsWith(".git/")));
  });

  it("reports a detached head", async () => {
    const root = makeRepo();
    mkdirSync(join(root, ".git"), { recursive: true });
    writeFileSync(
      join(root, ".git", "HEAD"),
      "9f2a1b4c5d6e7f8091a2b3c4d5e6f708192a3b4c\n",
    );

    const result = await scanRepository(root);
    assert.deepEqual(result.git.head, {
      kind: "detached",
      commit: "9f2a1b4c5d6e7f8091a2b3c4d5e6f708192a3b4c",
    });
  });

  it("detects a gitfile (worktree/submodule) without reading it as a directory", async () => {
    const root = makeRepo();
    writeFileSync(join(root, ".git"), "gitdir: /elsewhere/.git/worktrees/x\n");

    const result = await scanRepository(root);
    assert.equal(result.git.detected, true);
    assert.deepEqual(result.git.head, { kind: "gitfile" });
    assert.ok(!structurally(result).includes("/elsewhere/"));
  });

  it("never echoes hostile .git/HEAD content", async () => {
    for (const hostile of [
      "ref: ../../../../etc/passwd\n",
      "ref: /etc/passwd\n",
      "ref: refs/heads/../../escape\n",
      "not a ref at all\n",
      "\n",
    ]) {
      const root = makeRepo();
      mkdirSync(join(root, ".git"), { recursive: true });
      writeFileSync(join(root, ".git", "HEAD"), hostile);

      const result = await scanRepository(root);
      assert.equal(result.git.head.kind, "unknown", hostile.trim() || "<empty>");
      assert.equal(result.git.head.ref, undefined);
      const serialized = structurally(result);
      assert.ok(!serialized.includes("etc/passwd"));
      assert.ok(!serialized.includes("not a ref"));
    }
  });

  it("stays silent when there is no git metadata", async () => {
    const root = makeRepo({ "src/index.js": "" });
    const result = await scanRepository(root);
    assert.equal(result.git.detected, false);
    assert.deepEqual(result.git.evidence, []);
    assert.equal(result.scan.complete, true);
  });
});

// ─── Ignore policy ──────────────────────────────────────────────────────────

describe("scanner: ignore policy", () => {
  it("excludes default ignored directories without traversing them", async () => {
    const root = makeRepo({
      "src/index.js": "",
      "node_modules/left-pad/index.js": "",
      "dist/bundle.js": "",
      ".git/config": "",
      ".venv/lib/site.py": "",
    });
    const result = await scanRepository(root);

    assert.deepEqual(filePaths(result), ["src/index.js"]);
    const ignoredPaths = result.ignored.map((entry) => entry.path).sort();
    assert.deepEqual(ignoredPaths, [
      ".git",
      ".venv",
      "dist",
      "node_modules",
    ]);
    assert.ok(
      result.ignored.every(
        (entry) => entry.policy === IGNORE_POLICIES.DEFAULT_DIRECTORY,
      ),
    );
    assert.ok(DEFAULT_IGNORED_DIRECTORIES.includes("node_modules"));
    assert.equal(result.ignore.sources[0].status, "absent");
  });

  it("applies a root .gitignore to files and directories", async () => {
    const root = makeRepo({
      "keep.js": "",
      "debug.log": "",
      "generated/out.js": "",
      "generated/nested/deep.js": "",
      "src/app.js": "",
      ".gitignore": "*.log\ngenerated/\n",
    });
    const result = await scanRepository(root);

    assert.deepEqual(filePaths(result), [
      ".gitignore",
      "keep.js",
      "src/app.js",
    ]);
    assert.deepEqual(result.ignored, [
      {
        path: "debug.log",
        name: "debug.log",
        isDirectory: false,
        policy: IGNORE_POLICIES.GITIGNORE,
      },
      {
        path: "generated",
        name: "generated",
        isDirectory: true,
        policy: IGNORE_POLICIES.GITIGNORE,
      },
    ]);
    // Descendants of an ignored directory are pruned, not listed twice.
    assert.ok(!result.ignored.some((entry) => entry.path.includes("nested")));
    assert.equal(result.ignore.sources[0].status, "applied");
  });

  it("honours anchored, path and directory-only patterns", async () => {
    const root = makeRepo({
      "root-only.txt": "",
      "src/root-only.txt": "",
      "generated/out.js": "",
      "src/generated/keep.js": "",
      "scratch/notes.txt": "",
      "scripts/scratch": "",
      "nested/cached/data.js": "",
      ".gitignore": "/root-only.txt\n/generated\nscratch/\ncached/\n",
    });
    const result = await scanRepository(root);

    assert.ok(!filePaths(result).includes("root-only.txt"), "anchored file");
    assert.ok(!filePaths(result).includes("generated/out.js"), "anchored directory");
    assert.ok(
      filePaths(result).includes("src/root-only.txt"),
      "an anchored file pattern must not match at depth",
    );
    assert.ok(
      filePaths(result).includes("src/generated/keep.js"),
      "an anchored directory pattern must not match at depth",
    );
    assert.ok(!filePaths(result).includes("scratch/notes.txt"), "directory-only match");
    assert.ok(
      filePaths(result).includes("scripts/scratch"),
      "a directory-only pattern must not exclude a file with the same name",
    );
    assert.ok(
      !filePaths(result).includes("nested/cached/data.js"),
      "an unanchored directory pattern matches at any depth",
    );
    assert.deepEqual(
      result.ignored.map((entry) => entry.path),
      ["generated", "nested/cached", "root-only.txt", "scratch"],
    );
  });

  it("reports unsupported .gitignore syntax instead of half-applying it", async () => {
    const root = makeRepo({
      "keep.log": "",
      "debug.log": "",
      "cache.db": "",
      ".gitignore": "*.log\n!keep.log\n**/cache.db\n",
    });
    const result = await scanRepository(root);

    assert.deepEqual(result.ignore.unsupported, [
      { path: ".gitignore", line: 2, reason: "negation-unsupported" },
      { path: ".gitignore", line: 3, reason: "double-star-unsupported" },
    ]);
    // Negation is not applied, so the supposedly re-included file stays ignored.
    // The limitation is visible in `ignore.unsupported` rather than silent.
    assert.ok(!filePaths(result).includes("keep.log"));
    assert.ok(filePaths(result).includes("cache.db"));
  });

  it("keeps ignored paths out of the inventory and out of scan errors", async () => {
    const root = makeRepo({
      "generated/out.js": "",
      "src/index.js": "",
      ".gitignore": "generated/\n",
    });
    const result = await scanRepository(root, { maxFiles: 10 });

    assert.equal(result.scan.complete, true);
    assert.deepEqual(result.scan.errors, []);
    assert.equal(result.statistics.ignored, 1);
    assert.equal(result.statistics.unreadable, 0);
    assert.ok(!filePaths(result).includes("generated/out.js"));
  });

  it("distinguishes ignored from skipped", async () => {
    const root = makeRepo({
      "a.txt": "",
      "b.txt": "",
      "c.txt": "",
      "d.txt": "",
      "excluded.txt": "",
      ".gitignore": "excluded.txt\n",
    });

    // Ignored: seen and excluded by policy. Never an error, never truncation.
    const full = await scanRepository(root);
    assert.deepEqual(full.ignored.map((entry) => entry.path), ["excluded.txt"]);
    assert.deepEqual(
      full.files.map((entry) => entry.path),
      [".gitignore", "a.txt", "b.txt", "c.txt", "d.txt"],
    );
    assert.equal(full.scan.complete, true);
    assert.equal(full.scan.truncated, false);
    assert.deepEqual(full.scan.errors, []);
    assert.equal(full.statistics.ignored, 1);

    // Skipped: not inspected at all because a limit stopped the scan. It is
    // reported as incomplete coverage, not as an ignore decision.
    const limited = await scanRepository(root, { maxFiles: 2 });
    assert.equal(limited.files.length, 2);
    assert.equal(limited.scan.truncated, true);
    assert.equal(limited.scan.complete, false);
    assert.deepEqual(limited.statistics.truncatedBy, [TRUNCATION_REASONS.FILE_LIMIT]);
    assert.deepEqual(limited.scan.errors, [], "skipping is not an error");
    assert.equal(limited.statistics.ignored, limited.ignored.length);
    assert.ok(
      limited.ignored.every((entry) => entry.policy === IGNORE_POLICIES.GITIGNORE),
      "a skipped path is never recorded as an ignore decision",
    );
    assert.ok(
      !limited.files.some((entry) => entry.path === "excluded.txt"),
      "an ignored file is never inventoried",
    );
  });

  it("reports an unreadable .gitignore rather than silently ignoring it", async () => {
    if (!SYMLINKS_AVAILABLE) return;
    const root = makeRepo({ "a.txt": "" });
    symlinkSync(join(root, "missing-target"), join(root, ".gitignore"), "file");

    const result = await scanRepository(root);

    assert.equal(result.ignore.sources[0].path, ".gitignore");
    assert.equal(result.ignore.sources[0].status, "unreadable");
    assert.equal(result.ignore.sources[0].reason, "SYMLINK_NOT_ALLOWED");
    assert.equal(result.scan.complete, true);
  });

  it("parses gitignore rules deterministically", () => {
    const parsed = parseGitignore(
      "# comment\n\n*.log\n/root-only\ndir/\n!keep\n**/x\n",
    );

    assert.deepEqual(
      parsed.patterns.map((pattern) => ({
        raw: pattern.raw,
        anchored: pattern.anchored,
        directoryOnly: pattern.directoryOnly,
        matchPath: pattern.matchPath,
      })),
      [
        { raw: "*.log", anchored: false, directoryOnly: false, matchPath: false },
        { raw: "/root-only", anchored: true, directoryOnly: false, matchPath: true },
        { raw: "dir/", anchored: false, directoryOnly: true, matchPath: false },
      ],
    );
    assert.deepEqual(parsed.unsupported, [
      { path: ".gitignore", line: 6, reason: "negation-unsupported" },
      { path: ".gitignore", line: 7, reason: "double-star-unsupported" },
    ]);
  });

  it("matches ignore policy entries as documented", () => {
    const policy = buildIgnorePolicy({ gitignoreText: "*.log\n/generated\n" });

    assert.equal(
      isIgnored(policy, { path: "a/b/deep.log", name: "deep.log", isDirectory: false }),
      true,
    );
    assert.equal(
      isIgnored(policy, {
        path: "generated",
        name: "generated",
        isDirectory: true,
      }),
      true,
    );
    assert.equal(
      isIgnored(policy, {
        path: "generated/out.js",
        name: "out.js",
        isDirectory: false,
      }),
      true,
      "a pattern matching a directory excludes its contents",
    );
    assert.equal(
      isIgnored(policy, { path: "src/keep.js", name: "keep.js", isDirectory: false }),
      false,
    );
    assert.equal(
      isIgnored(policy, { path: "sub/generated", name: "generated", isDirectory: true }),
      false,
      "an anchored pattern must not match at depth",
    );
  });
});

// ─── Partial failures ───────────────────────────────────────────────────────

describe("scanner: partial failures", () => {
  it(
    "reports an unreadable directory without failing the scan",
    { skip: WINDOWS ? "Windows ACL semantics differ" : false },
    async (t) => {
      const root = makeRepo({ "ok/file.txt": "", "restricted/secret.txt": "" });
      const restricted = join(root, "restricted");
      chmodSync(restricted, 0o000);
      try {
        const result = await scanRepository(root);
        if (result.scan.errors.length === 0) {
          t.skip("process bypasses directory permissions (e.g. root)");
          return;
        }

        assert.equal(result.scan.complete, false);
        assert.equal(result.scan.truncated, false);
        assert.equal(result.statistics.unreadable, 1);
        assert.equal(result.scan.errors[0].kind, "PERMISSION_DENIED");
        assert.equal(result.scan.errors[0].operation, "listDirectory");
        assert.equal(result.scan.errors[0].path, "restricted");
        assert.ok(filePaths(result).includes("ok/file.txt"));
      } finally {
        chmodSync(restricted, 0o755);
      }
    },
  );

  it("still completes the rest of the inventory around a bad symlink", async () => {
    if (!SYMLINKS_AVAILABLE) return;
    const root = makeRepo({ "src/index.js": "" });
    symlinkSync(join(root, "does-not-exist"), join(root, "broken"), "file");

    const result = await scanRepository(root);
    assert.equal(result.scan.complete, true);
    assert.deepEqual(result.symlinks.map((entry) => entry.path), ["broken"]);
    assert.deepEqual(filePaths(result), ["src/index.js"]);
  });

  it("keeps raw host filesystem errors out of the scan result", async () => {
    const root = makeRepo({ "src/index.js": "" });
    const missing = join(TMP_ROOT, "nope");
    const result = await scanRepository(missing);

    const serialized = structurally(result);
    assert.ok(!serialized.includes("ENOENT"));
    assert.ok(!serialized.includes("spawn"));
    assert.ok(!serialized.includes(missing));
    assert.equal(result.scan.errors[0].kind, "NOT_FOUND");
  });
});

// ─── Security regressions ───────────────────────────────────────────────────

describe("scanner: boundary security", () => {
  it(
    "never reads through a symlink that escapes the requested root",
    { skip: SYMLINK_SKIP },
    async () => {
      const outside = makeRepo({ "secret.txt": "top secret", "keys/id_rsa": "" });
      const root = makeRepo({ "src/index.js": "" });
      symlinkSync(outside, join(root, "escape"), "dir");
      symlinkSync(join(outside, "secret.txt"), join(root, "secret.txt"), "file");

      const result = await scanRepository(root);

      assert.deepEqual(filePaths(result), ["src/index.js"]);
      assert.deepEqual(
        result.symlinks.map((entry) => entry.path).sort(),
        ["escape", "secret.txt"],
      );
      const serialized = structurally(result);
      assert.ok(!serialized.includes(outside));
      assert.ok(!serialized.includes("top secret"));
      assert.ok(!serialized.includes("keys"));
    },
  );

  it("stays inside the requested root when the repository contains traversal-shaped names", async () => {
    const root = makeRepo({ "src/index.js": "" });
    const outside = makeRepo({ "secret.txt": "" });
    // A literal `..` cannot exist as a filename, but a *name that looks like*
    // traversal can, and it must be treated as an ordinary name.
    writeFileSync(join(root, "..%2f..%2fetc"), "x");
    if (SYMLINKS_AVAILABLE) symlinkSync(join(root, "src"), join(root, "loop"), "dir");

    const result = await scanRepository(root);

    assert.ok(filePaths(result).includes("..%2f..%2fetc"));
    assert.ok(!structurally(result).includes(outside));
    assert.equal(result.scan.complete, true);
  });

  it("accepts a root that is itself a symlink, treating it as the boundary", async () => {
    if (!SYMLINKS_AVAILABLE) return;
    const real = makeRepo({ "src/index.js": "" });
    const linkRoot = join(TMP_ROOT, `root-link-${counter++}`);
    symlinkSync(real, linkRoot, "dir");

    const result = await scanRepository(linkRoot);

    assert.deepEqual(filePaths(result), ["src/index.js"]);
    // The declared boundary is the requested root, and it resolves to the real
    // repository, so a symlinked root widens nothing.
    assert.equal(realpathSync(result.root), realpathSync(real));
    assert.equal(result.scan.complete, true);
  });

  it("includes no absolute host path in the result apart from the root", async () => {
    const outside = makeRepo({ "secret.txt": "" });
    const root = makeRepo({
      "package.json": "{}",
      "src/index.ts": "",
      "tests/index.test.js": "",
      ".github/workflows/ci.yml": "",
      "README.md": "",
    });

    const result = await scanRepository(root);

    // Walk every serialized string and check that the only absolute path in the
    // whole result is the declared root.
    const strings = [];
    const collect = (value) => {
      if (typeof value === "string") strings.push(value);
      else if (Array.isArray(value)) value.forEach(collect);
      else if (value && typeof value === "object") Object.values(value).forEach(collect);
    };
    collect(JSON.parse(structurally(result)));

    const isAbsolute = (value) => value.startsWith("/") || /^[A-Za-z]:[\\/]/.test(value);
    assert.deepEqual(
      strings.filter(isAbsolute),
      [result.root],
      "only the declared root may be an absolute host path",
    );
    assert.ok(!strings.some((value) => value.includes(outside)));
  });

  it("enforces the truncated/complete invariant in the contract itself", () => {
    const draft = createScanResult({
      root: "/repo",
      scannedAt: new Date(0).toISOString(),
    });
    assert.equal(draft.scan.complete, false, "a draft is never complete by default");
    assert.equal(validateScanResult(draft), draft);

    assert.throws(
      () =>
        validateScanResult({
          ...draft,
          scan: { ...draft.scan, complete: true, truncated: true },
        }),
      ValidationError,
    );
    assert.throws(
      () => validateScanResult({ ...draft, files: [{ path: "b" }, { path: "a" }] }),
      ValidationError,
      "unsorted collections are a contract violation",
    );
    assert.throws(
      () => validateScanResult({ ...draft, root: "" }),
      ValidationError,
    );
    assert.throws(() => validateScanResult(null), ValidationError);
  });

  it("never reads the repository through raw filesystem APIs", () => {
    // Architectural guard: the scanner must go through the Phase 8A boundary, so
    // it may not import `node:fs` or spawn anything.
    const scannerDir = join(process.cwd(), "src", "repository", "scanner");
    const files = [];
    const walkSources = (dir) => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name);
        if (entry.isDirectory()) walkSources(full);
        else if (entry.name.endsWith(".js")) files.push(full);
      }
    };
    walkSources(scannerDir);

    assert.ok(files.length >= 10, "expected the scanner modules to be present");
    const importSpecifiers = (source) =>
      [
        ...source.matchAll(/\bfrom\s+["']([^"']+)["']/g),
        ...source.matchAll(/\bimport\s*\(\s*["']([^"']+)["']\s*\)/g),
        ...source.matchAll(/\brequire\s*\(\s*["']([^"']+)["']\s*\)/g),
      ].map((match) => match[1]);

    for (const file of files) {
      const specifiers = importSpecifiers(readFileSync(file, "utf8"));
      for (const specifier of specifiers) {
        assert.ok(
          !/^node:(fs|child_process|net|http|https|worker_threads|dns|tls)(\/|$)/.test(
            specifier,
          ),
          `${file} must not import ${specifier}`,
        );
        for (const forbidden of [
          "tools.js",
          "tool-registry",
          "http-server",
          "stdio-server",
          "repository-model",
        ]) {
          assert.ok(
            !specifier.includes(forbidden),
            `${file} must not depend on ${forbidden}`,
          );
        }
      }
    }
  });
});

// ─── Result contract ────────────────────────────────────────────────────────

describe("scanner: result contract", () => {
  it("does not contain any analyzer output", async () => {
    const root = makeRepo({
      "package.json": JSON.stringify({ name: "demo" }),
      "src/index.js": "",
    });
    const result = await scanRepository(root);
    const serialized = structurally(result);

    for (const verdict of [
      "severity",
      "score",
      "grade",
      "verdict",
      "recommendation",
      "production-ready",
      "vulnerab",
    ]) {
      assert.ok(
        !serialized.includes(verdict),
        `a scanner result must not carry "${verdict}"`,
      );
    }
    assert.deepEqual(result.scan.errors, []);
  });

  it("exposes the same detected sections for an empty repository", async () => {
    const root = makeRepo();
    const result = await scanRepository(root);

    for (const section of [
      result.tests,
      result.cicd,
      result.documentation,
      result.configuration,
    ]) {
      assert.equal(section.detected, false);
      assert.deepEqual(section.evidence, []);
    }
    assert.deepEqual(result.statistics, {
      filesScanned: 0,
      directoriesScanned: 0,
      symlinksScanned: 0,
      ignored: 0,
      unreadable: 0,
      truncatedBy: [],
    });
    assert.deepEqual(result.ignore.unsupported, []);
  });
});
