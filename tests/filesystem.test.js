/**
 * Code Guardian — Phase 8A Filesystem + Path Infrastructure Tests
 *
 * Focused tests for `src/repository/filesystem`. Fixtures live under
 * `.test-tmp` and are isolated from the user's real filesystem.
 *
 * Run with: node --test tests/filesystem.test.js
 */

import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync,
  mkdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import nodePath, { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  DEFAULT_SCAN_LIMITS,
  RepositoryError,
  ValidationError,
} from "../src/core/index.js";

import {
  DEFAULT_WALK_OPTIONS,
  DIRECTORY_ENTRY_TYPES,
  FILESYSTEM_ERROR_CODES,
  FILESYSTEM_ERROR_KINDS,
  FilesystemError,
  LINK_TARGET_KINDS,
  LINK_UNKNOWN_REASONS,
  SYMLINK_POLICY,
  classifyFilesystemError,
  classifyLinkTarget,
  createPathTools,
  filesystemErrorMessage,
  isContained,
  joinWithin,
  listDirectory,
  normalizeRoot,
  readFile,
  readLink,
  resolvePath,
  resolveWithin,
  sanitizeFilesystemPath,
  toFilesystemError,
  toRepositoryRelative,
  walk,
} from "../src/repository/filesystem/index.js";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const PLUGIN_DIR = fileURLToPath(new URL("..", import.meta.url));
const TMP_ROOT = join(PLUGIN_DIR, ".test-tmp");
let fixtureCounter = 0;
const created = [];

function register(dir) {
  created.push(dir);
  return dir;
}

/** Create an isolated fixture directory with the given files/dirs. */
function makeFixture(files = {}, dirs = []) {
  const dir = join(
    TMP_ROOT,
    `fs-${process.pid}-${Date.now()}-${fixtureCounter++}`,
  );
  mkdirSync(dir, { recursive: true });
  for (const sub of dirs) {
    mkdirSync(join(dir, sub), { recursive: true });
  }
  for (const [relPath, content] of Object.entries(files)) {
    const full = join(dir, relPath);
    mkdirSync(join(full, ".."), { recursive: true });
    writeFileSync(full, content);
  }
  return dir;
}

/** Probe whether the platform allows creating directory and file symlinks. */
function symlinksSupported() {
  const probe = join(TMP_ROOT, `symlink-probe-${process.pid}-${Date.now()}`);
  try {
    mkdirSync(join(probe, "target"), { recursive: true });
    writeFileSync(join(probe, "target", "file.txt"), "x");
    symlinkSync(join(probe, "target"), join(probe, "link-dir"), "dir");
    symlinkSync(
      join(probe, "target", "file.txt"),
      join(probe, "link-file.txt"),
      "file",
    );
    return true;
  } catch {
    return false;
  } finally {
    try {
      rmSync(probe, { recursive: true, force: true });
    } catch {}
  }
}

const SYMLINKS_SUPPORTED = symlinksSupported();
const SYMLINK_SKIP = SYMLINKS_SUPPORTED
  ? false
  : "platform does not permit creating symlinks";
const WINDOWS_SKIP =
  process.platform === "win32" ? "Windows uses backslash separators" : false;

function isInvalidPathError(error) {
  return (
    error instanceof FilesystemError &&
    error.kind === FILESYSTEM_ERROR_KINDS.INVALID_PATH
  );
}

after(() => {
  for (const dir of created) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {}
  }
});

// ─── Path semantics ──────────────────────────────────────────────────────────

describe("path utilities", () => {
  const root = "/repo";

  it("normalizes a repository root to an absolute path", () => {
    assert.equal(normalizeRoot(root), nodePath.resolve(root));
    assert.equal(normalizeRoot(root + "/"), nodePath.resolve(root));
  });

  it("rejects an empty or non-string root", () => {
    for (const bad of ["", "   ", null, undefined, 42]) {
      assert.throws(() => normalizeRoot(bad), isInvalidPathError);
    }
  });

  it("treats the root as contained in itself with relative '.'", () => {
    assert.equal(isContained(root, root), true);
    assert.equal(toRepositoryRelative(root, root), ".");
    assert.equal(resolveWithin(root, "."), nodePath.resolve(root));
  });

  it("contains a direct child", () => {
    assert.equal(isContained(root, "file.js"), true);
    assert.equal(isContained(root, join(root, "file.js")), true);
    assert.equal(toRepositoryRelative(root, join(root, "file.js")), "file.js");
  });

  it("contains a nested child and reports a POSIX relative path", () => {
    const nested = join(root, "src", "auth", "login.js");
    assert.equal(isContained(root, nested), true);
    assert.equal(toRepositoryRelative(root, nested), "src/auth/login.js");
  });

  it("rejects a sibling that merely shares a string prefix", () => {
    const sibling = root + "-other";
    assert.equal(sibling.startsWith(root), true, "string prefix would say yes");
    assert.equal(isContained(root, sibling), false);
    assert.equal(isContained(root, join(sibling, "file.js")), false);
    assert.throws(() => resolveWithin(root, sibling), isInvalidPathError);
    assert.throws(() => toRepositoryRelative(root, sibling), isInvalidPathError);
  });

  it("rejects parent traversal that escapes the root", () => {
    const escaping = join(root, "src", "..", "..", "outside");
    assert.equal(isContained(root, escaping), false);
    assert.throws(() => resolveWithin(root, "../outside"), isInvalidPathError);
    assert.throws(() => joinWithin(root, "..", "outside"), isInvalidPathError);
  });

  it("normalizes redundant separators", () => {
    assert.equal(
      toRepositoryRelative(root, "src//nested///file.js"),
      "src/nested/file.js",
    );
  });

  it("keeps absolute paths outside the root out of containment", () => {
    const outside = nodePath.resolve("/etc/passwd");
    assert.equal(resolvePath(root, outside), outside);
    assert.equal(isContained(root, outside), false);
    assert.throws(() => resolveWithin(root, outside), isInvalidPathError);
  });

  it("rejects an empty resolve target", () => {
    assert.throws(() => resolvePath(root, ""), isInvalidPathError);
    assert.throws(() => resolvePath(root, "   "), isInvalidPathError);
  });

  it(
    "treats backslashes literally on POSIX",
    { skip: WINDOWS_SKIP },
    () => {
      const winStyle = root + "\\sub\\file.js";
      assert.equal(isContained(root, winStyle), false);
    },
  );

  it("honors Windows separators and drive letters via path.win32", () => {
    const win = createPathTools(nodePath.win32);
    const winRoot = "C:\\repo";

    assert.equal(win.normalizeRoot(winRoot), winRoot);
    assert.equal(win.isContained(winRoot, "C:\\repo\\src\\file.js"), true);
    assert.equal(
      win.toRepositoryRelative(winRoot, "C:\\repo\\src\\file.js"),
      "src/file.js",
    );
    // Forward slashes are separators on Windows too.
    assert.equal(win.isContained(winRoot, "C:/repo/src/file.js"), true);
    // Sibling-prefix collision and different drives are both rejected.
    assert.equal(win.isContained(winRoot, "C:\\repo-other\\file.js"), false);
    assert.equal(win.isContained(winRoot, "D:\\repo\\file.js"), false);
    assert.throws(
      () => win.resolveWithin(winRoot, "C:\\repo\\..\\outside"),
      (error) =>
        error instanceof FilesystemError &&
        error.kind === FILESYSTEM_ERROR_KINDS.INVALID_PATH,
    );
  });
});

// ─── Error semantics ─────────────────────────────────────────────────────────

describe("filesystem error semantics", () => {
  it("extends the Core RepositoryError with structured details", () => {
    const error = new FilesystemError({
      kind: FILESYSTEM_ERROR_KINDS.NOT_FOUND,
      operation: "readFile",
      path: "a/b.js",
    });
    assert.ok(error instanceof FilesystemError);
    assert.ok(error instanceof RepositoryError);
    assert.equal(error.name, "FilesystemError");
    assert.equal(error.kind, "NOT_FOUND");
    assert.equal(error.code, FILESYSTEM_ERROR_CODES.NOT_FOUND);
    assert.equal(error.category, "repository");
    assert.deepEqual(error.details, {
      kind: "NOT_FOUND",
      operation: "readFile",
      path: "a/b.js",
    });
  });

  it("defaults an unknown kind to the generic filesystem error", () => {
    const error = new FilesystemError({ kind: "NOT_A_KIND" });
    assert.equal(error.kind, FILESYSTEM_ERROR_KINDS.FILESYSTEM_ERROR);
    assert.equal(error.code, FILESYSTEM_ERROR_CODES.FILESYSTEM_ERROR);
  });

  it("does not leak stack or cause when serialized", () => {
    const error = new FilesystemError({
      kind: FILESYSTEM_ERROR_KINDS.FILESYSTEM_ERROR,
      cause: new Error("internal detail"),
    });
    const json = error.toJSON();
    assert.ok(!("stack" in json));
    assert.ok(!("cause" in json));
  });

  it("classifies Node errno codes without guessing", () => {
    assert.equal(
      classifyFilesystemError({ code: "ENOENT" }),
      FILESYSTEM_ERROR_KINDS.NOT_FOUND,
    );
    assert.equal(
      classifyFilesystemError({ code: "ENOTDIR" }),
      FILESYSTEM_ERROR_KINDS.NOT_FOUND,
    );
    assert.equal(
      classifyFilesystemError({ code: "EACCES" }),
      FILESYSTEM_ERROR_KINDS.PERMISSION_DENIED,
    );
    assert.equal(
      classifyFilesystemError({ code: "EPERM" }),
      FILESYSTEM_ERROR_KINDS.PERMISSION_DENIED,
    );
    assert.equal(
      classifyFilesystemError({ code: "EINVAL" }),
      FILESYSTEM_ERROR_KINDS.INVALID_PATH,
    );
    assert.equal(
      classifyFilesystemError({ code: "ESOMETHING" }),
      FILESYSTEM_ERROR_KINDS.FILESYSTEM_ERROR,
    );
    assert.equal(
      classifyFilesystemError(undefined),
      FILESYSTEM_ERROR_KINDS.FILESYSTEM_ERROR,
    );
  });

  it("wraps arbitrary errors via toFilesystemError", () => {
    const wrapped = toFilesystemError(
      Object.assign(new Error("nope"), { code: "ENOENT" }),
      { operation: "readFile", path: "x.js" },
    );
    assert.ok(wrapped instanceof FilesystemError);
    assert.equal(wrapped.kind, FILESYSTEM_ERROR_KINDS.NOT_FOUND);
    assert.equal(wrapped.details.operation, "readFile");
  });

  it("passes an existing FilesystemError through unchanged", () => {
    const original = new FilesystemError({
      kind: FILESYSTEM_ERROR_KINDS.INVALID_PATH,
    });
    assert.equal(toFilesystemError(original), original);
  });
});

// ─── Error sanitization (Phase 8A correction 2) ──────────────────────────────

describe("filesystem error sanitization", () => {
  it("never copies a raw Node message that embeds an absolute path", () => {
    const nodeError = Object.assign(
      new Error(
        "ENOENT: no such file or directory, open 'C:\\Users\\secret\\repo\\file.txt'",
      ),
      { code: "ENOENT" },
    );
    const error = toFilesystemError(nodeError, {
      operation: "readFile",
      path: "file.txt",
    });
    const json = error.toJSON();

    assert.equal(error.kind, FILESYSTEM_ERROR_KINDS.NOT_FOUND);
    assert.equal(json.message, "readFile: filesystem path not found");
    assert.equal(json.details.path, "file.txt");
    assert.ok(!json.message.includes("C:\\Users\\secret"));
    assert.ok(!JSON.stringify(json).includes("C:\\Users\\secret"));
  });

  it("serializes neither stack nor cause nor the raw cause message", () => {
    const error = toFilesystemError(new Error("/abs/path/leak"), {
      operation: "listDirectory",
      path: "src",
    });
    const json = error.toJSON();
    assert.ok(!("stack" in json));
    assert.ok(!("cause" in json));
    assert.ok(!JSON.stringify(json).includes("/abs/path/leak"));
  });

  it("drops absolute inputs from details.path", () => {
    assert.equal(sanitizeFilesystemPath("/etc/passwd"), null);
    assert.equal(sanitizeFilesystemPath("C:\\Users\\secret"), null);
    assert.equal(sanitizeFilesystemPath("\\\\server\\share"), null);
    assert.equal(sanitizeFilesystemPath(""), null);
    assert.equal(sanitizeFilesystemPath("src/index.js"), "src/index.js");

    const error = new FilesystemError({
      kind: FILESYSTEM_ERROR_KINDS.INVALID_PATH,
      operation: "resolveWithin",
      path: "/etc/passwd",
    });
    assert.equal(error.details.path, null);
    assert.ok(!JSON.stringify(error.toJSON()).includes("/etc/passwd"));
  });

  it("keeps a repository-relative details.path intact", () => {
    const error = new FilesystemError({
      kind: FILESYSTEM_ERROR_KINDS.NOT_FOUND,
      operation: "readFile",
      path: "src/index.js",
    });
    assert.equal(error.details.path, "src/index.js");
  });

  it("derives a deterministic message from kind and operation", () => {
    assert.equal(
      filesystemErrorMessage(FILESYSTEM_ERROR_KINDS.NOT_FOUND, "readFile"),
      "readFile: filesystem path not found",
    );
    assert.equal(
      filesystemErrorMessage(FILESYSTEM_ERROR_KINDS.PERMISSION_DENIED),
      "filesystem permission denied",
    );
    assert.equal(
      filesystemErrorMessage(FILESYSTEM_ERROR_KINDS.SYMLINK_NOT_ALLOWED),
      "symlink traversal is not allowed",
    );
  });

  it("keeps error classification unchanged", () => {
    assert.equal(
      classifyFilesystemError({ code: "EACCES" }),
      FILESYSTEM_ERROR_KINDS.PERMISSION_DENIED,
    );
    assert.equal(
      classifyFilesystemError({ code: "ENOENT" }),
      FILESYSTEM_ERROR_KINDS.NOT_FOUND,
    );
    // The new kind has a stable code, and existing kinds are unchanged.
    assert.equal(
      FILESYSTEM_ERROR_CODES.SYMLINK_NOT_ALLOWED,
      "CG_FS_SYMLINK_NOT_ALLOWED",
    );
    assert.equal(FILESYSTEM_ERROR_CODES.NOT_FOUND, "CG_FS_NOT_FOUND");
    assert.equal(FILESYSTEM_ERROR_CODES.INVALID_PATH, "CG_FS_INVALID_PATH");
  });

  it("never serializes an absolute path from a containment rejection", async () => {
    const root = register(makeFixture({}));
    const outside = join(root, "..", "..", `outside-${Date.now()}.txt`);
    const result = await readFile(root, outside);
    assert.equal(result.ok, false);
    assert.equal(result.error.kind, FILESYSTEM_ERROR_KINDS.INVALID_PATH);
    assert.equal(result.error.details.path, null);
    assert.ok(!JSON.stringify(result.error.toJSON()).includes(root));
  });
});

// ─── readFile ────────────────────────────────────────────────────────────────

describe("readFile", () => {
  it("reads an existing file and reports its relative path", async () => {
    const root = register(makeFixture({ "src/index.js": "hello" }));
    const result = await readFile(root, "src/index.js");
    assert.equal(result.ok, true);
    assert.equal(result.content, "hello");
    assert.equal(result.relative, "src/index.js");
    assert.equal(result.path, join(root, "src", "index.js"));
  });

  it("supports a binary/buffer read", async () => {
    const root = register(makeFixture({ "bytes.bin": "ab" }));
    const result = await readFile(root, "bytes.bin", { encoding: null });
    assert.equal(result.ok, true);
    assert.ok(Buffer.isBuffer(result.content));
  });

  it("reports a missing file as NOT_FOUND", async () => {
    const root = register(makeFixture({}));
    const result = await readFile(root, "missing.txt");
    assert.equal(result.ok, false);
    assert.equal(result.error.kind, FILESYSTEM_ERROR_KINDS.NOT_FOUND);
    assert.equal(result.error.code, FILESYSTEM_ERROR_CODES.NOT_FOUND);
    assert.equal(result.error.details.operation, "readFile");
  });

  it("never returns null for a failure", async () => {
    const root = register(makeFixture({}));
    const result = await readFile(root, "nope.txt");
    assert.notEqual(result, null);
    assert.equal(result.ok, false);
    assert.ok(result.error instanceof FilesystemError);
  });

  it("rejects a path that escapes the root", async () => {
    const root = register(makeFixture({}));
    const result = await readFile(root, "../outside.txt");
    assert.equal(result.ok, false);
    assert.equal(result.error.kind, FILESYSTEM_ERROR_KINDS.INVALID_PATH);
  });

  it("reports a directory read as a typed error, not a cache hit", async () => {
    const root = register(makeFixture({}, ["dir"]));
    const result = await readFile(root, "dir");
    assert.equal(result.ok, false);
    assert.ok(result.error instanceof FilesystemError);
  });

  it(
    "reports permission denied when the platform enforces it",
    { skip: process.platform === "win32" ? "Windows ACL semantics differ" : false },
    async (t) => {
      const root = register(makeFixture({ "secret.txt": "x" }));
      const file = join(root, "secret.txt");
      chmodSync(file, 0o000);
      try {
        const result = await readFile(root, "secret.txt");
        if (result.ok) {
          t.skip("process bypasses file permissions (e.g. root)");
          return;
        }
        assert.equal(result.error.kind, FILESYSTEM_ERROR_KINDS.PERMISSION_DENIED);
      } finally {
        chmodSync(file, 0o644);
      }
    },
  );
});

// ─── listDirectory ───────────────────────────────────────────────────────────

describe("listDirectory", () => {
  it("lists entries deterministically with their types", async () => {
    const root = register(
      makeFixture({ "b.txt": "b", "a.txt": "a", "sub/c.txt": "c" }),
    );
    const result = await listDirectory(root, ".");
    assert.equal(result.ok, true);
    assert.equal(result.relative, ".");
    assert.deepEqual(
      result.entries.map((entry) => entry.name),
      ["a.txt", "b.txt", "sub"],
    );

    const byName = Object.fromEntries(
      result.entries.map((entry) => [entry.name, entry.type]),
    );
    assert.equal(byName["a.txt"], DIRECTORY_ENTRY_TYPES.FILE);
    assert.equal(byName["sub"], DIRECTORY_ENTRY_TYPES.DIRECTORY);

    const sub = result.entries.find((entry) => entry.name === "sub");
    assert.equal(sub.relative, "sub");
  });

  it("defaults to the repository root", async () => {
    const root = register(makeFixture({ "only.txt": "" }));
    const result = await listDirectory(root);
    assert.equal(result.ok, true);
    assert.deepEqual(
      result.entries.map((entry) => entry.name),
      ["only.txt"],
    );
  });

  it("reports a missing directory as NOT_FOUND", async () => {
    const root = register(makeFixture({}));
    const result = await listDirectory(root, "nope");
    assert.equal(result.ok, false);
    assert.equal(result.error.kind, FILESYSTEM_ERROR_KINDS.NOT_FOUND);
  });

  it("reports a non-directory target as an error, never an empty list", async () => {
    const root = register(makeFixture({ "file.txt": "x" }));
    const result = await listDirectory(root, "file.txt");
    assert.equal(result.ok, false);
    assert.ok(result.error instanceof FilesystemError);
  });

  it("rejects an escaping directory path", async () => {
    const root = register(makeFixture({}));
    const result = await listDirectory(root, "..");
    assert.equal(result.ok, false);
    assert.equal(result.error.kind, FILESYSTEM_ERROR_KINDS.INVALID_PATH);
  });
});

// ─── Symlink policy enforcement (Phase 8A correction 1) ──────────────────────

describe("symlink policy enforcement", () => {
  it(
    "rejects readFile through a symlink to a file outside the repository",
    { skip: SYMLINK_SKIP },
    async () => {
      const outside = register(makeFixture({ "secret.txt": "top secret" }));
      const root = register(makeFixture({ "real.txt": "ok" }));
      symlinkSync(join(outside, "secret.txt"), join(root, "link.txt"), "file");

      const result = await readFile(root, "link.txt");
      assert.equal(result.ok, false);
      assert.equal(
        result.error.kind,
        FILESYSTEM_ERROR_KINDS.SYMLINK_NOT_ALLOWED,
      );
      assert.equal(
        result.error.code,
        FILESYSTEM_ERROR_CODES.SYMLINK_NOT_ALLOWED,
      );
      assert.equal(result.error.details.operation, "readFile");
      assert.equal(result.error.details.path, "link.txt");
      assert.equal(result.relative, "link.txt");
    },
  );

  it(
    "rejects readFile through a symlinked path component",
    { skip: SYMLINK_SKIP },
    async () => {
      const outside = register(makeFixture({ "secret.txt": "top secret" }));
      const root = register(makeFixture({ "a/ok.txt": "ok" }));
      symlinkSync(outside, join(root, "a", "link-dir"), "dir");

      const result = await readFile(root, "a/link-dir/secret.txt");
      assert.equal(result.ok, false);
      assert.equal(
        result.error.kind,
        FILESYSTEM_ERROR_KINDS.SYMLINK_NOT_ALLOWED,
      );
      assert.equal(result.error.details.path, "a/link-dir/secret.txt");
    },
  );

  it(
    "rejects readFile through a symlink even when it points inside the repository",
    { skip: SYMLINK_SKIP },
    async () => {
      const root = register(makeFixture({ "real.txt": "ok" }));
      symlinkSync(join(root, "real.txt"), join(root, "alias.txt"), "file");

      const result = await readFile(root, "alias.txt");
      assert.equal(result.ok, false);
      assert.equal(
        result.error.kind,
        FILESYSTEM_ERROR_KINDS.SYMLINK_NOT_ALLOWED,
      );
    },
  );

  it(
    "rejects listDirectory on a symlink to a directory outside the repository",
    { skip: SYMLINK_SKIP },
    async () => {
      const outside = register(makeFixture({ "outside.txt": "x" }));
      const root = register(makeFixture({}));
      symlinkSync(outside, join(root, "link-dir"), "dir");

      const result = await listDirectory(root, "link-dir");
      assert.equal(result.ok, false);
      assert.equal(
        result.error.kind,
        FILESYSTEM_ERROR_KINDS.SYMLINK_NOT_ALLOWED,
      );
      assert.equal(result.error.details.operation, "listDirectory");
      assert.equal(result.error.details.path, "link-dir");
      assert.ok(!("entries" in result), "must not enumerate through a symlink");
    },
  );

  it(
    "keeps walk recording symlinks without following or recurring into them",
    { skip: SYMLINK_SKIP },
    async () => {
      const outside = register(makeFixture({ "outside.txt": "x" }));
      const root = register(makeFixture({ "real/file.txt": "" }));
      symlinkSync(outside, join(root, "real", "link-out"), "dir");
      symlinkSync(root, join(root, "real", "loop"), "dir");

      const result = await walk(root, { maxDepth: 10 });
      assert.equal(result.symlinkPolicy, SYMLINK_POLICY);
      assert.ok(result.symlinks.some((e) => e.relative === "real/link-out"));
      assert.ok(result.symlinks.some((e) => e.relative === "real/loop"));
      assert.ok(
        !result.directories.some((d) => d.relative.includes("link-out")),
      );
      assert.ok(!result.directories.some((d) => d.relative.includes("loop")));
      assert.ok(!result.files.some((f) => f.relative.includes("outside")));
      assert.equal(result.complete, true);
    },
  );

  it("still reads real files and lists real directories under the policy", async () => {
    const root = register(makeFixture({ "src/index.js": "hello" }));
    const file = await readFile(root, "src/index.js");
    assert.equal(file.ok, true);
    const listing = await listDirectory(root, ".");
    assert.equal(listing.ok, true);
  });
});

// ─── walk ────────────────────────────────────────────────────────────────────

describe("walk", () => {
  it("defaults to the Phase 7 scan-limit baseline", () => {
    assert.equal(DEFAULT_WALK_OPTIONS.maxFiles, DEFAULT_SCAN_LIMITS.maxFiles);
    assert.equal(DEFAULT_WALK_OPTIONS.maxDepth, DEFAULT_SCAN_LIMITS.maxDepth);
    assert.equal(DEFAULT_WALK_OPTIONS.maxFiles, 10000);
    assert.equal(DEFAULT_WALK_OPTIONS.maxDepth, 20);
    assert.equal(SYMLINK_POLICY, "not-followed");
  });

  it("walks a tree and reports a complete scan", async () => {
    const root = register(
      makeFixture({
        "README.md": "#",
        "src/index.js": "x",
        "src/util/helper.js": "y",
        "tests/unit/a.test.js": "z",
      }),
    );
    const result = await walk(root, { maxDepth: 10 });

    assert.equal(result.complete, true);
    assert.equal(result.truncated, false);
    assert.deepEqual(result.errors, []);
    assert.equal(result.root, normalizeRoot(root));
    assert.equal(result.symlinkPolicy, SYMLINK_POLICY);
    assert.deepEqual(result.limits, {
      maxFiles: DEFAULT_WALK_OPTIONS.maxFiles,
      maxDepth: 10,
    });
    assert.deepEqual(
      result.files.map((file) => file.relative).sort(),
      [
        "README.md",
        "src/index.js",
        "src/util/helper.js",
        "tests/unit/a.test.js",
      ],
    );
    assert.deepEqual(
      result.directories.map((dir) => dir.relative).sort(),
      ["src", "src/util", "tests", "tests/unit"],
    );
  });

  it("records the effective limits", async () => {
    const root = register(makeFixture({ "a.txt": "" }));
    const result = await walk(root, { maxFiles: 5, maxDepth: 3 });
    assert.deepEqual(result.limits, { maxFiles: 5, maxDepth: 3 });
  });

  it("truncates when maxFiles is reached and reports it", async () => {
    const root = register(
      makeFixture({ "a.txt": "", "b.txt": "", "c.txt": "" }),
    );
    const result = await walk(root, { maxFiles: 2, maxDepth: 5 });
    assert.equal(result.files.length, 2);
    assert.equal(result.truncated, true);
    assert.equal(result.complete, false);
  });

  it("does not report truncation when the file count fits exactly", async () => {
    const root = register(makeFixture({ "a.txt": "", "b.txt": "" }));
    const result = await walk(root, { maxFiles: 2, maxDepth: 5 });
    assert.equal(result.truncated, false);
    assert.equal(result.complete, true);
  });

  it("truncates when maxDepth is reached and reports it", async () => {
    const root = register(makeFixture({ "a/b/c/deep.txt": "" }));
    const result = await walk(root, { maxDepth: 2, maxFiles: 100 });
    assert.equal(result.truncated, true);
    assert.equal(result.complete, false);
    // "a" is opened; "a/b" is recorded but not opened.
    assert.deepEqual(
      result.directories.map((dir) => dir.relative).sort(),
      ["a", "a/b"],
    );
  });

  it("excludes ignored directories and records them", async () => {
    const root = register(
      makeFixture({ "src/a.js": "", "node_modules/b.js": "" }),
    );
    const result = await walk(root, {
      maxDepth: 5,
      ignore: ["node_modules"],
    });
    assert.ok(!result.directories.some((dir) => dir.name === "node_modules"));
    assert.ok(
      result.ignored.some((entry) => entry.relative === "node_modules"),
    );
    assert.ok(
      !result.files.some((file) => file.relative.includes("node_modules")),
    );
    assert.equal(result.complete, true);
  });

  it("reports a missing root as an error and stays incomplete", async () => {
    const missing = join(TMP_ROOT, `missing-${process.pid}-${Date.now()}`);
    const result = await walk(missing);
    assert.equal(result.complete, false);
    assert.equal(result.truncated, false);
    assert.equal(result.errors.length, 1);
    assert.equal(result.errors[0].kind, FILESYSTEM_ERROR_KINDS.NOT_FOUND);
    assert.equal(result.errors[0].details.operation, "listDirectory");
  });

  it(
    "never reports a scan with unreadable directories as complete",
    { skip: process.platform === "win32" ? "Windows ACL semantics differ" : false },
    async (t) => {
      const root = register(
        makeFixture({ "ok/file.txt": "", "restricted/secret.txt": "" }),
      );
      const restricted = join(root, "restricted");
      chmodSync(restricted, 0o000);
      try {
        const result = await walk(root, { maxDepth: 5 });
        if (result.errors.length === 0) {
          t.skip("process bypasses directory permissions (e.g. root)");
          return;
        }
        assert.equal(result.complete, false);
        assert.equal(
          result.errors[0].kind,
          FILESYSTEM_ERROR_KINDS.PERMISSION_DENIED,
        );
      } finally {
        chmodSync(restricted, 0o755);
      }
    },
  );

  it(
    "records symlinks without following them",
    { skip: SYMLINK_SKIP },
    async () => {
      const outside = register(makeFixture({ "outside-file.txt": "" }));
      const root = register(makeFixture({ "real/file.txt": "" }));
      symlinkSync(outside, join(root, "real", "link-out"), "dir");

      const result = await walk(root, { maxDepth: 5 });
      assert.equal(result.complete, true, "a symlink is not an error");
      assert.equal(result.truncated, false);
      assert.ok(
        result.symlinks.some((entry) => entry.relative === "real/link-out"),
      );
      assert.ok(
        !result.directories.some((dir) => dir.relative === "real/link-out"),
      );
      assert.ok(
        !result.files.some((file) => file.relative.includes("outside-file")),
      );
    },
  );

  it(
    "does not loop on symlink cycles",
    { skip: SYMLINK_SKIP },
    async () => {
      const root = register(makeFixture({ "a/file.txt": "" }));
      symlinkSync(root, join(root, "a", "loop"), "dir");

      const result = await walk(root, { maxDepth: 10 });
      assert.equal(result.complete, true);
      assert.ok(
        result.symlinks.some((entry) => entry.relative === "a/loop"),
      );
      assert.ok(
        !result.directories.some((dir) => dir.relative === "a/loop"),
      );
    },
  );

  it("rejects invalid limits instead of silently ignoring them", async () => {
    const root = register(makeFixture({ "a.txt": "" }));
    await assert.rejects(() => walk(root, { maxFiles: 0 }), ValidationError);
    await assert.rejects(() => walk(root, { maxDepth: -1 }), ValidationError);
    await assert.rejects(() => walk(root, { maxDepth: 1.5 }), ValidationError);
    await assert.rejects(() => walk(root, { maxFiles: "10" }), ValidationError);
    await assert.rejects(
      () => walk(root, { ignore: "node_modules" }),
      ValidationError,
    );
  });
});

// ─── Symlink inspection and bounded reads (Phase 12 corrections) ─────────────

describe("symlink inspection (readLink)", () => {
  it("classifies a relative target that stays inside the repository", async () => {
    const root = register(makeFixture({ "real.txt": "ok", "a/keep.txt": "x" }));
    symlinkSync("../real.txt", join(root, "a", "alias"), "file");

    const result = await readLink(root, "a/alias");
    assert.equal(result.ok, true);
    assert.equal(result.relative, "a/alias");
    assert.deepEqual(result.target, {
      kind: LINK_TARGET_KINDS.INSIDE,
      path: "real.txt",
      reason: null,
    });
  });

  it(
    "classifies an absolute target that leaves the repository as outside, and keeps the raw path out of the result",
    { skip: SYMLINK_SKIP },
    async () => {
      const outside = register(makeFixture({ "secret.txt": "top secret" }));
      const root = register(makeFixture({ "real.txt": "ok" }));
      symlinkSync(join(outside, "secret.txt"), join(root, "escape"), "file");

      const result = await readLink(root, "escape");
      assert.equal(result.ok, true);
      assert.deepEqual(result.target, {
        kind: LINK_TARGET_KINDS.OUTSIDE,
        path: null,
        reason: null,
      });
      // The target's text is discarded: no host location travels with the result.
      const serialized = JSON.stringify(result.target);
      assert.equal(serialized.includes(outside), false);
      assert.equal(serialized.includes("secret.txt"), false);
    },
  );

  it(
    "classifies a traversal target that normalizes outside the repository",
    { skip: SYMLINK_SKIP },
    async () => {
      const root = register(makeFixture({ "a/keep.txt": "x" }));
      symlinkSync("../../outside", join(root, "a", "up"), "file");

      const result = await readLink(root, "a/up");
      assert.equal(result.target.kind, LINK_TARGET_KINDS.OUTSIDE);
    },
  );

  it(
    "classifies a target that climbs back to the repository root",
    { skip: SYMLINK_SKIP },
    async () => {
      const root = register(makeFixture({ "a/keep.txt": "x" }));
      symlinkSync("..", join(root, "a", "root-link"), "dir");

      const result = await readLink(root, "a/root-link");
      // The root has no repository-relative form, so it is recorded as `inside`
      // with a null path rather than as a fabricated ".".
      assert.deepEqual(result.target, {
        kind: LINK_TARGET_KINDS.INSIDE,
        path: null,
        reason: null,
      });
    },
  );

  it(
    "never follows the link it inspects, and never reads its target",
    { skip: SYMLINK_SKIP },
    async () => {
      const outside = register(makeFixture({ "secret.txt": "top secret" }));
      const root = register(makeFixture({ "real.txt": "ok" }));
      symlinkSync(outside, join(root, "link-dir"), "dir");

      const result = await readLink(root, "link-dir");
      assert.equal(result.ok, true);
      assert.equal(result.target.kind, LINK_TARGET_KINDS.OUTSIDE);
      assert.equal("content" in result, false);
      assert.equal("entries" in result, false);

      // Following the same path through readFile is still refused.
      const read = await readFile(root, "link-dir/secret.txt");
      assert.equal(read.ok, false);
      assert.equal(read.error.kind, FILESYSTEM_ERROR_KINDS.SYMLINK_NOT_ALLOWED);
    },
  );

  it(
    "refuses to inspect a link behind a symlinked directory",
    { skip: SYMLINK_SKIP },
    async () => {
      const real = register(makeFixture({ "inner": "" }));
      const root = register(makeFixture({ "keep.txt": "" }));
      symlinkSync(real, join(root, "linked-dir"), "dir");
      symlinkSync(join(real, "inner"), join(real, "inner-link"), "file");

      const result = await readLink(root, "linked-dir/inner-link");
      assert.equal(result.ok, false);
      assert.equal(result.error.kind, FILESYSTEM_ERROR_KINDS.SYMLINK_NOT_ALLOWED);
      assert.equal(result.relative, "linked-dir/inner-link");
    },
  );

  it("rejects a path that is not a symlink with a stable, path-free error", async () => {
    const root = register(makeFixture({ "real.txt": "ok" }));
    const result = await readLink(root, "real.txt");
    assert.equal(result.ok, false);
    assert.equal(result.error.kind, FILESYSTEM_ERROR_KINDS.NOT_A_SYMLINK);
    assert.equal(result.error.code, FILESYSTEM_ERROR_CODES.NOT_A_SYMLINK);
    assert.equal(result.error.toJSON().details.path, "real.txt");

    const missing = await readLink(root, "nope");
    assert.equal(missing.ok, false);
    assert.equal(missing.error.kind, FILESYSTEM_ERROR_KINDS.NOT_FOUND);
  });

  it("refuses a target outside the requested root without inspecting it", async () => {
    const root = register(makeFixture({ "real.txt": "ok" }));
    const result = await readLink(root, "../outside");
    assert.equal(result.ok, false);
    assert.equal(result.error.kind, FILESYSTEM_ERROR_KINDS.INVALID_PATH);
  });
});

describe("link target classification", () => {
  const root = nodePath.resolve("/repo");

  it("classifies without touching the filesystem", () => {
    assert.deepEqual(classifyLinkTarget(root, nodePath.resolve("/repo/a/l"), "b"), {
      kind: LINK_TARGET_KINDS.INSIDE,
      path: "a/b",
      reason: null,
    });
    assert.equal(
      classifyLinkTarget(root, nodePath.resolve("/repo/a/l"), "/etc/passwd").kind,
      LINK_TARGET_KINDS.OUTSIDE,
    );
    assert.equal(
      classifyLinkTarget(root, nodePath.resolve("/repo/a/l"), "../../../etc").kind,
      LINK_TARGET_KINDS.OUTSIDE,
    );
    assert.deepEqual(classifyLinkTarget(root, nodePath.resolve("/repo/a/l"), "."), {
      kind: LINK_TARGET_KINDS.INSIDE,
      path: "a",
      reason: null,
    });
  });

  it("reports an unusable target as unknown rather than guessing", () => {
    for (const raw of ["", null, undefined, "bad\u0000target", 42]) {
      const target = classifyLinkTarget(root, nodePath.resolve("/repo/a/l"), raw);
      assert.equal(target.kind, LINK_TARGET_KINDS.UNKNOWN, String(raw));
      assert.equal(target.reason, LINK_UNKNOWN_REASONS.UNREADABLE);
      assert.equal(target.path, null);
    }
  });
});

describe("bounded reads", () => {
  it("reads at most maxBytes and reports the truncation", async () => {
    const root = register(makeFixture({ "big.txt": "0123456789" }));

    const exact = await readFile(root, "big.txt", { maxBytes: 10 });
    assert.equal(exact.ok, true);
    assert.equal(exact.content, "0123456789");
    assert.equal(exact.bytesRead, 10);
    assert.equal(exact.truncated, false);

    const over = await readFile(root, "big.txt", { maxBytes: 9 });
    assert.equal(over.content, "0123456789".slice(0, 9));
    assert.equal(over.bytesRead, 9);
    assert.equal(over.truncated, true);

    const zero = await readFile(root, "big.txt", { maxBytes: 0 });
    assert.equal(zero.content, "");
    assert.equal(zero.truncated, true);

    const larger = await readFile(root, "big.txt", { maxBytes: 4096 });
    assert.equal(larger.truncated, false);
    assert.equal(larger.bytesRead, 10);
  });

  it("returns raw bytes for a bounded binary read", async () => {
    const root = register(makeFixture({ "bin.dat": "ab\u0000cd" }));
    const result = await readFile(root, "bin.dat", { encoding: null, maxBytes: 128 });
    assert.equal(result.ok, true);
    assert.ok(Buffer.isBuffer(result.content));
    assert.equal(result.content.includes(0), true);
    assert.equal(result.bytesRead, 5);
  });

  it("rejects an invalid byte budget instead of reading unbounded", async () => {
    const root = register(makeFixture({ "a.txt": "x" }));
    for (const maxBytes of [-1, 1.5, Number.MAX_SAFE_INTEGER + 2, "10", NaN]) {
      const result = await readFile(root, "a.txt", { maxBytes });
      assert.equal(result.ok, false, String(maxBytes));
      assert.equal(result.error.kind, FILESYSTEM_ERROR_KINDS.INVALID_PATH);
    }
  });

  it("still refuses to read through a symlink when bounded", async () => {
    const root = register(makeFixture({ "real.txt": "secret-value" }));
    if (!SYMLINKS_SUPPORTED) return;
    symlinkSync(join(root, "real.txt"), join(root, "alias.txt"), "file");
    const result = await readFile(root, "alias.txt", { maxBytes: 128 });
    assert.equal(result.ok, false);
    assert.equal(result.error.kind, FILESYSTEM_ERROR_KINDS.SYMLINK_NOT_ALLOWED);
  });
});

