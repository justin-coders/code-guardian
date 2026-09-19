/**
 * Code Guardian — Phase 8B-H Adversarial Security Harness
 *
 * Attacks the two accepted security boundaries with attacker-shaped input:
 *
 *   Phase 8A — repository containment, symlink policy, filesystem error
 *              sanitization, walk limits.
 *   Phase 8B — executable resolution/authorization, execution cwd, environment
 *              policy, shell safety, resource limits, cancellation and
 *              information sanitization.
 *
 * Every test states the invariant being defended, and the assertions are written
 * so that *weakening the protection makes the test fail* (verified by mutation
 * for the load-bearing cases). Where a boundary deliberately does not cover
 * something, the test says so instead of pretending otherwise.
 *
 * Fixtures are short-lived Node processes (`process.execPath`) inside a unique
 * OS-temp directory, so the harness is portable, deterministic and
 * network-independent.
 *
 * Run with: node --test tests/security-adversarial.test.js
 */

import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import nodePath, { basename, dirname, join } from "node:path";

import { ValidationError } from "../src/core/index.js";

import {
  EXECUTION_CONTROL_ENVIRONMENT_VARIABLES,
  EXECUTION_ERROR_KINDS,
  EXECUTION_STATUS,
  MAX_TIMER_DELAY_MS,
  commandIdentity,
  runExecution,
} from "../src/execution/index.js";

import {
  FILESYSTEM_ERROR_KINDS,
  FilesystemError,
  createPathTools,
  listDirectory,
  readFile,
  sanitizeFilesystemPath,
  walk,
} from "../src/repository/filesystem/index.js";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const TMP_ROOT = join(
  tmpdir(),
  `cg-adversarial-${process.pid}-${Date.now()}`,
);
const NODE = process.execPath;
const NODE_ID = commandIdentity(NODE);
const WINDOWS = process.platform === "win32";

let counter = 0;

/** Create a disposable tree; `files` are repository-relative paths. */
function makeFixture(files = {}, dirs = []) {
  const dir = join(TMP_ROOT, `fix-${counter++}`);
  mkdirSync(dir, { recursive: true });
  for (const sub of dirs) mkdirSync(join(dir, sub), { recursive: true });
  for (const [relative, content] of Object.entries(files)) {
    const full = join(dir, relative);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
  return dir;
}

/** A file that exists but cannot be executed. */
function makeImpostor(dir, name) {
  const path = join(dir, name);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, "not-a-real-executable\n");
  return path;
}

/** Symlink support varies by platform and account; probe once. */
const SYMLINKS_AVAILABLE = (() => {
  const probe = mkdtempSync(join(tmpdir(), "cg-symlink-probe-"));
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

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isProcessAlive(pid) {
  if (!pid) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code === "EPERM";
  }
}

function normalizeForCompare(value) {
  const resolved = realpathSync(String(value).trim());
  return WINDOWS ? resolved.toLowerCase() : resolved;
}

/** A Core ExecutionPolicy-shaped policy that authorizes Node inside `root`. */
function nodePolicy(root, overrides = {}) {
  return { allowedRoots: [root], allowCommands: [NODE_ID], ...overrides };
}

/** An ExecutionRequest running `script` with Node itself. */
function nodeRequest(root, script, extra = {}) {
  return {
    command: NODE,
    args: ["-e", script],
    policy: nodePolicy(root),
    ...extra,
  };
}

/**
 * Record the timers and abort listeners the runner creates so a leak is a test
 * failure rather than a silent resource drain.
 */
function createTimerAudit() {
  const realSetTimeout = globalThis.setTimeout;
  const realClearTimeout = globalThis.clearTimeout;
  const created = new Map();
  const cleared = new Set();

  return {
    start() {
      globalThis.setTimeout = (handler, delayMs, ...args) => {
        const handle = realSetTimeout(handler, delayMs, ...args);
        created.set(handle, delayMs);
        return handle;
      };
      globalThis.clearTimeout = (handle) => {
        cleared.add(handle);
        return realClearTimeout(handle);
      };
    },
    stop() {
      globalThis.setTimeout = realSetTimeout;
      globalThis.clearTimeout = realClearTimeout;
    },
    /** Timers created with one of `delays` that were never explicitly cleared. */
    orphans(delays) {
      return [...created.entries()]
        .filter(([handle, delayMs]) => delays.includes(delayMs) && !cleared.has(handle))
        .map(([, delayMs]) => delayMs);
    },
  };
}

/** An AbortSignal-shaped object that counts its listeners. */
function countingSignal() {
  const listeners = new Set();
  return {
    aborted: false,
    addEventListener(type, listener) {
      if (type === "abort") listeners.add(listener);
    },
    removeEventListener(type, listener) {
      if (type === "abort") listeners.delete(listener);
    },
    listenerCount: () => listeners.size,
    abort() {
      this.aborted = true;
      for (const listener of [...listeners]) listener();
    },
  };
}

after(() => {
  rmSync(TMP_ROOT, { recursive: true, force: true });
});

// ─── A. Path attacks ─────────────────────────────────────────────────────────

describe("adversarial: path attacks", () => {
  it("refuses a NUL byte in a path without crashing or leaking", async () => {
    const root = makeFixture({ "ok.txt": "ok" });

    const read = await readFile(root, "a\0b");
    assert.equal(read.ok, false);
    assert.ok(read.error instanceof FilesystemError);
    assert.equal(read.error.details.path, null, "NUL paths are not reportable");
    assert.ok(!read.error.message.includes("\0"));

    const listing = await listDirectory(root, "\0");
    assert.equal(listing.ok, false);
    assert.equal(listing.error.details.path, null);
  });

  it(
    "treats backslash traversal as a name on POSIX, never as an escape",
    { skip: WINDOWS ? "backslashes are separators on Windows" : false },
    async () => {
      const outside = makeFixture({ "secret.txt": "top secret" });
      const root = makeFixture();
      const target = `..\\..\\${basename(outside)}\\secret.txt`;

      const result = await readFile(root, target);
      assert.equal(result.ok, false);
      assert.ok(
        !JSON.stringify(result.error).includes(outside),
        "an escape attempt must not serialize the outside location",
      );
    },
  );

  it("keeps UNC containment semantic under Windows path rules", () => {
    const win = createPathTools(nodePath.win32);
    const share = "\\\\srv\\share\\repo";

    assert.equal(win.isContained(share, "\\\\srv\\share\\repo\\src\\a.js"), true);
    assert.equal(win.isContained(share, "\\\\srv\\share\\repo-other\\a.js"), false);
    assert.equal(win.isContained(share, "\\\\other\\share\\repo\\a.js"), false);
    assert.throws(
      () => win.resolveWithin(share, "..\\..\\other"),
      (error) =>
        error instanceof FilesystemError &&
        error.kind === FILESYSTEM_ERROR_KINDS.INVALID_PATH,
    );
  });

  it(
    "refuses a chain of symlinks that ends outside the root",
    { skip: SYMLINK_SKIP },
    async () => {
      const outside = makeFixture({ "secret.txt": "top secret" });
      const fileRoot = makeFixture();
      symlinkSync(join(fileRoot, "l2"), join(fileRoot, "l1"), "file");
      symlinkSync(join(outside, "secret.txt"), join(fileRoot, "l2"), "file");

      const read = await readFile(fileRoot, "l1");
      assert.equal(read.ok, false);
      assert.equal(
        read.error.kind,
        FILESYSTEM_ERROR_KINDS.SYMLINK_NOT_ALLOWED,
      );

      const dirRoot = makeFixture();
      symlinkSync(join(dirRoot, "l2"), join(dirRoot, "l1"), "dir");
      symlinkSync(outside, join(dirRoot, "l2"), "dir");

      const listing = await listDirectory(dirRoot, "l1");
      assert.equal(listing.ok, false);
      assert.equal(
        listing.error.kind,
        FILESYSTEM_ERROR_KINDS.SYMLINK_NOT_ALLOWED,
      );

      const walked = await walk(dirRoot, { maxDepth: 10 });
      assert.equal(walked.complete, true, "a chain is not an error");
      assert.equal(walked.errors.length, 0);
      assert.ok(walked.symlinks.some((entry) => entry.relative === "l1"));
      assert.ok(
        !JSON.stringify(walked).includes(outside),
        "the chain target must never appear in the walk",
      );
    },
  );
});

// ─── B. Executable authorization attacks ─────────────────────────────────────

describe("adversarial: executable authorization", () => {
  it("refuses a same-basename executable reached through relative forms", async () => {
    const root = makeFixture();
    makeImpostor(root, "node"); // <root>/node, i.e. `./node`
    const sibling = makeFixture();
    makeImpostor(sibling, "node");

    const attempts = ["./node", `../${basename(sibling)}/node`];

    for (const command of attempts) {
      const result = await runExecution({
        command,
        args: ["-e", "process.exit(0)"],
        cwd: root,
        policy: nodePolicy(root),
      });
      assert.equal(
        result.status,
        EXECUTION_STATUS.REJECTED,
        `${command} must not be authorized by the bare name`,
      );
      assert.equal(
        result.error.kind,
        EXECUTION_ERROR_KINDS.COMMAND_UNTRUSTED_LOCATION,
      );
      assert.equal(result.pid, null, `${command} must never spawn`);
    }
  });

  it("resolves a bare allowed name through the trusted environment, never the cwd", async () => {
    // The *bare* name is the legitimate path: it stays authorized and must
    // resolve to the trusted runtime even though the working directory contains
    // a same-basename file that a cwd- or PATH-first lookup would pick up.
    const root = makeFixture();
    makeImpostor(root, "node");

    const result = await runExecution({
      command: "node",
      args: ["-e", "process.stdout.write(process.execPath)"],
      cwd: root,
      policy: nodePolicy(root),
    });

    assert.equal(result.status, EXECUTION_STATUS.COMPLETED);
    assert.equal(result.policy.allowed, true);
    assert.notEqual(
      normalizeForCompare(result.stdout),
      normalizeForCompare(join(root, "node")),
      "a cwd-first lookup would have run the same-basename impostor",
    );
  });

  it("keeps identity matching exact for lookalike names", () => {
    assert.notEqual(commandIdentity(`${NODE_ID}-malicious`), NODE_ID);
    assert.notEqual(commandIdentity(`${NODE_ID}.bak`), NODE_ID);
    assert.notEqual(commandIdentity(`${NODE_ID}2`), NODE_ID);
    // Case sensitivity is a platform property, not an oversight: POSIX filenames
    // are case-sensitive, Windows names are not.
    assert.equal(
      commandIdentity("Node") === NODE_ID,
      WINDOWS,
      "a casing variant must not resolve to the allowed identity on POSIX",
    );
  });

  it(
    "refuses a symlinked executable whose target lies outside the allowed roots",
    { skip: SYMLINK_SKIP },
    async () => {
      const root = makeFixture();
      const realToolDir = makeFixture({ node: "#!/bin/sh\nexit 0\n" });
      const toolsDir = join(root, "tools");
      mkdirSync(toolsDir, { recursive: true });
      const link = join(toolsDir, WINDOWS ? "node.exe" : "node");
      symlinkSync(join(realToolDir, "node"), link, "file");

      const refused = await runExecution({
        command: link,
        policy: nodePolicy(root, { allowedExecutableRoots: [toolsDir] }),
      });
      assert.equal(refused.status, EXECUTION_STATUS.REJECTED);
      assert.equal(
        refused.error.kind,
        EXECUTION_ERROR_KINDS.COMMAND_UNTRUSTED_LOCATION,
        "the canonical target, not the link, decides trust",
      );
      assert.equal(refused.pid, null);

      // Positive control: authorizing the target directory is deliberate
      // authorization, so the boundary must not over-reject.
      const permitted = await runExecution({
        command: link,
        policy: nodePolicy(root, { allowedExecutableRoots: [realToolDir] }),
      });
      assert.equal(permitted.policy.allowed, true);
      assert.notEqual(permitted.status, EXECUTION_STATUS.REJECTED);
    },
  );

  it("grants nothing for a missing or non-directory executable root", async () => {
    const root = makeFixture();
    const impostorDir = makeFixture();
    const impostor = makeImpostor(impostorDir, "node");
    const fileNotDir = makeImpostor(root, "not-a-dir.txt");

    for (const entry of [join(TMP_ROOT, "does-not-exist"), fileNotDir]) {
      const result = await runExecution({
        command: impostor,
        policy: nodePolicy(root, { allowedExecutableRoots: [entry] }),
      });
      assert.equal(result.status, EXECUTION_STATUS.REJECTED);
      assert.equal(
        result.error.kind,
        EXECUTION_ERROR_KINDS.COMMAND_UNTRUSTED_LOCATION,
      );
      assert.equal(result.pid, null);
    }
  });

  it(
    "authorizes the canonical file an explicit path entry denotes, and nothing else",
    { skip: SYMLINK_SKIP },
    async () => {
      const root = makeFixture();
      const realDir = makeFixture({ node: "#!/bin/sh\nexit 0\n" });
      const binDir = join(root, "bin");
      mkdirSync(binDir, { recursive: true });
      const link = join(binDir, WINDOWS ? "node.exe" : "node");
      symlinkSync(join(realDir, "node"), link, "file");

      // An explicit path entry is a deliberate location decision: it authorizes
      // the canonical file the path denotes. This is not an escalation, because
      // replacing a policy-named file with a link requires the same write access
      // that would let an attacker replace its contents.
      const named = await runExecution({
        command: link,
        policy: nodePolicy(root, { allowCommands: [link] }),
      });
      assert.equal(named.policy.allowed, true);

      // ...and it authorizes nothing else: another file is not covered by it.
      const other = await runExecution({
        command: NODE,
        policy: nodePolicy(root, { allowCommands: [link] }),
      });
      assert.equal(other.status, EXECUTION_STATUS.REJECTED);
      assert.equal(other.error.kind, EXECUTION_ERROR_KINDS.COMMAND_NOT_ALLOWED);
      assert.ok(!JSON.stringify(other.error).includes(realDir));
    },
  );
});

// ─── C. Environment attacks ──────────────────────────────────────────────────

describe("adversarial: environment policy", () => {
  it("refuses every execution-control variable and never echoes its value", async () => {
    const root = makeFixture();

    for (const [index, name] of EXECUTION_CONTROL_ENVIRONMENT_VARIABLES.entries()) {
      const secret = `cg-secret-${index}-value`;
      await assert.rejects(
        () =>
          runExecution({
            ...nodeRequest(root, "process.exit(0)"),
            environment: { [name]: secret },
          }),
        (error) => {
          assert.ok(error instanceof ValidationError, `${name} must be refused`);
          assert.ok(
            !JSON.stringify(error).includes(secret),
            `${name} must not echo its value`,
          );
          return true;
        },
      );
    }
  });

  it("applies reserved-name matching with platform case semantics", async () => {
    const root = makeFixture();

    if (WINDOWS) {
      // Windows environment names are case-insensitive, so a casing variant is
      // the same reserved variable.
      await assert.rejects(
        () =>
          runExecution({
            ...nodeRequest(root, "process.exit(0)"),
            environment: { Node_Options: "--require=/evil" },
          }),
        ValidationError,
      );
      return;
    }

    // POSIX names are case-sensitive, so a lower-case spelling is a *different*
    // variable: it must stay usable while being unable to redirect execution.
    const result = await runExecution({
      command: "node",
      args: ["-e", "process.stdout.write(String(process.env.node_options))"],
      policy: nodePolicy(root),
      environment: { node_options: "--require=/evil" },
    });
    assert.equal(result.status, EXECUTION_STATUS.COMPLETED);
    assert.equal(result.stdout, "--require=/evil");
  });

  it("resolves a bare allowed command with no inherited environment", async () => {
    const root = makeFixture();

    // Resolution must depend on the runner's trusted environment, never on what
    // the caller hands the child, so removing the child environment entirely
    // cannot make an allowed command unresolvable or run something else.
    const result = await runExecution(
      { command: "node", args: ["-e", "process.exit(0)"], policy: nodePolicy(root) },
      { inheritEnvironment: false },
    );
    assert.equal(result.status, EXECUTION_STATUS.COMPLETED);
  });

  it("never serializes environment values or duplicates arguments", async () => {
    const root = makeFixture();
    const envSecret = "cg-env-secret-3f9a";
    const argSecret = "cg-arg-secret-7c1b";

    const result = await runExecution({
      command: NODE,
      args: ["-e", "process.exit(0)", argSecret],
      policy: nodePolicy(root, { allowCommands: [] }),
      environment: { CG_ADV_SECRET: envSecret },
    });

    assert.equal(result.status, EXECUTION_STATUS.REJECTED);
    assert.ok(!("environment" in result) && !("env" in result));
    assert.ok(
      !JSON.stringify(result).includes(envSecret),
      "environment values must never be stored in a result",
    );
    assert.ok(!JSON.stringify(result.error).includes(envSecret));
    assert.ok(!JSON.stringify(result.error).includes(argSecret));
    // Arguments are the caller's own request data; they must not be copied into
    // any *other* result field.
    const withoutArgs = JSON.stringify({ ...result, args: [] });
    assert.ok(!withoutArgs.includes(argSecret));
  });
});

// ─── D. Working-directory attacks ────────────────────────────────────────────

describe("adversarial: working directory", () => {
  it("reports a policy rejection before a malicious cwd", async () => {
    const root = makeFixture();
    const outside = makeFixture();
    const hostiles = ["..", join("..", "..", "etc"), outside, "does-not-exist"];

    for (const cwd of hostiles) {
      const notAllowed = await runExecution({
        command: NODE,
        args: ["-e", "process.exit(0)"],
        cwd,
        policy: nodePolicy(root, { allowCommands: [] }),
      });
      assert.equal(notAllowed.status, EXECUTION_STATUS.REJECTED);
      assert.equal(
        notAllowed.error.kind,
        EXECUTION_ERROR_KINDS.COMMAND_NOT_ALLOWED,
        `cwd ${cwd}: the policy decision must be reported first`,
      );
      assert.equal(notAllowed.pid, null);

      const denied = await runExecution({
        command: NODE,
        args: ["-e", "process.exit(0)"],
        cwd,
        policy: nodePolicy(root, { denyCommands: [NODE_ID] }),
      });
      assert.equal(
        denied.error.kind,
        EXECUTION_ERROR_KINDS.COMMAND_DENIED,
        `cwd ${cwd}: an explicit deny must always be visible`,
      );
      assert.equal(denied.pid, null);
    }
  });

  it("rejects a hostile cwd when the command itself is authorized", async () => {
    const root = makeFixture();
    const outside = makeFixture();

    const cases = [
      { cwd: "..", kind: EXECUTION_ERROR_KINDS.CWD_OUTSIDE_ROOT },
      { cwd: join("a", "..", "..", "b"), kind: EXECUTION_ERROR_KINDS.CWD_OUTSIDE_ROOT },
      { cwd: outside, kind: EXECUTION_ERROR_KINDS.CWD_OUTSIDE_ROOT },
      { cwd: "missing-dir", kind: EXECUTION_ERROR_KINDS.CWD_NOT_FOUND },
      { cwd: "\0", kind: EXECUTION_ERROR_KINDS.CWD_INVALID },
    ];

    for (const { cwd, kind } of cases) {
      const result = await runExecution({
        command: NODE,
        args: ["-e", "process.exit(0)"],
        cwd,
        policy: nodePolicy(root),
      });
      assert.equal(result.status, EXECUTION_STATUS.REJECTED, `cwd ${cwd}`);
      assert.equal(result.error.kind, kind, `cwd ${cwd}`);
      assert.equal(result.pid, null, `cwd ${cwd} must never spawn`);
      assert.ok(
        !JSON.stringify(result).includes(outside),
        `cwd ${cwd} must not serialize a host location`,
      );
    }
  });

  it(
    "rejects a cwd symlink that resolves outside the allowed root",
    { skip: SYMLINK_SKIP },
    async () => {
      const root = makeFixture();
      const outside = makeFixture();
      symlinkSync(outside, join(root, "escape"), "dir");

      const result = await runExecution(
        nodeRequest(root, "process.exit(0)", { cwd: "escape" }),
      );
      assert.equal(result.status, EXECUTION_STATUS.REJECTED);
      assert.equal(result.error.kind, EXECUTION_ERROR_KINDS.CWD_OUTSIDE_ROOT);
      assert.equal(result.pid, null);
    },
  );

  it(
    "accepts a cwd symlink that stays inside the allowed root",
    { skip: SYMLINK_SKIP },
    async () => {
      const root = makeFixture({ "real/keep.txt": "" });
      symlinkSync(join(root, "real"), join(root, "alias"), "dir");

      const result = await runExecution(
        nodeRequest(root, "process.stdout.write(process.cwd())", {
          cwd: "alias",
        }),
      );
      assert.equal(result.status, EXECUTION_STATUS.COMPLETED);
      assert.equal(
        normalizeForCompare(result.stdout),
        normalizeForCompare(join(root, "real")),
        "the child must run in the resolved directory",
      );
      assert.equal(result.cwd, "real", "the realpath is reported");
    },
  );

  it("accepts a cwd nested under a secondary allowed root", async () => {
    const primary = makeFixture();
    const secondary = makeFixture({ "sub/keep.txt": "" });

    const result = await runExecution({
      command: NODE,
      args: ["-e", "process.stdout.write(process.cwd())"],
      cwd: join(secondary, "sub"),
      policy: {
        allowedRoots: [primary, secondary],
        allowCommands: [NODE_ID],
      },
    });

    assert.equal(result.status, EXECUTION_STATUS.COMPLETED);
    assert.equal(
      normalizeForCompare(result.stdout),
      normalizeForCompare(join(secondary, "sub")),
    );
    // Documented behavior: the relative form is defined against the primary
    // root only, so a cwd under another root has no relative form.
    assert.equal(result.cwd, null);
  });
});

// ─── E. Process lifecycle races ──────────────────────────────────────────────

describe("adversarial: process lifecycle", () => {
  const SLOW = "setTimeout(() => {}, 8000)";
  const STUBBORN = "process.on('SIGTERM', () => {}); setTimeout(() => {}, 8000)";

  it("cleans up every timer it creates on every terminal path", async () => {
    const root = makeFixture();
    const impostor = makeImpostor(root, "impostor");
    const audit = createTimerAudit();

    const cases = [
      {
        label: "normal exit",
        delay: 7001,
        grace: 7003,
        request: nodeRequest(root, "process.exit(0)", {
          policy: nodePolicy(root, { maxDurationMs: 7001 }),
        }),
        options: { terminationGraceMs: 7003 },
      },
      {
        label: "spawn failure",
        delay: 7011,
        grace: 7013,
        request: {
          command: impostor,
          policy: nodePolicy(root, { allowCommands: [impostor], maxDurationMs: 7011 }),
        },
        options: { terminationGraceMs: 7013 },
      },
      {
        label: "timeout with forced termination",
        delay: 173,
        grace: 149,
        request: nodeRequest(root, STUBBORN, {
          policy: nodePolicy(root, { maxDurationMs: 173 }),
        }),
        options: { terminationGraceMs: 149 },
      },
      {
        label: "cancellation",
        delay: 7021,
        grace: 7023,
        request: nodeRequest(root, SLOW, {
          policy: nodePolicy(root, { maxDurationMs: 7021 }),
        }),
        options: { terminationGraceMs: 7023, abortAfterMs: 60 },
      },
    ];

    for (const scenario of cases) {
      const controller = new AbortController();
      let timer = null;
      if (scenario.options.abortAfterMs) {
        timer = setTimeout(
          () => controller.abort(),
          scenario.options.abortAfterMs,
        );
      }
      const { abortAfterMs, ...runnerOptions } = scenario.options;
      audit.start();
      try {
        const result = await runExecution(scenario.request, {
          ...runnerOptions,
          signal: abortAfterMs ? controller.signal : undefined,
        });
        assert.ok(result.status, `${scenario.label} must settle`);
      } finally {
        audit.stop();
        if (timer) clearTimeout(timer);
      }
      assert.deepEqual(
        audit.orphans([scenario.delay, scenario.grace]),
        [],
        `${scenario.label} must not orphan a timeout or grace timer`,
      );
    }
  });

  it("removes its abort listener on every terminal path", async () => {
    const root = makeFixture();
    const impostor = makeImpostor(root, "impostor");

    const cases = [
      {
        label: "normal exit",
        request: nodeRequest(root, "process.exit(0)"),
        options: {},
      },
      {
        label: "spawn failure",
        request: {
          command: impostor,
          policy: nodePolicy(root, { allowCommands: [impostor] }),
        },
        options: {},
      },
      {
        label: "timeout",
        request: nodeRequest(root, SLOW, {
          policy: nodePolicy(root, { maxDurationMs: 150 }),
        }),
        options: { terminationGraceMs: 150 },
      },
      {
        label: "cancellation",
        request: nodeRequest(root, SLOW, {
          policy: nodePolicy(root, { maxDurationMs: 7043 }),
        }),
        options: { abortAfterMs: 60, terminationGraceMs: 150 },
      },
    ];

    for (const scenario of cases) {
      const signal = countingSignal();
      const { abortAfterMs, ...runnerOptions } = scenario.options;
      let timer = null;
      if (abortAfterMs) {
        timer = setTimeout(() => signal.abort(), abortAfterMs);
      }
      try {
        await runExecution(scenario.request, { ...runnerOptions, signal });
      } finally {
        if (timer) clearTimeout(timer);
      }
      assert.equal(
        signal.listenerCount(),
        0,
        `${scenario.label} must deregister its abort listener`,
      );
    }
  });

  it("settles once and coherently across abort/timeout collisions", async () => {
    const root = makeFixture();
    const timeoutMs = 200;
    // The runner arms its timeout only after asynchronous cwd resolution, so an
    // outside caller cannot schedule a truly simultaneous abort. The ordering is
    // therefore pinned at both extremes, and every in-between delay must still
    // produce a single, coherent settlement.
    const cases = [
      { abortAfterMs: 60, expected: EXECUTION_STATUS.CANCELED },
      { abortAfterMs: 150, expected: null },
      { abortAfterMs: 200, expected: null },
      { abortAfterMs: 260, expected: null },
      { abortAfterMs: 400, expected: EXECUTION_STATUS.TIMED_OUT },
    ];

    for (const { abortAfterMs, expected } of cases) {
      const signal = countingSignal();
      setTimeout(() => signal.abort(), abortAfterMs);

      const result = await runExecution(
        nodeRequest(root, SLOW, {
          policy: nodePolicy(root, { maxDurationMs: timeoutMs }),
        }),
        { signal, terminationGraceMs: 200 },
      );

      assert.ok(
        [EXECUTION_STATUS.TIMED_OUT, EXECUTION_STATUS.CANCELED].includes(
          result.status,
        ),
        `abort at ${abortAfterMs}ms: unexpected status ${result.status}`,
      );
      if (expected !== null) {
        assert.equal(result.status, expected, `abort at ${abortAfterMs}ms`);
      }
      // Status and flags must agree whichever way the race fell.
      assert.equal(result.timedOut, result.status === EXECUTION_STATUS.TIMED_OUT);
      assert.ok(result.timedOut || result.canceled, "a termination cause exists");
      assert.equal(result.killed, true);

      const snapshot = JSON.stringify({
        status: result.status,
        duration: result.duration,
        exitCode: result.exitCode,
      });
      await delay(250);
      assert.equal(
        JSON.stringify({
          status: result.status,
          duration: result.duration,
          exitCode: result.exitCode,
        }),
        snapshot,
        "a settled result must never mutate",
      );
      if (result.pid) {
        assert.equal(isProcessAlive(result.pid), false, "no orphaned child");
      }
    }
  });

  it("reports a timeout deterministically when timeout and abort both fire", async () => {
    const root = makeFixture();
    const timeoutMs = 200;
    const graceMs = 300;
    const audit = createTimerAudit();
    const controller = new AbortController();
    // The child ignores SIGTERM, so it stays alive long enough for the abort to
    // land after the timeout: both causes are recorded before the forced kill.
    setTimeout(() => controller.abort(), 300);

    audit.start();
    let result;
    try {
      result = await runExecution(
        nodeRequest(root, STUBBORN, {
          policy: nodePolicy(root, { maxDurationMs: timeoutMs }),
        }),
        { signal: controller.signal, terminationGraceMs: graceMs },
      );
    } finally {
      audit.stop();
    }

    assert.equal(result.status, EXECUTION_STATUS.TIMED_OUT, "timeout wins");
    assert.equal(result.timedOut, true);
    assert.equal(result.killed, true);
    // Windows cannot catch SIGTERM, so the child is gone before the abort can
    // land; on POSIX both causes are recorded and the timeout still wins.
    assert.equal(result.canceled, !WINDOWS);
    assert.deepEqual(audit.orphans([timeoutMs, graceMs]), []);
    if (result.pid) {
      await delay(400);
      assert.equal(isProcessAlive(result.pid), false, "no orphaned child");
    }
  });

  it("force-kills a cancellation-resistant child and leaves nothing behind", async () => {
    const root = makeFixture();
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 100);

    const result = await runExecution(
      nodeRequest(root, STUBBORN, {
        policy: nodePolicy(root, { maxDurationMs: 8000 }),
      }),
      { signal: controller.signal, terminationGraceMs: 120 },
    );

    assert.equal(result.status, EXECUTION_STATUS.CANCELED);
    assert.equal(result.canceled, true);
    assert.equal(result.killed, true);
    if (result.pid) {
      await delay(300);
      assert.equal(isProcessAlive(result.pid), false, "SIGKILL must land");
    }
  });

  it("settles once when a child exits while cancellation is in flight", async () => {
    const root = makeFixture();
    const observed = new Set();

    for (let attempt = 0; attempt < 5; attempt += 1) {
      const signal = countingSignal();
      const exitDelay = 100;
      setTimeout(() => signal.abort(), exitDelay + attempt * 8);
      const request = nodeRequest(
        root,
        `setTimeout(() => process.exit(0), ${exitDelay})`,
        { policy: nodePolicy(root, { maxDurationMs: 7050 }) },
      );

      const result = await runExecution(request, {
        signal,
        terminationGraceMs: 150,
      });

      assert.ok(
        [EXECUTION_STATUS.COMPLETED, EXECUTION_STATUS.CANCELED].includes(
          result.status,
        ),
        `unexpected status ${result.status}`,
      );
      observed.add(result.status);

      const snapshot = JSON.stringify([result.status, result.exitCode]);
      await delay(150);
      assert.equal(
        JSON.stringify([result.status, result.exitCode]),
        snapshot,
        "exactly one settlement",
      );
    }

    assert.ok(observed.size >= 1);
  });
});

// ─── F. Output and resource attacks ──────────────────────────────────────────

describe("adversarial: output and resource limits", () => {
  it("captures exactly at the limit and truncates one byte past it", async () => {
    const root = makeFixture();
    const limit = 64;

    const exact = await runExecution(
      nodeRequest(root, `process.stdout.write('x'.repeat(${limit}))`),
      { maxStdoutBytes: limit },
    );
    assert.equal(exact.stdout, "x".repeat(limit));
    assert.equal(exact.stdoutTruncated, false);

    const over = await runExecution(
      nodeRequest(root, `process.stdout.write('x'.repeat(${limit + 1}))`),
      { maxStdoutBytes: limit },
    );
    assert.equal(Buffer.byteLength(over.stdout), limit);
    assert.equal(over.stdoutTruncated, true);
    assert.equal(over.truncated, true);
    assert.equal(over.status, EXECUTION_STATUS.COMPLETED, "truncation is not termination");
  });

  it("bounds a rapid multi-chunk burst on each stream independently", async () => {
    const root = makeFixture();
    const stdoutCap = 8192;
    const stderrCap = 4096;

    const result = await runExecution(
      nodeRequest(
        root,
        "for (let i = 0; i < 400; i += 1) process.stdout.write('a'.repeat(512));" +
          "for (let i = 0; i < 200; i += 1) process.stderr.write('b'.repeat(512));",
      ),
      { maxStdoutBytes: stdoutCap, maxStderrBytes: stderrCap },
    );

    assert.equal(result.status, EXECUTION_STATUS.COMPLETED);
    assert.equal(result.exitCode, 0);
    assert.equal(result.stdoutTruncated, true);
    assert.equal(result.stderrTruncated, true);
    assert.ok(Buffer.byteLength(result.stdout) <= stdoutCap);
    assert.ok(Buffer.byteLength(result.stderr) <= stderrCap);
  });

  it("stays bounded when output continues until the timeout", async () => {
    const root = makeFixture();
    const cap = 1024;

    const result = await runExecution(
      nodeRequest(
        root,
        "const t = setInterval(() => process.stdout.write('y'.repeat(1024)), 1);" +
          "setTimeout(() => clearInterval(t), 8000);",
        { policy: nodePolicy(root, { maxDurationMs: 250 }) },
      ),
      { maxStdoutBytes: cap, terminationGraceMs: 150 },
    );

    assert.equal(result.status, EXECUTION_STATUS.TIMED_OUT);
    assert.equal(result.stdoutTruncated, true);
    assert.ok(Buffer.byteLength(result.stdout) <= cap);
  });
});

// ─── G. Effective-limit integrity ────────────────────────────────────────────

describe("adversarial: effective limit integrity", () => {
  it("refuses an effective timeout the platform timer cannot represent", async () => {
    const root = makeFixture();

    // `setTimeout` clamps a delay above 2^31-1 ms to 1 ms, which would kill an
    // authorized command almost immediately while the result still reported the
    // declared budget as an enforced limit.
    await assert.rejects(
      () =>
        runExecution(
          nodeRequest(root, "setTimeout(() => {}, 4000)", {
            policy: nodePolicy(root, { maxDurationMs: MAX_TIMER_DELAY_MS + 1 }),
          }),
        ),
      (error) => {
        assert.ok(error instanceof ValidationError);
        assert.ok(JSON.stringify(error.details).includes("timeoutMs"));
        return true;
      },
    );
  });

  it("refuses an out-of-range termination grace period", async () => {
    const root = makeFixture();

    await assert.rejects(
      () =>
        runExecution(nodeRequest(root, "process.exit(0)"), {
          terminationGraceMs: MAX_TIMER_DELAY_MS + 1,
        }),
      (error) => {
        assert.ok(error instanceof ValidationError);
        assert.ok(JSON.stringify(error.details).includes("terminationGraceMs"));
        return true;
      },
    );
  });

  it("accepts the maximum representable delay and records it truthfully", async () => {
    const root = makeFixture();

    const result = await runExecution(
      nodeRequest(root, "process.exit(0)", {
        policy: nodePolicy(root, { maxDurationMs: MAX_TIMER_DELAY_MS }),
      }),
    );

    assert.equal(result.status, EXECUTION_STATUS.COMPLETED);
    assert.equal(result.limits.timeoutMs, MAX_TIMER_DELAY_MS);
  });

  it("keeps an unrepresentable policy ceiling that the request narrows usable", async () => {
    const root = makeFixture();

    // Only the *effective* delay is range-checked, so an authorization ceiling
    // that is always narrowed by the request keeps working.
    const result = await runExecution(
      nodeRequest(root, "process.exit(0)", {
        policy: nodePolicy(root, { maxDurationMs: 2 ** 40 }),
        timeout: 2000,
      }),
    );

    assert.equal(result.status, EXECUTION_STATUS.COMPLETED);
    assert.equal(result.limits.timeoutMs, 2000);
  });
});

// ─── H. Information leakage ──────────────────────────────────────────────────

describe("adversarial: information leakage", () => {
  it("keeps host paths, stacks and causes out of every rejection", async () => {
    const root = makeFixture();
    const outside = makeFixture();
    const untrusted = makeFixture();
    const untrustedCommand = makeImpostor(untrusted, "node");
    const impostor = makeImpostor(root, "impostor");

    const cases = [
      {
        label: "not allowed",
        status: EXECUTION_STATUS.REJECTED,
        kind: EXECUTION_ERROR_KINDS.COMMAND_NOT_ALLOWED,
        request: { command: NODE, policy: nodePolicy(root, { allowCommands: [] }) },
      },
      {
        label: "denied",
        status: EXECUTION_STATUS.REJECTED,
        kind: EXECUTION_ERROR_KINDS.COMMAND_DENIED,
        request: {
          command: NODE,
          policy: nodePolicy(root, { denyCommands: [NODE_ID] }),
        },
      },
      {
        label: "untrusted location",
        status: EXECUTION_STATUS.REJECTED,
        kind: EXECUTION_ERROR_KINDS.COMMAND_UNTRUSTED_LOCATION,
        request: { command: untrustedCommand, policy: nodePolicy(root) },
      },
      {
        label: "cwd outside root",
        status: EXECUTION_STATUS.REJECTED,
        kind: EXECUTION_ERROR_KINDS.CWD_OUTSIDE_ROOT,
        request: { command: NODE, cwd: outside, policy: nodePolicy(root) },
      },
      {
        label: "cwd missing",
        status: EXECUTION_STATUS.REJECTED,
        kind: EXECUTION_ERROR_KINDS.CWD_NOT_FOUND,
        request: { command: NODE, cwd: "missing-dir", policy: nodePolicy(root) },
      },
      {
        label: "spawn failed",
        status: EXECUTION_STATUS.SPAWN_FAILED,
        kind: EXECUTION_ERROR_KINDS.SPAWN_FAILED,
        request: {
          command: impostor,
          policy: nodePolicy(root, { allowCommands: [impostor] }),
        },
      },
    ];

    for (const scenario of cases) {
      const result = await runExecution(scenario.request);
      assert.equal(result.status, scenario.status, scenario.label);
      assert.equal(result.error.kind, scenario.kind, scenario.label);

      const serialized = JSON.stringify(result.error);
      for (const hostPath of [root, outside, untrusted, TMP_ROOT]) {
        assert.ok(
          !serialized.includes(hostPath),
          `${scenario.label} must not serialize ${hostPath}`,
        );
      }
      assert.ok(!serialized.includes("at "), `${scenario.label}: no stack`);
      assert.ok(
        !Object.hasOwn(JSON.parse(serialized), "cause"),
        `${scenario.label}: cause must not be serialized`,
      );
      const { command } = result.error.details;
      assert.ok(
        command === null ||
          !command.includes("/") &&
            !command.includes(nodePath.sep),
        `${scenario.label}: details.command must stay a bare identity`,
      );
    }
  });

  it("never serializes the resolved executable location", async () => {
    const root = makeFixture();

    const result = await runExecution({
      command: "node",
      args: ["-e", "process.exit(0)"],
      policy: nodePolicy(root),
    });

    assert.equal(result.status, EXECUTION_STATUS.COMPLETED);
    assert.equal(result.cwd, ".");
    assert.deepEqual(Object.keys(result.policy).sort(), [
      "allowed",
      "identity",
      "kind",
      "reason",
    ]);
    const serialized = JSON.stringify(result);
    assert.ok(
      !serialized.includes(dirname(realpathSync(NODE))),
      "the trusted executable directory must not be serialized",
    );
    assert.ok(!serialized.includes(root));
  });

  it("keeps an out-of-root filesystem target out of the serialized error", async () => {
    const root = makeFixture();
    const outside = makeFixture({ "secret.txt": "top secret" });

    const result = await readFile(root, join(outside, "secret.txt"));
    assert.equal(result.ok, false);
    assert.equal(result.error.kind, FILESYSTEM_ERROR_KINDS.INVALID_PATH);
    assert.equal(result.error.details.path, null);
    assert.ok(!JSON.stringify(result.error).includes(outside));
  });

  it("drops absolute, drive-letter, UNC and NUL inputs from serialized paths", () => {
    assert.equal(sanitizeFilesystemPath("/etc/passwd"), null);
    assert.equal(sanitizeFilesystemPath("C:\\repo\\file.js"), null);
    assert.equal(sanitizeFilesystemPath("\\\\srv\\share\\file.js"), null);
    assert.equal(sanitizeFilesystemPath("a\0b"), null);
    assert.equal(sanitizeFilesystemPath(""), null);
    assert.equal(sanitizeFilesystemPath("src/index.js"), "src/index.js");
  });
});
