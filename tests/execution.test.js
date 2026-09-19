/**
 * Code Guardian — Phase 8B Command Execution Boundary Tests
 *
 * Focused tests for `src/execution`. Fixtures live under `.test-tmp`; commands
 * are Node itself (`process.execPath`) so the suite is portable, deterministic
 * and network-independent.
 *
 * Run with: node --test tests/execution.test.js
 */

import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

import {
  EXECUTION_COMMAND_PRECEDENCE,
  EXECUTION_STATES,
  ValidationError,
  createExecutionRequest,
} from "../src/core/index.js";

import {
  CommandExecutionError,
  EXECUTION_ERROR_KINDS,
  EXECUTION_STATUS,
  commandIdentity,
  runExecution,
} from "../src/execution/index.js";

// ─── Fixtures ────────────────────────────────────────────────────────────────

// Fixtures live in a unique OS-temp directory rather than the repo's shared
// `.test-tmp`, which other suites (integration) wipe between runs.
const TMP_ROOT = join(
  tmpdir(),
  `code-guardian-exec-${process.pid}-${Date.now()}`,
);
const NODE = process.execPath;
const NODE_ID = commandIdentity(NODE);
const WINDOWS = process.platform === "win32";

let counter = 0;
const created = [];

function register(dir) {
  created.push(dir);
  return dir;
}

function makeRoot(files = {}, dirs = []) {
  const dir = join(
    TMP_ROOT,
    `exec-${process.pid}-${Date.now()}-${counter++}`,
  );
  mkdirSync(dir, { recursive: true });
  for (const sub of dirs) mkdirSync(join(dir, sub), { recursive: true });
  for (const [relPath, content] of Object.entries(files)) {
    const full = join(dir, relPath);
    mkdirSync(join(full, ".."), { recursive: true });
    writeFileSync(full, content);
  }
  return register(dir);
}

/** A policy that authorizes Node itself inside `root`. */
function policy(root, overrides = {}) {
  return { allowedRoots: [root], allowCommands: [NODE_ID], ...overrides };
}

/** A Core ExecutionRequest-shaped helper for `node -e`. */
function nodeRequest(root, script, extra = {}) {
  return {
    command: NODE,
    args: ["-e", script],
    policy: policy(root),
    ...extra,
  };
}

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
  const resolved = realpathSync(value.trim());
  return WINDOWS ? resolved.toLowerCase() : resolved;
}

after(() => {
  for (const dir of created) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {}
  }
  try {
    rmSync(TMP_ROOT, { recursive: true, force: true });
  } catch {}
});

// ─── Command validation ──────────────────────────────────────────────────────

describe("execution input validation", () => {
  it("rejects an empty command", async () => {
    await assert.rejects(
      () => runExecution({ command: "   " }),
      ValidationError,
    );
  });

  it("rejects a non-string command", async () => {
    await assert.rejects(() => runExecution({ command: 42 }), ValidationError);
    await assert.rejects(() => runExecution({}), ValidationError);
  });

  it("rejects non-array args", async () => {
    await assert.rejects(
      () => runExecution({ command: NODE, args: "x" }),
      ValidationError,
    );
  });

  it("rejects a non-string argument", async () => {
    await assert.rejects(
      () => runExecution({ command: NODE, args: ["-e", 5] }),
      ValidationError,
    );
  });

  it("rejects unknown request fields", async () => {
    await assert.rejects(
      () => runExecution({ command: NODE, bogus: true }),
      ValidationError,
    );
  });

  it("rejects malformed timeout, limits and policy", async () => {
    await assert.rejects(
      () => runExecution({ command: NODE, timeout: 0 }),
      ValidationError,
    );
    await assert.rejects(
      () => runExecution({ command: NODE, limits: { maxOutputBytes: -1 } }),
      ValidationError,
    );
    await assert.rejects(
      () => runExecution({ command: NODE, policy: { allowCommands: "node" } }),
      ValidationError,
    );
    await assert.rejects(
      () => runExecution({ command: NODE, cwd: "" }),
      ValidationError,
    );
  });

  it("rejects unknown options and an explicit shell", async () => {
    await assert.rejects(
      () => runExecution({ command: NODE }, { bogus: 1 }),
      ValidationError,
    );
    await assert.rejects(
      () => runExecution({ command: NODE }, { shell: true }),
      ValidationError,
    );
  });

  it("rejects a malformed abort signal", async () => {
    await assert.rejects(
      () => runExecution({ command: NODE }, { signal: "nope" }),
      ValidationError,
    );
  });
});

// ─── Shell safety ────────────────────────────────────────────────────────────

describe("shell safety", () => {
  const root = register(makeRoot());

  it("passes shell metacharacters literally", async () => {
    const script =
      "process.stdout.write(JSON.stringify(process.argv.slice(1)))";
    const result = await runExecution(
      nodeRequest(root, script, {
        args: [
          "-e",
          script,
          "a && b",
          "$(whoami)",
          "; rm -rf /",
          "| cat",
          "> out.txt",
        ],
      }),
    );
    assert.equal(result.status, EXECUTION_STATUS.COMPLETED);
    assert.deepEqual(JSON.parse(result.stdout), [
      "a && b",
      "$(whoami)",
      "; rm -rf /",
      "| cat",
      "> out.txt",
    ]);
  });

  it("does not perform command substitution", async () => {
    const script = "process.stdout.write(String(process.argv[1]))";
    const result = await runExecution(
      nodeRequest(root, script, { args: ["-e", script, "$(whoami)"] }),
    );
    assert.equal(result.stdout, "$(whoami)");
  });

  it("does not interpret the command string as a shell line", async () => {
    const shellLine = `${NODE} -e "process.exit(0)"`;
    const result = await runExecution({
      command: shellLine,
      policy: policy(root, { allowCommands: [commandIdentity(shellLine)] }),
    });
    // A shell would have executed it; spawn must treat it as one executable.
    assert.equal(result.status, EXECUTION_STATUS.SPAWN_FAILED);
  });
});

// ─── Command policy ──────────────────────────────────────────────────────────

describe("command policy", () => {
  const root = register(makeRoot());

  it("executes an allowed command and records the decision", async () => {
    const result = await runExecution(nodeRequest(root, "process.exit(0)"));
    assert.equal(result.status, EXECUTION_STATUS.COMPLETED);
    assert.equal(result.policy.allowed, true);
    assert.equal(result.policy.identity, NODE_ID);
    assert.equal(result.error, null);
  });

  it("does not spawn a command that is not allowlisted", async () => {
    const result = await runExecution({
      command: NODE,
      policy: policy(root, { allowCommands: [] }),
    });
    assert.equal(result.status, EXECUTION_STATUS.REJECTED);
    assert.equal(result.error.kind, EXECUTION_ERROR_KINDS.COMMAND_NOT_ALLOWED);
    assert.equal(result.error.code, "CG_EXEC_COMMAND_NOT_ALLOWED");
    assert.equal(result.pid, null, "must not spawn");
  });

  it("deny overrides allow", async () => {
    const result = await runExecution({
      command: NODE,
      policy: policy(root, {
        allowCommands: [NODE_ID],
        denyCommands: [NODE_ID],
      }),
    });
    assert.equal(result.status, EXECUTION_STATUS.REJECTED);
    assert.equal(result.error.kind, EXECUTION_ERROR_KINDS.COMMAND_DENIED);
    assert.equal(result.pid, null);
  });

  it("an empty deny list denies nothing", async () => {
    const result = await runExecution(
      nodeRequest(root, "process.exit(0)", {
        policy: policy(root, { allowCommands: [NODE_ID], denyCommands: [] }),
      }),
    );
    assert.equal(result.status, EXECUTION_STATUS.COMPLETED);
  });

  it("an empty allow list allows nothing", async () => {
    const result = await runExecution({
      command: NODE,
      policy: policy(root, { allowCommands: [], denyCommands: [] }),
    });
    assert.equal(result.status, EXECUTION_STATUS.REJECTED);
    assert.equal(result.error.kind, EXECUTION_ERROR_KINDS.COMMAND_NOT_ALLOWED);
  });

  it("a deny-only policy authorizes nothing", async () => {
    const result = await runExecution({
      command: NODE,
      policy: policy(root, { allowCommands: [], denyCommands: ["npm"] }),
    });
    assert.equal(result.status, EXECUTION_STATUS.REJECTED);
  });

  it("a command-prefix collision does not bypass the allowlist", async () => {
    const impostor = `${NODE_ID}-malicious`;
    const result = await runExecution({
      command: impostor,
      policy: policy(root, { allowCommands: [NODE_ID] }),
    });
    assert.equal(result.status, EXECUTION_STATUS.REJECTED);
    assert.equal(result.error.kind, EXECUTION_ERROR_KINDS.COMMAND_NOT_ALLOWED);
  });

  it("accepts a Core ExecutionRequest unchanged", async () => {
    const request = createExecutionRequest({
      command: NODE,
      args: ["-e", "process.exit(0)"],
      cwd: root,
      policy: policy(root),
    });
    const result = await runExecution(request);
    assert.equal(result.status, EXECUTION_STATUS.COMPLETED);
  });

  it("does not leak command arguments through a rejection error", async () => {
    const secret = "s3cr3t-argument-value";
    const result = await runExecution({
      command: NODE,
      args: ["-e", "process.exit(0)", secret],
      policy: policy(root, { allowCommands: [] }),
    });
    assert.equal(result.status, EXECUTION_STATUS.REJECTED);
    assert.ok(!JSON.stringify(result.error).includes(secret));
    assert.ok(!JSON.stringify(result.error.toJSON()).includes(secret));
  });

  it("matches executable identity, not location, and follows Phase 7 precedence", () => {
    assert.equal(EXECUTION_COMMAND_PRECEDENCE, "deny-overrides-allow");
    assert.equal(commandIdentity("/usr/bin/node"), "node");
    assert.equal(commandIdentity("node"), "node");
    assert.notEqual(commandIdentity("node-malicious"), "node");
  });
});

// ─── Working directory ───────────────────────────────────────────────────────

describe("working directory security", () => {
  it("defaults to the allowed root", async () => {
    const root = register(makeRoot());
    const result = await runExecution(
      nodeRequest(root, "process.stdout.write(process.cwd())"),
    );
    assert.equal(result.status, EXECUTION_STATUS.COMPLETED);
    assert.equal(normalizeForCompare(result.stdout), normalizeForCompare(root));
    assert.equal(result.cwd, ".");
  });

  it("allows a child directory", async () => {
    const root = register(makeRoot({}, ["sub"]));
    const result = await runExecution(
      nodeRequest(root, "process.stdout.write(process.cwd())", {
        cwd: "sub",
      }),
    );
    assert.equal(
      normalizeForCompare(result.stdout),
      normalizeForCompare(join(root, "sub")),
    );
    assert.equal(result.cwd, "sub");
  });

  it("rejects a sibling-prefix directory", async () => {
    const root = register(makeRoot());
    const sibling = register(join(TMP_ROOT, `${basename(root)}-other`));
    mkdirSync(sibling, { recursive: true });

    const result = await runExecution(nodeRequest(root, "", { cwd: sibling }));
    assert.equal(result.status, EXECUTION_STATUS.REJECTED);
    assert.equal(result.error.kind, EXECUTION_ERROR_KINDS.CWD_OUTSIDE_ROOT);
    assert.equal(result.pid, null);
  });

  it("rejects a parent traversal escape", async () => {
    const root = register(makeRoot());
    const result = await runExecution(
      nodeRequest(root, "", { cwd: join("..", "outside") }),
    );
    assert.equal(result.status, EXECUTION_STATUS.REJECTED);
    assert.equal(result.error.kind, EXECUTION_ERROR_KINDS.CWD_OUTSIDE_ROOT);
  });

  it("rejects an outside absolute directory", async () => {
    const root = register(makeRoot());
    const outside = register(makeRoot());
    const result = await runExecution(nodeRequest(root, "", { cwd: outside }));
    assert.equal(result.status, EXECUTION_STATUS.REJECTED);
    assert.equal(result.error.kind, EXECUTION_ERROR_KINDS.CWD_OUTSIDE_ROOT);
  });

  it("reports a missing directory", async () => {
    const root = register(makeRoot());
    const result = await runExecution(
      nodeRequest(root, "", { cwd: "does-not-exist" }),
    );
    assert.equal(result.status, EXECUTION_STATUS.REJECTED);
    assert.equal(result.error.kind, EXECUTION_ERROR_KINDS.CWD_NOT_FOUND);
  });

  it("rejects a file used as the working directory", async () => {
    const root = register(makeRoot({ "file.txt": "x" }));
    const result = await runExecution(nodeRequest(root, "", { cwd: "file.txt" }));
    assert.equal(result.status, EXECUTION_STATUS.REJECTED);
    assert.equal(result.error.kind, EXECUTION_ERROR_KINDS.CWD_NOT_DIRECTORY);
  });

  it("rejects when no allowed root is configured", async () => {
    const result = await runExecution({
      command: NODE,
      policy: { allowedRoots: [], allowCommands: [NODE_ID] },
    });
    assert.equal(result.status, EXECUTION_STATUS.REJECTED);
    assert.equal(result.error.kind, EXECUTION_ERROR_KINDS.NO_ALLOWED_ROOTS);
  });

  it(
    "reports a permission failure distinguishably",
    { skip: WINDOWS ? "Windows ACL semantics differ" : false },
    async (t) => {
      const root = register(makeRoot({}, ["locked"]));
      const locked = join(root, "locked");
      const { chmodSync } = await import("node:fs");
      chmodSync(locked, 0o000);
      try {
        const result = await runExecution(
          nodeRequest(root, "", { cwd: "locked" }),
        );
        if (result.status === EXECUTION_STATUS.COMPLETED) {
          t.skip("process bypasses directory permissions (e.g. root)");
          return;
        }
        assert.equal(
          result.error.kind,
          EXECUTION_ERROR_KINDS.CWD_PERMISSION_DENIED,
        );
      } finally {
        chmodSync(locked, 0o755);
      }
    },
  );
});

// ─── Execution results ───────────────────────────────────────────────────────

describe("execution results", () => {
  const root = register(makeRoot());

  it("completes a successful command", async () => {
    const result = await runExecution(
      nodeRequest(root, "process.stdout.write('hello')"),
    );
    assert.equal(result.status, EXECUTION_STATUS.COMPLETED);
    assert.equal(result.exitCode, 0);
    assert.equal(result.stdout, "hello");
    assert.equal(result.signal, null);
    assert.equal(result.timedOut, false);
    assert.equal(result.killed, false);
    assert.ok(result.duration >= 0);
  });

  it("reports a non-zero exit as a process result", async () => {
    const result = await runExecution(
      nodeRequest(root, "process.stderr.write('bad'); process.exit(3)"),
    );
    assert.equal(result.status, EXECUTION_STATUS.NON_ZERO_EXIT);
    assert.equal(result.exitCode, 3);
    assert.equal(result.stderr, "bad");
    assert.equal(result.error, null, "a non-zero exit is not a runner error");
  });

  it("reports a spawn failure", async () => {
    const missing = "cg-definitely-missing-executable-8b";
    const result = await runExecution({
      command: missing,
      policy: policy(root, { allowCommands: [missing] }),
    });
    assert.equal(result.status, EXECUTION_STATUS.SPAWN_FAILED);
    assert.equal(result.error.kind, EXECUTION_ERROR_KINDS.SPAWN_FAILED);
    assert.equal(result.pid, null);
    assert.equal(result.exitCode, null);
  });

  it(
    "reports signal termination",
    { skip: WINDOWS ? "POSIX signal reporting only" : false },
    async () => {
      const result = await runExecution(
        nodeRequest(root, "process.kill(process.pid, 'SIGTERM')"),
      );
      assert.equal(result.status, EXECUTION_STATUS.KILLED);
      assert.equal(result.signal, "SIGTERM");
      assert.equal(result.killed, true);
    },
  );

  it("exposes a structured result shape", async () => {
    const result = await runExecution(nodeRequest(root, "process.exit(0)"));
    for (const field of [
      "status",
      "command",
      "args",
      "identity",
      "cwd",
      "pid",
      "exitCode",
      "signal",
      "stdout",
      "stderr",
      "duration",
      "timedOut",
      "killed",
      "canceled",
      "stdoutTruncated",
      "stderrTruncated",
      "truncated",
      "limits",
      "policy",
      "error",
    ]) {
      assert.ok(field in result, `result should declare "${field}"`);
    }
    assert.ok(result.error === null || result.error instanceof CommandExecutionError);
  });

  it("keeps Phase 7 result states aligned with Core", () => {
    assert.equal(EXECUTION_STATUS.COMPLETED, EXECUTION_STATES.COMPLETED);
    assert.equal(EXECUTION_STATUS.TIMED_OUT, EXECUTION_STATES.TIMED_OUT);
    assert.equal(EXECUTION_STATUS.KILLED, EXECUTION_STATES.KILLED);
    assert.equal(EXECUTION_STATUS.NON_ZERO_EXIT, EXECUTION_STATES.NON_ZERO_EXIT);
  });
});

// ─── Timeouts ────────────────────────────────────────────────────────────────

describe("timeouts and termination", () => {
  it("times out a command that never exits", async () => {
    const root = register(makeRoot());
    const result = await runExecution(
      nodeRequest(root, "setTimeout(() => {}, 10000)", {
        policy: policy(root, { maxDurationMs: 200 }),
      }),
      { terminationGraceMs: 150 },
    );
    assert.equal(result.status, EXECUTION_STATUS.TIMED_OUT);
    assert.equal(result.timedOut, true);
    assert.ok(result.duration >= 150);
  });

  it("honours the timeout without waiting for the full duration", async () => {
    const root = register(makeRoot());
    const start = Date.now();
    const result = await runExecution(
      nodeRequest(root, "setTimeout(() => {}, 10000)", {
        policy: policy(root, { maxDurationMs: 250 }),
      }),
      { terminationGraceMs: 250 },
    );
    assert.equal(result.status, EXECUTION_STATUS.TIMED_OUT);
    assert.ok(Date.now() - start < 5000, "must not wait for the child");
  });

  it("force-terminates a process that ignores the termination request", async () => {
    const root = register(makeRoot());
    const result = await runExecution(
      nodeRequest(
        root,
        "process.on('SIGTERM', () => {}); setTimeout(() => {}, 10000)",
        { policy: policy(root, { maxDurationMs: 200 }) },
      ),
      { terminationGraceMs: 150 },
    );
    assert.equal(result.status, EXECUTION_STATUS.TIMED_OUT);
  });

  it("leaves no orphaned process after a timeout", async () => {
    const root = register(makeRoot());
    const result = await runExecution(
      nodeRequest(root, "setTimeout(() => {}, 10000)", {
        policy: policy(root, { maxDurationMs: 200 }),
      }),
      { terminationGraceMs: 150 },
    );
    assert.ok(result.pid, "should have spawned a process");
    await delay(400);
    assert.equal(isProcessAlive(result.pid), false, "child must be gone");
  });

  it("settles exactly once and does not mutate a completed result", async () => {
    const root = register(makeRoot());
    const result = await runExecution(
      nodeRequest(root, "process.exit(0)", {
        policy: policy(root, { maxDurationMs: 2000 }),
      }),
    );
    const snapshot = { status: result.status, duration: result.duration };
    await delay(200);
    assert.equal(result.status, snapshot.status);
    assert.equal(result.duration, snapshot.duration);
    assert.equal(result.status, EXECUTION_STATUS.COMPLETED);
  });

  it("does not wait for a long timeout when the process exits early", async () => {
    const root = register(makeRoot());
    const result = await runExecution(
      nodeRequest(root, "process.exit(0)", {
        policy: policy(root, { maxDurationMs: 5000 }),
      }),
    );
    assert.equal(result.status, EXECUTION_STATUS.COMPLETED);
    assert.ok(result.duration < 5000);
  });

  it("stays consistent when a process exits near the timeout boundary", async () => {
    const root = register(makeRoot());
    for (let i = 0; i < 5; i += 1) {
      const result = await runExecution(
        nodeRequest(root, "process.exit(0)", {
          policy: policy(root, { maxDurationMs: 50 }),
        }),
        { terminationGraceMs: 50 },
      );
      assert.ok(
        result.status === EXECUTION_STATUS.COMPLETED ||
          result.status === EXECUTION_STATUS.TIMED_OUT,
        `unexpected status ${result.status}`,
      );
      assert.equal(result.status === EXECUTION_STATUS.TIMED_OUT, result.timedOut);
    }
  });
});

// ─── Output limits ───────────────────────────────────────────────────────────

describe("output limits", () => {
  const root = register(makeRoot());

  it("captures stdout under the limit completely", async () => {
    const result = await runExecution(
      nodeRequest(root, "process.stdout.write('hello world')"),
      { maxStdoutBytes: 100 },
    );
    assert.equal(result.stdout, "hello world");
    assert.equal(result.stdoutTruncated, false);
    assert.equal(result.truncated, false);
  });

  it("bounds stdout over the limit and reports truncation", async () => {
    const result = await runExecution(
      nodeRequest(root, "process.stdout.write('x'.repeat(5000))"),
      { maxStdoutBytes: 100 },
    );
    assert.ok(result.stdout.length <= 100);
    assert.equal(result.stdoutTruncated, true);
    assert.equal(result.truncated, true);
  });

  it("bounds stderr independently", async () => {
    const result = await runExecution(
      nodeRequest(root, "process.stderr.write('e'.repeat(5000))"),
      { maxStdoutBytes: 5000, maxStderrBytes: 64 },
    );
    assert.ok(result.stderr.length <= 64);
    assert.equal(result.stderrTruncated, true);
    assert.equal(result.stdoutTruncated, false);
  });

  it("applies stdout and stderr limits independently", async () => {
    const result = await runExecution(
      nodeRequest(
        root,
        "process.stdout.write('x'.repeat(5000)); process.stderr.write('ok')",
      ),
      { maxStdoutBytes: 64, maxStderrBytes: 5000 },
    );
    assert.equal(result.stdoutTruncated, true);
    assert.equal(result.stderrTruncated, false);
    assert.equal(result.stderr, "ok");
  });

  it("keeps captured output bounded in memory", async () => {
    const result = await runExecution(
      nodeRequest(root, "process.stdout.write('y'.repeat(20000))"),
      { maxStdoutBytes: 128, maxStderrBytes: 128 },
    );
    assert.ok(Buffer.byteLength(result.stdout) <= 128);
    assert.equal(result.truncated, true);
    assert.equal(result.status, EXECUTION_STATUS.COMPLETED);
  });
});

// ─── Limit precedence ────────────────────────────────────────────────────────

describe("limit precedence", () => {
  const root = register(makeRoot());

  it("lets a stricter policy timeout beat a larger request timeout", async () => {
    const result = await runExecution(
      nodeRequest(root, "process.exit(0)", {
        policy: policy(root, { maxDurationMs: 300 }),
        timeout: 100000,
      }),
    );
    assert.equal(result.limits.timeoutMs, 300);
  });

  it("lets a stricter request timeout narrow the policy", async () => {
    const result = await runExecution(
      nodeRequest(root, "process.exit(0)", {
        policy: policy(root, { maxDurationMs: 100000 }),
        timeout: 250,
      }),
    );
    assert.equal(result.limits.timeoutMs, 250);
  });

  it("does not let a request widen the policy output ceiling", async () => {
    const result = await runExecution(
      nodeRequest(root, "process.exit(0)", {
        policy: policy(root, { maxOutputBytes: 64 }),
        limits: { maxOutputBytes: 100000 },
      }),
    );
    assert.equal(result.limits.maxStdoutBytes, 64);
    assert.equal(result.limits.maxStderrBytes, 64);
  });

  it("allows a per-stream override to tighten each stream only", async () => {
    const result = await runExecution(
      nodeRequest(root, "process.exit(0)", {
        policy: policy(root, { maxOutputBytes: 1000 }),
      }),
      { maxStdoutBytes: 10 },
    );
    assert.equal(result.limits.maxStdoutBytes, 10);
    assert.equal(result.limits.maxStderrBytes, 1000);
  });

  it("resolves limits most-restrictively and deterministically", async () => {
    const result = await runExecution(
      nodeRequest(root, "process.exit(0)", {
        policy: policy(root, {
          maxDurationMs: 400,
          maxOutputBytes: 200,
        }),
        timeout: 5000,
        limits: { maxOutputBytes: 9000 },
      }),
      { maxStdoutBytes: 50, maxStderrBytes: 5000 },
    );
    assert.deepEqual(result.limits.timeoutMs, 400);
    assert.deepEqual(result.limits.maxStdoutBytes, 50);
    assert.deepEqual(result.limits.maxStderrBytes, 200);
  });
});

// ─── Environment ─────────────────────────────────────────────────────────────

describe("environment policy", () => {
  const root = register(makeRoot());

  it("applies string overrides to the child", async () => {
    const result = await runExecution(
      nodeRequest(root, "process.stdout.write(process.env.CG_EXEC_FLAG ?? '')", {
        environment: { CG_EXEC_FLAG: "override" },
      }),
    );
    assert.equal(result.stdout, "override");
  });

  it("inherits the parent environment by default", async () => {
    const original = process.env.CG_EXEC_INHERIT;
    process.env.CG_EXEC_INHERIT = "parent";
    try {
      const result = await runExecution(
        nodeRequest(
          root,
          "process.stdout.write(process.env.CG_EXEC_INHERIT ?? '')",
        ),
      );
      assert.equal(result.stdout, "parent");
    } finally {
      if (original === undefined) delete process.env.CG_EXEC_INHERIT;
      else process.env.CG_EXEC_INHERIT = original;
    }
  });

  it("can omit inheritance explicitly", async () => {
    const original = process.env.CG_EXEC_INHERIT2;
    process.env.CG_EXEC_INHERIT2 = "parent";
    try {
      const result = await runExecution(
        nodeRequest(
          root,
          "process.stdout.write(process.env.CG_EXEC_INHERIT2 ?? '')",
        ),
        { inheritEnvironment: false },
      );
      assert.equal(result.stdout, "");
    } finally {
      if (original === undefined) delete process.env.CG_EXEC_INHERIT2;
      else process.env.CG_EXEC_INHERIT2 = original;
    }
  });

  it("does not mutate the parent process environment", async () => {
    const result = await runExecution(
      nodeRequest(root, "process.exit(0)", {
        environment: { CG_EXEC_MUTATION_PROBE: "leak" },
      }),
    );
    assert.equal(result.status, EXECUTION_STATUS.COMPLETED);
    assert.equal(process.env.CG_EXEC_MUTATION_PROBE, undefined);
  });

  it("never exposes the environment in the result", async () => {
    const secret = "s3cr3t-value-do-not-serialize";
    const result = await runExecution(
      nodeRequest(root, "process.exit(0)", {
        environment: { CG_EXEC_SECRET: secret },
      }),
    );
    assert.ok(!("environment" in result));
    assert.ok(!("env" in result));
    assert.ok(!JSON.stringify(result).includes(secret));
  });

  it("rejects invalid environment overrides", async () => {
    await assert.rejects(
      () => runExecution({ command: NODE, environment: "PATH" }),
      ValidationError,
    );
    await assert.rejects(
      () => runExecution({ command: NODE, environment: { BAD: 5 } }),
      ValidationError,
    );
    await assert.rejects(
      () => runExecution({ command: NODE, environment: { "1BAD": "x" } }),
      ValidationError,
    );
    await assert.rejects(
      () => runExecution({ command: NODE, environment: { OK: undefined } }),
      ValidationError,
    );
  });
});

// ─── Cancellation ────────────────────────────────────────────────────────────

describe("cancellation", () => {
  it("cancels a running execution", async () => {
    const root = register(makeRoot());
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 150);

    const result = await runExecution(
      nodeRequest(root, "setTimeout(() => {}, 10000)", {
        policy: policy(root, { maxDurationMs: 10000 }),
      }),
      { signal: controller.signal, terminationGraceMs: 150 },
    );
    assert.equal(result.status, EXECUTION_STATUS.CANCELED);
    assert.equal(result.canceled, true);
  });

  it("cancels before spawning when already aborted", async () => {
    const root = register(makeRoot());
    const controller = new AbortController();
    controller.abort();

    const result = await runExecution(
      nodeRequest(root, "process.exit(0)"),
      { signal: controller.signal },
    );
    assert.equal(result.status, EXECUTION_STATUS.CANCELED);
    assert.equal(result.pid, null);
  });

  it("leaves no orphaned process after cancellation", async () => {
    const root = register(makeRoot());
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 150);

    const result = await runExecution(
      nodeRequest(root, "setTimeout(() => {}, 10000)", {
        policy: policy(root, { maxDurationMs: 10000 }),
      }),
      { signal: controller.signal, terminationGraceMs: 150 },
    );
    clearTimeout(timer);
    assert.ok(result.pid);
    await delay(400);
    assert.equal(isProcessAlive(result.pid), false, "child must be gone");
  });
});
