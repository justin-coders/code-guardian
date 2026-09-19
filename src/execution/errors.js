/**
 * Code Guardian — Execution Error Semantics (Phase 8B)
 *
 * Pre-spawn outcomes (policy rejection, working-directory rejection) and spawn
 * failures are fundamentally different from a process that ran and exited
 * non-zero. This module gives them stable, structured, *sanitized*
 * representations.
 *
 * Boundary note: this layer depends on Core — never the other way around. The
 * error extends the Core `ExecutionError`, so it stays distinguishable
 * (category `execution`) without teaching Core about operating-system details.
 *
 * Sanitization: messages are derived from the failure kind, never copied from a
 * raw Node error (which can embed absolute paths or other local detail), and
 * `details` records only `{ kind, command, cwd }` where `command` is a bare
 * executable identity and `cwd` is a repository-relative path. Command
 * arguments are deliberately never recorded here, because they may carry
 * secrets.
 */

import nodePath from "node:path";

import { ExecutionError } from "../core/index.js";
import { sanitizeFilesystemPath } from "../repository/filesystem/index.js";

/** Stable kinds for execution failures. */
export const EXECUTION_ERROR_KINDS = Object.freeze({
  COMMAND_DENIED: "command-denied",
  COMMAND_NOT_ALLOWED: "command-not-allowed",
  COMMAND_NOT_RESOLVED: "command-not-resolved",
  COMMAND_UNTRUSTED_LOCATION: "command-untrusted-location",
  NO_ALLOWED_ROOTS: "no-allowed-roots",
  CWD_OUTSIDE_ROOT: "cwd-outside-root",
  CWD_INVALID: "cwd-invalid",
  CWD_NOT_FOUND: "cwd-not-found",
  CWD_NOT_DIRECTORY: "cwd-not-directory",
  CWD_PERMISSION_DENIED: "cwd-permission-denied",
  SPAWN_FAILED: "spawn-failed",
});

/** Stable, machine-readable codes for each execution failure kind. */
export const EXECUTION_ERROR_CODES = Object.freeze({
  COMMAND_DENIED: "CG_EXEC_COMMAND_DENIED",
  COMMAND_NOT_ALLOWED: "CG_EXEC_COMMAND_NOT_ALLOWED",
  COMMAND_NOT_RESOLVED: "CG_EXEC_COMMAND_NOT_RESOLVED",
  COMMAND_UNTRUSTED_LOCATION: "CG_EXEC_COMMAND_UNTRUSTED_LOCATION",
  NO_ALLOWED_ROOTS: "CG_EXEC_NO_ALLOWED_ROOTS",
  CWD_OUTSIDE_ROOT: "CG_EXEC_CWD_OUTSIDE_ROOT",
  CWD_INVALID: "CG_EXEC_CWD_INVALID",
  CWD_NOT_FOUND: "CG_EXEC_CWD_NOT_FOUND",
  CWD_NOT_DIRECTORY: "CG_EXEC_CWD_NOT_DIRECTORY",
  CWD_PERMISSION_DENIED: "CG_EXEC_CWD_PERMISSION_DENIED",
  SPAWN_FAILED: "CG_EXEC_SPAWN_FAILED",
});

/** Deterministic message fragments, keyed by failure kind. */
const KIND_MESSAGES = Object.freeze({
  [EXECUTION_ERROR_KINDS.COMMAND_DENIED]: "command is denied by policy",
  [EXECUTION_ERROR_KINDS.COMMAND_NOT_ALLOWED]:
    "command is not in the allowlist",
  [EXECUTION_ERROR_KINDS.COMMAND_NOT_RESOLVED]:
    "command executable could not be resolved",
  [EXECUTION_ERROR_KINDS.COMMAND_UNTRUSTED_LOCATION]:
    "command executable location is not trusted",
  [EXECUTION_ERROR_KINDS.NO_ALLOWED_ROOTS]:
    "no allowed execution root is configured",
  [EXECUTION_ERROR_KINDS.CWD_OUTSIDE_ROOT]:
    "working directory is outside the allowed roots",
  [EXECUTION_ERROR_KINDS.CWD_INVALID]: "working directory is invalid",
  [EXECUTION_ERROR_KINDS.CWD_NOT_FOUND]: "working directory does not exist",
  [EXECUTION_ERROR_KINDS.CWD_NOT_DIRECTORY]:
    "working directory is not a directory",
  [EXECUTION_ERROR_KINDS.CWD_PERMISSION_DENIED]:
    "working directory permission denied",
  [EXECUTION_ERROR_KINDS.SPAWN_FAILED]: "command could not be spawned",
});

const KIND_CODES = Object.freeze(
  Object.fromEntries(
    Object.entries(EXECUTION_ERROR_KINDS).map(([name, value]) => [
      value,
      EXECUTION_ERROR_CODES[name],
    ]),
  ),
);

function normaliseKind(kind) {
  return Object.values(EXECUTION_ERROR_KINDS).includes(kind)
    ? kind
    : EXECUTION_ERROR_KINDS.SPAWN_FAILED;
}

/**
 * Build the deterministic, path-free message for a failure.
 * @param {string} kind
 * @returns {string}
 */
export function executionErrorMessage(kind) {
  return KIND_MESSAGES[normaliseKind(kind)];
}

/** Reduce a command to a bare, safe identity (no directory parts, no NUL). */
export function sanitizeCommandIdentity(value) {
  if (typeof value !== "string" || value.trim() === "") return null;
  const base = nodePath.basename(value);
  if (base.includes("\0")) return null;
  return base;
}

/**
 * A structured execution failure.
 *
 * `details` records `{ kind, command, cwd }` only. The original error is
 * retained solely as an internal `cause` and is never serialized.
 */
export class CommandExecutionError extends ExecutionError {
  /**
   * @param {object} [options]
   * @param {string} [options.kind] One of `EXECUTION_ERROR_KINDS`.
   * @param {string} [options.code] Override the derived machine code.
   * @param {string} [options.command] Executable identity (bare name).
   * @param {string} [options.cwd] Repository-relative working directory.
   * @param {Error} [options.cause] Underlying error (never auto-exposed).
   */
  constructor(options = {}) {
    const kind = normaliseKind(options.kind);
    super(executionErrorMessage(kind), {
      code: options.code ?? KIND_CODES[kind],
      details: {
        kind,
        command: sanitizeCommandIdentity(options.command),
        cwd: sanitizeFilesystemPath(options.cwd),
      },
      cause: options.cause,
    });
    /** The distinguished failure kind. */
    this.kind = kind;
  }
}
