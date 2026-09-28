/**
 * Code Guardian — Scanner Dockerfile Structure Policy (Phase 20)
 *
 * The production-readiness auditor needs two facts about a container definition that
 * no earlier phase observed: whether the Dockerfile declares a **healthcheck**, and
 * whether it is a **multi-stage** build. Both are stated by the file's own
 * instructions, and both are exactly the kind of observation this architecture
 * insists on: read a bounded amount of the file, report the structure, invent
 * nothing.
 *
 * ### It reads instructions, it does not interpret a build
 *
 * This is a **line-level instruction reader**, not a Dockerfile parser and certainly
 * not a build evaluator. It recognises the instruction name at the start of each
 * logical line and reads exactly two of them:
 *
 *   - `FROM`          one build stage. `FROM <image> AS <name>` names it.
 *                     `stages > 1` is the multi-stage observation.
 *   - `HEALTHCHECK`   a healthcheck declaration. `HEALTHCHECK NONE` disables one.
 *
 * Every other instruction (`RUN`, `COPY`, `ENV`, `ARG`, …) is counted and otherwise
 * ignored, so nothing here depends on the meaning of a command, on shell syntax, on
 * a base image, on a registry or on the network. Whether the healthcheck is *good*,
 * whether the stages are *well chosen*, whether the image is *small* or the build
 * *reproducible* are judgments this architecture has no evidence for, and none of
 * them is expressible in the returned record.
 *
 * ### Refusal is a result, not a failure
 *
 * When the file cannot be read as a sequence of instructions this module does not
 * guess: it returns a bounded `reason` plus a bounded `detail`, which the caller
 * records as an *unestablished* observation. A reviewer therefore sees "the
 * structure of `Dockerfile` was not established, because its instructions exceeded
 * the bound" instead of a Dockerfile that silently appears to declare nothing.
 *
 * ### Boundedness, on every axis
 *
 *   - bytes read from any one file (`maxFileBytes`);
 *   - files inspected in one scan (`maxFiles`);
 *   - logical instructions examined in one file (`maxInstructions`);
 *   - bytes examined on any one line (`maxLineBytes`);
 *   - build stages retained (`maxStages`).
 *
 * Crossing any of them is reported as `too-large` with the axis as its detail, so a
 * truncated read is never presented as a complete one.
 *
 * Nothing here touches the filesystem, a process, the network or a clock: the text is
 * supplied by the caller, so every rule below is unit-testable on any platform.
 */

/**
 * The scanner signal this policy supplies and the configuration detector consumes.
 *
 * Held as a plain string rather than imported from the scan contract, because the
 * contract layer imports the policy layer and a cycle would be the result. A test
 * pins it to `SCAN_SIGNALS.DOCKERFILE`, so the two can never drift silently.
 */
export const DOCKERFILE_SIGNAL = "dockerfile";

/**
 * Which inventory entries are Dockerfiles.
 *
 * Shared with the configuration detector, so the file this policy reads is exactly
 * the file that detector reports as a `dockerfile` configuration signal — one table,
 * no drift.
 */
export const DOCKERFILE_RULES = Object.freeze([
  { basenamePattern: "Dockerfile*", caseInsensitive: true, signal: DOCKERFILE_SIGNAL },
  { basenamePattern: "*.dockerfile", caseInsensitive: true, signal: DOCKERFILE_SIGNAL },
]);

/** Hard bounds on Dockerfile structure inspection in one scan. */
export const DOCKERFILE_INSPECTION_LIMITS = Object.freeze({
  /** Bytes read from any single Dockerfile. */
  maxFileBytes: 65536,
  /** Dockerfiles inspected in one scan. */
  maxFiles: 64,
  /** Logical instructions examined in one file. */
  maxInstructions: 512,
  /** Bytes examined on any one logical line. */
  maxLineBytes: 4096,
  /** Build stages retained from one file. */
  maxStages: 32,
});

/**
 * Why a Dockerfile's structure is not established.
 *
 * Closed vocabulary: a consumer switches on these values, so a new reason has to be
 * added here deliberately rather than appearing as free text.
 */
export const DOCKERFILE_UNPARSED_REASONS = Object.freeze({
  READ_FAILED: "read-failed",
  NOT_TEXT: "not-text",
  TOO_LARGE: "too-large",
  BUDGET_EXHAUSTED: "budget-exhausted",
  UNSUPPORTED_SYNTAX: "unsupported-syntax",
});

/**
 * The bounded cause behind a refusal.
 *
 * `detail` never carries file text — it is a lower-case identifier naming the axis
 * or the syntax shape that stopped the reading.
 */
export const DOCKERFILE_DETAILS = Object.freeze({
  INSTRUCTION_LIMIT: "instruction-limit",
  LINE_LIMIT: "line-limit",
  STAGE_LIMIT: "stage-limit",
  UNRECOGNIZED_LINE: "unrecognized-line",
  UNREADABLE: "unreadable",
  TRUNCATED_READ: "truncated-read",
});

const REASON_VALUES = Object.freeze(Object.values(DOCKERFILE_UNPARSED_REASONS));

/** Whether a value is a Dockerfile refusal reason this policy can produce. */
export function isDockerfileUnparsedReason(value) {
  return typeof value === "string" && REASON_VALUES.includes(value);
}

/** An instruction name: a letter followed by letters, digits, `_`, `.` or `-`. */
const INSTRUCTION_TOKEN = /^[A-Za-z][A-Za-z0-9_.-]*$/;

/** A stage name, as `FROM … AS <name>` states it. */
const STAGE_NAME = /[A-Za-z0-9][A-Za-z0-9_.-]*/;

/** A trailing `AS <name>` clause on a `FROM` line, ignoring case. */
const AS_CLAUSE = /(?:^|\s)AS\s+([A-Za-z0-9][A-Za-z0-9_.-]*)\s*$/i;

/** The empty structure record: a Dockerfile whose content established nothing. */
export function emptyDockerfileStructure() {
  return {
    stages: 0,
    multiStage: false,
    stageNames: [],
    healthcheck: false,
    healthcheckDisabled: false,
    instructions: 0,
  };
}

/**
 * The empty structure record for a Dockerfile whose structure is not established.
 *
 * @param {string} reason One of `DOCKERFILE_UNPARSED_REASONS`.
 * @param {string|null} detail Bounded cause token, or `null`.
 * @returns {object} A record whose structure claims are all `false`/`0`.
 */
export function unestablishedDockerfileStructure(reason, detail) {
  const bounded = REASON_VALUES.includes(reason) ? reason : DOCKERFILE_UNPARSED_REASONS.READ_FAILED;
  return {
    parsed: false,
    reason: bounded,
    detail: typeof detail === "string" && detail.trim() !== "" ? detail : null,
    truncated: bounded === DOCKERFILE_UNPARSED_REASONS.TOO_LARGE,
    ...emptyDockerfileStructure(),
  };
}

/**
 * Read the logical lines of a Dockerfile body.
 *
 * A line ending in `\` continues onto the next one, which is how a long `HEALTHCHECK
 * CMD …` and a `FROM` with continuations are written. Comments and blank lines are
 * skipped — a `#` line is a Dockerfile comment wherever it appears, and a
 * parser directive (`# syntax=…`) is a comment too.
 *
 * @param {string} text
 * @param {object} limits
 * @returns {{ok: true, lines: string[]} | {ok: false, reason: string, detail: string}}
 */
function readInstructions(text, limits) {
  const collected = [];
  let pending = null;

  for (const raw of text.split(/\r?\n/)) {
    if (raw.length > limits.maxLineBytes) {
      return {
        ok: false,
        reason: DOCKERFILE_UNPARSED_REASONS.TOO_LARGE,
        detail: DOCKERFILE_DETAILS.LINE_LIMIT,
      };
    }

    const line = pending === null ? raw : `${pending} ${raw}`;
    const withoutTrailing = line.replace(/\s+$/, "");

    if (withoutTrailing.endsWith("\\")) {
      pending = withoutTrailing.slice(0, -1).replace(/\s+$/, "");
      continue;
    }
    pending = null;

    const candidate = line.trim();
    if (candidate === "" || candidate.startsWith("#")) continue;

    collected.push(candidate);
    if (collected.length > limits.maxInstructions) {
      return {
        ok: false,
        reason: DOCKERFILE_UNPARSED_REASONS.TOO_LARGE,
        detail: DOCKERFILE_DETAILS.INSTRUCTION_LIMIT,
      };
    }
  }

  // A file that ends mid-continuation is treated as ending there: Docker accepts that
  // with a warning, and inventing a following line would fabricate an instruction.
  if (pending !== null && pending.trim() !== "") collected.push(pending.trim());

  return { ok: true, lines: collected };
}

/**
 * Read the structure of one Dockerfile body.
 *
 * @param {unknown} text The file's text, as read through the Phase 8A boundary.
 * @param {object} [limits] Defaults to `DOCKERFILE_INSPECTION_LIMITS`.
 * @returns {{ok: true, instructions: number, stages: number, multiStage: boolean,
 *   stageNames: string[], healthcheck: boolean, healthcheckDisabled: boolean}
 *   | {ok: false, reason: string, detail: string|null}}
 */
export function parseDockerfileStructure(text, limits = DOCKERFILE_INSPECTION_LIMITS) {
  if (typeof text !== "string" || text.includes("\u0000")) {
    return { ok: false, reason: DOCKERFILE_UNPARSED_REASONS.NOT_TEXT, detail: null };
  }

  const read = readInstructions(text, limits);
  if (!read.ok) return read;

  let stages = 0;
  let healthcheck = false;
  let healthcheckDisabled = false;
  const stageNames = new Set();

  for (const line of read.lines) {
    const separator = line.search(/\s/);
    const token = separator === -1 ? line : line.slice(0, separator);
    if (!INSTRUCTION_TOKEN.test(token)) {
      return {
        ok: false,
        reason: DOCKERFILE_UNPARSED_REASONS.UNSUPPORTED_SYNTAX,
        detail: DOCKERFILE_DETAILS.UNRECOGNIZED_LINE,
      };
    }

    const instruction = token.toUpperCase();
    const rest = separator === -1 ? "" : line.slice(separator + 1).trim();

    if (instruction === "FROM") {
      stages += 1;
      if (stages > limits.maxStages) {
        return {
          ok: false,
          reason: DOCKERFILE_UNPARSED_REASONS.TOO_LARGE,
          detail: DOCKERFILE_DETAILS.STAGE_LIMIT,
        };
      }
      // `FROM <image> AS <name>`. A reference to an earlier stage by index
      // (`FROM 0`) or by name is not distinguished: the observation this phase
      // records is the *structure* — how many stages, and which ones are named —
      // never what an image reference resolves to.
      const clause = AS_CLAUSE.exec(rest);
      if (clause !== null && STAGE_NAME.test(clause[1])) stageNames.add(clause[1]);
    } else if (instruction === "HEALTHCHECK") {
      // `HEALTHCHECK NONE` cancels an inherited healthcheck. It is recorded as a
      // *disabled* declaration rather than as an absent one: a reader must be able to
      // tell "this file says there is no healthcheck" from "this file says nothing".
      if (/^NONE\b/i.test(rest)) healthcheckDisabled = true;
      else healthcheck = true;
    }
  }

  return {
    ok: true,
    instructions: read.lines.length,
    stages,
    multiStage: stages > 1,
    stageNames: [...stageNames].sort(),
    healthcheck,
    healthcheckDisabled,
  };
}
