/**
 * Code Guardian — Code Quality Summary (Official Roadmap Phase 12)
 *
 * The analyzer's structured answer to "what code-quality infrastructure does this repository
 * declare, and what can be established about it". It is a pure function of the frozen
 * RepositoryModel, so two runs over the same model produce the same map — no clock, no random
 * source, no unordered iteration.
 *
 * Each of the nine roadmap domains carries a `state` drawn from the five official states plus
 * the domain's own facts. The mapping is deliberately conservative:
 *
 *   detected         an artifact or indicator was observed, but nothing established it works
 *   verified         a tool is configured **and** a CI workflow is observed containing its
 *                    documented invocation — the strongest claim this phase makes
 *   failed           an expected operation demonstrably failed (a manifest whose parse failed)
 *   unknown          the domain applies but the evidence does not establish the answer
 *   not_applicable   the domain genuinely has no subject over *complete* coverage
 *
 * ### Open tooling domains vs measured indicator domains
 *
 * The three tooling domains (linting, formatting, type checking) are **open**: a tool can be
 * invoked without a configuration file, a matching script name or a declared dependency, so
 * the absence of every recognized marker does **not** establish the tooling's absence. When the
 * repository has source, an unmarked tooling domain is therefore `unknown`, never
 * `not_applicable` — the discipline Official Phase 11 established.
 *
 * The indicator domains (dead code, complexity, unsafe patterns) are **measured**: they report
 * a graph shape the model either establishes or does not. An established graph with no
 * indicator is `not_applicable` (no indicator subject); a graph the model did not establish is
 * `unknown`. Duplication is neither: the model provides no measurement at all, so it is always
 * `unknown` when source exists.
 *
 * `unknown` is never clean, and `not_applicable` is never used because evidence is missing.
 *
 * ### The one `failed` this phase can establish
 *
 * `failed` is reserved for an operation the model demonstrably failed, and the only such
 * operation in this build is reading a manifest: a `package.json` whose parse failed cannot
 * have its declared scripts read. The `qualityScripts` entry carries that state when every
 * observed manifest failed to parse. The three tooling domains do **not** borrow it — they are
 * open, so a blocked script channel is one unavailable channel among several, not proof that
 * the tooling is absent.
 */

import {
  CODE_QUALITY_LIMITS,
  CODE_QUALITY_STATES,
  QUALITY_CONFIGURATION_SIGNALS,
  TYPE_CHECK_CONFIG_BASENAMES,
} from "./contracts.js";
import {
  basenameOf,
  configurationBySignal,
  hasSourceSubject,
  importGraphEvidence,
  languageIds,
  manifestFacts,
  queryFor,
  sourceAbsence,
  symbolGraphEvidence,
} from "./signals.js";
import { TOOLING_DOMAINS, toolingEvidence } from "./tooling.js";

const STATES = CODE_QUALITY_STATES;

/** The state of a tooling domain: open, so an unmarked domain with source is `unknown`. */
function toolingState(evidence, absenceEstablished) {
  if (evidence.verified) return STATES.VERIFIED;
  if (evidence.observed) return STATES.DETECTED;
  if (evidence.hasSource) return STATES.UNKNOWN;
  return absenceEstablished ? STATES.NOT_APPLICABLE : STATES.UNKNOWN;
}

/** The state of an indicator domain: `unknown` when the model could not measure it. */
function indicatorState({ observed, measurable, hasSource, absenceEstablished }) {
  if (observed) return STATES.DETECTED;
  if (!measurable) return STATES.UNKNOWN;
  if (!hasSource) return absenceEstablished ? STATES.NOT_APPLICABLE : STATES.UNKNOWN;
  return STATES.NOT_APPLICABLE;
}

/** The tooling summary entry for one domain. */
function toolingEntry(query, domain, absenceEstablished) {
  const evidence = toolingEvidence(query, domain);
  return Object.freeze({
    state: toolingState(evidence, absenceEstablished),
    configurations: evidence.configurations.map((entity) => entity.path).sort(),
    scripts: [...evidence.scriptNames],
    dependencies: [...evidence.dependencyNames],
    ciTools: [...evidence.ciTools],
    languages: [...evidence.languageIds],
    failedManifests: [...evidence.failedManifests],
  });
}

/** The configuration inconsistencies the model establishes (mirrors the rule's own reading). */
function configurationInconsistencies(query) {
  const entries = [];

  const compilerConfigs = configurationBySignal(
    query,
    QUALITY_CONFIGURATION_SIGNALS.BUILD,
  ).filter((entity) => TYPE_CHECK_CONFIG_BASENAMES.includes(basenameOf(entity.path)));
  const basenames = new Set(compilerConfigs.map((entity) => basenameOf(entity.path)));
  if (basenames.has("tsconfig.json") && basenames.has("jsconfig.json")) {
    entries.push({ kind: "conflicting-compiler-configuration", domain: "type-checking" });
  }

  for (const domain of TOOLING_DOMAINS) {
    const evidence = toolingEvidence(query, domain);
    if (evidence.configurations.length === 0) continue;
    const connected =
      evidence.scriptNames.length > 0 ||
      evidence.dependencyNames.length > 0 ||
      evidence.ciTools.length > 0;
    if (!connected) entries.push({ kind: "configuration-without-execution-path", domain });
  }

  return entries;
}

/**
 * Build the code-quality summary for an AnalysisContext.
 *
 * @param {object} context A validated AnalysisContext.
 * @returns {object} Frozen summary with one entry per roadmap domain.
 */
export function summarizeCodeQuality(context) {
  const query = queryFor(context);
  const absence = sourceAbsence(context);
  const hasSource = hasSourceSubject(query);

  const tooling = {};
  for (const domain of TOOLING_DOMAINS) {
    tooling[domain] = toolingEntry(query, domain, absence.established);
  }

  // ── Dead code ─────────────────────────────────────────────────────────────
  const symbol = symbolGraphEvidence(query);
  const imports = importGraphEvidence(query);
  const deadCodeObserved = symbol.unusedExports.length > 0 || imports.orphans.length > 0;
  const deadCodeMeasurable = symbol.established || imports.established;
  const deadCode = {
    state: indicatorState({
      observed: deadCodeObserved,
      measurable: deadCodeMeasurable,
      hasSource,
      absenceEstablished: absence.established,
    }),
    unusedExports: symbol.unusedExports.length,
    orphanModules: imports.orphans.length,
    symbolGraphState: symbol.state,
    importGraphState: imports.state,
  };

  // ── Complexity ────────────────────────────────────────────────────────────
  const largeModules = [...symbol.moduleSymbolCounts.entries()].filter(
    ([, count]) => count >= CODE_QUALITY_LIMITS.LARGE_MODULE_SYMBOLS,
  ).length;
  const complexity = {
    state: indicatorState({
      observed: largeModules > 0,
      measurable: symbol.established,
      hasSource,
      absenceEstablished: absence.established,
    }),
    measure: "module-scope-declarations",
    threshold: CODE_QUALITY_LIMITS.LARGE_MODULE_SYMBOLS,
    measuredModules: symbol.moduleSymbolCounts.size,
    largeModules,
  };

  // ── Duplication ───────────────────────────────────────────────────────────
  const duplication = {
    state: hasSource
      ? STATES.UNKNOWN
      : absence.established
        ? STATES.NOT_APPLICABLE
        : STATES.UNKNOWN,
    measure: null,
  };

  // ── Unsafe patterns ───────────────────────────────────────────────────────
  const unsafePattern = {
    state: indicatorState({
      observed: symbol.dynamicScopeSources.length > 0,
      measurable: symbol.established,
      hasSource,
      absenceEstablished: absence.established,
    }),
    dynamicScopeSources: symbol.dynamicScopeSources.map((source) => source.path).sort(),
  };

  // ── Maintainability ───────────────────────────────────────────────────────
  const missing = TOOLING_DOMAINS.filter(
    (domain) => tooling[domain].state === STATES.UNKNOWN || tooling[domain].state === STATES.NOT_APPLICABLE,
  );
  // The maintainability claim is a *gap* claim — "no recognized tooling was observed" —
  // so like the rule that emits it, it may only be asserted over established coverage.
  const maintainabilityEstablished = absence.established && missing.length > 0;
  const maintainability = {
    state: !hasSource
      ? absence.established
        ? STATES.NOT_APPLICABLE
        : STATES.UNKNOWN
      : missing.length > 0
        ? absence.established
          ? STATES.DETECTED
          : STATES.UNKNOWN
        : STATES.NOT_APPLICABLE,
    missingDomains: maintainabilityEstablished ? missing : [],
  };

  // ── Declared quality scripts ──────────────────────────────────────────────
  //
  // The one place this phase can observe a *failed* operation. A `package.json`
  // whose parse failed is an established acquisition failure — its declared scripts
  // cannot be read — so when every observed manifest failed, the scripts sub-domain is
  // `failed` rather than `unknown`. That is deliberately not the state of the three
  // tooling domains, which are *open*: a linter can be invoked with no script at all,
  // so a failed script channel does not establish that linting is absent.
  const manifests = manifestFacts(query);
  const parsedManifests = manifests.filter((record) => record.parsed);
  const failedManifests = manifests.filter((record) => record.parseStatus === "failed");
  const declaredQualityScripts = [
    ...new Set(TOOLING_DOMAINS.flatMap((domain) => tooling[domain].scripts)),
  ].sort();
  const qualityScripts = {
    state:
      manifests.length === 0
        ? STATES.NOT_APPLICABLE
        : failedManifests.length > 0 && parsedManifests.length === 0
          ? STATES.FAILED
          : declaredQualityScripts.length > 0
            ? STATES.DETECTED
            : parsedManifests.length > 0
              ? STATES.NOT_APPLICABLE
              : STATES.UNKNOWN,
    declared: declaredQualityScripts,
    failedManifests: failedManifests.map((record) => record.path),
  };

  // ── Configuration consistency ─────────────────────────────────────────────
  const inconsistencies = configurationInconsistencies(query);
  const anyConfiguration = TOOLING_DOMAINS.some(
    (domain) => tooling[domain].configurations.length > 0,
  );
  const configurationConsistency = {
    state:
      inconsistencies.length > 0
        ? STATES.DETECTED
        : !absence.established
          ? STATES.UNKNOWN
          : STATES.NOT_APPLICABLE,
    inconsistencies,
  };

  const applicabilityEntry = {
    state: hasSource ? STATES.DETECTED : absence.established ? STATES.NOT_APPLICABLE : STATES.UNKNOWN,
    hasSource,
    languages: languageIds(query),
    anyConfiguration,
  };

  return Object.freeze({
    applicability: Object.freeze(applicabilityEntry),
    linting: Object.freeze(tooling.linting),
    formatting: Object.freeze(tooling.formatting),
    typeChecking: Object.freeze(tooling["type-checking"]),
    deadCode: Object.freeze(deadCode),
    complexity: Object.freeze(complexity),
    duplication: Object.freeze(duplication),
    unsafePattern: Object.freeze(unsafePattern),
    qualityScripts: Object.freeze(qualityScripts),
    maintainability: Object.freeze(maintainability),
    configurationConsistency: Object.freeze(configurationConsistency),
    coverageBasis: absence,
  });
}
