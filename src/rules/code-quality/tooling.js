/**
 * Code Guardian — Quality Tooling Evidence (Official Roadmap Phase 12)
 *
 * The single place the linting/formatting/type-checking domains are *read* from the model.
 * Both the tooling rules and the summary call it, so a rule's outcome and the summary's state
 * cannot disagree about what "linting is established" means.
 *
 * The evidence is deliberately three-channel:
 *
 *   configuration   a recognized configuration file was observed (the scanner's
 *                   `lint-configuration` / `format-configuration` signal, or a build
 *                   configuration whose basename is a compiler configuration)
 *   script          a declared manifest script whose *name* names the tool
 *   dependency      a declared dependency whose name is the tool
 *
 * Any one makes the domain `detected`; any one **plus** a CI workflow whose content contains
 * the tool's documented invocation makes it `verified`. Nothing here claims a run succeeded.
 */

import { QUALITY_CONFIGURATION_SIGNALS, TYPE_CHECK_CONFIG_BASENAMES } from "./contracts.js";
import { QUALITY_TOOLING } from "./rules/languages/index.js";
import {
  basenameOf,
  ciQualityObservation,
  configurationBySignal,
  declaredDependencyNames,
  declaredScriptNames,
  hasSourceSubject,
  languageIds,
  manifestFacts,
  scriptNamesMatching,
} from "./signals.js";

/** The roadmap's three tooling domains, in fixed order. */
export const TOOLING_DOMAINS = Object.freeze(["linting", "formatting", "type-checking"]);

/** The configuration signal each tooling domain is read through. */
const CONFIG_SIGNAL = Object.freeze({
  linting: QUALITY_CONFIGURATION_SIGNALS.LINT,
  formatting: QUALITY_CONFIGURATION_SIGNALS.FORMAT,
  "type-checking": QUALITY_CONFIGURATION_SIGNALS.BUILD,
});

/**
 * Everything the model establishes about one tooling domain.
 *
 * @param {object} query A repository query handle.
 * @param {string} domain One of `TOOLING_DOMAINS`.
 * @returns {object} Frozen.
 */
export function toolingEvidence(query, domain) {
  const tooling = QUALITY_TOOLING[domain] ?? {
    dependencies: [],
    scriptWords: [],
    ciTools: [],
  };

  const allConfigurations = configurationBySignal(query, CONFIG_SIGNAL[domain]);
  const configurations =
    domain === "type-checking"
      ? allConfigurations.filter((entity) =>
          TYPE_CHECK_CONFIG_BASENAMES.includes(basenameOf(entity.path)),
        )
      : allConfigurations;

  const scriptNames = scriptNamesMatching(declaredScriptNames(query), tooling.scriptWords);
  const dependencyNames = declaredDependencyNames(query).filter((name) =>
    tooling.dependencies.includes(name),
  );

  const ci = ciQualityObservation(query);
  const ciTools = ci.tools.filter((id) => tooling.ciTools.includes(id));

  const manifests = manifestFacts(query);
  const failedManifests = manifests.filter((record) => record.parseStatus === "failed");

  const observed = configurations.length > 0 || scriptNames.length > 0 || dependencyNames.length > 0;
  const verified = observed && ciTools.length > 0;

  return Object.freeze({
    domain,
    observed,
    verified,
    hasSource: hasSourceSubject(query),
    languageIds: languageIds(query),
    configurations,
    scriptNames,
    dependencyNames,
    ciTools,
    ciProviders: ci.providers,
    ciUnreadEntries: ci.unreadEntries,
    failedManifests: failedManifests.map((record) => record.path),
    scriptsTruncated: manifests.some((record) => record.scriptsTruncated),
  });
}
