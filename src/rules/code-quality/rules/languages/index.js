/**
 * Code Guardian — Language Quality Profiles (Official Roadmap Phase 12)
 *
 * The modular language boundary's composition point. Each ecosystem states its own tool
 * vocabulary in its own module; this module unions them into the single table the generic
 * domain rules read. A rule therefore never branches on a language — it asks "which declared
 * dependencies, scripts and CI tools establish this domain across every language the
 * repository might use", and the per-language knowledge stays in one file per language.
 *
 * `languageIds` is the union of every profile's languages: it is what makes the pack's
 * *language-aware* reporting possible (which ecosystems the repository actually contains)
 * without any rule naming a language itself.
 */

import { GO_QUALITY_PROFILE } from "./go.js";
import { JAVASCRIPT_QUALITY_PROFILE } from "./javascript.js";
import { PYTHON_QUALITY_PROFILE } from "./python.js";
import { RUST_QUALITY_PROFILE } from "./rust.js";

/** The shipped language profiles, sorted by id so ordering never depends on import order. */
export const QUALITY_LANGUAGE_PROFILES = Object.freeze(
  [JAVASCRIPT_QUALITY_PROFILE, PYTHON_QUALITY_PROFILE, RUST_QUALITY_PROFILE, GO_QUALITY_PROFILE].sort(
    (a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
  ),
);

/** The roadmap's three tooling domains, in fixed order. */
export const QUALITY_TOOLING_DOMAINS = Object.freeze([
  "linting",
  "formatting",
  "type-checking",
]);

/** Union of a list of string lists, sorted and de-duplicated. */
function unionOf(lists) {
  const set = new Set();
  for (const list of lists) for (const value of list) if (typeof value === "string") set.add(value);
  return Object.freeze([...set].sort());
}

/**
 * The union vocabulary the generic tooling rules read.
 *
 * @returns {{languageIds: string[], tooling: object}} Frozen.
 */
function compose() {
  const languageIds = unionOf(QUALITY_LANGUAGE_PROFILES.map((profile) => profile.languageIds));
  const tooling = {};
  for (const domain of QUALITY_TOOLING_DOMAINS) {
    const entries = QUALITY_LANGUAGE_PROFILES.map((profile) => profile[domain] ?? {});
    tooling[domain] = Object.freeze({
      dependencies: unionOf(entries.map((entry) => entry.dependencies ?? [])),
      scriptWords: unionOf(entries.map((entry) => entry.scriptWords ?? [])),
      ciTools: unionOf(entries.map((entry) => entry.ciTools ?? [])),
    });
  }
  return Object.freeze({ languageIds, tooling: Object.freeze(tooling) });
}

const COMPOSED = compose();

/** Every language id any shipped profile covers, sorted. */
export const QUALITY_LANGUAGE_IDS = COMPOSED.languageIds;

/**
 * The union tooling vocabulary, keyed by the roadmap's three tooling domains.
 *
 *   dependencies  dependency names that establish the domain's tooling
 *   scriptWords   words a declared script name may contain to establish the domain
 *   ciTools       closed quality-tool ids that serve the domain in CI
 */
export const QUALITY_TOOLING = COMPOSED.tooling;
