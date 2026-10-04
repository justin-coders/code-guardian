/**
 * Code Guardian — Dependency Duplicate Versions Rule (Official Roadmap Phase 15)
 *
 * The "duplicate versions" domain. Duplication is established only by **resolved** versions: a
 * package whose lockfile resolution records disagree — `a@1.2.0` and `a@2.4.0` both present — is
 * a real duplicate. Two differing manifest *specifiers* (`^1.2.0` and `^2.0.0`) establish
 * nothing about installed versions, so they are never reported.
 *
 * The rule states which evidence it used (the lockfile-resolution records on the dependency
 * entity) and answers `unknown` when no resolution could be established but the domain has a
 * subject.
 */

import { createRule } from "../../../core/index.js";

import {
  DEPENDENCY_ANALYSIS_BASES,
  DEPENDENCY_ANALYSIS_CATEGORY,
  DEPENDENCY_ANALYSIS_CONFIDENCE,
  DEPENDENCY_ANALYSIS_RULE_IDS,
  DEPENDENCY_ANALYSIS_RULE_VERSION,
  DEPENDENCY_ANALYSIS_STATES,
} from "../contracts.js";
import { dependencyCoverageEstablished, dependencyEntities, queryFor } from "../signals.js";

import { capFindings, keyFragment, unknownDetection } from "./shared.js";

const CATEGORY = DEPENDENCY_ANALYSIS_CATEGORY;
const VERSION = DEPENDENCY_ANALYSIS_RULE_VERSION;
const IDS = DEPENDENCY_ANALYSIS_RULE_IDS;
const BASES = DEPENDENCY_ANALYSIS_BASES;
const STATES = DEPENDENCY_ANALYSIS_STATES;

export const dependencyDuplicateRules = Object.freeze([
  createRule({
    id: IDS.DUPLICATE_VERSIONS,
    version: VERSION,
    category: CATEGORY,
    title: "A dependency resolves to more than one version",
    description:
      "A dependency entity carries lockfile resolution records that disagree about the version: the same package is resolved at two or more distinct versions. The finding names the package, the ecosystem, the resolved versions and the lockfiles that stated them. It reports only resolved versions — two differing specifiers in a manifest establish nothing about the installed tree.",
    severity: "low",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const dependencies = dependencyEntities(query);

      if (dependencies.length === 0) {
        return {
          findings: [],
          evidence: [],
          metadata: { basis: BASES.LOCKFILE_RESOLUTION, state: STATES.NOT_APPLICABLE, dependencies: 0 },
        };
      }

      const candidates = [];
      let withResolutions = 0;
      for (const dependency of dependencies) {
        const versions = [...new Set((dependency.resolutions ?? []).map((entry) => entry.version))].sort();
        if (versions.length > 0) withResolutions += 1;
        if (versions.length < 2) continue;
        const evidenceIds = [
          ...new Set((dependency.resolutions ?? []).flatMap((entry) => entry.evidenceIds ?? [])),
        ].sort();
        const manifestPaths = [
          ...new Set((dependency.resolutions ?? []).map((entry) => entry.manifestPath)),
        ].sort();
        candidates.push({
          id: dependency.id,
          ecosystem: dependency.ecosystem,
          name: dependency.name,
          versions,
          manifestPaths,
          evidenceIds,
        });
      }

      candidates.sort((a, b) => {
        if (a.ecosystem !== b.ecosystem) return a.ecosystem < b.ecosystem ? -1 : 1;
        return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
      });

      const { entries, truncated } = capFindings(candidates.filter((entry) => entry.evidenceIds.length > 0));
      const findings = entries.map((entry) => ({
        confidence: DEPENDENCY_ANALYSIS_CONFIDENCE.OBSERVED_FACT,
        description: `\`${entry.name}\` (${entry.ecosystem}) resolves to ${entry.versions.length} distinct versions — ${entry.versions.map((version) => `\`${version}\``).join(", ")} — in ${entry.manifestPaths.length === 0 ? "a lockfile" : `\`${entry.manifestPaths.join("`, `")}\``}. This is established by the lockfile resolution records, not by declared ranges.`,
        evidence: [...entry.evidenceIds],
        metadata: {
          basis: BASES.LOCKFILE_RESOLUTION,
          state: STATES.ESTABLISHED,
          fingerprintKey: `duplicate:${keyFragment(entry.ecosystem)}:${keyFragment(entry.name)}`,
          ecosystem: entry.ecosystem,
          package: entry.name,
          versions: [...entry.versions],
          manifestPaths: [...entry.manifestPaths],
        },
      }));

      if (findings.length > 0) {
        return {
          findings,
          evidence: [],
          metadata: {
            basis: BASES.LOCKFILE_RESOLUTION,
            state: STATES.ESTABLISHED,
            dependencies: dependencies.length,
            withResolutions,
            reported: findings.length,
            truncated,
          },
        };
      }

      if (withResolutions === 0) {
        const absence = dependencyCoverageEstablished(query);
        if (!absence.established) {
          return unknownDetection(
            `no resolved version was observed, but ${absence.reason}`,
          );
        }
      }

      return {
        findings: [],
        evidence: [],
        metadata: {
          basis: BASES.LOCKFILE_RESOLUTION,
          state: STATES.ESTABLISHED,
          dependencies: dependencies.length,
          withResolutions,
          reported: 0,
        },
      };
    },
    remediation: {},
    metadata: {
      tags: ["dependency", "duplicate-versions", "lockfile"],
      falsePositives: ["two lockfiles in different sub-projects that pin different versions by design"],
    },
  }),
]);
