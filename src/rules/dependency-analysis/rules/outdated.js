/**
 * Code Guardian — Dependency Outdated Rule (Official Roadmap Phase 15)
 *
 * The "outdated dependencies" domain. A version is outdated only when an authoritative release
 * source establishes a newer one, so this rule compares the version *instances* the repository
 * establishes against external release metadata, per ecosystem.
 *
 * It never mistakes a declared range for an installed version: an instance is a resolved version
 * from a lockfile, or a pinned declaration with no lockfile resolution. A dependency declared
 * only as a range, with no resolution, produces no instance and is not compared.
 *
 * When the release metadata is absent, malformed, or does not cover an instance's ecosystem, the
 * rule answers `unknown` — never "current". When it covers every instance and none is behind,
 * the domain is clean.
 */

import { createRule } from "../../../core/index.js";

import {
  DEPENDENCY_ANALYSIS_BASES,
  DEPENDENCY_ANALYSIS_CATEGORY,
  DEPENDENCY_ANALYSIS_CONFIDENCE,
  DEPENDENCY_ANALYSIS_RULE_IDS,
  DEPENDENCY_ANALYSIS_RULE_VERSION,
  DEPENDENCY_ANALYSIS_STATES,
  DEPENDENCY_INTELLIGENCE_STATES,
} from "../contracts.js";
import {
  readDependencyIntelligence,
  releasesByPackage,
  sourceById,
} from "../intelligence.js";
import { dependencyEntities, queryFor } from "../signals.js";
import { compareVersions, isComparableEcosystem } from "../versions.js";

import { versionInstances } from "./comparison.js";
import { capFindings, keyFragment, unknownDetection } from "./shared.js";

const CATEGORY = DEPENDENCY_ANALYSIS_CATEGORY;
const VERSION = DEPENDENCY_ANALYSIS_RULE_VERSION;
const IDS = DEPENDENCY_ANALYSIS_RULE_IDS;
const BASES = DEPENDENCY_ANALYSIS_BASES;
const STATES = DEPENDENCY_ANALYSIS_STATES;

export const dependencyOutdatedRules = Object.freeze([
  createRule({
    id: IDS.OUTDATED,
    version: VERSION,
    category: CATEGORY,
    title: "A resolved dependency is behind an authoritative release",
    description:
      "An external release source establishes a newer version than the version instance this repository resolved or pinned, in an ecosystem whose version semantics this build compares. The finding names the package, the ecosystem, the instance's version (and how it was established) and the newer version, and records the release source id and revision it used. It never treats a declared range as an installed version and never concludes from release metadata it does not have.",
    severity: "low",
    applicability: {},
    detect: (context) => {
      const query = queryFor(context);
      const intelligence = readDependencyIntelligence(context);

      if (intelligence.state !== DEPENDENCY_INTELLIGENCE_STATES.VALID) {
        return unknownDetection(
          `external release metadata is "${intelligence.state}", so no version can be judged current or outdated`,
        );
      }

      const instances = versionInstances(query);
      const dependencies = dependencyEntities(query);
      if (instances.length === 0) {
        if (dependencies.length === 0) {
          return {
            findings: [],
            evidence: [],
            metadata: { basis: BASES.EXTERNAL_RELEASE, state: STATES.NOT_APPLICABLE, dependencies: 0 },
          };
        }
        return unknownDetection(
          "no resolved or pinned version instance was established, so no version was compared",
        );
      }

      const releases = releasesByPackage(intelligence);
      const findings = [];
      let uncovered = 0;

      for (const instance of instances) {
        if (!isComparableEcosystem(instance.ecosystem)) {
          uncovered += 1;
          continue;
        }
        const records = releases.get(`${instance.ecosystem}:${instance.name}`) ?? [];
        if (records.length !== 1) {
          uncovered += 1;
          continue;
        }
        const release = records[0];
        const comparison = compareVersions(instance.ecosystem, instance.version, release.latest);
        if (comparison === null) {
          uncovered += 1;
          continue;
        }
        if (comparison >= 0) continue;
        const source = sourceById(intelligence, release.sourceId);
        if (instance.evidenceIds.length === 0) continue;
        findings.push({
          confidence: DEPENDENCY_ANALYSIS_CONFIDENCE.EXTERNAL_MATCH,
          description: `\`${instance.name}\` (${instance.ecosystem}) is at ${instance.version}, established by ${instance.basis === "lockfile-resolution" ? "a lockfile resolution" : "a pinned declaration"}, while release source \`${release.sourceId}\` (revision \`${source?.revision ?? "unknown"}\`) reports ${release.latest} as the latest version. This comparison uses the repository's own version instance and the versioned external release metadata; it does not assert that a declared range is the installed version.`,
          evidence: [...instance.evidenceIds],
          metadata: {
            basis: BASES.EXTERNAL_RELEASE,
            state: STATES.DETECTED,
            fingerprintKey: `outdated:${keyFragment(instance.ecosystem)}:${keyFragment(instance.name)}:${keyFragment(instance.version)}`,
            ecosystem: instance.ecosystem,
            package: instance.name,
            current: instance.version,
            instanceBasis: instance.basis,
            latest: release.latest,
            sourceId: release.sourceId,
            sourceRevision: source?.revision ?? null,
          },
        });
      }

      const { entries, truncated } = capFindings(findings);

      if (entries.length > 0) {
        return {
          findings: entries,
          evidence: [],
          metadata: {
            basis: BASES.EXTERNAL_RELEASE,
            state: STATES.DETECTED,
            instances: instances.length,
            reported: entries.length,
            uncovered,
            truncated,
          },
        };
      }

      if (uncovered > 0) {
        return unknownDetection(
          `release metadata did not cover ${uncovered} version instance(s), so the domain cannot be concluded`,
        );
      }

      return {
        findings: [],
        evidence: [],
        metadata: {
          basis: BASES.EXTERNAL_RELEASE,
          state: STATES.ESTABLISHED,
          instances: instances.length,
          reported: 0,
          uncovered: 0,
        },
      };
    },
    remediation: {},
    metadata: {
      tags: ["dependency", "outdated", "external"],
      falsePositives: ["a release source whose latest tag is not a supported release"],
    },
  }),
]);
