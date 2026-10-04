/**
 * Code Guardian — Dependency Version Instances (Official Roadmap Phase 15)
 *
 * The comparison basis for the outdated and vulnerability domains. The roadmap is explicit that
 * a declared *range* is not an installed version, so this module builds the list of version
 * *instances* the repository actually establishes:
 *
 *   resolved instance   a lockfile recorded a resolved version (`resolutions`)
 *   pinned instance     no lockfile resolved it, but the manifest pinned an exact version
 *
 * A dependency declared only as a range, with no resolution, produces **no instance** — and the
 * rules that consume instances answer `unknown` for it rather than comparing a range as if it
 * were an installed version.
 */

import { dependencyEntities, dependencyResolutions } from "../signals.js";
import { exactDeclaredVersion } from "../versions.js";

/**
 * Every version instance the repository establishes, de-duplicated and sorted.
 *
 * @param {object} query
 * @returns {Array<{dependencyId: string, ecosystem: string, name: string, version: string,
 *   basis: string, manifestPath: string|null, evidenceIds: string[]}>}
 */
export function versionInstances(query) {
  const records = new Map();
  const resolvedIds = new Set();

  for (const resolution of dependencyResolutions(query)) {
    resolvedIds.add(resolution.dependencyId);
    const key = `${resolution.ecosystem}\u0000${resolution.name}\u0000${resolution.version}`;
    const existing = records.get(key);
    if (existing === undefined) {
      records.set(key, {
        dependencyId: resolution.dependencyId,
        ecosystem: resolution.ecosystem,
        name: resolution.name,
        version: resolution.version,
        basis: "lockfile-resolution",
        manifestPath: resolution.manifestPath,
        evidenceIds: [...resolution.evidenceIds],
      });
    } else {
      for (const id of resolution.evidenceIds) {
        if (!existing.evidenceIds.includes(id)) existing.evidenceIds.push(id);
      }
    }
  }

  // A pinned declaration is only a *version* when the manifest stated an exact version and no
  // lockfile resolved that dependency — otherwise the resolution is the installed truth.
  for (const dependency of dependencyEntities(query)) {
    if (resolvedIds.has(dependency.id)) continue;
    for (const declaration of dependency.declarations ?? []) {
      if (declaration.direct !== true) continue;
      const exact = exactDeclaredVersion(declaration.spec);
      if (exact === null) continue;
      const key = `${dependency.ecosystem}\u0000${dependency.name}\u0000${exact}`;
      if (records.has(key)) continue;
      records.set(key, {
        dependencyId: dependency.id,
        ecosystem: dependency.ecosystem,
        name: dependency.name,
        version: exact,
        basis: "pinned-declaration",
        manifestPath: declaration.manifestPath,
        evidenceIds: [...(declaration.evidenceIds ?? [])],
      });
    }
  }

  return [...records.values()]
    .sort((a, b) => {
      if (a.ecosystem !== b.ecosystem) return a.ecosystem < b.ecosystem ? -1 : 1;
      if (a.name !== b.name) return a.name < b.name ? -1 : 1;
      if (a.version === b.version) return a.basis < b.basis ? -1 : a.basis > b.basis ? 1 : 0;
      return a.version < b.version ? -1 : 1;
    })
    .map((record) => ({ ...record, evidenceIds: [...record.evidenceIds].sort() }));
}
