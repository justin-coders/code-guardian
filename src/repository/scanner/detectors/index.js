/**
 * Code Guardian — Detector Aggregation (Phase 8C)
 *
 * Runs every detector against one repository view and returns the detected
 * sections in a fixed order. Ordering matters in exactly one place: manifests are
 * detected *before* languages, because manifest and lockfile evidence contributes
 * language signals (a Python project may declare itself with `pyproject.toml`
 * before it has any `.py` file in scope).
 *
 * Every detector is a pure function of the view except the five that read file
 * content through the Phase 8A boundary (manifests, git, content, containers and
 * imports). None
 * of them spawn a process, touch the network, or write to the repository. `content`
 * and `containers` read files the scan did not have to read, so both budget
 * themselves and record what they could not interpret.
 */

import { detectApi } from "./api.js";
import { detectCicd } from "./cicd.js";
import { detectConfiguration } from "./configuration.js";
import { detectContainers } from "./containers.js";
import { detectContent } from "./content.js";
import { detectDependencies } from "./dependencies.js";
import { detectDocumentation } from "./documentation.js";
import { detectGit } from "./git.js";
import { detectImports } from "./imports.js";
import { detectLanguages } from "./languages.js";
import { detectManifests } from "./manifests.js";
import { detectSemantics } from "./semantics.js";
import { detectTesting } from "./testing.js";

export { detectApi, detectCicd, detectConfiguration, detectContainers, detectContent };
export { detectDependencies, detectDocumentation, detectGit, detectImports };
export { detectLanguages, detectManifests, detectSemantics, detectTesting };

/**
 * Run all detectors.
 *
 * @param {object} view Repository view built by the scanner.
 * @returns {Promise<object>} The detected sections.
 */
export async function runDetectors(view) {
  const manifests = await detectManifests(view);

  return {
    languages: detectLanguages(view, manifests),
    manifests,
    // Dependency acquisition reads the manifests the detector above inventoried,
    // so it can never read a file the scan did not observe.
    dependencies: await detectDependencies(view, manifests),
    tests: detectTesting(view),
    cicd: detectCicd(view),
    documentation: detectDocumentation(view),
    configuration: detectConfiguration(view),
    git: await detectGit(view),
    content: await detectContent(view),
    containers: await detectContainers(view),
    // Phase 16 — module acquisition. It reads the source files the inventory
    // observed, so it can never read a file the walk did not see, and it resolves
    // nothing: specifiers are recorded as written and the model decides what they
    // point at.
    imports: await detectImports(view),
    // Phase 17 — the same module sources re-read for their *semantic* facts. It runs
    // after `imports` so a failure in one acquisition cannot hide the other, and it
    // resolves nothing either: declarations, exports, reference counts and call sites
    // are recorded as observed, and resolution against the repository is the model's
    // question, because the model owns entity identity.
    semantics: await detectSemantics(view),
    // Phase 18 — the same module sources re-read for their API route declarations.
    // It runs after `semantics` so a failure in one acquisition cannot hide the
    // other, and it resolves nothing: a route's handler name is recorded as written,
    // and whether it denotes a symbol is the model's question.
    api: await detectApi(view),
  };
}
