/**
 * Code Guardian — Detector Aggregation (Phase 8C)
 *
 * Runs every detector against one repository view and returns the detected
 * sections in a fixed order. Ordering matters in exactly one place: manifests are
 * detected *before* languages, because manifest and lockfile evidence contributes
 * language signals (a Python project may declare itself with `pyproject.toml`
 * before it has any `.py` file in scope).
 *
 * Every detector is a pure function of the view except the three that read file
 * content through the Phase 8A boundary (manifests, git and content). None of them
 * spawn a process, touch the network, or write to the repository. `content` is the
 * only one that reads files the scan did not have to read, so it is the only one
 * that budgets itself (see `CONTENT_INSPECTION_LIMITS`) and records what it could
 * not inspect.
 */

import { detectCicd } from "./cicd.js";
import { detectConfiguration } from "./configuration.js";
import { detectContent } from "./content.js";
import { detectDocumentation } from "./documentation.js";
import { detectGit } from "./git.js";
import { detectLanguages } from "./languages.js";
import { detectManifests } from "./manifests.js";
import { detectTesting } from "./testing.js";

export { detectCicd, detectConfiguration, detectContent, detectDocumentation, detectGit };
export { detectLanguages, detectManifests, detectTesting };

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
    tests: detectTesting(view),
    cicd: detectCicd(view),
    documentation: detectDocumentation(view),
    configuration: detectConfiguration(view),
    git: await detectGit(view),
    content: await detectContent(view),
  };
}
