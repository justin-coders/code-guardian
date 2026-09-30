/**
 * Code Guardian — RepositoryModel Contract & Invariants (Phase 8D)
 *
 * Two layers validate a built model:
 *
 *   1. `validateRepositoryModel` (Core, Phase 7) is the authority on the
 *      contracted *shape*: required areas, typed collections, nested Evidence
 *      records, and the rule that a truncated scan is never complete.
 *   2. `validateRepositoryModelGraph` (here) is the authority on the *model's own
 *      meaning*: entity identity, path relativity, parent/containment coherence,
 *      provenance, and graph reachability.
 *
 * They are separate because they answer different questions. Core must accept a
 * model produced by any scanner; this layer rejects a model that contradicts
 * itself, which is a stronger claim.
 *
 * Nothing here judges the repository. An invalid model is a *plumbing* failure,
 * not a finding: it means the builder was given an inconsistent ScanResult, or the
 * builder itself regressed.
 */

import {
  REPOSITORY_MODEL_JUDGMENT_AREAS,
  REPOSITORY_MODEL_VERSION,
  ValidationError,
} from "../../core/index.js";

import {
  ARCHITECTURE_EDGE_TYPES,
  ARCHITECTURE_EDGE_TYPE_VALUES,
  ARCHITECTURE_GRAPH_LIMITS,
  ARCHITECTURE_GRAPH_STATES,
  ARCHITECTURE_GRAPH_STATE_VALUES,
  ARCHITECTURE_NODE_KINDS,
  isEstablishedState,
  REPOSITORY_NODE_KIND,
} from "./architecture-graph.js";
import {
  DEPENDENCY_GRAPH_EDGE_TYPE_VALUES,
  DEPENDENCY_GRAPH_LIMITS,
  DEPENDENCY_GRAPH_STATES,
  DEPENDENCY_GRAPH_STATE_VALUES,
} from "./dependency-graph.js";
import {
  API_CALLABLE_FORMS,
  API_FRAMEWORKS,
  API_PROBLEM_REASONS,
  API_RECEIVER_KINDS,
  API_ROUTE_METHODS,
  API_SHAPE_REASONS,
  API_SOURCE_STATUSES,
  DEPENDENCY_SCOPES,
  DEPENDENCY_SOURCE_STATUSES,
  DEPENDENCY_SPEC_KINDS,
  IMPORT_MODULE_EXTENSIONS,
  IMPORT_PROBLEM_REASONS,
  IMPORT_SOURCE_REASONS,
  IMPORT_SOURCE_STATUSES as IMPORT_SOURCE_STATUS_VALUES,
  IMPORT_SPECIFIER_KINDS,
  MIDDLEWARE_FRAMEWORKS,
  MIDDLEWARE_PROBLEM_REASONS,
  MIDDLEWARE_REGISTRATIONS as ENTITY_MIDDLEWARE_REGISTRATIONS,
  MIDDLEWARE_SCOPES as ENTITY_MIDDLEWARE_SCOPES,
  MIDDLEWARE_SOURCE_REASONS,
  MIDDLEWARE_SOURCE_STATUSES,
  MIDDLEWARE_UNRESOLVED_REASONS as ENTITY_MIDDLEWARE_UNRESOLVED_REASONS,
  SEMANTIC_MODULE_EXTENSIONS,
  SEMANTIC_PROBLEM_REASONS,
  SEMANTIC_SOURCE_REASONS,
  SEMANTIC_SOURCE_STATUSES as SEMANTIC_SOURCE_STATUS_VALUES,
  SYMBOL_BINDING_KINDS,
  SYMBOL_EXPORT_FORMS,
  SYMBOL_KINDS,
  SYMBOL_OCCURRENCE_FORMS,
  projectModuleSpecifier,
  projectSymbolName,
} from "./entities.js";
import {
  IMPORT_GRAPH_EDGE_TYPE_VALUES,
  IMPORT_GRAPH_LIMITS,
  IMPORT_GRAPH_STATES,
  IMPORT_GRAPH_STATE_VALUES,
  INTERPRETED_LANGUAGE_IDS,
  UNRESOLVED_REFERENCE_REASON_VALUES,
  isEstablishedState as isImportGraphEstablished,
} from "./import-graph.js";
import {
  SYMBOL_GRAPH_EDGE_TYPES,
  SYMBOL_GRAPH_EDGE_TYPE_VALUES,
  SYMBOL_GRAPH_LIMITS,
  SYMBOL_GRAPH_STATES,
  SYMBOL_GRAPH_STATE_VALUES,
  SYMBOL_UNRESOLVED_KINDS,
  SYMBOL_UNRESOLVED_REASON_VALUES,
  isEstablishedSymbolState,
  symbolIdOf,
} from "./symbol-graph.js";
import {
  API_GRAPH_EDGE_TYPES,
  API_GRAPH_EDGE_TYPE_VALUES,
  API_GRAPH_LIMITS,
  API_GRAPH_STATES,
  API_GRAPH_STATE_VALUES,
  API_UNRESOLVED_KINDS,
  API_UNRESOLVED_REASON_VALUES,
  apiRouteIdOf,
  isEstablishedApiState,
} from "./api-graph.js";
import {
  MIDDLEWARE_CLASSIFICATION_VALUES,
  MIDDLEWARE_EDGE_TYPES,
  MIDDLEWARE_EDGE_TYPE_VALUES,
  MIDDLEWARE_GRAPH_LIMITS,
  MIDDLEWARE_GRAPH_STATES,
  MIDDLEWARE_GRAPH_STATE_VALUES,
  MIDDLEWARE_PROTECTION_STATES,
  MIDDLEWARE_PROTECTION_VALUES,
  MIDDLEWARE_REGISTRATIONS as GRAPH_MIDDLEWARE_REGISTRATIONS,
  MIDDLEWARE_SCOPES as GRAPH_MIDDLEWARE_SCOPES,
  MIDDLEWARE_UNRESOLVED_KINDS,
  MIDDLEWARE_UNRESOLVED_REASON_VALUES,
  isEstablishedMiddlewareState,
} from "./middleware-graph.js";
import {
  PRODUCTION_OBSERVATION_KINDS,
  PRODUCTION_REPORT_LIMITS,
  PRODUCTION_REPORT_STATES,
  PRODUCTION_REPORT_STATE_VALUES,
  PRODUCTION_REPORT_VERSION,
  PRODUCTION_SECTIONS,
  PRODUCTION_SECTION_TITLES,
  PRODUCTION_UNKNOWN_REASONS,
  PRODUCTION_UNSUPPORTED_REASONS,
  isEstablishedProductionState,
} from "./production-report.js";
import {
  PRODUCTION_RISK_BASIS_BY_KIND,
  PRODUCTION_RISK_CLASSIFICATION_BY_KIND,
  PRODUCTION_RISK_CLASSIFICATIONS,
  PRODUCTION_RISK_CLASSIFICATION_VALUES,
  PRODUCTION_RISK_CONFIDENCE_VALUES,
  PRODUCTION_RISK_FINDING_KINDS,
  PRODUCTION_RISK_REPORT_LIMITS,
  PRODUCTION_RISK_REPORT_VERSION,
  PRODUCTION_RISK_SECTIONS,
  PRODUCTION_RISK_SEVERITIES,
  PRODUCTION_RISK_SEVERITY_BY_KIND,
  PRODUCTION_RISK_SEVERITY_VALUES,
  PRODUCTION_RISK_SECTION_TITLES,
  PRODUCTION_RISK_STATES,
  PRODUCTION_RISK_STATE_VALUES,
  PRODUCTION_RISK_UNKNOWN_REASONS,
  PRODUCTION_RISK_UNSUPPORTED_REASONS,
  isEstablishedRiskState,
  renderRiskRemediation,
  renderRiskStatement,
} from "./production-risk-report.js";
import {
  MAX_RELEASE_WORKFLOWS,
  POLICY_DOCUMENT_KEYS,
  POLICY_DOCUMENT_METADATA_KEYS,
  POLICY_DOCUMENT_PATH,
  POLICY_DOCUMENT_PRESET_KEY,
  POLICY_DOCUMENT_SCHEMA,
  POLICY_DOCUMENT_VERSION,
  POLICY_DOMAINS,
  POLICY_LIMITS,
  POLICY_STATES,
  POLICY_STATE_VALUES,
  POLICY_UNKNOWN_REASON_VALUES,
  isEstablishedPolicyState,
  policyDocumentDomains,
  policyDocumentSettingCount,
} from "./policy.js";
// Phase 23 — the preset layer is a leaf this model consumes. The contract re-resolves a published
// policy to prove its effective document and provenance are *derived* from the declared one rather
// than merely shaped like it, which is what keeps "never lose provenance" a property of the model.
import { POLICY_PRESET_ORIGIN, effectivePolicyIssues } from "../../policy/index.js";
import {
  COMPLIANCE_CHECK_IDS,
  COMPLIANCE_LIMITS,
  COMPLIANCE_OBSERVED_VALUES,
  COMPLIANCE_SECTIONS,
  COMPLIANCE_SECTION_STATES,
  COMPLIANCE_SECTION_STATE_VALUES,
  COMPLIANCE_STATES,
  COMPLIANCE_STATE_VALUES,
  COMPLIANCE_STATUSES,
  COMPLIANCE_STATUS_VALUES,
  COMPLIANCE_UNKNOWN_REASON_VALUES,
  COMPLIANCE_VERSION,
  POLICY_REQUIREMENT_BINDING,
  renderComplianceRationale,
} from "./compliance-report.js";
import { GRAPH_RELATIONSHIP_TYPES, RELATIONSHIP_TYPES } from "./graph.js";
import { ENTITY_KINDS } from "./identity.js";
import {
  depthOfPath,
  parentPathOf,
  requireRepositoryRelativePath,
} from "./paths.js";
import { COVERAGE_GUARANTEES } from "./query.js";

/** Builder identity recorded in `metadata`. */
export const REPOSITORY_MODEL_BUILDER = "phase-8d-repository-model";

/** Builder version, bumped when entity shapes change incompatibly. */
export const REPOSITORY_MODEL_BUILDER_VERSION = "1";

/** The builder returns a deeply frozen model; recorded for consumers. */
export const MODEL_IMMUTABILITY = "frozen";

/**
 * The signal a container build-context observation carries, re-declared here rather
 * than imported from the scanner (the model must not depend on the acquisition
 * layer). A test in `tests/architecture-graph.test.js` pins it against the model's
 * own `CONTAINER_SIGNALS` vocabulary, so a rename on either side fails the suite.
 */
const BUILD_CONTEXT_SIGNAL = "compose-build-context";

/**
 * Entity collections the validator inspects, in a fixed order.
 *
 * A descriptor is `{ label, kind, select(model) }`, so both the validator and
 * `collectModelEntities` share one definition of "what entities this model has".
 */
export const MODEL_ENTITY_COLLECTIONS = Object.freeze([
  { label: "files.entries", kind: ENTITY_KINDS.FILE, select: (model) => model.files.entries },
  {
    label: "files.directories",
    kind: ENTITY_KINDS.DIRECTORY,
    select: (model) => model.files.directories,
  },
  {
    label: "files.symlinks",
    kind: ENTITY_KINDS.SYMLINK,
    select: (model) => model.files.symlinks,
  },
  { label: "languages", kind: ENTITY_KINDS.LANGUAGE, select: (model) => model.languages },
  { label: "frameworks", kind: ENTITY_KINDS.FRAMEWORK, select: (model) => model.frameworks },
  {
    label: "manifests.ecosystems",
    kind: ENTITY_KINDS.ECOSYSTEM,
    select: (model) => model.manifests.ecosystems,
  },
  { label: "manifests.entries", kind: ENTITY_KINDS.MANIFEST, select: (model) => model.manifests.entries },
  {
    label: "dependencies.entries",
    kind: ENTITY_KINDS.DEPENDENCY,
    select: (model) => model.dependencies.entries,
  },
  { label: "tests.entries", kind: ENTITY_KINDS.TEST, select: (model) => model.tests.entries },
  { label: "ci.entries", kind: ENTITY_KINDS.CICD, select: (model) => model.ci.entries },
  {
    label: "documentation.entries",
    kind: ENTITY_KINDS.DOCUMENTATION,
    select: (model) => model.documentation.entries,
  },
  {
    label: "configuration.entries",
    kind: ENTITY_KINDS.CONFIGURATION,
    select: (model) => model.configuration.entries,
  },
  { label: "git.entity", kind: ENTITY_KINDS.GIT, select: (model) => [model.git.entity] },
]);

/**
 * Every entity in the model, as `{ label, kind, entity }` records.
 * @param {object} model
 * @returns {Array<{ label: string, kind: string, entity: object }>}
 */
export function collectModelEntities(model) {
  const out = [];
  for (const descriptor of MODEL_ENTITY_COLLECTIONS) {
    const entities = descriptor.select(model) ?? [];
    for (const entity of entities) {
      out.push({ label: descriptor.label, kind: descriptor.kind, entity });
    }
  }
  return out;
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim() !== "";
}

/**
 * A count the graph states. A count is a number of things that exist, so anything a
 * reader could mistake for one — a fraction, a negative, `NaN`, a numeric string — has to
 * be rejected rather than coerced, because every bound and total in the graph area is
 * compared against these.
 */
function isNonNegativeInteger(value) {
  return Number.isInteger(value) && value >= 0;
}

/** A sorted, de-duplicated list of strings, for comparing two sets of ids. */
function sortedStringList(values) {
  return [...new Set(values.filter((value) => typeof value === "string"))].sort();
}

function checkIndexCoverage(model, entityIds, evidenceIds, ctx) {
  const indexed = new Set(Object.keys(model.indexes.entitiesById ?? {}));
  for (const id of entityIds) {
    if (!indexed.has(id)) ctx.fail(`indexes.entitiesById`, `does not index entity "${id}"`);
  }
  for (const id of indexed) {
    if (!entityIds.has(id)) {
      ctx.fail(`indexes.entitiesById`, `indexes unknown entity "${id}"`);
    }
  }

  const indexedEvidence = new Set(Object.keys(model.indexes.evidenceById ?? {}));
  for (const id of evidenceIds) {
    if (!indexedEvidence.has(id)) {
      ctx.fail(`indexes.evidenceById`, `missing evidence "${id}"`);
    }
  }

  for (const [path, id] of Object.entries(model.indexes.filesByPath ?? {})) {
    const entity = model.indexes.entitiesById?.[id];
    if (entity === undefined || entity.path !== path || entity.kind !== ENTITY_KINDS.FILE) {
      ctx.fail(`indexes.filesByPath`, `entry "${path}" does not resolve to that file`);
    }
  }

  const relationshipCount = model.relationships.length;
  for (const key of ["relationshipsByFrom", "relationshipsByTo"]) {
    for (const positions of Object.values(model.indexes[key] ?? {})) {
      for (const position of positions) {
        if (!Number.isInteger(position) || position < 0 || position >= relationshipCount) {
          ctx.fail(`indexes.${key}`, "must hold positions inside the relationship list");
        }
      }
    }
  }
}

/**
 * Validate the model's internal coherence.
 *
 * @param {object} model A model produced by `buildRepositoryModel`.
 * @returns {object} The same model when valid.
 * @throws {ValidationError} Listing every invariant it found broken.
 */
/**
 * Validate a policy document against the model's own closed schema.
 *
 * The document is the one payload in this model whose *contents* decide later answers, so the
 * check is complete rather than sampled: declared domains only, declared keys only, correctly
 * typed values, and the canonical order the entity layer rebuilds them in.
 */
function collectPolicyDocumentIssues(document, fail, path) {
  if (!isPlainObject(document)) {
    fail(path, "must be a plain object or null");
    return;
  }
  const domains = Object.keys(document);
  for (const domain of domains) {
    if (!POLICY_DOMAINS.includes(domain)) {
      fail(`${path}.${domain}`, "must be a declared policy domain");
      return;
    }
  }
  if (domains.join("\u0000") !== POLICY_DOMAINS.filter((d) => domains.includes(d)).join("\u0000")) {
    fail(path, "must state its domains in the declared order");
  }
  for (const domain of domains) {
    const settings = document[domain];
    if (!isPlainObject(settings)) {
      fail(`${path}.${domain}`, "must be a plain object of declared settings");
      continue;
    }
    const keys = Object.keys(settings);
    for (const key of keys) {
      if (!POLICY_DOCUMENT_KEYS[domain].includes(key)) {
        fail(`${path}.${domain}.${key}`, "is not a setting this schema declares");
        continue;
      }
      const value = settings[key];
      if (POLICY_DOCUMENT_SCHEMA[domain][key] === "boolean") {
        if (typeof value !== "boolean") fail(`${path}.${domain}.${key}`, "must be a boolean");
      } else if (
        !Number.isInteger(value) ||
        value < 0 ||
        value > MAX_RELEASE_WORKFLOWS
      ) {
        fail(`${path}.${domain}.${key}`, "must be a whole number within the declared bound");
      }
    }
    if (keys.join("\u0000") !== POLICY_DOCUMENT_KEYS[domain].filter((k) => keys.includes(k)).join("\u0000")) {
      fail(`${path}.${domain}`, "must state its settings in the declared order");
    }
  }
}

/**
 * Validate the *declared* policy document — what the repository wrote, before it was resolved.
 *
 * It is the same closed schema the model already checks, plus the two document-level fields Phase 23
 * added: the pinned `version` and the optional `preset` name. Both are metadata about the document,
 * and the preset name is deliberately *not* checked against a registry here: whether a preset exists
 * is the resolver's question, and a validator that answered it would need the registry it is meant
 * to be checking the result of.
 */
function collectDeclaredPolicyIssues(document, fail, path) {
  if (!isPlainObject(document)) {
    fail(path, "must be a plain object or null");
    return;
  }
  const keys = Object.keys(document);
  const metadata = keys.filter((key) => POLICY_DOCUMENT_METADATA_KEYS.includes(key));
  const domains = keys.filter((key) => POLICY_DOMAINS.includes(key));
  if (metadata.length + domains.length !== keys.length) {
    fail(path, "must state only its version, its preset and declared domains");
    return;
  }
  if (
    metadata.join("\u0000") !==
    POLICY_DOCUMENT_METADATA_KEYS.filter((key) => metadata.includes(key)).join("\u0000")
  ) {
    fail(path, "must state its version and preset in the declared order");
  }
  if (keys.slice(0, metadata.length).join("\u0000") !== metadata.join("\u0000")) {
    fail(path, "must state its version and preset before its domains");
  }
  if (document.version !== POLICY_DOCUMENT_VERSION) {
    fail(`${path}.version`, `must be "${POLICY_DOCUMENT_VERSION}"`);
  }
  if (Object.hasOwn(document, POLICY_DOCUMENT_PRESET_KEY)) {
    const preset = document[POLICY_DOCUMENT_PRESET_KEY];
    if (typeof preset !== "string" || preset === "") {
      fail(`${path}.${POLICY_DOCUMENT_PRESET_KEY}`, "must name a preset");
    }
  }
  const projected = {};
  for (const domain of POLICY_DOMAINS) {
    if (Object.hasOwn(document, domain)) projected[domain] = document[domain];
  }
  collectPolicyDocumentIssues(projected, fail, path);
}

/**
 * Validate the repository policy area.
 *
 * Every field is pinned to the state it claims. The two that carry the phase's weight are the
 * document and the answer flag: a document exists if and only if the state is `established`, and
 * `established` is true for exactly the two states that answer "what does this repository
 * declare?" — `established` and `absent`. So a model can neither claim an answer about a
 * document it did not read, nor present an unreadable document as an answer.
 *
 * Phase 23 adds four fields to the area without loosening any of that. `document` is now the
 * *effective* policy — the preset merged with the repository's own values — and it is the only
 * thing the compliance engine ever sees. `declared`, `preset` and `provenance` are carried exactly
 * when an effective policy exists, and the last of the checks here **re-resolves** the declared
 * document and compares the result: a published effective policy that is not the one its own
 * declaration resolves to is a validation failure, so provenance cannot be hand-written into a
 * model any more than a compliance item can.
 */
function collectPolicyAreaIssues(model, fail) {
  const area = model.policy;
  if (!isPlainObject(area)) {
    fail("policy", "must be a plain object");
    return;
  }
  const evidence = new Set((model.evidence ?? []).map((record) => record?.id));

  if (typeof area.detected !== "boolean") fail("policy.detected", "must be a boolean");
  if (typeof area.established !== "boolean") fail("policy.established", "must be a boolean");
  if (!POLICY_STATE_VALUES.includes(area.state)) {
    fail("policy.state", "must be a documented policy state");
  }
  if (area.established !== isEstablishedPolicyState(area.state)) {
    fail("policy.established", "must agree with the state it reports");
  }

  const document = area.document ?? null;
  if (document !== null) collectPolicyDocumentIssues(document, fail, "policy.document");
  if ((document !== null) !== (area.state === POLICY_STATES.ESTABLISHED)) {
    fail("policy.document", "must be carried exactly when the state is established");
  }

  // Phase 23 — the declared document, the preset that was applied and the provenance of every
  // effective value. All three are carried exactly when an effective policy was resolved.
  const declaredDocument = area.declared ?? null;
  const presetRecord = area.preset ?? null;
  const provenanceRecord = area.provenance ?? null;
  if ((declaredDocument !== null) !== (document !== null)) {
    fail("policy.declared", "must be carried exactly when an effective policy was resolved");
  }
  if (declaredDocument !== null) {
    collectDeclaredPolicyIssues(declaredDocument, fail, "policy.declared");
  }
  if ((provenanceRecord !== null) !== (document !== null)) {
    fail("policy.provenance", "must be carried exactly when an effective policy was resolved");
  }
  if (presetRecord !== null) {
    if (!isPlainObject(presetRecord)) {
      fail("policy.preset", "must be a plain object or null");
    } else {
      if (typeof presetRecord.name !== "string" || presetRecord.name === "") {
        fail("policy.preset.name", "must name the preset that was applied");
      }
      if (presetRecord.version !== POLICY_DOCUMENT_VERSION) {
        fail("policy.preset.version", "must be the pinned policy version");
      }
      if (presetRecord.origin !== POLICY_PRESET_ORIGIN) {
        fail("policy.preset.origin", "must name the built-in origin");
      }
    }
  }
  if (document !== null && presetRecord === null && provenanceRecord !== null) {
    if (provenanceRecord.preset !== null) {
      fail("policy.preset", "must name the preset the provenance records");
    }
  }
  if (presetRecord !== null && provenanceRecord !== null) {
    if (provenanceRecord.preset !== presetRecord.name) {
      fail("policy.preset.name", "must be the preset the provenance records");
    }
  }
  if (declaredDocument !== null && provenanceRecord !== null) {
    for (const issue of effectivePolicyIssues({
      declared: declaredDocument,
      effective: document,
      provenance: provenanceRecord,
    })) {
      fail("policy", issue);
    }
  }

  const coverage = area.coverage;
  if (!isPlainObject(coverage)) {
    fail("policy.coverage", "must be a plain object");
    return;
  }
  if (coverage.state !== area.state) fail("policy.coverage.state", "must agree with the area state");
  if (coverage.established !== area.established) {
    fail("policy.coverage.established", "must agree with the area state");
  }
  for (const field of ["complete", "inspected", "truncated"]) {
    if (typeof coverage[field] !== "boolean") {
      fail(`policy.coverage.${field}`, "must be a boolean");
    }
  }
  if (coverage.complete !== isEstablishedPolicyState(area.state)) {
    fail("policy.coverage.complete", "must agree with the state it reports");
  }
  if (coverage.truncated !== (area.state === POLICY_STATES.TRUNCATED)) {
    fail("policy.coverage.truncated", "must agree with the state it reports");
  }
  if (coverage.path !== POLICY_DOCUMENT_PATH) {
    fail("policy.coverage.path", "must be the contracted policy document path");
  }
  const answered = isEstablishedPolicyState(area.state);
  if (answered && coverage.reason !== null) {
    fail("policy.coverage.reason", "must be null when the reading answered");
  }
  if (!answered) {
    if (!POLICY_UNKNOWN_REASON_VALUES.includes(coverage.reason)) {
      fail("policy.coverage.reason", "must document why the reading did not answer");
    }
  }
  if (coverage.detail !== null && !isNonEmptyString(coverage.detail)) {
    fail("policy.coverage.detail", "must be a bounded identifier or null");
  }

  const declared = policyDocumentDomains(document);
  if (!Array.isArray(coverage.domains)) {
    fail("policy.coverage.domains", "must be an array");
  } else if (
    coverage.domains.join("\u0000") !== declared.join("\u0000") ||
    new Set(coverage.domains).size !== coverage.domains.length
  ) {
    fail("policy.coverage.domains", "must be the document's domains in declared order, each once");
  }
  if (coverage.settings !== policyDocumentSettingCount(document)) {
    fail("policy.coverage.settings", "must count the settings the document states");
  }

  if (!Array.isArray(coverage.evidenceIds)) {
    fail("policy.coverage.evidenceIds", "must be an array");
    return;
  }
  const uniqueEvidence = [...new Set(coverage.evidenceIds)].sort();
  if (JSON.stringify(uniqueEvidence) !== JSON.stringify(coverage.evidenceIds)) {
    fail("policy.coverage.evidenceIds", "must be sorted and unique");
  }
  for (const id of coverage.evidenceIds) {
    if (!evidence.has(id)) fail(`policy.coverage.evidenceIds`, `must cite a carried observation (${id})`);
  }
  if ((coverage.evidenceIds.length > 0) !== (area.detected === true)) {
    fail(
      "policy.coverage.evidenceIds",
      "must carry the document's observation exactly when the document was observed",
    );
  }
  if (!isPlainObject(coverage.limits)) fail("policy.coverage.limits", "must be a plain object");
  if (coverage.limits?.maxDomains !== POLICY_LIMITS.maxDomains) {
    fail("policy.coverage.limits.maxDomains", "must be the schema's own bound");
  }
}

/**
 * Validate the compliance report.
 *
 * The report is recomputed rather than sampled. Each section's state follows from its items, its
 * counts are the items it carries, its evidence union is the items' own citations, the report's
 * three item lists are exactly its sections' items by status, its state follows from its
 * sections, and every item's rationale is *re-rendered* from the item's own fields. The two
 * checks that give the phase its teeth are the last two: a `violation` must cite repository
 * evidence **and** the policy document, and an item's `expected` value must be the policy the
 * model actually carries — so no item can accuse the repository of contradicting a requirement
 * the repository never declared.
 */
function collectComplianceIssues(model, fail) {
  const area = model.compliance;
  if (!isPlainObject(area)) {
    fail("compliance", "must be a plain object");
    return;
  }
  const evidence = new Set((model.evidence ?? []).map((record) => record?.id));
  const document = isPlainObject(model.policy?.document) ? model.policy.document : null;
  const policyEvidenceIds = [...(model.policy?.coverage?.evidenceIds ?? [])].sort();

  if (typeof area.detected !== "boolean") fail("compliance.detected", "must be a boolean");
  if (typeof area.established !== "boolean") {
    fail("compliance.established", "must be a boolean");
  }
  if (!COMPLIANCE_STATE_VALUES.includes(area.state)) {
    fail("compliance.state", "must be a documented compliance state");
  }

  const report = area.report;
  if (!isPlainObject(report)) {
    fail("compliance.report", "must be a plain object");
    return;
  }
  if (report.version !== COMPLIANCE_VERSION) {
    fail("compliance.report.version", "must be the report version this builder produces");
  }
  if (!COMPLIANCE_STATE_VALUES.includes(report.state)) {
    fail("compliance.report.state", "must be a documented compliance state");
  }
  if (report.state !== area.state) {
    fail("compliance.report.state", "must agree with the area it belongs to");
  }
  if (report.established !== area.established) {
    fail("compliance.report.established", "must agree with the area it belongs to");
  }

  const sections = report.sections;
  if (!Array.isArray(sections)) {
    fail("compliance.report.sections", "must be an array");
    return;
  }
  if (sections.length !== COMPLIANCE_SECTIONS.length) {
    fail("compliance.report.sections", "must carry every policy domain exactly once");
  }
  const names = sections.map((section) => section?.name);
  if (names.join("\u0000") !== COMPLIANCE_SECTIONS.join("\u0000")) {
    fail("compliance.report.sections", "must be ordered by domain and carry each once");
  }

  sections.forEach((section, index) => {
    const at = `compliance.report.sections[${index}]`;
    if (!isPlainObject(section)) {
      fail(at, "must be a plain object");
      return;
    }
    if (!isNonEmptyString(section.title)) fail(`${at}.title`, "must be a non-empty title");
    if (!COMPLIANCE_SECTION_STATE_VALUES.includes(section.state)) {
      fail(`${at}.state`, "must be a documented section state");
    }
    if (section.established !== (section.state !== COMPLIANCE_SECTION_STATES.UNKNOWN)) {
      fail(`${at}.established`, "must agree with the state it reports");
    }
    if (typeof section.policyDeclared !== "boolean") {
      fail(`${at}.policyDeclared`, "must be a boolean");
    }
    if (section.policyDeclared !== (document !== null && isPlainObject(document[section.name]))) {
      fail(`${at}.policyDeclared`, "must agree with the policy this model carries");
    }

    const keys = section.policyKeys;
    if (!Array.isArray(keys)) {
      fail(`${at}.policyKeys`, "must be an array");
    } else {
      const expectedKeys = POLICY_DOCUMENT_KEYS[section.name] ?? [];
      for (const key of keys) {
        if (!expectedKeys.includes(key)) fail(`${at}.policyKeys`, "must be keys the schema declares");
      }
      if (keys.join("\u0000") !== expectedKeys.filter((key) => keys.includes(key)).join("\u0000")) {
        fail(`${at}.policyKeys`, "must be in schema order, each once");
      }
      const declaredKeys = document !== null && isPlainObject(document[section.name])
        ? Object.keys(document[section.name])
        : [];
      if (keys.join("\u0000") !== declaredKeys.join("\u0000")) {
        fail(`${at}.policyKeys`, "must be the keys the document declares for this domain");
      }
    }

    const items = Array.isArray(section.items) ? section.items : [];
    if (!Array.isArray(section.items)) fail(`${at}.items`, "must be an array");
    const seenIds = new Set();
    items.forEach((item, itemIndex) => {
      const itemAt = `${at}.items[${itemIndex}]`;
      if (!isPlainObject(item)) {
        fail(itemAt, "must be a plain object");
        return;
      }
      if (item.domain !== section.name) fail(`${itemAt}.domain`, "must be the section's own domain");
      if (!(POLICY_DOCUMENT_KEYS[section.name] ?? []).includes(item.key)) {
        fail(`${itemAt}.key`, "must be a policy key this domain declares");
      }
      if (item.policyKey !== `${section.name}.${item.key}`) {
        fail(`${itemAt}.policyKey`, "must name the policy key it measures");
      }
      const expectedId =
        item.subject === null || item.subject === undefined
          ? item.policyKey
          : `${item.policyKey}:${item.subject}`;
      if (item.id !== expectedId) fail(`${itemAt}.id`, "must be derived from its key and subject");
      if (seenIds.has(item.id)) fail(`${itemAt}.id`, "must be unique within the section");
      seenIds.add(item.id);

      // The requirement the item measures must be the one the model actually carries. This is
      // the check that makes "no inferred policy" a property of the model rather than a promise.
      const declared = document === null ? undefined : document[section.name]?.[item.key];
      if (declared === undefined) {
        fail(`${itemAt}.expected`, "must be a requirement the policy declares");
      } else if (item.expected !== declared) {
        fail(`${itemAt}.expected`, "must be the value the policy declares");
      }

      const vocabulary = COMPLIANCE_OBSERVED_VALUES[item.policyKey] ?? [];
      if (item.policyKey === "ci.maxReleaseWorkflows") {
        if (
          !(Number.isInteger(item.observed) && item.observed >= 0) &&
          !vocabulary.includes(item.observed)
        ) {
          fail(`${itemAt}.observed`, "must be a count or a documented observation");
        }
      } else if (!vocabulary.includes(item.observed)) {
        fail(`${itemAt}.observed`, "must be one of the observations this key declares");
      }
      if (!COMPLIANCE_STATUS_VALUES.includes(item.status)) {
        fail(`${itemAt}.status`, "must be one of: pass, violation, unknown");
      }
      if (item.subject !== null && !isNonEmptyString(item.subject)) {
        fail(`${itemAt}.subject`, "must name its subject or be null");
      }
      if (item.basis !== null && !isNonEmptyString(item.basis)) {
        fail(`${itemAt}.basis`, "must name the basis it rests on, or be null");
      }
      if (item.rationale !== renderComplianceRationale(item)) {
        fail(`${itemAt}.rationale`, "must be the sentence its own fields render");
      }
      if (
        typeof item.rationale !== "string" ||
        item.rationale.length > COMPLIANCE_LIMITS.maxRationaleLength
      ) {
        fail(`${itemAt}.rationale`, "must stay within the rationale bound");
      }

      if (!Array.isArray(item.evidenceIds) || !Array.isArray(item.policyEvidenceIds)) {
        fail(`${itemAt}.evidenceIds`, "must be arrays");
        return;
      }
      if (
        JSON.stringify([...new Set(item.evidenceIds)].sort()) !== JSON.stringify(item.evidenceIds) ||
        JSON.stringify([...new Set(item.policyEvidenceIds)].sort()) !==
          JSON.stringify(item.policyEvidenceIds)
      ) {
        fail(`${itemAt}.evidenceIds`, "must be sorted and unique");
      }
      for (const id of item.evidenceIds) {
        if (!evidence.has(id)) fail(`${itemAt}.evidenceIds`, `must cite a carried observation (${id})`);
      }
      for (const id of item.policyEvidenceIds) {
        if (!policyEvidenceIds.includes(id)) {
          fail(`${itemAt}.policyEvidenceIds`, "must cite the policy document's own observation");
        }
      }
      // An accusation is two-sided, always.
      if (item.status === COMPLIANCE_STATUSES.VIOLATION) {
        if (item.evidenceIds.length === 0) {
          fail(`${itemAt}.evidenceIds`, "must cite the observation a violation rests on");
        }
        if (item.policyEvidenceIds.length === 0) {
          fail(`${itemAt}.policyEvidenceIds`, "must cite the policy a violation contradicts");
        }
      }
    });

    const order = compareComplianceItems;
    const sorted = [...items].sort(order);
    if (JSON.stringify(items.map((item) => item?.id)) !== JSON.stringify(sorted.map((item) => item?.id))) {
      fail(`${at}.items`, "must be sorted by key, subject and id");
    }

    const violations = items.filter((item) => item?.status === COMPLIANCE_STATUSES.VIOLATION);
    const passed = items.filter((item) => item?.status === COMPLIANCE_STATUSES.PASS);
    const unknowns = items.filter((item) => item?.status === COMPLIANCE_STATUSES.UNKNOWN);

    let expectedState;
    if (items.length === 0) expectedState = COMPLIANCE_SECTION_STATES.UNKNOWN;
    else if (violations.length > 0) expectedState = COMPLIANCE_SECTION_STATES.VIOLATION;
    else if (passed.length > 0 && unknowns.length === 0) expectedState = COMPLIANCE_SECTION_STATES.PASS;
    else if (passed.length > 0) expectedState = COMPLIANCE_SECTION_STATES.PARTIAL;
    else expectedState = COMPLIANCE_SECTION_STATES.UNKNOWN;
    if (section.state !== expectedState) {
      fail(`${at}.state`, "must follow from the items it carries");
    }

    const counts = section.counts;
    if (!isPlainObject(counts)) {
      fail(`${at}.counts`, "must be a plain object");
    } else if (
      counts.items !== items.length ||
      counts.violations !== violations.length ||
      counts.passed !== passed.length ||
      counts.unknown !== unknowns.length
    ) {
      fail(`${at}.counts`, "must count the items it carries");
    }

    const union = [...new Set(items.flatMap((item) => [...(item?.evidenceIds ?? []), ...(item?.policyEvidenceIds ?? [])]))].sort();
    if (!Array.isArray(section.evidenceIds) || section.evidenceIds.join("\u0000") !== union.join("\u0000")) {
      fail(`${at}.evidenceIds`, "must be every citation its items make, sorted");
    }
    if (
      !Array.isArray(section.policyEvidenceIds) ||
      section.policyEvidenceIds.join("\u0000") !== policyEvidenceIds.join("\u0000")
    ) {
      fail(`${at}.policyEvidenceIds`, "must be the policy document's own observation");
    }

    const abstentions = section.unknown;
    if (!Array.isArray(abstentions)) {
      fail(`${at}.unknown`, "must be an array");
    } else {
      if (abstentions.length > COMPLIANCE_LIMITS.maxUnknownReasonsPerSection) {
        fail(`${at}.unknown`, "must stay within the abstention bound");
      }
      if (
        JSON.stringify(abstentions.map((r) => `${r?.reason}\u0000${r?.detail ?? ""}`)) !==
        JSON.stringify(
          [...abstentions]
            .map((r) => `${r?.reason}\u0000${r?.detail ?? ""}`)
            .sort(),
        )
      ) {
        fail(`${at}.unknown`, "must be ordered by reason then detail");
      }
      const pairs = new Set();
      for (const record of abstentions) {
        if (!isPlainObject(record)) {
          fail(`${at}.unknown`, "every abstention must be a plain object");
          continue;
        }
        if (!COMPLIANCE_UNKNOWN_REASON_VALUES.includes(record.reason)) {
          fail(`${at}.unknown`, "must name a documented reason");
        }
        if (record.detail !== null && !isNonEmptyString(record.detail)) {
          fail(`${at}.unknown`, "must carry a bounded detail or null");
        }
        if (!Number.isInteger(record.count) || record.count <= 0) {
          fail(`${at}.unknown`, "must count the reasons it merges");
        }
        const pair = `${record.reason}\u0000${record.detail ?? ""}`;
        if (pairs.has(pair)) fail(`${at}.unknown`, "must merge abstentions that share a reason");
        pairs.add(pair);
      }
    }

    const coverage = section.coverage;
    if (!isPlainObject(coverage)) {
      fail(`${at}.coverage`, "must be a plain object");
      return;
    }
    if (coverage.state !== section.state) fail(`${at}.coverage.state`, "must agree with the section");
    if (coverage.established !== section.established) {
      fail(`${at}.coverage.established`, "must agree with the section");
    }
    if (coverage.policyDeclared !== section.policyDeclared) {
      fail(`${at}.coverage.policyDeclared`, "must agree with the section");
    }
    if (typeof coverage.complete !== "boolean" || typeof coverage.truncated !== "boolean") {
      fail(`${at}.coverage`, "must state completeness and truncation as booleans");
    }
    if (
      coverage.items !== items.length ||
      coverage.violations !== violations.length ||
      coverage.passed !== passed.length ||
      coverage.unknown !== unknowns.length ||
      coverage.evidence !== union.length ||
      coverage.unknownReasons !== (Array.isArray(abstentions) ? abstentions.length : 0)
    ) {
      fail(`${at}.coverage`, "must count what the section carries");
    }
  });

  const flat = (status) =>
    sections.flatMap((section) =>
      (Array.isArray(section?.items) ? section.items : []).filter(
        (item) => item?.status === status,
      ),
    );
  for (const [field, status] of [
    ["violations", COMPLIANCE_STATUSES.VIOLATION],
    ["passed", COMPLIANCE_STATUSES.PASS],
    ["unknown", COMPLIANCE_STATUSES.UNKNOWN],
  ]) {
    const expectedItems = flat(status);
    if (!Array.isArray(report[field])) {
      fail(`compliance.report.${field}`, "must be an array");
    } else if (JSON.stringify(report[field].map((item) => item?.id)) !== JSON.stringify(expectedItems.map((item) => item?.id))) {
      fail(`compliance.report.${field}`, `must be every ${status} item the sections carry, in order`);
    }
  }

  const allItems = sections.flatMap((section) => (Array.isArray(section?.items) ? section.items : []));
  const anyTruncated = sections.some((section) => section?.coverage?.truncated === true);
  const everyPass = sections.every(
    (section) => section?.state === COMPLIANCE_SECTION_STATES.PASS,
  );
  const anyEstablished = sections.some((section) => section?.established === true);
  const expectedState =
    flat(COMPLIANCE_STATUSES.VIOLATION).length > 0
      ? COMPLIANCE_STATES.VIOLATION
      : anyTruncated
        ? COMPLIANCE_STATES.TRUNCATED
        : everyPass
          ? COMPLIANCE_STATES.PASS
          : anyEstablished
            ? COMPLIANCE_STATES.PARTIAL
            : COMPLIANCE_STATES.UNKNOWN;
  if (report.state !== expectedState) {
    fail("compliance.report.state", "must follow from the sections it summarises");
  }
  if (report.established !== anyEstablished) {
    fail("compliance.report.established", "must follow from the sections it summarises");
  }
  if (area.detected !== allItems.length > 0) {
    fail("compliance.detected", "must say whether any requirement was measured");
  }

  const coverage = report.coverage;
  if (!isPlainObject(coverage)) {
    fail("compliance.report.coverage", "must be a plain object");
    return;
  }
  if (coverage.state !== report.state) fail("compliance.report.coverage.state", "must agree with the report");
  if (coverage.established !== report.established) {
    fail("compliance.report.coverage.established", "must agree with the report");
  }
  if (coverage.complete !== (report.state === COMPLIANCE_STATES.PASS)) {
    fail("compliance.report.coverage.complete", "must agree with the report state");
  }
  if (coverage.truncated !== anyTruncated) {
    fail("compliance.report.coverage.truncated", "must agree with the sections");
  }
  if (
    coverage.sections !== sections.length ||
    coverage.sectionsEstablished !== sections.filter((section) => section?.established === true).length ||
    coverage.items !== allItems.length ||
    coverage.violations !== flat(COMPLIANCE_STATUSES.VIOLATION).length ||
    coverage.passed !== flat(COMPLIANCE_STATUSES.PASS).length ||
    coverage.unknown !== flat(COMPLIANCE_STATUSES.UNKNOWN).length
  ) {
    fail("compliance.report.coverage", "must count what the report carries");
  }
  if (coverage.policyState !== (model.policy?.state ?? null)) {
    fail("compliance.report.coverage.policyState", "must agree with the policy this model carries");
  }
  if (coverage.policyEstablished !== (model.policy?.established === true)) {
    fail("compliance.report.coverage.policyEstablished", "must agree with the policy this model carries");
  }
  const declaredDomains = policyDocumentDomains(document);
  if (JSON.stringify(coverage.policyDomains) !== JSON.stringify(declaredDomains)) {
    fail("compliance.report.coverage.policyDomains", "must be the domains the document declares");
  }
  if (coverage.policySettings !== policyDocumentSettingCount(document)) {
    fail("compliance.report.coverage.policySettings", "must count the settings the document states");
  }
  const union = [...new Set(allItems.flatMap((item) => [...(item?.evidenceIds ?? []), ...(item?.policyEvidenceIds ?? [])]))].sort();
  if (!Array.isArray(coverage.evidence) || coverage.evidence.join("\u0000") !== union.join("\u0000")) {
    fail("compliance.report.coverage.evidence", "must be every citation the report makes");
  }
  if (!isPlainObject(coverage.limits)) {
    fail("compliance.report.coverage.limits", "must be a plain object");
  } else if (coverage.limits.maxItemsPerSection !== COMPLIANCE_LIMITS.maxItemsPerSection) {
    fail("compliance.report.coverage.limits.maxItemsPerSection", "must be the report's own bound");
  }

  const unknownReasons = coverage.unknownReasons;
  if (!isPlainObject(unknownReasons)) {
    fail("compliance.report.coverage.unknownReasons", "must be a plain object");
  } else {
    const expected = {};
    for (const section of sections) {
      for (const record of section?.unknown ?? []) {
        if (!isPlainObject(record) || typeof record.reason !== "string") continue;
        expected[record.reason] = (expected[record.reason] ?? 0) + (record.count ?? 0);
      }
    }
    const keys = Object.keys(unknownReasons);
    if (keys.join("\u0000") !== keys.slice().sort().join("\u0000")) {
      fail("compliance.report.coverage.unknownReasons", "must be ordered by reason");
    }
    for (const key of [...new Set([...keys, ...Object.keys(expected)])]) {
      if (unknownReasons[key] !== expected[key]) {
        fail(
          `compliance.report.coverage.unknownReasons.${key}`,
          "must total the sections' own abstentions",
        );
      }
    }
  }

  // `detected` one level up is the same statement the report's item lists make, so a model that
  // carries an item it does not count, or counts one it does not carry, is rejected here.
  if (area.coverage !== undefined) {
    if (!isPlainObject(area.coverage)) {
      fail("compliance.coverage", "must be a plain object");
    } else {
      for (const field of ["state", "established", "complete", "truncated", "sections", "items"]) {
        if (area.coverage[field] !== report.coverage[field]) {
          fail(`compliance.coverage.${field}`, "must agree with the report it summarises");
        }
      }
    }
  }
}

/** The canonical order of a compliance section's items. */
function compareComplianceItems(a, b) {
  const left = `${a?.key}\u0000${a?.subject ?? ""}\u0000${a?.id ?? ""}`;
  const right = `${b?.key}\u0000${b?.subject ?? ""}\u0000${b?.id ?? ""}`;
  return left === right ? 0 : left < right ? -1 : 1;
}

/**
 * Every policy key the schema declares, as `domain.key`.
 *
 * @returns {string[]}
 */
export function policyKeyIds() {
  return POLICY_DOMAINS.flatMap((domain) =>
    POLICY_DOCUMENT_KEYS[domain].map((key) => `${domain}.${key}`),
  );
}

/**
 * The policy keys the report has no measurement for.
 *
 * Exported so the focused suite can pin the two tables together in both directions; the
 * load-time check below makes the same statement a build-time guarantee, because a declared
 * setting with no measurement would be a policy this build silently ignores — the one outcome
 * this phase forbids.
 */
export function unmeasuredPolicyKeys() {
  const checked = new Set(COMPLIANCE_CHECK_IDS);
  return policyKeyIds().filter((id) => !checked.has(id));
}

/** Policy keys a check measures that the schema does not declare. */
export function unknownPolicyCheckKeys() {
  const declared = new Set(policyKeyIds());
  return COMPLIANCE_CHECK_IDS.filter((id) => !declared.has(id));
}

const UNMEASURED_POLICY_KEYS = [
  ...unmeasuredPolicyKeys().map((id) => `${id}: no compliance check measures this policy key`),
  ...unknownPolicyCheckKeys().map((id) => `${id}: no policy schema declares this measured key`),
  ...COMPLIANCE_CHECK_IDS.filter((id) => {
    const [domain, key] = id.split(".");
    return POLICY_REQUIREMENT_BINDING[domain]?.[key] === undefined;
  }).map((id) => `${id}: no requirement binding decides when this key binds`),
];

if (UNMEASURED_POLICY_KEYS.length > 0) {
  throw new ValidationError("Invalid compliance check table", {
    details: { contract: "ComplianceChecks", issues: UNMEASURED_POLICY_KEYS },
  });
}

export function validateRepositoryModelGraph(model) {
  const issues = [];
  const fail = (path, message) => issues.push(`${path}: ${message}`);

  if (!isPlainObject(model)) {
    throw new ValidationError("Invalid repository model", {
      details: { contract: "RepositoryModelGraph", issues: ["model: must be a plain object"] },
    });
  }

  // ── Identity ──────────────────────────────────────────────────────────────
  if (model.version !== REPOSITORY_MODEL_VERSION) {
    fail("version", `must be "${REPOSITORY_MODEL_VERSION}"`);
  }
  if (!isNonEmptyString(model.identity?.repositoryId)) {
    fail("identity.repositoryId", "must be a non-empty string");
  }
  if (!isNonEmptyString(model.identity?.root)) {
    fail("identity.root", "must be a non-empty string");
  }
  if (model.identity?.name !== null) {
    fail("identity.name", "must be null: the scan does not determine a repository name");
  }

  // ── Entities ──────────────────────────────────────────────────────────────
  const descriptors = collectModelEntities(model);
  const entityIds = new Set();
  const entityById = new Map();
  const seen = new Set();
  const repositoryId = model.identity?.repositoryId;

  for (const { label, kind, entity } of descriptors) {
    if (!isPlainObject(entity)) {
      fail(`${label}`, "every entity must be a plain object");
      continue;
    }
    if (!isNonEmptyString(entity.id)) {
      fail(`${label}`, "entity id must be a non-empty string");
      continue;
    }
    if (seen.has(entity.id)) {
      fail(`${label}`, `duplicate entity id "${entity.id}"`);
      continue;
    }
    seen.add(entity.id);
    entityIds.add(entity.id);
    entityById.set(entity.id, entity);

    if (entity.kind !== kind) {
      fail(`${label}[${entity.id}]`, `entity kind must be "${kind}"`);
    }
    if (!entity.id.startsWith(`${kind}:`) && kind !== ENTITY_KINDS.GIT) {
      fail(`${label}[${entity.id}]`, `entity id must start with "${kind}:"`);
    }

    // Path-shaped entities carry a string path; value-shaped ones (language,
    // framework, ecosystem, git) carry `null`.
    if (typeof entity.path === "string") {
      try {
        requireRepositoryRelativePath(entity.path, `${label}[${entity.id}].path`);
      } catch (error) {
        fail(`${label}[${entity.id}].path`, "must be a canonical repository-relative path");
      }
      if (depthOfPath(entity.path) !== entity.depth) {
        fail(`${label}[${entity.id}].depth`, "must agree with the entity path");
      }
    }

    if (entity.evidenceIds.length === 0 && kind !== ENTITY_KINDS.GIT) {
      fail(`${label}[${entity.id}]`, "every entity must reference at least one observation");
    }
  }

  const directoryIds = new Set(
    model.files.directories.map((directory) => directory.id),
  );

  for (const file of [...model.files.entries, ...model.files.symlinks]) {
    const expected = parentPathOf(file.path);
    const expectedId =
      expected === null ? repositoryId : `${ENTITY_KINDS.DIRECTORY}:${expected}`;
    if (file.directoryId !== expectedId) {
      fail(`files[${file.path}].directoryId`, "must be the directory that contains the path");
    }
    if (file.directoryId !== repositoryId && !directoryIds.has(file.directoryId)) {
      fail(`files[${file.path}].directoryId`, "must resolve to an observed directory");
    }
  }

  for (const directory of model.files.directories) {
    const expected = parentPathOf(directory.path);
    const expectedId = expected === null ? null : `${ENTITY_KINDS.DIRECTORY}:${expected}`;
    if (directory.parentId !== expectedId) {
      fail(`files.directories[${directory.path}].parentId`, "must be the path's parent directory");
    }
    if (directory.depth > 1 && directory.parentId === null) {
      fail(`files.directories[${directory.path}].parentId`, "a nested directory must have a parent");
    }
    if (directory.parentId !== null && !directoryIds.has(directory.parentId)) {
      fail(`files.directories[${directory.path}].parentId`, "must resolve to an observed directory");
    }
  }

  for (const manifest of model.manifests.entries) {
    const expected = parentPathOf(manifest.path);
    const expectedId =
      expected === null ? repositoryId : `${ENTITY_KINDS.DIRECTORY}:${expected}`;
    if (manifest.directoryId !== expectedId) {
      fail(`manifests[${manifest.path}].directoryId`, "must be the directory that contains the path");
    }
  }

  // ── Dependency semantics ─────────────────────────────────────────────────
  //
  // A dependency is the one entity kind whose *content* is a graph: declarations
  // point at manifests, resolutions point at lockfiles, and both must resolve to
  // entities the model contains. Validating that here is what makes the dependency
  // query layer's answers traceable — an unverifiable edge would let a rule cite
  // provenance that does not exist.
  const manifestIds = new Set(model.manifests.entries.map((manifest) => manifest.id));
  const ecosystemIds = new Set(model.manifests.ecosystems.map((ecosystem) => ecosystem.id));
  const scopes = Object.values(DEPENDENCY_SCOPES);
  const specKinds = Object.values(DEPENDENCY_SPEC_KINDS);

  for (const dependency of model.dependencies.entries ?? []) {
    const at = `dependencies[${dependency?.id}]`;
    if (!isNonEmptyString(dependency?.ecosystem)) {
      fail(at, "must record the ecosystem it belongs to");
      continue;
    }
    if (!ecosystemIds.has(dependency.ecosystemId)) {
      fail(at, "must belong to an ecosystem the scan observed");
    }
    if (dependency.path !== null) {
      fail(at, "must not carry a path: a dependency is identified by (ecosystem, name)");
    }
    if (dependency.id !== `${ENTITY_KINDS.DEPENDENCY}:${dependency.ecosystem}:${dependency.name}`) {
      fail(at, "id must be derived from the ecosystem and the name");
    }

    let facts = 0;
    for (const declaration of dependency.declarations ?? []) {
      facts += 1;
      if (!manifestIds.has(declaration.manifestId)) {
        fail(at, "a declaration must cite a manifest the model contains");
      }
      if (!scopes.includes(declaration.scope)) {
        fail(at, `declaration scope must be one of: ${scopes.join(", ")}`);
      }
      if (!specKinds.includes(declaration.specKind)) {
        fail(at, `declaration specKind must be one of: ${specKinds.join(", ")}`);
      }
      if (typeof declaration.direct !== "boolean") {
        fail(at, "declaration direct must be a boolean");
      }
    }
    for (const resolution of dependency.resolutions ?? []) {
      facts += 1;
      if (!manifestIds.has(resolution.manifestId)) {
        fail(at, "a resolution must cite a lockfile the model contains");
      }
    }
    for (const path of dependency.referencedBy ?? []) {
      facts += 1;
      if (typeof path !== "string" || !manifestIds.has(`${ENTITY_KINDS.MANIFEST}:${path}`)) {
        fail(at, "a referencing edge must name a manifest the model contains");
      }
    }
    if (facts === 0) {
      fail(at, "must be declared, resolved or named by an edge somewhere in the model");
    }

    const declared = (dependency.declarations ?? []).some((entry) => entry.direct === true);
    if (dependency.direct !== declared) {
      fail(at, "direct must agree with the declarations it carries");
    }
    const resolved = (dependency.resolutions ?? []).length > 0;
    if (dependency.resolved !== resolved) {
      fail(at, "resolved must agree with the resolutions it carries");
    }
  }

  for (const source of model.dependencies.sources ?? []) {
    if (!manifestIds.has(`${ENTITY_KINDS.MANIFEST}:${source.path}`)) {
      fail(`dependencies.sources[${source.path}]`, "must name a manifest the model contains");
    }
    if (!DEPENDENCY_SOURCE_STATUSES.includes(source.status)) {
      fail(`dependencies.sources[${source.path}].status`, "must be a documented source status");
    }
    if (!isNonEmptyString(source.evidenceId)) {
      fail(`dependencies.sources[${source.path}]`, "must cite the observation it rests on");
    }
    if (typeof source.truncated !== "boolean") {
      fail(`dependencies.sources[${source.path}].truncated`, "must be a boolean");
    }
  }

  // The coverage statement may not claim more than the sources support: `complete`
  // means every dependency source in the repository was read and interpreted, which
  // is exactly what `scan.complete` plus a clean source list means.
  if (model.dependencies.coverage?.complete === true) {
    const clean = (model.dependencies.sources ?? []).every(
      (source) => source.status === "parsed" && (source.problems ?? []).length === 0,
    );
    if (!clean) {
      fail(
        "dependencies.coverage.complete",
        "cannot be true unless every dependency source was parsed without problems",
      );
    }
  }

  // ── Provenance ────────────────────────────────────────────────────────────
  const evidenceIds = new Set();
  for (const record of model.evidence) {
    if (!isPlainObject(record) || !isNonEmptyString(record.id)) {
      fail("evidence", "every observation must carry an id");
      continue;
    }
    if (evidenceIds.has(record.id)) fail("evidence", `duplicate observation id "${record.id}"`);
    evidenceIds.add(record.id);
    if (!("path" in (record.location ?? {}))) {
      fail(`evidence[${record.id}]`, "every observation must locate a repository-relative path");
    }
  }
  for (const { label, entity } of descriptors) {
    for (const id of entity.evidenceIds ?? []) {
      if (!evidenceIds.has(id)) {
        fail(`${label}[${entity.id}]`, `references unknown observation "${id}"`);
      }
    }
  }

  // ── Relationships ─────────────────────────────────────────────────────────
  const known = new Set([...entityIds, repositoryId]);
  for (const relationship of model.relationships) {
    if (!isPlainObject(relationship)) {
      fail("relationships", "every relationship must be a plain object");
      continue;
    }
    if (!GRAPH_RELATIONSHIP_TYPES.includes(relationship.type)) {
      fail("relationships", `unknown relationship type "${String(relationship.type)}"`);
    }
    if (!known.has(relationship.from)) {
      fail("relationships", `unknown relationship source "${String(relationship.from)}"`);
    }
    if (!known.has(relationship.to)) {
      fail("relationships", `unknown relationship target "${String(relationship.to)}"`);
    }
  }
  // Every entity must be connected to the repository, so a consumer can always
  // reach it without scanning the whole edge list. The containment set is built
  // once; testing it per entity would make validation quadratic.
  const contained = new Set(
    (model.indexes.relationshipsByFrom?.[repositoryId] ?? [])
      .map((position) => model.relationships[position])
      .filter((relationship) => relationship?.type === RELATIONSHIP_TYPES.CONTAINS)
      .map((relationship) => relationship.to),
  );
  for (const id of entityIds) {
    if (!contained.has(id)) fail("relationships", `"${id}" is not connected to the repository`);
  }

  // ── Dependency graph (Phase 14) ───────────────────────────────────────────
  //
  // The graph is a projection of the dependency entities and the `depends-on`
  // relationships above, so validating it here is what stops it from becoming a
  // second, disagreeing source of truth: every node must be a dependency entity the
  // model contains, every edge must be a relationship the model already states (in
  // both directions — no invented edge, no silently dropped one), and every edge's
  // provenance must resolve to real observations and real manifests.
  const graph = model.dependencies.graph;
  if (!isPlainObject(graph)) {
    fail("dependencies.graph", "must be a plain object");
  } else {
    const dependencyById = new Map(
      (model.dependencies.entries ?? []).map((dependency) => [dependency.id, dependency]),
    );

    if (!isNonEmptyString(graph.version)) {
      fail("dependencies.graph.version", "must be a non-empty string");
    }
    if (!DEPENDENCY_GRAPH_STATE_VALUES.includes(graph.state)) {
      fail(
        "dependencies.graph.state",
        `must be one of: ${DEPENDENCY_GRAPH_STATE_VALUES.join(", ")}`,
      );
    }
    if (typeof graph.established !== "boolean") {
      fail("dependencies.graph.established", "must be a boolean");
    } else if (
      graph.established !==
      (graph.state !== DEPENDENCY_GRAPH_STATES.UNKNOWN &&
        graph.state !== DEPENDENCY_GRAPH_STATES.UNSUPPORTED)
    ) {
      fail("dependencies.graph.established", "must agree with the state it reports");
    }

    const nodeIds = new Set();
    if (!Array.isArray(graph.nodes)) {
      fail("dependencies.graph.nodes", "must be an array");
    } else if (graph.nodes.length > DEPENDENCY_GRAPH_LIMITS.MAX_NODES) {
      fail("dependencies.graph.nodes", "must stay within the graph node bound");
    } else {
      graph.nodes.forEach((node, index) => {
        const at = `dependencies.graph.nodes[${index}]`;
        if (!isPlainObject(node)) {
          fail(at, "must be a plain object");
          return;
        }
        if (typeof node.id !== "string" || !dependencyById.has(node.id)) {
          fail(at, "must name a dependency entity the model contains");
          return;
        }
        if (nodeIds.has(node.id)) fail(at, `duplicate graph node "${node.id}"`);
        nodeIds.add(node.id);
        if (node.id !== `${ENTITY_KINDS.DEPENDENCY}:${node.ecosystem}:${node.name}`) {
          fail(at, "id must be derived from the ecosystem and the name");
        }
        const entity = dependencyById.get(node.id);
        for (const field of ["declared", "direct", "resolved"]) {
          if (typeof node[field] !== "boolean") {
            fail(at, `${field} must be a boolean`);
            continue;
          }
          if (node[field] !== (entity[field] === true)) {
            fail(at, `${field} must agree with the dependency entity it names`);
          }
        }
      });
      // Deterministic ordering is part of the contract, not a nicety: two builds of
      // one repository state must produce byte-identical graphs.
      for (let next = 1; next < graph.nodes.length; next += 1) {
        const previous = graph.nodes[next - 1]?.id;
        const current = graph.nodes[next]?.id;
        if (typeof previous === "string" && typeof current === "string" && !(previous < current)) {
          fail(`dependencies.graph.nodes[${next}]`, "nodes must be sorted by id and unique");
        }
      }
      if (nodeIds.size !== dependencyById.size) {
        fail(
          "dependencies.graph.nodes",
          "every dependency entity must project to exactly one node",
        );
      }
    }

    const edgeKeys = new Set();
    if (!Array.isArray(graph.edges)) {
      fail("dependencies.graph.edges", "must be an array");
    } else if (graph.edges.length > DEPENDENCY_GRAPH_LIMITS.MAX_EDGES) {
      fail("dependencies.graph.edges", "must stay within the graph edge bound");
    } else {
      graph.edges.forEach((edge, index) => {
        const at = `dependencies.graph.edges[${index}]`;
        if (!isPlainObject(edge)) {
          fail(at, "must be a plain object");
          return;
        }
        if (!DEPENDENCY_GRAPH_EDGE_TYPE_VALUES.includes(edge.type)) {
          fail(at, `type must be one of: ${DEPENDENCY_GRAPH_EDGE_TYPE_VALUES.join(", ")}`);
        }
        for (const endpoint of ["from", "to"]) {
          if (!nodeIds.has(edge[endpoint])) {
            fail(at, `${endpoint} must name a graph node`);
          }
        }
        const key = `${edge.from}\u0000${edge.type}\u0000${edge.to}`;
        if (edgeKeys.has(key)) fail(at, "must not repeat an edge the graph already states");
        edgeKeys.add(key);

        if (!Array.isArray(edge.evidenceIds) || edge.evidenceIds.length === 0) {
          fail(at, "must cite at least one observation");
        } else {
          for (const id of edge.evidenceIds) {
            if (!evidenceIds.has(id)) fail(at, `references unknown observation "${String(id)}"`);
          }
        }
        if (!Array.isArray(edge.manifestPaths) || edge.manifestPaths.length === 0) {
          fail(at, "must name the lockfile that established it");
        } else {
          for (const path of edge.manifestPaths) {
            if (
              typeof path !== "string" ||
              path.startsWith("/") ||
              !manifestIds.has(`${ENTITY_KINDS.MANIFEST}:${path}`)
            ) {
              fail(at, "provenance must name a manifest the model contains");
            }
          }
        }
      });
      for (let next = 1; next < graph.edges.length; next += 1) {
        const previous = graph.edges[next - 1];
        const current = graph.edges[next];
        if (
          isPlainObject(previous) &&
          isPlainObject(current) &&
          !(
            previous.from < current.from ||
            (previous.from === current.from && previous.to < current.to)
          )
        ) {
          fail(`dependencies.graph.edges[${next}]`, "edges must be sorted by endpoints, unique");
        }
      }
    }

    // The two views of one fact must agree exactly.
    const relationshipEdges = new Set(
      (model.relationships ?? [])
        .filter((relationship) => relationship?.type === RELATIONSHIP_TYPES.DEPENDS_ON)
        .map(
          (relationship) =>
            `${relationship.from}\u0000${relationship.type}\u0000${relationship.to}`,
        ),
    );
    for (const key of edgeKeys) {
      if (!relationshipEdges.has(key)) {
        fail("dependencies.graph.edges", "an edge must be a depends-on relationship the model states");
      }
    }
    for (const key of relationshipEdges) {
      if (!edgeKeys.has(key)) {
        fail("dependencies.graph.edges", "a depends-on relationship must appear in the graph");
      }
    }

    const graphCoverage = graph.coverage;
    if (!isPlainObject(graphCoverage)) {
      fail("dependencies.graph.coverage", "must be a plain object");
    } else {
      if (graphCoverage.state !== graph.state) {
        fail("dependencies.graph.coverage.state", "must agree with the graph state");
      }
      if (graphCoverage.nodes !== nodeIds.size) {
        fail("dependencies.graph.coverage.nodes", "must count the nodes the graph contains");
      }
      if (graphCoverage.edges !== edgeKeys.size) {
        fail("dependencies.graph.coverage.edges", "must count the edges the graph contains");
      }
      if (!Array.isArray(graphCoverage.unestablishedSources)) {
        fail("dependencies.graph.coverage.unestablishedSources", "must be an array");
      }
      const versionInstances = graphCoverage.versionInstances;
      if (!isPlainObject(versionInstances)) {
        fail("dependencies.graph.coverage.versionInstances", "must state the identity limitation");
      } else if (!Array.isArray(versionInstances.packages)) {
        fail("dependencies.graph.coverage.versionInstances.packages", "must be an array");
      } else if (
        versionInstances.packages.length > DEPENDENCY_GRAPH_LIMITS.MAX_AMBIGUOUS_PACKAGES
      ) {
        fail(
          "dependencies.graph.coverage.versionInstances.packages",
          "must stay within the graph bound",
        );
      }
    }
  }

  // ── Architecture graph (Phase 15) ─────────────────────────────────────────
  //
  // Another projection of the same model, so it is validated the same way the
  // dependency graph is: every node must be an entity the model contains (or the
  // repository node), every edge must re-state a fact the model already established
  // — a `contains`/`parent`/`located_in` containment, a `declares-dependency`, a
  // `framework` relationship, or a container declaration observation — and every
  // edge's provenance must resolve to real observations. An edge the model does not
  // support is rejected here rather than becoming a finding.
  const architectureGraph = model.architecture?.graph;
  if (!isPlainObject(architectureGraph)) {
    fail("architecture.graph", "must be a plain object");
  } else {
    if (!isNonEmptyString(architectureGraph.version)) {
      fail("architecture.graph.version", "must be a non-empty string");
    }
    if (!ARCHITECTURE_GRAPH_STATE_VALUES.includes(architectureGraph.state)) {
      fail(
        "architecture.graph.state",
        `must be one of: ${ARCHITECTURE_GRAPH_STATE_VALUES.join(", ")}`,
      );
    }
    if (typeof architectureGraph.established !== "boolean") {
      fail("architecture.graph.established", "must be a boolean");
    } else if (architectureGraph.established !== isEstablishedState(architectureGraph.state)) {
      fail("architecture.graph.established", "must agree with the state it reports");
    }

    const architectureNodeIds = new Set();
    const architectureNodeById = new Map();
    if (!Array.isArray(architectureGraph.nodes)) {
      fail("architecture.graph.nodes", "must be an array");
    } else if (architectureGraph.nodes.length > ARCHITECTURE_GRAPH_LIMITS.MAX_NODES) {
      fail("architecture.graph.nodes", "must stay within the graph node bound");
    } else {
      architectureGraph.nodes.forEach((node, index) => {
        const at = `architecture.graph.nodes[${index}]`;
        if (!isPlainObject(node)) {
          fail(at, "must be a plain object");
          return;
        }
        if (typeof node.id !== "string" || node.id.trim() === "") {
          fail(at, "must carry a non-empty id");
          return;
        }
        if (architectureNodeIds.has(node.id)) fail(at, `duplicate graph node "${node.id}"`);
        architectureNodeIds.add(node.id);
        architectureNodeById.set(node.id, node);

        if (node.id === repositoryId) {
          if (node.kind !== REPOSITORY_NODE_KIND) {
            fail(at, `the repository node must have kind "${REPOSITORY_NODE_KIND}"`);
          }
          if (node.path !== null) fail(at, "the repository node must not carry a path");
          return;
        }
        if (!ARCHITECTURE_NODE_KINDS.includes(node.kind)) {
          fail(at, `kind must be one of: ${ARCHITECTURE_NODE_KINDS.join(", ")}`);
        }
        const entity = entityById.get(node.id);
        if (entity === undefined) {
          fail(at, "must name an entity the model contains");
          return;
        }
        if (entity.kind !== node.kind) {
          fail(at, "kind must agree with the entity it names");
        }
        if (node.path !== null) {
          try {
            requireRepositoryRelativePath(node.path, `${at}.path`);
          } catch (error) {
            fail(`${at}.path`, "must be a canonical repository-relative path");
          }
          if (node.path !== entity.path) {
            fail(at, "path must agree with the entity it names");
          }
        }
      });
      // Deterministic ordering is part of the contract, not a nicety: two builds of
      // one repository state must produce byte-identical graphs.
      for (let next = 1; next < architectureGraph.nodes.length; next += 1) {
        const previous = architectureGraph.nodes[next - 1]?.id;
        const current = architectureGraph.nodes[next]?.id;
        if (typeof previous === "string" && typeof current === "string" && !(previous < current)) {
          fail(`architecture.graph.nodes[${next}]`, "nodes must be sorted by id and unique");
        }
      }
      for (const { label, entity } of descriptors) {
        if (!ARCHITECTURE_NODE_KINDS.includes(entity.kind)) continue;
        if (!architectureNodeIds.has(entity.id)) {
          fail(
            `architecture.graph.nodes`,
            `${label}[${entity.id}] must project to a graph node`,
          );
        }
      }
    }

    // The container declarations the model recorded, by observation id. Used to check
    // that a container edge is the *same* declaration it cites: an edge whose
    // endpoints disagree with the observation behind it (a different Dockerfile, a
    // different Compose file, a different context) is provenance that does not exist.
    const buildContextObservations = new Map();
    for (const record of model.evidence) {
      if (record?.data?.signal !== BUILD_CONTEXT_SIGNAL) continue;
      buildContextObservations.set(record.id, {
        path: record.location?.path ?? null,
        source: record.data.source ?? null,
        contextPath: record.data.contextPath ?? null,
      });
    }

    const architectureEdgeKeys = new Set();
    if (!Array.isArray(architectureGraph.edges)) {
      fail("architecture.graph.edges", "must be an array");
    } else if (architectureGraph.edges.length > ARCHITECTURE_GRAPH_LIMITS.MAX_EDGES) {
      fail("architecture.graph.edges", "must stay within the graph edge bound");
    } else {
      const relationshipKeys = new Set(
        (model.relationships ?? []).map(
          (relationship) =>
            `${relationship.from}\u0000${relationship.type}\u0000${relationship.to}`,
        ),
      );
      architectureGraph.edges.forEach((edge, index) => {
        const at = `architecture.graph.edges[${index}]`;
        if (!isPlainObject(edge)) {
          fail(at, "must be a plain object");
          return;
        }
        if (!ARCHITECTURE_EDGE_TYPE_VALUES.includes(edge.type)) {
          fail(at, `type must be one of: ${ARCHITECTURE_EDGE_TYPE_VALUES.join(", ")}`);
        }
        for (const endpoint of ["from", "to"]) {
          if (!architectureNodeIds.has(edge[endpoint])) {
            fail(at, `${endpoint} must name a graph node`);
          }
        }
        const key = `${edge.from}\u0000${edge.to}\u0000${edge.type}`;
        if (architectureEdgeKeys.has(key)) fail(at, "must not repeat an edge the graph already states");
        architectureEdgeKeys.add(key);

        if (!Array.isArray(edge.evidenceIds) || edge.evidenceIds.length === 0) {
          fail(at, "must cite at least one observation");
        } else {
          for (const id of edge.evidenceIds) {
            if (!evidenceIds.has(id)) fail(at, `references unknown observation "${String(id)}"`);
          }
        }
        if (!Array.isArray(edge.sourcePaths) || edge.sourcePaths.length === 0) {
          fail(at, "must name the path whose observation stated it");
        } else {
          for (const path of edge.sourcePaths) {
            if (typeof path !== "string" || path.startsWith("/")) {
              fail(at, "provenance paths must be repository-relative");
            }
          }
        }
        if (!Array.isArray(edge.services)) {
          fail(at, "services must be an array (empty for a non-container edge)");
        }

        // Every edge must re-state a fact the model already established. The three
        // containment forms are one fact stated in one direction here; the container
        // forms are established by an observation, because the model has no
        // relationship for build wiring.
        switch (edge.type) {
          case ARCHITECTURE_EDGE_TYPES.CONTAINS: {
            const forms = [
              `${edge.from}\u0000contains\u0000${edge.to}`,
              `${edge.to}\u0000located_in\u0000${edge.from}`,
              `${edge.to}\u0000parent\u0000${edge.from}`,
            ];
            if (!forms.some((form) => relationshipKeys.has(form))) {
              fail(at, "a containment edge must be containment the model already states");
            }
            break;
          }
          case ARCHITECTURE_EDGE_TYPES.DECLARES_DEPENDENCY:
          case ARCHITECTURE_EDGE_TYPES.FRAMEWORK: {
            const form = `${edge.from}\u0000${edge.type}\u0000${edge.to}`;
            if (!relationshipKeys.has(form)) {
              fail(at, `a ${edge.type} edge must be a relationship the model already states`);
            }
            break;
          }
          case ARCHITECTURE_EDGE_TYPES.DECLARES_BUILD:
          case ARCHITECTURE_EDGE_TYPES.BUILD_CONTEXT: {
            const declares = edge.type === ARCHITECTURE_EDGE_TYPES.DECLARES_BUILD;
            // The declaration's Dockerfile is the edge's `to` when a Compose file
            // declares a build, and its `from` when the Dockerfile is placed in its
            // context root.
            const dockerfilePath = declares
              ? (architectureNodeById.get(edge.to)?.path ?? null)
              : (architectureNodeById.get(edge.from)?.path ?? null);
            const sourcePath = declares ? (architectureNodeById.get(edge.from)?.path ?? null) : null;
            const contextPath = declares
              ? undefined
              : edge.to === repositoryId
                ? null
                : (architectureNodeById.get(edge.to)?.path ?? undefined);

            const matched = (edge.evidenceIds ?? []).some((id) => {
              const observation = buildContextObservations.get(id);
              if (observation === undefined) return false;
              if (observation.path !== dockerfilePath) return false;
              return declares
                ? observation.source === sourcePath
                : observation.contextPath === contextPath;
            });
            if (!matched) {
              fail(at, "must cite the container declaration that established exactly it");
            }
            break;
          }
          default:
            break;
        }
      });
      for (let next = 1; next < architectureGraph.edges.length; next += 1) {
        const previous = architectureGraph.edges[next - 1];
        const current = architectureGraph.edges[next];
        if (!isPlainObject(previous) || !isPlainObject(current)) continue;
        const orderedBefore =
          previous.from < current.from ||
          (previous.from === current.from &&
            (previous.to < current.to ||
              (previous.to === current.to && previous.type < current.type)));
        if (!orderedBefore) {
          fail(`architecture.graph.edges[${next}]`, "edges must be sorted by endpoints, unique");
        }
      }
    }

    if (!Array.isArray(architectureGraph.buildContexts)) {
      fail("architecture.graph.buildContexts", "must be an array");
    } else if (
      architectureGraph.buildContexts.length > ARCHITECTURE_GRAPH_LIMITS.MAX_BUILD_DECLARATIONS
    ) {
      fail("architecture.graph.buildContexts", "must stay within the graph bound");
    } else {
      architectureGraph.buildContexts.forEach((record, index) => {
        const at = `architecture.graph.buildContexts[${index}]`;
        if (!isPlainObject(record)) {
          fail(at, "must be a plain object");
          return;
        }
        for (const field of ["source", "service", "dockerfile"]) {
          if (!isNonEmptyString(record[field])) fail(at, `${field} must be a non-empty string`);
        }
        for (const field of ["source", "dockerfile"]) {
          if (typeof record[field] === "string" && record[field].startsWith("/")) {
            fail(at, `${field} must be repository-relative`);
          }
        }
        if (record.context !== null && !isNonEmptyString(record.context)) {
          fail(at, "context must be null (the repository root) or a repository-relative path");
        }
        if (typeof record.context === "string" && record.context.startsWith("/")) {
          fail(at, "context must be repository-relative");
        }
        if (!buildContextObservations.has(record.evidenceId)) {
          fail(at, "must cite the observation it rests on");
        }
      });
      for (let next = 1; next < architectureGraph.buildContexts.length; next += 1) {
        const previous = architectureGraph.buildContexts[next - 1];
        const current = architectureGraph.buildContexts[next];
        if (!isPlainObject(previous) || !isPlainObject(current)) continue;
        const previousKey = `${previous.source}\u0000${previous.service}\u0000${previous.dockerfile}`;
        const currentKey = `${current.source}\u0000${current.service}\u0000${current.dockerfile}`;
        if (!(previousKey < currentKey)) {
          fail(
            `architecture.graph.buildContexts[${next}]`,
            "declarations must be sorted by source, service and Dockerfile",
          );
        }
      }
    }

    const architectureCoverage = architectureGraph.coverage;
    if (!isPlainObject(architectureCoverage)) {
      fail("architecture.graph.coverage", "must be a plain object");
    } else {
      if (architectureCoverage.state !== architectureGraph.state) {
        fail("architecture.graph.coverage.state", "must agree with the graph state");
      }
      if (architectureCoverage.established !== architectureGraph.established) {
        fail("architecture.graph.coverage.established", "must agree with the graph state");
      }
      if (architectureCoverage.nodes !== architectureNodeIds.size) {
        fail("architecture.graph.coverage.nodes", "must count the nodes the graph contains");
      }
      if (architectureCoverage.edges !== architectureEdgeKeys.size) {
        fail("architecture.graph.coverage.edges", "must count the edges the graph contains");
      }
      if (!Array.isArray(architectureCoverage.unestablishedSources)) {
        fail("architecture.graph.coverage.unestablishedSources", "must be an array");
      } else if (
        architectureCoverage.unestablishedSources.length >
        ARCHITECTURE_GRAPH_LIMITS.MAX_UNESTABLISHED_SOURCES
      ) {
        fail(
          "architecture.graph.coverage.unestablishedSources",
          "must stay within the graph bound",
        );
      }
      // The state may not claim more than the scan and the sources support.
      if (architectureCoverage.state === ARCHITECTURE_GRAPH_STATES.COMPLETE) {
        if (architectureCoverage.complete !== true || architectureCoverage.truncated === true) {
          fail(
            "architecture.graph.coverage.state",
            "cannot be complete unless the scan covered the repository",
          );
        }
        if ((architectureCoverage.unestablishedSources ?? []).length > 0) {
          fail(
            "architecture.graph.coverage.state",
            "cannot be complete while an architecture source is unestablished",
          );
        }
      }
    }
  }

  // ── Import graph (Phase 16) ───────────────────────────────────────────────
  //
  // The graph's nodes must be files the model contains, its edges must join two of
  // those nodes and cite the *importing* file's own observation, and an unresolved
  // reference must be a reference that produced no edge. That last check is what
  // keeps the two halves of the projection from contradicting each other: a
  // specifier cannot be both "we established where this points" and "we could not
  // establish where this points".
  {
    const importsArea = model.imports;
    if (!isPlainObject(importsArea)) {
      fail("imports", "must be a plain object");
    } else {
      const fileIds = new Set(model.files.entries.map((file) => file.id));
      const evidenceById = new Map(
        (Array.isArray(model.evidence) ? model.evidence : []).map((record) => [record?.id, record]),
      );
      const sourceByPath = new Map();
      const entries = importsArea.entries;

      if (typeof importsArea.detected !== "boolean") {
        fail("imports.detected", "must be a boolean");
      }
      if (!Array.isArray(entries)) {
        fail("imports.entries", "must be an array");
      } else {
        for (const source of entries) {
          const at = `imports.entries[${source?.path}]`;
          if (!isPlainObject(source)) {
            fail("imports.entries", "every module source must be a plain object");
            continue;
          }
          if (!fileIds.has(`${ENTITY_KINDS.FILE}:${source.path}`)) {
            fail(at, "must name a file the model contains");
            continue;
          }
          if (sourceByPath.has(source.path)) fail(at, "must describe each module source once");
          sourceByPath.set(source.path, source);

          if (!IMPORT_MODULE_EXTENSIONS.includes(source.extension)) {
            fail(at, "must carry a module source extension");
          }
          if (!entityIds.has(source.languageId)) {
            fail(at, "language must name a language the model contains");
          }
          if (!IMPORT_SOURCE_STATUS_VALUES.includes(source.status)) {
            fail(at, `status must be one of: ${IMPORT_SOURCE_STATUS_VALUES.join(", ")}`);
          }
          if (source.reason !== null && !IMPORT_SOURCE_REASONS.includes(source.reason)) {
            fail(at, `reason must be null or one of: ${IMPORT_SOURCE_REASONS.join(", ")}`);
          }
          if (source.status === "parsed" && source.reason !== null) {
            fail(at, "a parsed module source must not carry an acquisition reason");
          }
          if (source.status !== "parsed" && source.reason === null) {
            fail(at, "a module source that was not parsed must record why");
          }
          for (const problem of source.problems ?? []) {
            if (!IMPORT_PROBLEM_REASONS.includes(problem)) {
              fail(at, `unknown import problem "${String(problem)}"`);
            }
          }
          if (!Array.isArray(source.references)) {
            fail(at, "must carry a references array");
          } else {
            for (const reference of source.references) {
              if (!isPlainObject(reference) || !IMPORT_SPECIFIER_KINDS.includes(reference.kind)) {
                fail(at, "references must carry a documented module reference kind");
                continue;
              }
              // Bounded, printable, non-empty text: the same projection the model
              // applies at build time, enforced here as a contract so a tampered
              // model cannot smuggle a control character or an unbounded string into
              // a path candidate or a consumer's output.
              if (projectModuleSpecifier(reference.specifier) === null) {
                fail(at, "references must carry bounded, printable specifier text");
              }
            }
            if (source.status !== "parsed" && source.references.length > 0) {
              fail(at, "a module source that was not parsed states no reference");
            }
          }
          if (!evidenceIds.has(source.evidenceId)) {
            fail(at, "must cite the observation that recorded it");
          }
        }
        for (let next = 1; next < entries.length; next += 1) {
          if (entries[next - 1]?.path >= entries[next]?.path) {
            fail(`imports.entries[${next}]`, "must be sorted by path and unique");
            break;
          }
        }
      }
      if (importsArea.count !== (Array.isArray(entries) ? entries.length : 0)) {
        fail("imports.count", "must count the module sources the area carries");
      }

      const graph = importsArea.graph;
      if (!isPlainObject(graph)) {
        fail("imports.graph", "must be a plain object");
      } else {
        const nodeIds = new Set();
        if (!isNonEmptyString(graph.version)) {
          fail("imports.graph.version", "must be a non-empty string");
        }
        if (!IMPORT_GRAPH_STATE_VALUES.includes(graph.state)) {
          fail("imports.graph.state", `must be one of: ${IMPORT_GRAPH_STATE_VALUES.join(", ")}`);
        }
        if (typeof graph.established !== "boolean") {
          fail("imports.graph.established", "must be a boolean");
        } else if (graph.established !== isImportGraphEstablished(graph.state)) {
          fail("imports.graph.established", "must agree with the state it reports");
        }

        if (!Array.isArray(graph.nodes)) {
          fail("imports.graph.nodes", "must be an array");
        } else if (graph.nodes.length > IMPORT_GRAPH_LIMITS.MAX_NODES) {
          fail("imports.graph.nodes", "must stay within the graph node bound");
        } else {
          graph.nodes.forEach((node, index) => {
            const at = `imports.graph.nodes[${index}]`;
            if (!isPlainObject(node)) {
              fail(at, "must be a plain object");
              return;
            }
            if (typeof node.id !== "string" || !fileIds.has(node.id)) {
              fail(at, "must name a file entity the model contains");
              return;
            }
            if (nodeIds.has(node.id)) fail(at, `duplicate graph node "${node.id}"`);
            nodeIds.add(node.id);
            const file = entityById.get(node.id);
            if (node.path !== file.path) fail(at, "path must agree with the file it names");
            if (node.module !== IMPORT_MODULE_EXTENSIONS.includes(file.extension)) {
              fail(at, "module must agree with the file's extension");
            }
            const expectedStatus = sourceByPath.get(node.path)?.status ?? null;
            if (node.status !== expectedStatus) {
              fail(at, "status must agree with the module source record it names");
            }
          });
          for (let next = 1; next < graph.nodes.length; next += 1) {
            const previous = graph.nodes[next - 1]?.id;
            const current = graph.nodes[next]?.id;
            if (typeof previous === "string" && typeof current === "string" && !(previous < current)) {
              fail(`imports.graph.nodes[${next}]`, "nodes must be sorted by id and unique");
            }
          }
          // Every module source the acquisition read is a node of this graph: a source
          // that vanished from the node set would silently remove a file from the
          // graph while its references stayed in the edge or unresolved list.
          for (const source of sourceByPath.values()) {
            if (!nodeIds.has(`${ENTITY_KINDS.FILE}:${source.path}`)) {
              fail(`imports.graph.nodes`, `must contain the module source "${source.path}"`);
              break;
            }
          }
        }

        const edgeKeys = new Set();
        const statedSpecifiers = new Set();
        if (!Array.isArray(graph.edges)) {
          fail("imports.graph.edges", "must be an array");
        } else if (graph.edges.length > IMPORT_GRAPH_LIMITS.MAX_EDGES) {
          fail("imports.graph.edges", "must stay within the graph edge bound");
        } else {
          graph.edges.forEach((edge, index) => {
            const at = `imports.graph.edges[${index}]`;
            if (!isPlainObject(edge)) {
              fail(at, "must be a plain object");
              return;
            }
            if (!IMPORT_GRAPH_EDGE_TYPE_VALUES.includes(edge.type)) {
              fail(at, `type must be one of: ${IMPORT_GRAPH_EDGE_TYPE_VALUES.join(", ")}`);
            }
            for (const endpoint of ["from", "to"]) {
              if (!nodeIds.has(edge[endpoint])) {
                fail(at, `${endpoint} must name a graph node`);
              }
            }
            const key = `${edge.from}\u0000${edge.type}\u0000${edge.to}`;
            if (edgeKeys.has(key)) fail(at, "must not repeat an edge the graph already states");
            edgeKeys.add(key);

            if (!Array.isArray(edge.specifiers) || edge.specifiers.length === 0) {
              fail(at, "must record the specifier(s) that established it");
            } else {
              for (const specifier of edge.specifiers) {
                if (typeof specifier !== "string" || specifier === "") {
                  fail(at, "specifiers must be non-empty text");
                }
                if (nodeIds.has(edge.from)) {
                  statedSpecifiers.add(`${edge.from}\u0000${specifier}`);
                }
              }
              for (let next = 1; next < edge.specifiers.length; next += 1) {
                if (edge.specifiers[next - 1] >= edge.specifiers[next]) {
                  fail(at, "specifiers must be sorted and unique");
                  break;
                }
              }
            }
            if (!Array.isArray(edge.kinds) || edge.kinds.length === 0) {
              fail(at, "must record how the reference was declared");
            } else {
              for (const kind of edge.kinds) {
                if (!IMPORT_SPECIFIER_KINDS.includes(kind)) {
                  fail(at, `unknown module reference kind "${String(kind)}"`);
                }
              }
            }
            if (!Array.isArray(edge.evidenceIds) || edge.evidenceIds.length === 0) {
              fail(at, "must cite at least one observation");
            } else {
              const ownerPath = entityById.get(edge.from)?.path;
              for (const id of edge.evidenceIds) {
                if (!evidenceIds.has(id)) {
                  fail(at, `references unknown observation "${String(id)}"`);
                  continue;
                }
                // Provenance must be the *importing* file's own observation. Any
                // other file's observation would attribute a reference to the wrong
                // source — a finding that points at a file that never stated it.
                if (evidenceById.get(id)?.location?.path !== ownerPath) {
                  fail(at, "must cite the importing file's own observation");
                }
              }
            }
            // Provenance must be the importing file itself. An edge citing another
            // file's observation would be provenance that does not exist.
            if (!Array.isArray(edge.sourcePaths) || edge.sourcePaths.length === 0) {
              fail(at, "must name the file whose observation stated it");
            } else {
              for (const path of edge.sourcePaths) {
                if (path !== entityById.get(edge.from)?.path) {
                  fail(at, "provenance must be the importing file");
                }
                if (!fileIds.has(`${ENTITY_KINDS.FILE}:${path}`)) {
                  fail(at, "provenance must name a file the model contains");
                }
              }
            }
          });
          for (let next = 1; next < graph.edges.length; next += 1) {
            const previous = graph.edges[next - 1];
            const current = graph.edges[next];
            if (
              isPlainObject(previous) &&
              isPlainObject(current) &&
              !(
                previous.from < current.from ||
                (previous.from === current.from &&
                  (previous.to < current.to ||
                    (previous.to === current.to && previous.type < current.type)))
              )
            ) {
              fail(`imports.graph.edges[${next}]`, "edges must be sorted by (from, to, type)");
            }
          }
        }

        if (!Array.isArray(graph.unresolved)) {
          fail("imports.graph.unresolved", "must be an array");
        } else if (graph.unresolved.length > IMPORT_GRAPH_LIMITS.MAX_UNRESOLVED) {
          fail("imports.graph.unresolved", "must stay within the unresolved bound");
        } else {
          graph.unresolved.forEach((record, index) => {
            const at = `imports.graph.unresolved[${index}]`;
            if (!isPlainObject(record)) {
              fail(at, "must be a plain object");
              return;
            }
            if (!nodeIds.has(`${ENTITY_KINDS.FILE}:${record.path}`)) {
              fail(at, "must name a graph node");
            }
            if (sourceByPath.get(record.path)?.status !== "parsed") {
              fail(at, "must belong to a module source that was parsed");
            }
            if (typeof record.specifier !== "string" || record.specifier === "") {
              fail(at, "must carry the specifier that was written");
            }
            if (!IMPORT_SPECIFIER_KINDS.includes(record.kind)) {
              fail(at, "kind must be a documented module reference kind");
            }
            if (!UNRESOLVED_REFERENCE_REASON_VALUES.includes(record.reason)) {
              fail(at, `reason must be one of: ${UNRESOLVED_REFERENCE_REASON_VALUES.join(", ")}`);
            }
            if (!evidenceIds.has(record.evidenceId)) {
              fail(at, "must cite the observation that recorded it");
            }
            // A specifier cannot be both resolved and unresolved for one file.
            if (statedSpecifiers.has(`${ENTITY_KINDS.FILE}:${record.path}\u0000${record.specifier}`)) {
              fail(at, "must not state a reference the graph established as an edge");
            }
          });
          for (let next = 1; next < graph.unresolved.length; next += 1) {
            const previous = graph.unresolved[next - 1];
            const current = graph.unresolved[next];
            if (isPlainObject(previous) && isPlainObject(current)) {
              const key = (record) => `${record.path}\u0000${record.specifier}\u0000${record.kind}`;
              if (key(previous) > key(current)) {
                fail(`imports.graph.unresolved[${next}]`, "must be sorted deterministically");
              }
            }
          }
        }

        const graphCoverage = graph.coverage;
        if (!isPlainObject(graphCoverage)) {
          fail("imports.graph.coverage", "must be a plain object");
        } else {
          if (graphCoverage.state !== graph.state) {
            fail("imports.graph.coverage.state", "must agree with the graph state");
          }
          if (graphCoverage.established !== graph.established) {
            fail("imports.graph.coverage.established", "must agree with the graph state");
          }
          if (graphCoverage.nodes !== nodeIds.size) {
            fail("imports.graph.coverage.nodes", "must count the nodes the graph contains");
          }
          if (graphCoverage.edges !== edgeKeys.size) {
            fail("imports.graph.coverage.edges", "must count the edges the graph contains");
          }
          if (graphCoverage.sources !== (Array.isArray(entries) ? entries.length : 0)) {
            fail("imports.graph.coverage.sources", "must count the module sources acquired");
          }
          if (graphCoverage.truncated !== (graph.state === IMPORT_GRAPH_STATES.TRUNCATED)) {
            fail("imports.graph.coverage.truncated", "must agree with the graph state");
          }
          if (graphCoverage.complete !== (graph.state === IMPORT_GRAPH_STATES.COMPLETE)) {
            fail("imports.graph.coverage.complete", "must agree with the graph state");
          }
          if (Array.isArray(graph.unresolved)) {
            if (graphCoverage.unresolvedReported !== graph.unresolved.length) {
              fail(
                "imports.graph.coverage.unresolvedReported",
                "must count the unresolved references the graph carries",
              );
            }
            if (
              graphCoverage.unresolvedTruncated !== true &&
              graphCoverage.unresolved !== graph.unresolved.length
            ) {
              fail(
                "imports.graph.coverage.unresolved",
                "must count every unresolved reference when none were dropped",
              );
            }
          }
          if (Array.isArray(graph.edges)) {
            if (graphCoverage.edgesTruncated !== true && graphCoverage.edges !== graph.edges.length) {
              fail("imports.graph.coverage.edges", "must count every edge when none were dropped");
            }
          }
          if (!Array.isArray(graphCoverage.unestablishedSources)) {
            fail("imports.graph.coverage.unestablishedSources", "must be an array");
          } else if (
            graphCoverage.unestablishedSources.length >
            IMPORT_GRAPH_LIMITS.MAX_UNESTABLISHED_SOURCES
          ) {
            fail("imports.graph.coverage.unestablishedSources", "must stay within the graph bound");
          }
          // The other half of the coverage statement: source files in languages this
          // build does not read. The count is checked against the file entities the
          // model contains, so a graph cannot claim to have read every source file
          // while the inventory holds files no part of this phase reads.
          const uninterpreted = graphCoverage.uninterpretedSources;
          const uninterpretedObserved = [...entityById.values()].filter(
            (entity) =>
              entity?.kind === ENTITY_KINDS.FILE &&
              typeof entity.languageId === "string" &&
              !INTERPRETED_LANGUAGE_IDS.includes(entity.languageId),
          ).length;
          if (!Number.isInteger(uninterpreted) || uninterpreted < 0) {
            fail(
              "imports.graph.coverage.uninterpretedSources",
              "must be a non-negative integer count of source files",
            );
          } else if (uninterpreted !== uninterpretedObserved) {
            fail(
              "imports.graph.coverage.uninterpretedSources",
              "must count the source files in languages this build does not read",
            );
          }
          if (!Array.isArray(graphCoverage.uninterpretedExtensions)) {
            fail("imports.graph.coverage.uninterpretedExtensions", "must be an array");
          } else if (
            graphCoverage.uninterpretedExtensions.length >
            IMPORT_GRAPH_LIMITS.MAX_UNINTERPRETED_EXTENSIONS
          ) {
            fail(
              "imports.graph.coverage.uninterpretedExtensions",
              "must stay within the graph bound",
            );
          } else if (
            graphCoverage.uninterpretedExtensions.some(
              (extension) => typeof extension !== "string" || !/^\.[a-z0-9]+$/.test(extension),
            )
          ) {
            fail(
              "imports.graph.coverage.uninterpretedExtensions",
              "must be lower-case, dot-prefixed extensions",
            );
          }
          // The state may not claim more than the sources support.
          if (graph.state === IMPORT_GRAPH_STATES.COMPLETE) {
            if (graphCoverage.truncated === true) {
              fail("imports.graph.state", "cannot be complete and truncated at once");
            }
            if (graphCoverage.unestablishedSources.length > 0) {
              fail(
                "imports.graph.state",
                "cannot be complete while a module source is unestablished",
              );
            }
            for (const source of sourceByPath.values()) {
              if (source.status !== "parsed" || (source.problems ?? []).length > 0) {
                fail("imports.graph.state", "cannot be complete while a source has a problem");
                break;
              }
            }
          }
          if (graph.state === IMPORT_GRAPH_STATES.UNSUPPORTED) {
            // Two ways to establish nothing: every module source is a format this
            // build does not parse, or there is no module source at all because every
            // source file is in a language it does not read.
            if (sourceByPath.size > 0) {
              for (const source of sourceByPath.values()) {
                if (source.status !== "unsupported") {
                  fail(
                    "imports.graph.state",
                    "cannot be unsupported unless every module source is an unparsed format",
                  );
                  break;
                }
              }
            } else if (!(uninterpreted > 0)) {
              fail(
                "imports.graph.state",
                "cannot be unsupported without an unparsed format or an unread language",
              );
            }
          }
          if (
            graph.state === IMPORT_GRAPH_STATES.COMPLETE &&
            uninterpreted > 0 &&
            (Array.isArray(entries) ? entries.length : 0) === 0
          ) {
            fail(
              "imports.graph.state",
              "cannot be complete when every source file is in a language this build does not read",
            );
          }
        }
      }

      if (isPlainObject(importsArea.coverage) && isPlainObject(importsArea.graph?.coverage)) {
        if (importsArea.coverage.unresolved !== importsArea.graph.coverage.unresolved) {
          fail("imports.coverage.unresolved", "must agree with the graph it summarises");
        }
      }

      // The two views of one fact must agree exactly: every graph edge is an
      // `imports` relationship and every `imports` relationship is a graph edge. A
      // projection that dropped an edge (or a relationship list that invented one)
      // would make a generic graph query and an import query answer differently.
      const relationshipEdges = new Set(
        (model.relationships ?? [])
          .filter((relationship) => relationship?.type === RELATIONSHIP_TYPES.IMPORTS)
          .map(
            (relationship) =>
              `${relationship.from}\u0000${relationship.type}\u0000${relationship.to}`,
          ),
      );
      const graphEdgeKeys = new Set(
        (Array.isArray(importsArea.graph?.edges) ? importsArea.graph.edges : []).map(
          (graphEdge) => `${graphEdge?.from}\u0000${graphEdge?.type}\u0000${graphEdge?.to}`,
        ),
      );
      if (relationshipEdges.size !== graphEdgeKeys.size) {
        fail(
          "imports.graph.edges",
          "must state exactly the `imports` relationships the model records",
        );
      } else {
        for (const key of graphEdgeKeys) {
          if (!relationshipEdges.has(key)) {
            fail(
              "imports.graph.edges",
              "must state exactly the `imports` relationships the model records",
            );
            break;
          }
        }
      }
    }
  }

  // ── Symbol graph (Phase 17) ───────────────────────────────────────────────
  //
  // The semantic projection's contract. It is the strictest of the graph areas, and
  // deliberately so: a symbol graph makes *resolution* claims, so a malformed one can
  // mislead a rule into reporting a relationship the repository never established.
  //
  // Three invariants carry most of the weight:
  //
  //   - a node's id **is** the identity of the binding it describes (path + name), so a
  //     fabricated symbol cannot be smuggled in by inventing an id;
  //   - a *use* of a symbol (`declares`, `references`, `calls`) may only name a symbol
  //     declared in a file whose own observation stated the edge, while `exports` and
  //     `imports-binding` may point at another module — that is what those relations mean;
  //   - a state of `complete` requires the scan behind it to have finished, which is the
  //     one claim an empty graph must never make over an unfinished scan.
  {
    const symbolsArea = model.symbols;
    if (!isPlainObject(symbolsArea)) {
      fail("symbols", "must be a plain object");
    } else {
      const filePaths = new Set(model.files.entries.map((file) => file.path));
      const fileIds = new Set(model.files.entries.map((file) => file.id));
      const evidenceIds = new Set(
        (Array.isArray(model.evidence) ? model.evidence : []).map((record) => record?.id),
      );
      const sourceByPath = new Map();
      const entries = symbolsArea.entries;

      if (typeof symbolsArea.detected !== "boolean") {
        fail("symbols.detected", "must be a boolean");
      }
      if (!Array.isArray(entries)) {
        fail("symbols.entries", "must be an array");
      } else {
        for (const source of entries) {
          const at = `symbols.entries[${source?.path}]`;
          if (!isPlainObject(source)) {
            fail("symbols.entries", "every semantic source must be a plain object");
            continue;
          }
          if (!filePaths.has(source.path)) {
            fail(at, "must name a file the model observed");
            continue;
          }
          if (sourceByPath.has(source.path)) fail(at, "must describe each semantic source once");
          sourceByPath.set(source.path, source);

          if (!SEMANTIC_MODULE_EXTENSIONS.includes(source.extension)) {
            fail(at, "must carry a module source extension this build covers");
          }
          if (!entityIds.has(source.languageId)) {
            fail(at, "language must name a language the model contains");
          }
          if (!SEMANTIC_SOURCE_STATUS_VALUES.includes(source.status)) {
            fail(at, `status must be one of: ${SEMANTIC_SOURCE_STATUS_VALUES.join(", ")}`);
          }
          if (source.reason !== null && !SEMANTIC_SOURCE_REASONS.includes(source.reason)) {
            fail(at, `reason must be null or one of: ${SEMANTIC_SOURCE_REASONS.join(", ")}`);
          }
          if (source.status === "parsed" && source.reason !== null) {
            fail(at, "a parsed semantic source must not carry an acquisition reason");
          }
          if (source.status !== "parsed" && source.reason === null) {
            fail(at, "a semantic source that was not parsed must record why");
          }
          if (typeof source.truncated !== "boolean") {
            fail(at, "truncated must be a boolean");
          }
          for (const problem of source.problems ?? []) {
            if (!SEMANTIC_PROBLEM_REASONS.includes(problem)) {
              fail(at, `unknown semantic problem "${String(problem)}"`);
            }
          }

          const established = isPlainObject(source.established) ? source.established : null;
          if (established === null) {
            fail(at, "must state what it established");
          } else {
            for (const field of [
              "declarationsEstablished",
              "resolutionEstablished",
              "exportsEstablished",
            ]) {
              if (typeof established[field] !== "boolean") {
                fail(at, `${field} must be a boolean`);
              }
            }
            // Resolution is a claim *about* a declaration set: it cannot be established
            // where that set is not.
            if (
              established.resolutionEstablished === true &&
              established.declarationsEstablished !== true
            ) {
              fail(at, "resolution cannot be established while declarations are not");
            }
            if (source.status !== "parsed") {
              for (const field of [
                "declarationsEstablished",
                "resolutionEstablished",
                "exportsEstablished",
              ]) {
                if (established[field] !== false) {
                  fail(at, "a source that was not scanned establishes nothing");
                  break;
                }
              }
            }
          }

          if (!Array.isArray(source.declarations)) {
            fail(at, "must carry a declarations array");
          } else {
            for (const declaration of source.declarations) {
              if (!isPlainObject(declaration)) {
                fail(at, "declarations must be plain objects");
                continue;
              }
              if (projectSymbolName(declaration.name) === null) {
                fail(at, "declaration names must be bounded identifier text");
              }
              if (!Array.isArray(declaration.kinds) || declaration.kinds.length === 0) {
                fail(at, "a declaration must state at least one kind");
                continue;
              }
              for (const kind of declaration.kinds) {
                if (!SYMBOL_KINDS.includes(kind)) {
                  fail(at, `declaration kinds must be one of: ${SYMBOL_KINDS.join(", ")}`);
                  break;
                }
              }
              if (!Array.isArray(declaration.exportNames)) {
                fail(at, "a declaration must carry its exported names");
              } else {
                for (const name of declaration.exportNames) {
                  if (projectSymbolName(name) === null) {
                    fail(at, "exported names must be bounded identifier text");
                  }
                }
              }
              for (const field of ["exported", "shadowed", "reassigned"]) {
                if (typeof declaration[field] !== "boolean") {
                  fail(at, `${field} must be a boolean`);
                }
              }
              for (const field of ["callable", "constructable"]) {
                const value = declaration[field];
                if (value !== true && value !== false && value !== null) {
                  fail(at, `${field} must be true, false or null`);
                }
              }
              if (declaration.binding !== null) {
                if (!isPlainObject(declaration.binding)) {
                  fail(at, "binding must be null or a plain object");
                } else if (!SYMBOL_BINDING_KINDS.includes(declaration.binding.bindingKind)) {
                  fail(at, `binding kinds must be one of: ${SYMBOL_BINDING_KINDS.join(", ")}`);
                } else if (
                  declaration.binding.specifier !== null &&
                  projectModuleSpecifier(declaration.binding.specifier) === null
                ) {
                  fail(at, "a binding specifier must be null or bounded, printable text");
                }
              }
            }
            if (source.status !== "parsed" && source.declarations.length > 0) {
              fail(at, "a source that was not scanned declares nothing");
            }
          }

          if (!Array.isArray(source.exports)) {
            fail(at, "must carry an exports array");
          } else {
            for (const entry of source.exports) {
              if (!isPlainObject(entry)) {
                fail(at, "export clauses must be plain objects");
                continue;
              }
              if (!SYMBOL_EXPORT_FORMS.includes(entry.form)) {
                fail(at, `export forms must be one of: ${SYMBOL_EXPORT_FORMS.join(", ")}`);
                continue;
              }
              if (entry.name !== null && projectSymbolName(entry.name) === null) {
                fail(at, "an exported name must be null or bounded identifier text");
              }
              if (entry.localName !== null && projectSymbolName(entry.localName) === null) {
                fail(at, "a local export name must be null or bounded identifier text");
              }
              if (entry.specifier !== null && projectModuleSpecifier(entry.specifier) === null) {
                fail(at, "an export specifier must be null or bounded, printable text");
              }
            }
            if (source.status !== "parsed" && source.exports.length > 0) {
              fail(at, "a source that was not scanned exports nothing");
            }
          }

          if (!Array.isArray(source.starExports)) {
            fail(at, "must carry a starExports array");
          } else {
            for (const specifier of source.starExports) {
              if (projectModuleSpecifier(specifier) === null) {
                fail(at, "a star export must carry bounded, printable specifier text");
              }
            }
          }

          if (!Array.isArray(source.references)) {
            fail(at, "must carry a references array");
          } else {
            for (const reference of source.references) {
              if (!isPlainObject(reference)) {
                fail(at, "references must be plain objects");
                continue;
              }
              if (projectSymbolName(reference.name) === null) {
                fail(at, "a referenced name must be bounded identifier text");
              }
              if (!SYMBOL_OCCURRENCE_FORMS.includes(reference.form)) {
                fail(at, `occurrence forms must be one of: ${SYMBOL_OCCURRENCE_FORMS.join(", ")}`);
              }
              if (!isNonNegativeInteger(reference.count) || reference.count < 1) {
                fail(at, "a reference count must be a positive integer");
              }
            }
            if (source.status !== "parsed" && source.references.length > 0) {
              fail(at, "a source that was not scanned references nothing");
            }
          }

          if (!isPlainObject(source.counts)) {
            fail(at, "must carry its acquisition counts");
          } else {
            for (const field of [
              "declarations",
              "exports",
              "names",
              "references",
              "calls",
              "constructs",
              "tokens",
            ]) {
              if (!isNonNegativeInteger(source.counts[field])) {
                fail(at, `counts.${field} must be a non-negative integer`);
              }
            }
          }

          if (!evidenceIds.has(source.evidenceId)) {
            fail(at, "must cite the observation that recorded it");
          }
        }
        for (let next = 1; next < entries.length; next += 1) {
          if (entries[next - 1]?.path >= entries[next]?.path) {
            fail(`symbols.entries[${next}]`, "must be sorted by path and unique");
            break;
          }
        }
      }
      if (symbolsArea.count !== (Array.isArray(entries) ? entries.length : 0)) {
        fail("symbols.count", "must count the semantic sources the area carries");
      }

      const graph = symbolsArea.graph;
      if (!isPlainObject(graph)) {
        fail("symbols.graph", "must be a plain object");
      } else {
        const nodeIds = new Set();
        const evidenceIdSet = evidenceIds;
        const sourcePathSet = new Set(sourceByPath.keys());

        if (typeof graph.version !== "string" || graph.version === "") {
          fail("symbols.graph.version", "must be a non-empty string");
        }
        if (!SYMBOL_GRAPH_STATE_VALUES.includes(graph.state)) {
          fail("symbols.graph.state", `must be one of: ${SYMBOL_GRAPH_STATE_VALUES.join(", ")}`);
        }
        if (typeof graph.established !== "boolean") {
          fail("symbols.graph.established", "must be a boolean");
        } else if (graph.established !== isEstablishedSymbolState(graph.state)) {
          fail("symbols.graph.established", "must agree with the state it reports");
        }

        if (!Array.isArray(graph.nodes)) {
          fail("symbols.graph.nodes", "must be an array");
        } else if (graph.nodes.length > SYMBOL_GRAPH_LIMITS.MAX_SYMBOLS) {
          fail("symbols.graph.nodes", "must stay within the graph node bound");
        } else {
          graph.nodes.forEach((node, index) => {
            const at = `symbols.graph.nodes[${index}]`;
            if (!isPlainObject(node)) {
              fail(at, "must be a plain object");
              return;
            }
            if (typeof node.id !== "string" || node.id === "") {
              fail(`${at}.id`, "must be a non-empty string");
              return;
            }
            if (node.id !== symbolIdOf(node.path, node.name)) {
              fail(`${at}.id`, "must be the identity of the binding it describes");
            }
            if (!filePaths.has(node.path)) {
              fail(`${at}.path`, "must be a file the model observed");
            }
            if (node.fileId !== `file:${node.path}`) {
              fail(`${at}.fileId`, "must name the file the symbol is declared in");
            }
            if (projectSymbolName(node.name) === null) {
              fail(`${at}.name`, "must be bounded identifier text");
            }
            if (!Array.isArray(node.kinds) || node.kinds.length === 0) {
              fail(`${at}.kinds`, "must state at least one kind");
            } else {
              for (const kind of node.kinds) {
                if (!SYMBOL_KINDS.includes(kind)) {
                  fail(`${at}.kinds`, `must contain only: ${SYMBOL_KINDS.join(", ")}`);
                  break;
                }
              }
            }
            for (const field of ["exported", "shadowed", "reassigned"]) {
              if (typeof node[field] !== "boolean") fail(`${at}.${field}`, "must be a boolean");
            }
            for (const field of ["callable", "constructable"]) {
              const value = node[field];
              if (value !== true && value !== false && value !== null) {
                fail(`${at}.${field}`, "must be true, false or null");
              }
            }
            for (const field of ["referenceCount", "callCount", "constructCount"]) {
              if (!isNonNegativeInteger(node[field])) {
                fail(`${at}.${field}`, "must be a non-negative integer");
              }
            }
            if (!Array.isArray(node.exportNames)) {
              fail(`${at}.exportNames`, "must be an array");
            } else if (node.exported !== true && node.exportNames.length > 0) {
              fail(`${at}.exported`, "must be true when the symbol states exported names");
            }
            if (node.binding !== null && node.binding !== undefined) {
              if (!isPlainObject(node.binding)) {
                fail(`${at}.binding`, "must be a plain object or null");
              } else if (!SYMBOL_BINDING_KINDS.includes(node.binding.bindingKind)) {
                fail(`${at}.binding.bindingKind`, "must be a documented binding kind");
              }
            }
            if (nodeIds.has(node.id)) fail(`${at}.id`, "must be unique within the graph");
            nodeIds.add(node.id);
          });
          for (let next = 1; next < graph.nodes.length; next += 1) {
            if (String(graph.nodes[next - 1]?.id) >= String(graph.nodes[next]?.id)) {
              fail("symbols.graph.nodes", "nodes must be sorted by id and unique");
              break;
            }
          }
        }

        if (!Array.isArray(graph.edges)) {
          fail("symbols.graph.edges", "must be an array");
        } else if (graph.edges.length > SYMBOL_GRAPH_LIMITS.MAX_EDGES) {
          fail("symbols.graph.edges", "must stay within the graph edge bound");
        } else {
          graph.edges.forEach((edge, index) => {
            const at = `symbols.graph.edges[${index}]`;
            if (!isPlainObject(edge)) {
              fail(at, "must be a plain object");
              return;
            }
            if (!SYMBOL_GRAPH_EDGE_TYPE_VALUES.includes(edge.type)) {
              fail(`${at}.type`, `must be one of: ${SYMBOL_GRAPH_EDGE_TYPE_VALUES.join(", ")}`);
            }
            if (!Number.isInteger(edge.count) || edge.count < 1) {
              fail(`${at}.count`, "must be a positive integer");
            }
            if (!Array.isArray(edge.sourcePaths) || edge.sourcePaths.length === 0) {
              fail(`${at}.sourcePaths`, "must name the file whose observation stated the edge");
            } else if (edge.sourcePaths.some((path) => !filePaths.has(path))) {
              fail(`${at}.sourcePaths`, "must name files the model observed");
            }
            if (!Array.isArray(edge.evidenceIds) || edge.evidenceIds.length === 0) {
              fail(`${at}.evidenceIds`, "must cite the observation behind the edge");
            } else if (edge.evidenceIds.some((id) => !evidenceIdSet.has(id))) {
              fail(`${at}.evidenceIds`, "must cite observations the model holds");
            }

            const fromIsFile = fileIds.has(edge.from);
            const fromIsSymbol = nodeIds.has(edge.from);
            const toIsFile = fileIds.has(edge.to);
            const toIsSymbol = nodeIds.has(edge.to);
            if (!fromIsFile && !fromIsSymbol) {
              fail(`${at}.from`, "must name a file the model observed or a symbol in this graph");
            }
            if (!toIsFile && !toIsSymbol) {
              fail(`${at}.to`, "must name a file the model observed or a symbol in this graph");
            }
            if (
              edge.type === SYMBOL_GRAPH_EDGE_TYPES.DECLARES ||
              edge.type === SYMBOL_GRAPH_EDGE_TYPES.REFERENCES ||
              edge.type === SYMBOL_GRAPH_EDGE_TYPES.CALLS ||
              edge.type === SYMBOL_GRAPH_EDGE_TYPES.EXPORTS
            ) {
              if (!fromIsFile || !toIsSymbol) {
                fail(`${at}`, `a \`${edge.type}\` edge must join a file to a symbol`);
              }
            }
            if (edge.type === SYMBOL_GRAPH_EDGE_TYPES.IMPORTS_BINDING) {
              if (!fromIsSymbol || !toIsSymbol) {
                fail(`${at}`, "an `imports-binding` edge must join two symbols");
              }
            }
            // A *use* of a symbol (a declaration, a reference, a call) may only name a
            // symbol declared in the file whose observation stated the edge, so an
            // occurrence can never be attributed to a different file than the one that
            // stated it.
            //
            // `exports` and `imports-binding` are exempt because pointing at another
            // module is what those edges *mean*: a re-export publishes a symbol this file
            // did not declare, and an import binding resolves to the symbol the target
            // module exports. In both cases `sourcePaths` still names the file whose own
            // observation stated the relationship, which is the attribution that matters.
            const attributedToStatingFile =
              edge.type === SYMBOL_GRAPH_EDGE_TYPES.DECLARES ||
              edge.type === SYMBOL_GRAPH_EDGE_TYPES.REFERENCES ||
              edge.type === SYMBOL_GRAPH_EDGE_TYPES.CALLS;
            if (toIsSymbol && attributedToStatingFile && typeof edge.to === "string") {
              const separator = edge.to.indexOf("#");
              const symbolPath = edge.to.slice("symbol:".length, separator);
              if (!(edge.sourcePaths ?? []).includes(symbolPath)) {
                fail(
                  `${at}.to`,
                  "must name a symbol declared in a file whose observation stated the edge",
                );
              }
            }
          });
          for (let next = 1; next < graph.edges.length; next += 1) {
            const previous = graph.edges[next - 1];
            const current = graph.edges[next];
            if (!isPlainObject(previous) || !isPlainObject(current)) continue;
            // One relationship, stated once. `A --references--> B` twice would make
            // `referencesTo` double-count a symbol's uses and a finding per edge would
            // describe the same relationship twice, so the graph refuses to carry it.
            if (
              previous.from === current.from &&
              previous.to === current.to &&
              previous.type === current.type
            ) {
              fail("symbols.graph.edges", "must state each relationship once");
              break;
            }
            const ordered =
              previous.from < current.from ||
              (previous.from === current.from &&
                (previous.to < current.to ||
                  (previous.to === current.to && previous.type < current.type)));
            if (!ordered) {
              fail("symbols.graph.edges", "edges must be sorted by (from, to, type)");
              break;
            }
          }
        }

        if (!Array.isArray(graph.unresolved)) {
          fail("symbols.graph.unresolved", "must be an array");
        } else if (graph.unresolved.length > SYMBOL_GRAPH_LIMITS.MAX_UNRESOLVED) {
          fail("symbols.graph.unresolved", "must stay within the unresolved bound");
        } else {
          graph.unresolved.forEach((record, index) => {
            const at = `symbols.graph.unresolved[${index}]`;
            if (!isPlainObject(record)) {
              fail(at, "must be a plain object");
              return;
            }
            if (!filePaths.has(record.path)) {
              fail(`${at}.path`, "must name a file the model observed");
            }
            if (projectSymbolName(record.name) === null) {
              fail(`${at}.name`, "must be bounded identifier text");
            }
            if (!SYMBOL_UNRESOLVED_KINDS.includes(record.kind)) {
              fail(`${at}.kind`, `must be one of: ${SYMBOL_UNRESOLVED_KINDS.join(", ")}`);
            }
            if (!SYMBOL_UNRESOLVED_REASON_VALUES.includes(record.reason)) {
              fail(`${at}.reason`, "must be a documented unresolved reason");
            }
            if (record.evidenceId !== null && !evidenceIdSet.has(record.evidenceId)) {
              fail(`${at}.evidenceId`, "must cite an observation the model holds");
            }
          });
          for (let next = 1; next < graph.unresolved.length; next += 1) {
            const previous = graph.unresolved[next - 1];
            const current = graph.unresolved[next];
            const ordered =
              isPlainObject(previous) &&
              isPlainObject(current) &&
              (previous.path < current.path ||
                (previous.path === current.path &&
                  (previous.name < current.name ||
                    (previous.name === current.name && previous.kind <= current.kind))));
            if (!ordered) {
              fail("symbols.graph.unresolved", "must be sorted deterministically");
              break;
            }
          }
        }

        if (!isPlainObject(graph.coverage)) {
          fail("symbols.graph.coverage", "must be a plain object");
        } else {
          const graphCoverage = graph.coverage;
          if (graphCoverage.state !== graph.state) {
            fail("symbols.graph.coverage.state", "must agree with the graph state");
          }
          if (graphCoverage.established !== graph.established) {
            fail("symbols.graph.coverage.established", "must agree with the graph state");
          }
          if (graphCoverage.symbols !== (Array.isArray(graph.nodes) ? graph.nodes.length : 0)) {
            fail("symbols.graph.coverage.symbols", "must count the symbols the graph contains");
          }
          if (graphCoverage.edges !== (Array.isArray(graph.edges) ? graph.edges.length : 0)) {
            fail("symbols.graph.coverage.edges", "must count the edges the graph contains");
          }
          if (graphCoverage.truncated !== (graph.state === SYMBOL_GRAPH_STATES.TRUNCATED)) {
            fail("symbols.graph.coverage.truncated", "must agree with the graph state");
          }
          if (graphCoverage.complete !== (graph.state === SYMBOL_GRAPH_STATES.COMPLETE)) {
            fail("symbols.graph.coverage.complete", "must agree with the graph state");
          }
          if (graphCoverage.unresolved !== graph.unresolved.length) {
            fail("symbols.graph.coverage.unresolved", "must count every unresolved record");
          }
          if (graphCoverage.unresolvedReported !== graph.unresolved.length) {
            fail("symbols.graph.coverage.unresolvedReported", "must count every unresolved record");
          }
          if (!isNonNegativeInteger(graphCoverage.unestablished)) {
            fail("symbols.graph.coverage.unestablished", "must be a non-negative integer");
          }
          if (!Array.isArray(graphCoverage.unestablishedSources)) {
            fail("symbols.graph.coverage.unestablishedSources", "must be an array");
          } else if (
            graphCoverage.unestablishedSources.length > SYMBOL_GRAPH_LIMITS.MAX_UNESTABLISHED_SOURCES
          ) {
            fail("symbols.graph.coverage.unestablishedSources", "must stay within the graph bound");
          }
          if (graph.state === SYMBOL_GRAPH_STATES.COMPLETE) {
            // The projection only reaches `complete` when the scan behind it finished and
            // every semantic claim in it was established. Restating that here is what makes
            // the state trustworthy rather than merely produced: a tampered graph that
            // claims completeness over an unfinished scan has to be rejected.
            if (
              model.scan.complete !== true ||
              model.scan.truncated === true ||
              graphCoverage.complete !== true ||
              graphCoverage.truncated === true
            ) {
              fail("symbols.graph.state", "cannot be complete unless the scan covered the repository");
            }
            if (graphCoverage.unestablishedSources.length > 0) {
              fail("symbols.graph.state", "cannot be complete while a semantic source is unestablished");
            }
            for (const source of sourceByPath.values()) {
              // The projection reaches `complete` only when *every* source established all
              // three of its claims and carried no problem. Restating the full condition
              // here is the point: a tampered graph that claims completeness over a file
              // that could not be read has to be rejected, not trusted.
              if (
                source.status !== "parsed" ||
                (source.problems ?? []).length > 0 ||
                source.established.declarationsEstablished !== true ||
                source.established.resolutionEstablished !== true ||
                source.established.exportsEstablished !== true
              ) {
                fail("symbols.graph.state", "cannot be complete while a source is unestablished");
                break;
              }
            }
          }
          if (graph.state === SYMBOL_GRAPH_STATES.UNSUPPORTED && sourcePathSet.size === 0) {
            if (!(isNonNegativeInteger(graphCoverage.uninterpretedSources) && graphCoverage.uninterpretedSources > 0)) {
              fail(
                "symbols.graph.state",
                "cannot be unsupported without an unparsed format or an unread language",
              );
            }
          }
        }
      }

      if (isPlainObject(symbolsArea.coverage) && isPlainObject(symbolsArea.graph?.coverage)) {
        if (symbolsArea.coverage.unresolved !== symbolsArea.graph.coverage.unresolved) {
          fail("symbols.coverage.unresolved", "must agree with the graph it summarises");
        }
      }
    }
  }

  // ── API graph (Phase 18) ──────────────────────────────────────────────────
  //
  // Validated with the same care as the symbol graph, and for the same reason: a route
  // makes a claim (*this repository exposes this endpoint, handled by this symbol*), so a
  // malformed graph can mislead a rule into reporting an API surface the repository never
  // declared.
  //
  // The invariants that carry the weight:
  //
  //   - a route node's id **is** the identity of the endpoint (`route:METHOD:path`), so a
  //     fabricated route cannot be smuggled in by inventing an id;
  //   - `handled-by` / `middleware` may only name a symbol the Phase 17 graph carries, and
  //     a route may only be `declared` by a file the model observed — no invented endpoint;
  //   - a state of `complete` requires the scan behind it to have finished and every
  //     source to have established its route set.
  {
    const apiArea = model.api;
    if (!isPlainObject(apiArea)) {
      fail("api", "must be a plain object");
    } else {
      const filePaths = new Set(model.files.entries.map((file) => file.path));
      const fileIds = new Set(model.files.entries.map((file) => file.id));
      const symbolNodeIds = new Set(
        (Array.isArray(model.symbols?.graph?.nodes) ? model.symbols.graph.nodes : []).map(
          (node) => node.id,
        ),
      );
      const evidenceIds = new Set(
        (Array.isArray(model.evidence) ? model.evidence : []).map((record) => record?.id),
      );
      const entries = apiArea.entries;

      if (typeof apiArea.detected !== "boolean") fail("api.detected", "must be a boolean");
      if (!Array.isArray(entries)) {
        fail("api.entries", "must be an array");
      } else {
        const seen = new Set();
        for (const source of entries) {
          const at = `api.entries[${source?.path}]`;
          if (!isPlainObject(source)) {
            fail("api.entries", "every API source must be a plain object");
            continue;
          }
          if (!filePaths.has(source.path)) {
            fail(at, "must name a file the model observed");
            continue;
          }
          if (seen.has(source.path)) fail(at, "must describe each API source once");
          seen.add(source.path);

          if (!SEMANTIC_MODULE_EXTENSIONS.includes(source.extension)) {
            fail(`${at}.extension`, "must be a module source extension");
          }
          if (!API_SOURCE_STATUSES.includes(source.status)) {
            fail(`${at}.status`, "must be a documented API source status");
          }
          if (typeof source.established !== "boolean") {
            fail(`${at}.established`, "must be a boolean");
          }
          if (!Array.isArray(source.frameworks)) {
            fail(`${at}.frameworks`, "must be an array");
          } else {
            for (const framework of source.frameworks) {
              if (!API_FRAMEWORKS.includes(framework)) {
                fail(`${at}.frameworks`, "must name a supported framework");
              }
            }
          }
          if (!Array.isArray(source.routes)) {
            fail(`${at}.routes`, "must be an array");
          } else {
            for (const route of source.routes) {
              if (!API_ROUTE_METHODS.includes(route?.method)) {
                fail(`${at}.routes[].method`, "must be a recorded method");
              }
              if (typeof route?.path !== "string" || !route.path.startsWith("/")) {
                fail(`${at}.routes[].path`, "must be a route path");
              }
              if (!API_FRAMEWORKS.includes(route?.framework)) {
                fail(`${at}.routes[].framework`, "must name a supported framework");
              }
              if (!API_RECEIVER_KINDS.includes(route?.receiverKind)) {
                fail(`${at}.routes[].receiverKind`, "must be app or router");
              }
              const callables = [
                ...(route?.handler == null ? [] : [route.handler]),
                ...(Array.isArray(route?.middleware) ? route.middleware : []),
              ];
              for (const callable of callables) {
                if (!API_CALLABLE_FORMS.includes(callable?.form)) {
                  fail(`${at}.routes[].callables`, "must be a documented callable form");
                }
              }
            }
          }
          if (!Array.isArray(source.shapes)) {
            fail(`${at}.shapes`, "must be an array");
          } else {
            for (const shape of source.shapes) {
              if (!API_SHAPE_REASONS.includes(shape?.reason)) {
                fail(`${at}.shapes[].reason`, "must be a documented reason");
              }
            }
          }
          if (!Array.isArray(source.problems)) {
            fail(`${at}.problems`, "must be an array");
          } else {
            for (const problem of source.problems) {
              if (!API_PROBLEM_REASONS.includes(problem)) {
                fail(`${at}.problems[]`, "must be a documented problem");
              }
            }
          }
          if (!evidenceIds.has(source.evidenceId)) {
            fail(`${at}.evidenceId`, "must name an observation the model carries");
          }
        }
      }
      if (apiArea.count !== (Array.isArray(entries) ? entries.length : 0)) {
        fail("api.count", "must count the API sources the area carries");
      }

      const graph = apiArea.graph;
      if (!isPlainObject(graph)) {
        fail("api.graph", "must be a plain object");
      } else {
        const routeIds = new Set();
        if (!isNonEmptyString(graph.version)) fail("api.graph.version", "must be a non-empty string");
        if (!API_GRAPH_STATE_VALUES.includes(graph.state)) {
          fail("api.graph.state", `must be one of: ${API_GRAPH_STATE_VALUES.join(", ")}`);
        }
        if (typeof graph.established !== "boolean") {
          fail("api.graph.established", "must be a boolean");
        } else if (graph.established !== isEstablishedApiState(graph.state)) {
          fail("api.graph.established", "must agree with the state it reports");
        }

        if (!Array.isArray(graph.nodes)) {
          fail("api.graph.nodes", "must be an array");
        } else {
          if (graph.nodes.length > API_GRAPH_LIMITS.MAX_ROUTES) {
            fail("api.graph.nodes", "must stay within the graph node bound");
          }
          let previous = null;
          graph.nodes.forEach((node, index) => {
            const at = `api.graph.nodes[${index}]`;
            if (!isPlainObject(node)) {
              fail(at, "must be a plain object");
              return;
            }
            if (!API_ROUTE_METHODS.includes(node.method)) {
              fail(`${at}.method`, "must be a recorded method");
            }
            if (typeof node.path !== "string" || !node.path.startsWith("/")) {
              fail(`${at}.path`, "must be a route path");
            }
            if (node.id !== apiRouteIdOf(node.method, node.path)) {
              fail(`${at}.id`, "must be the identity of the endpoint it describes");
            }
            if (!Array.isArray(node.frameworks)) {
              fail(`${at}.frameworks`, "must be an array");
            } else {
              for (const framework of node.frameworks) {
                if (!API_FRAMEWORKS.includes(framework)) {
                  fail(`${at}.frameworks`, "must name a supported framework");
                }
              }
            }
            if (!Array.isArray(node.sourcePaths)) {
              fail(`${at}.sourcePaths`, "must be an array");
            } else {
              for (const sourcePath of node.sourcePaths) {
                if (!filePaths.has(sourcePath)) {
                  fail(`${at}.sourcePaths`, "must name files the model observed");
                }
              }
            }
            if (!Array.isArray(node.evidenceIds)) {
              fail(`${at}.evidenceIds`, "must be an array");
            } else {
              for (const evidenceId of node.evidenceIds) {
                if (!evidenceIds.has(evidenceId)) {
                  fail(`${at}.evidenceIds`, "must name observations the model carries");
                }
              }
            }
            if (previous !== null && previous >= node.id) {
              fail("api.graph.nodes", "nodes must be sorted by id and unique");
            }
            previous = node.id;
            routeIds.add(node.id);
          });
        }

        if (!Array.isArray(graph.edges)) {
          fail("api.graph.edges", "must be an array");
        } else {
          if (graph.edges.length > API_GRAPH_LIMITS.MAX_EDGES) {
            fail("api.graph.edges", "must stay within the graph edge bound");
          }
          let previousEdge = null;
          graph.edges.forEach((edge, index) => {
            const at = `api.graph.edges[${index}]`;
            if (!isPlainObject(edge)) {
              fail(at, "must be a plain object");
              return;
            }
            if (!API_GRAPH_EDGE_TYPE_VALUES.includes(edge.type)) {
              fail(`${at}.type`, "must be a documented edge type");
            }
            const endpointExists = (id) =>
              routeIds.has(id) || fileIds.has(id) || symbolNodeIds.has(id);
            if (!endpointExists(edge.from)) fail(`${at}.from`, "must name an entity the model carries");
            if (!endpointExists(edge.to)) fail(`${at}.to`, "must name an entity the model carries");
            if (edge.type === API_GRAPH_EDGE_TYPES.DECLARES) {
              if (!fileIds.has(edge.from) || !routeIds.has(edge.to)) {
                fail(`${at}`, "a `declares` edge must join a file to a route");
              }
            } else if (!routeIds.has(edge.from) || !symbolNodeIds.has(edge.to)) {
              fail(`${at}`, "a route relationship must join a route to a symbol");
            }
            if (!Array.isArray(edge.evidenceIds)) {
              fail(`${at}.evidenceIds`, "must be an array");
            } else {
              for (const evidenceId of edge.evidenceIds) {
                if (!evidenceIds.has(evidenceId)) {
                  fail(`${at}.evidenceIds`, "must name observations the model carries");
                }
              }
            }
            const key = `${edge.from}\u0000${edge.to}\u0000${edge.type}`;
            if (previousEdge !== null && key <= previousEdge) {
              fail("api.graph.edges", "must state each relationship once, sorted by (from, to, type)");
            }
            previousEdge = key;
          });
        }

        if (!Array.isArray(graph.unresolved)) {
          fail("api.graph.unresolved", "must be an array");
        } else {
          if (graph.unresolved.length > API_GRAPH_LIMITS.MAX_UNRESOLVED) {
            fail("api.graph.unresolved", "must stay within the unresolved bound");
          }
          let previousUnresolved = null;
          graph.unresolved.forEach((record, index) => {
            const at = `api.graph.unresolved[${index}]`;
            if (!isPlainObject(record)) {
              fail(at, "must be a plain object");
              return;
            }
            if (!filePaths.has(record.path)) {
              fail(`${at}.path`, "must name a file the model observed");
            }
            if (!API_UNRESOLVED_KINDS.includes(record.kind)) {
              fail(`${at}.kind`, "must be route, handler or middleware");
            }
            if (!API_UNRESOLVED_REASON_VALUES.includes(record.reason)) {
              fail(`${at}.reason`, "must be a documented reason");
            }
            const key = `${record.path}\u0000${record.reason}\u0000${record.route ?? ""}\u0000${record.kind}\u0000${record.name ?? ""}`;
            if (previousUnresolved !== null && key < previousUnresolved) {
              fail("api.graph.unresolved", "must be sorted deterministically");
            }
            previousUnresolved = key;
          });
        }

        const coverage = graph.coverage;
        if (!isPlainObject(coverage)) {
          fail("api.graph.coverage", "must be a plain object");
        } else {
          if (coverage.state !== graph.state) {
            fail("api.graph.coverage.state", "must agree with the graph state");
          }
          if (coverage.established !== graph.established) {
            fail("api.graph.coverage.established", "must agree with the graph state");
          }
          if (coverage.routes !== (Array.isArray(graph.nodes) ? graph.nodes.length : -1)) {
            fail("api.graph.coverage.routes", "must count the routes the graph contains");
          }
          if (coverage.edges !== (Array.isArray(graph.edges) ? graph.edges.length : -1)) {
            fail("api.graph.coverage.edges", "must count the edges the graph contains");
          }
          if (coverage.unresolved !== (Array.isArray(graph.unresolved) ? graph.unresolved.length : -1)) {
            fail("api.graph.coverage.unresolved", "must count every unresolved record");
          }
          if (coverage.truncated !== (graph.state === API_GRAPH_STATES.TRUNCATED)) {
            fail("api.graph.coverage.truncated", "must agree with the graph state");
          }
          if (coverage.complete !== (graph.state === API_GRAPH_STATES.COMPLETE)) {
            fail("api.graph.coverage.complete", "must agree with the graph state");
          }
          if (graph.state === API_GRAPH_STATES.COMPLETE) {
            if (model.scan.complete !== true) {
              fail("api.graph.state", "cannot be complete unless the scan covered the repository");
            }
            const sources = Array.isArray(entries) ? entries : [];
            if (sources.length > 0 && !sources.every((source) => source.established === true)) {
              fail("api.graph.state", "cannot be complete while an API source is unestablished");
            }
          }
        }
      }

      if (isPlainObject(apiArea.coverage) && isPlainObject(apiArea.graph?.coverage)) {
        if (apiArea.coverage.unresolved !== apiArea.graph.coverage.unresolved) {
          fail("api.coverage.unresolved", "must agree with the graph it summarises");
        }
      }
    }
  }

  // ── Completeness ──────────────────────────────────────────────────────────
  if (model.scan.truncated === true && model.scan.complete === true) {
    fail("scan", "a truncated model must not be complete");
  }
  const guarantee =
    model.scan.complete === true && model.scan.truncated !== true
      ? COVERAGE_GUARANTEES.COMPLETE
      : COVERAGE_GUARANTEES.PARTIAL;
  if (model.scan.coverage?.guarantee !== guarantee) {
    fail("scan.coverage.guarantee", `must be "${guarantee}" for this scan state`);
  }
  if (model.metadata?.immutability !== MODEL_IMMUTABILITY) {
    fail("metadata.immutability", `must be "${MODEL_IMMUTABILITY}"`);
  }

  // ── No judgments ──────────────────────────────────────────────────────────
  for (const judgment of REPOSITORY_MODEL_JUDGMENT_AREAS) {
    if (judgment in model) {
      fail(judgment, "the model records facts; judgments belong to analyzers");
    }
  }

  // ── Path-like fields must stay relative ───────────────────────────────────
  for (const { label, entity } of descriptors) {
    for (const field of ["path", "directory", "root"]) {
      const value = entity[field];
      if (typeof value === "string" && value !== model.identity.root && value.startsWith("/")) {
        fail(`${label}[${entity.id}].${field}`, "must not be an absolute path");
      }
    }
  }

  // ── Middleware graph (Phase 19) ───────────────────────────────────────────
  //
  // The middleware graph is validated against the two graphs it projects from, so a broken
  // projection fails the build here instead of reaching a rule as a plausible finding:
  //
  //   - every middleware node's id must be a symbol the Phase 17 graph carries, and the
  //     node must not invent a symbol of its own (`node.symbolId === node.id`);
  //   - every `protects` / `applies-to` target must be a route the API graph carries, and
  //     `precedes` must join two middleware nodes and `registered-on` a middleware node to
  //     a file the model observed — no invented endpoint;
  //   - a route's protection state must agree with its own middleware and unresolved
  //     counts, so a route that carries an unresolved observation can never read as
  //     unprotected;
  //   - a state of `complete` requires the scan behind it to have finished and every source
  //     to have established its registrations.
  {
    const middlewareArea = model.middleware;
    if (!isPlainObject(middlewareArea)) {
      fail("middleware", "must be a plain object");
    } else {
      const filePaths = new Set(model.files.entries.map((file) => file.path));
      const fileIds = new Set(model.files.entries.map((file) => file.id));
      const symbolNodeIds = new Set(
        (Array.isArray(model.symbols?.graph?.nodes) ? model.symbols.graph.nodes : []).map(
          (node) => node.id,
        ),
      );
      const apiRouteIds = new Set(
        (Array.isArray(model.api?.graph?.nodes) ? model.api.graph.nodes : []).map(
          (node) => node.id,
        ),
      );
      const evidenceIds = new Set(
        (Array.isArray(model.evidence) ? model.evidence : []).map((record) => record?.id),
      );
      const entries = middlewareArea.entries;

      if (typeof middlewareArea.detected !== "boolean") {
        fail("middleware.detected", "must be a boolean");
      }
      if (!Array.isArray(entries)) {
        fail("middleware.entries", "must be an array");
      } else {
        const seen = new Set();
        for (const source of entries) {
          const at = `middleware.entries[${source?.path}]`;
          if (!isPlainObject(source)) {
            fail("middleware.entries", "every middleware source must be a plain object");
            continue;
          }
          if (!filePaths.has(source.path)) {
            fail(at, "must name a file the model observed");
            continue;
          }
          if (seen.has(source.path)) fail(at, "must describe each middleware source once");
          seen.add(source.path);

          if (!SEMANTIC_MODULE_EXTENSIONS.includes(source.extension)) {
            fail(`${at}.extension`, "must be a module source extension");
          }
          if (!MIDDLEWARE_SOURCE_STATUSES.includes(source.status)) {
            fail(`${at}.status`, "must be a documented middleware source status");
          }
          if (typeof source.established !== "boolean") {
            fail(`${at}.established`, "must be a boolean");
          }
          if (typeof source.truncated !== "boolean") {
            fail(`${at}.truncated`, "must be a boolean");
          }
          if (!Array.isArray(source.frameworks)) {
            fail(`${at}.frameworks`, "must be an array");
          } else {
            for (const framework of source.frameworks) {
              if (!MIDDLEWARE_FRAMEWORKS.includes(framework)) {
                fail(`${at}.frameworks`, "must name a supported framework");
              }
            }
          }
          if (!Array.isArray(source.receivers)) {
            fail(`${at}.receivers`, "must be an array");
          }
          if (!Array.isArray(source.registrations)) {
            fail(`${at}.registrations`, "must be an array");
          } else {
            for (const registration of source.registrations) {
              const registrationAt = `${at}.registrations[]`;
              if (!ENTITY_MIDDLEWARE_REGISTRATIONS.includes(registration?.registration)) {
                fail(`${registrationAt}.registration`, "must be a documented registration kind");
              }
              if (!ENTITY_MIDDLEWARE_SCOPES.includes(registration?.scope)) {
                fail(`${registrationAt}.scope`, "must be a documented scope");
              }
              if (!API_RECEIVER_KINDS.includes(registration?.receiverKind)) {
                fail(`${registrationAt}.receiverKind`, "must be app or router");
              }
              for (const entry of registration?.middleware ?? []) {
                if (!API_CALLABLE_FORMS.includes(entry?.form)) {
                  fail(`${registrationAt}.middleware`, "must be a documented callable form");
                }
              }
              for (const observation of registration?.unresolved ?? []) {
                if (!ENTITY_MIDDLEWARE_UNRESOLVED_REASONS.includes(observation?.reason)) {
                  fail(`${registrationAt}.unresolved`, "must be a documented reason");
                }
              }
            }
          }
          if (!Array.isArray(source.mounts)) {
            fail(`${at}.mounts`, "must be an array");
          }
          if (!Array.isArray(source.problems)) {
            fail(`${at}.problems`, "must be an array");
          } else {
            for (const problem of source.problems) {
              if (!MIDDLEWARE_PROBLEM_REASONS.includes(problem)) {
                fail(`${at}.problems[]`, "must be a documented problem");
              }
            }
          }
          if (!MIDDLEWARE_SOURCE_REASONS.includes(source.reason) && source.reason !== null) {
            fail(`${at}.reason`, "must be null or a documented reason");
          }
          if (!evidenceIds.has(source.evidenceId)) {
            fail(`${at}.evidenceId`, "must name an observation the model carries");
          }
        }
      }
      if (middlewareArea.count !== (Array.isArray(entries) ? entries.length : 0)) {
        fail("middleware.count", "must count the middleware sources the area carries");
      }

      const graph = middlewareArea.graph;
      if (!isPlainObject(graph)) {
        fail("middleware.graph", "must be a plain object");
      } else {
        const middlewareIds = new Set();
        if (!isNonEmptyString(graph.version)) {
          fail("middleware.graph.version", "must be a non-empty string");
        }
        if (!MIDDLEWARE_GRAPH_STATE_VALUES.includes(graph.state)) {
          fail("middleware.graph.state", `must be one of: ${MIDDLEWARE_GRAPH_STATE_VALUES.join(", ")}`);
        }
        if (typeof graph.established !== "boolean") {
          fail("middleware.graph.established", "must be a boolean");
        } else if (graph.established !== isEstablishedMiddlewareState(graph.state)) {
          fail("middleware.graph.established", "must agree with the state it reports");
        }

        if (!Array.isArray(graph.nodes)) {
          fail("middleware.graph.nodes", "must be an array");
        } else {
          if (graph.nodes.length > MIDDLEWARE_GRAPH_LIMITS.MAX_MIDDLEWARE) {
            fail("middleware.graph.nodes", "must stay within the graph node bound");
          }
          let previous = null;
          graph.nodes.forEach((node, index) => {
            const at = `middleware.graph.nodes[${index}]`;
            if (!isPlainObject(node)) {
              fail(at, "must be a plain object");
              return;
            }
            if (!isNonEmptyString(node.id)) {
              fail(`${at}.id`, "must be a non-empty string");
              return;
            }
            if (!symbolNodeIds.has(node.id)) {
              fail(`${at}.id`, "must name a symbol the symbol graph carries");
            }
            if (node.symbolId !== node.id) {
              fail(`${at}.symbolId`, "must be the symbol identity the node reuses");
            }
            if (!filePaths.has(node.path)) {
              fail(`${at}.path`, "must name a file the model observed");
            }
            if (node.fileId !== `file:${node.path}`) {
              fail(`${at}.fileId`, "must be the file entity of the declaring path");
            }
            if (!MIDDLEWARE_CLASSIFICATION_VALUES.includes(node.classification)) {
              fail(`${at}.classification`, "must be a documented classification");
            }
            for (const field of ["scopes", "registrations", "hooks", "receivers", "frameworks"]) {
              if (!Array.isArray(node[field])) fail(`${at}.${field}`, "must be an array");
            }
            for (const scope of Array.isArray(node.scopes) ? node.scopes : []) {
              if (!GRAPH_MIDDLEWARE_SCOPES.includes(scope)) {
                fail(`${at}.scopes`, "must be a documented scope");
              }
            }
            for (const registration of Array.isArray(node.registrations) ? node.registrations : []) {
              if (!GRAPH_MIDDLEWARE_REGISTRATIONS.includes(registration)) {
                fail(`${at}.registrations`, "must be a documented registration kind");
              }
            }
            for (const framework of Array.isArray(node.frameworks) ? node.frameworks : []) {
              if (!MIDDLEWARE_FRAMEWORKS.includes(framework)) {
                fail(`${at}.frameworks`, "must name a supported framework");
              }
            }
            for (const sourcePath of Array.isArray(node.sourcePaths) ? node.sourcePaths : []) {
              if (!filePaths.has(sourcePath)) {
                fail(`${at}.sourcePaths`, "must name files the model observed");
              }
            }
            for (const evidenceId of Array.isArray(node.evidenceIds) ? node.evidenceIds : []) {
              if (!evidenceIds.has(evidenceId)) {
                fail(`${at}.evidenceIds`, "must name observations the model carries");
              }
            }
            if (previous !== null && previous >= node.id) {
              fail("middleware.graph.nodes", "nodes must be sorted by id and unique");
            }
            previous = node.id;
            middlewareIds.add(node.id);
          });
        }

        if (!Array.isArray(graph.edges)) {
          fail("middleware.graph.edges", "must be an array");
        } else {
          if (graph.edges.length > MIDDLEWARE_GRAPH_LIMITS.MAX_EDGES) {
            fail("middleware.graph.edges", "must stay within the graph edge bound");
          }
          let previousKey = null;
          graph.edges.forEach((edge, index) => {
            const at = `middleware.graph.edges[${index}]`;
            if (!isPlainObject(edge)) {
              fail(at, "must be a plain object");
              return;
            }
            if (!MIDDLEWARE_EDGE_TYPE_VALUES.includes(edge.type)) {
              fail(`${at}.type`, "must be a documented edge type");
            }
            const endpointExists = (id) =>
              middlewareIds.has(id) || apiRouteIds.has(id) || fileIds.has(id);
            if (!endpointExists(edge.from)) {
              fail(`${at}.from`, "must name an entity the model carries");
            }
            if (!endpointExists(edge.to)) {
              fail(`${at}.to`, "must name an entity the model carries");
            }
            if (edge.type === MIDDLEWARE_EDGE_TYPES.REGISTERED_ON) {
              if (!middlewareIds.has(edge.from) || !fileIds.has(edge.to)) {
                fail(at, "a `registered-on` edge must join a middleware node to a file");
              }
            } else if (edge.type === MIDDLEWARE_EDGE_TYPES.PRECEDES) {
              if (!middlewareIds.has(edge.from) || !middlewareIds.has(edge.to)) {
                fail(at, "a `precedes` edge must join two middleware nodes");
              }
            } else if (!middlewareIds.has(edge.from) || !apiRouteIds.has(edge.to)) {
              fail(at, "a protection edge must join a middleware node to a route");
            }
            for (const evidenceId of Array.isArray(edge.evidenceIds) ? edge.evidenceIds : []) {
              if (!evidenceIds.has(evidenceId)) {
                fail(`${at}.evidenceIds`, "must name observations the model carries");
              }
            }
            const key = `${edge.from}\u0000${edge.to}\u0000${edge.type}`;
            if (previousKey !== null && key <= previousKey) {
              fail(
                "middleware.graph.edges",
                "must state each relationship once, sorted by (from, to, type)",
              );
            }
            previousKey = key;
          });
        }

        if (!Array.isArray(graph.routes)) {
          fail("middleware.graph.routes", "must be an array");
        } else {
          if (graph.routes.length > MIDDLEWARE_GRAPH_LIMITS.MAX_ROUTES) {
            fail("middleware.graph.routes", "must stay within the route bound");
          }
          const middlewareNames = new Map();
          let previousRoute = null;
          graph.routes.forEach((route, index) => {
            const at = `middleware.graph.routes[${index}]`;
            if (!isPlainObject(route)) {
              fail(at, "must be a plain object");
              return;
            }
            if (!apiRouteIds.has(route.route)) {
              fail(`${at}.route`, "must name a route the API graph carries");
            }
            if (route.route !== apiRouteIdOf(route.method, route.path)) {
              fail(`${at}.route`, "must be the identity of the endpoint it describes");
            }
            if (!MIDDLEWARE_PROTECTION_VALUES.includes(route.protection)) {
              fail(`${at}.protection`, "must be a documented protection state");
            }
            if (!Array.isArray(route.middleware)) {
              fail(`${at}.middleware`, "must be an array");
              return;
            }
            let previousMiddleware = null;
            for (const middlewareId of route.middleware) {
              if (!middlewareIds.has(middlewareId)) {
                fail(`${at}.middleware`, "must name middleware nodes the graph carries");
              }
              if (previousMiddleware !== null && previousMiddleware >= middlewareId) {
                fail(
                  `${at}.middleware`,
                  "must state each middleware once, sorted by id (no duplicate chains)",
                );
              }
              previousMiddleware = middlewareId;
            }
            const unresolvedCount = isNonNegativeInteger(route.unresolvedCount)
              ? route.unresolvedCount
              : -1;
            if (route.protection === MIDDLEWARE_PROTECTION_STATES.PROTECTED) {
              if (route.middleware.length === 0) {
                fail(`${at}.protection`, "cannot be protected without established middleware");
              }
            } else if (route.middleware.length > 0) {
              fail(`${at}.protection`, "must be protected when middleware was established");
            }
            if (route.protection === MIDDLEWARE_PROTECTION_STATES.UNRESOLVED && unresolvedCount <= 0) {
              fail(`${at}.protection`, "cannot be unresolved without an unresolved observation");
            }
            if (
              route.protection === MIDDLEWARE_PROTECTION_STATES.NONE_OBSERVED &&
              unresolvedCount > 0
            ) {
              // The whole point of the unresolved state: an occurrence that could be
              // middleware must never read as "this route has no middleware".
              fail(
                `${at}.protection`,
                "cannot be none-observed while an unresolved middleware observation exists",
              );
            }
            if (previousRoute !== null && previousRoute >= route.route) {
              fail("middleware.graph.routes", "routes must be sorted by id and unique");
            }
            previousRoute = route.route;
            middlewareNames.set(route.route, route.middleware);
          });

          // Edge consistency: a route's middleware list and the protection edges that name
          // it must describe the same set, so a consumer cannot read two answers.
          if (Array.isArray(graph.edges)) {
            for (const route of graph.routes) {
              if (!isPlainObject(route) || !isNonEmptyString(route.route)) continue;
              const fromEdges = sortedStringList(
                graph.edges
                  .filter(
                    (edge) =>
                      isPlainObject(edge) &&
                      edge.to === route.route &&
                      (edge.type === MIDDLEWARE_EDGE_TYPES.PROTECTS ||
                        edge.type === MIDDLEWARE_EDGE_TYPES.APPLIES_TO),
                  )
                  .map((edge) => edge.from),
              );
              const fromRoute = sortedStringList(middlewareNames.get(route.route) ?? []);
              if (fromEdges.join(",") !== fromRoute.join(",")) {
                fail(
                  `middleware.graph.routes[${route.route}].middleware`,
                  "must agree with the protection edges that name the route",
                );
              }
            }
          }
        }

        if (!Array.isArray(graph.unresolved)) {
          fail("middleware.graph.unresolved", "must be an array");
        } else {
          if (graph.unresolved.length > MIDDLEWARE_GRAPH_LIMITS.MAX_UNRESOLVED) {
            fail("middleware.graph.unresolved", "must stay within the unresolved bound");
          }
          let previousUnresolved = null;
          graph.unresolved.forEach((record, index) => {
            const at = `middleware.graph.unresolved[${index}]`;
            if (!isPlainObject(record)) {
              fail(at, "must be a plain object");
              return;
            }
            if (!filePaths.has(record.path)) {
              fail(`${at}.path`, "must name a file the model observed");
            }
            if (!MIDDLEWARE_UNRESOLVED_KINDS.includes(record.kind)) {
              fail(`${at}.kind`, "must be a registration or a route middleware");
            }
            if (!MIDDLEWARE_UNRESOLVED_REASON_VALUES.includes(record.reason)) {
              fail(`${at}.reason`, "must be a documented reason");
            }
            if (record.route !== null && !apiRouteIds.has(record.route)) {
              fail(`${at}.route`, "must be null or a route the API graph carries");
            }
            const key = `${record.path}\u0000${record.reason}\u0000${record.route ?? ""}\u0000${record.kind}\u0000${record.name ?? ""}`;
            if (previousUnresolved !== null && key < previousUnresolved) {
              fail("middleware.graph.unresolved", "must be sorted deterministically");
            }
            previousUnresolved = key;
          });
        }

        const coverage = graph.coverage;
        if (!isPlainObject(coverage)) {
          fail("middleware.graph.coverage", "must be a plain object");
        } else {
          if (coverage.state !== graph.state) {
            fail("middleware.graph.coverage.state", "must agree with the graph state");
          }
          if (coverage.established !== graph.established) {
            fail("middleware.graph.coverage.established", "must agree with the graph state");
          }
          if (coverage.middleware !== (Array.isArray(graph.nodes) ? graph.nodes.length : -1)) {
            fail("middleware.graph.coverage.middleware", "must count the middleware the graph contains");
          }
          if (coverage.edges !== (Array.isArray(graph.edges) ? graph.edges.length : -1)) {
            fail("middleware.graph.coverage.edges", "must count the edges the graph contains");
          }
          if (coverage.routes !== (Array.isArray(graph.routes) ? graph.routes.length : -1)) {
            fail("middleware.graph.coverage.routes", "must count the routes the graph describes");
          }
          if (
            coverage.unresolved !==
            (Array.isArray(graph.unresolved) ? graph.unresolved.length : -1)
          ) {
            fail("middleware.graph.coverage.unresolved", "must count every unresolved record");
          }
          if (coverage.truncated !== (graph.state === MIDDLEWARE_GRAPH_STATES.TRUNCATED)) {
            fail("middleware.graph.coverage.truncated", "must agree with the graph state");
          }
          if (coverage.complete !== (graph.state === MIDDLEWARE_GRAPH_STATES.COMPLETE)) {
            fail("middleware.graph.coverage.complete", "must agree with the graph state");
          }
          if (Array.isArray(graph.routes)) {
            const byState = {};
            for (const value of MIDDLEWARE_PROTECTION_VALUES) byState[value] = 0;
            for (const route of graph.routes) byState[route?.protection] = (byState[route?.protection] ?? 0) + 1;
            if (coverage.protectedRoutes !== byState[MIDDLEWARE_PROTECTION_STATES.PROTECTED]) {
              fail("middleware.graph.coverage.protectedRoutes", "must count the protected routes");
            }
            if (coverage.unresolvedRoutes !== byState[MIDDLEWARE_PROTECTION_STATES.UNRESOLVED]) {
              fail("middleware.graph.coverage.unresolvedRoutes", "must count the unresolved routes");
            }
            if (
              coverage.unprotectedRoutes !== byState[MIDDLEWARE_PROTECTION_STATES.NONE_OBSERVED]
            ) {
              fail("middleware.graph.coverage.unprotectedRoutes", "must count the routes with no observed middleware");
            }
          }
          if (graph.state === MIDDLEWARE_GRAPH_STATES.COMPLETE) {
            if (model.scan.complete !== true) {
              fail("middleware.graph.state", "cannot be complete unless the scan covered the repository");
            }
            const sources = Array.isArray(entries) ? entries : [];
            if (sources.length > 0 && !sources.every((source) => source.established === true)) {
              fail(
                "middleware.graph.state",
                "cannot be complete while a middleware source is unestablished",
              );
            }
          }
        }
      }

      if (
        isPlainObject(middlewareArea.coverage) &&
        isPlainObject(middlewareArea.graph?.coverage)
      ) {
        if (middlewareArea.coverage.unresolved !== middlewareArea.graph.coverage.unresolved) {
          fail("middleware.coverage.unresolved", "must agree with the graph it summarises");
        }
      }
    }
  }

  // ── Production report (Phase 20) ───────────────────────────────────────────
  //
  // The production report is the one projection whose *output* is itself the artifact a
  // consumer reads, so it is validated as a document rather than merely as a shape. A
  // malformed report is a **validation failure**, never a finding: a report that names a
  // section twice, orders its observations non-deterministically, cites an observation the
  // model does not carry, or claims more coverage than its own records support would let a
  // rule report something the repository never established.
  //
  // Five invariants carry the weight:
  //
  //   - the six sections appear **exactly once each, in their declared order**, so a
  //     consumer can address them positionally and no domain can be silently dropped;
  //   - every observation's `kind` is in *its* section's vocabulary, so a kind cannot be
  //     smuggled into a section it does not belong to;
  //   - every cited evidence id resolves to an observation the model carries, which is the
  //     whole point of the report: "what proves this?" always has an answer;
  //   - observations are sorted by a unique key and unknown records by `(reason, detail)`,
  //     so two reports of one repository state are byte-identical;
  //   - a section's state agrees with its own coverage, its own evidence list and its own
  //     counts, so `complete` can never sit next to a truncation or an evidence-less
  //     observation.
  if (isPlainObject(model.production)) {
    const productionArea = model.production;
    const report = productionArea.report;

    if (!PRODUCTION_REPORT_STATE_VALUES.includes(productionArea.state)) {
      fail("production.state", "must be a documented report state");
    } else if (productionArea.established !== isEstablishedProductionState(productionArea.state)) {
      fail("production.established", "must agree with the state it reports");
    }

    /** A bounded, control-character-free detail token (or `null`). */
    const isBoundedDetail = (value) =>
      value === null ||
      (typeof value === "string" &&
        value.length > 0 &&
        value.length <= 120 &&
        // eslint-disable-next-line no-control-regex
        !/[\u0000-\u001f]/.test(value));

    /** A `counts` value: a non-negative integer, a boolean, or a nested object of those. */
    const countsIssue = (value, depth) => {
      if (depth > 3) return "must stay within the report's count depth";
      if (isPlainObject(value)) {
        for (const key of Object.keys(value)) {
          const issue = countsIssue(value[key], depth + 1);
          if (issue !== null) return issue;
        }
        return null;
      }
      if (typeof value === "boolean") return null;
      if (isNonNegativeInteger(value)) return null;
      return "must be a non-negative integer, a boolean, or a nested object of those";
    };

    if (!isPlainObject(report)) {
      fail("production.report", "must be a plain object");
    } else {
      if (report.version !== PRODUCTION_REPORT_VERSION) {
        fail("production.report.version", "must be the report version this builder produces");
      }
      if (!PRODUCTION_REPORT_STATE_VALUES.includes(report.state)) {
        fail("production.report.state", "must be a documented report state");
      } else if (report.state !== productionArea.state) {
        fail("production.report.state", "must agree with the area it belongs to");
      }
      if (report.established !== productionArea.established) {
        fail("production.report.established", "must agree with the area it belongs to");
      }

      if (!Array.isArray(report.sections)) {
        fail("production.report.sections", "must be an array");
      } else {
        if (report.sections.length !== PRODUCTION_SECTIONS.length) {
          fail("production.report.sections", "must carry every audit domain exactly once");
        }

        report.sections.forEach((section, index) => {
          const at = `production.report.sections[${index}]`;
          if (!isPlainObject(section)) {
            fail(at, "must be a plain object");
            return;
          }
          if (!PRODUCTION_SECTIONS.includes(section.name)) {
            fail(`${at}.name`, "must be a declared audit domain");
            return;
          }
          // Declared order, and therefore uniqueness: the domain at a position must be the
          // one that position declares, so a domain can neither appear twice nor move.
          if (PRODUCTION_SECTIONS[index] !== section.name) {
            fail("production.report.sections", "must be ordered by domain and carry each once");
          }

          if (section.title !== PRODUCTION_SECTION_TITLES[section.name]) {
            fail(`${at}.title`, "must be the declared title of the domain it reports");
          }
          if (!PRODUCTION_REPORT_STATE_VALUES.includes(section.state)) {
            fail(`${at}.state`, "must be a documented report state");
          }
          if (section.established !== isEstablishedProductionState(section.state)) {
            fail(`${at}.established`, "must agree with the state it reports");
          }

          if (!isPlainObject(section.counts)) {
            fail(`${at}.counts`, "must be a plain object");
          } else {
            const issue = countsIssue(section.counts, 0);
            if (issue !== null) fail(`${at}.counts`, issue);
          }

          const kinds = PRODUCTION_OBSERVATION_KINDS[section.name];
          const evidenceCited = new Set();
          if (!Array.isArray(section.observations)) {
            fail(`${at}.observations`, "must be an array");
          } else {
            if (section.observations.length > PRODUCTION_REPORT_LIMITS.maxObservationsPerSection) {
              fail(`${at}.observations`, "must stay within the report's observation bound");
            }
            let previousKey = null;
            section.observations.forEach((observation, position) => {
              const where = `${at}.observations[${position}]`;
              if (!isPlainObject(observation)) {
                fail(where, "must be a plain object");
                return;
              }
              if (!kinds.includes(observation.kind)) {
                fail(`${where}.kind`, "must be an observation kind this domain declares");
              }
              if (!isNonEmptyString(observation.key)) {
                fail(`${where}.key`, "must be a non-empty deterministic key");
              } else if (previousKey !== null && !(previousKey < observation.key)) {
                fail(`${at}.observations`, "must be sorted by key and carry each key once");
              }
              previousKey = observation.key;

              if (!Array.isArray(observation.evidenceIds) || observation.evidenceIds.length === 0) {
                fail(`${where}.evidenceIds`, "must cite at least one observation");
                return;
              }
              if (
                observation.evidenceIds.length >
                PRODUCTION_REPORT_LIMITS.maxEvidencePerObservation
              ) {
                fail(`${where}.evidenceIds`, "must stay within the citation bound");
              }
              let previousEvidence = null;
              for (const id of observation.evidenceIds) {
                if (!evidenceIds.has(id)) {
                  fail(`${where}.evidenceIds`, "must name observations the model carries");
                }
                if (previousEvidence !== null && !(previousEvidence < id)) {
                  fail(`${where}.evidenceIds`, "must be sorted and unique");
                }
                previousEvidence = id;
                evidenceCited.add(id);
              }
            });
          }

          if (!Array.isArray(section.evidenceIds)) {
            fail(`${at}.evidenceIds`, "must be an array");
          } else {
            let previousEvidence = null;
            for (const id of section.evidenceIds) {
              if (!evidenceIds.has(id)) {
                fail(`${at}.evidenceIds`, "must name observations the model carries");
              }
              if (previousEvidence !== null && !(previousEvidence < id)) {
                fail(`${at}.evidenceIds`, "must be sorted and unique");
              }
              previousEvidence = id;
            }
            // The section's list is the union of its observations' citations — nothing more
            // and nothing less, so a consumer can trust either view.
            const declared = [...evidenceCited].sort();
            if (declared.join("\u0000") !== section.evidenceIds.join("\u0000")) {
              fail(`${at}.evidenceIds`, "must be the union of its observations' citations");
            }
          }

          const reasons = PRODUCTION_UNKNOWN_REASONS[section.name];
          const reasonCounts = new Map();
          if (!Array.isArray(section.unknown)) {
            fail(`${at}.unknown`, "must be an array");
          } else {
            if (
              section.unknown.length >
              PRODUCTION_REPORT_LIMITS.maxUnknownReasonsPerSection + 1
            ) {
              fail(`${at}.unknown`, "must stay within the report's abstention bound");
            }
            let previousRecord = null;
            section.unknown.forEach((record, position) => {
              const where = `${at}.unknown[${position}]`;
              if (!isPlainObject(record)) {
                fail(where, "must be a plain object");
                return;
              }
              if (!reasons.includes(record.reason)) {
                fail(`${where}.reason`, "must be a reason this domain declares");
              }
              if (!isBoundedDetail(record.detail)) {
                fail(`${where}.detail`, "must be a bounded token or null");
              }
              if (!Number.isInteger(record.count) || record.count < 1) {
                fail(`${where}.count`, "must be a positive integer");
              } else {
                reasonCounts.set(
                  record.reason,
                  (reasonCounts.get(record.reason) ?? 0) + record.count,
                );
              }
              const key = `${record.reason}\u0000${record.detail ?? ""}`;
              if (previousRecord !== null && !(previousRecord < key)) {
                fail(`${at}.unknown`, "must be sorted by (reason, detail) and carry each once");
              }
              previousRecord = key;
            });
          }

          const coverage = section.coverage;
          if (!isPlainObject(coverage)) {
            fail(`${at}.coverage`, "must be a plain object");
            return;
          }
          if (coverage.state !== section.state) {
            fail(`${at}.coverage.state`, "must agree with the section state");
          }
          if (coverage.established !== section.established) {
            fail(`${at}.coverage.established`, "must agree with the section state");
          }
          if (coverage.observations !== (Array.isArray(section.observations) ? section.observations.length : -1)) {
            fail(`${at}.coverage.observations`, "must count the observations the section carries");
          }
          if (coverage.evidence !== (Array.isArray(section.evidenceIds) ? section.evidenceIds.length : -1)) {
            fail(`${at}.coverage.evidence`, "must count the evidence the section cites");
          }
          if (
            coverage.unknownReasons !== (Array.isArray(section.unknown) ? section.unknown.length : -1)
          ) {
            fail(`${at}.coverage.unknownReasons`, "must count the abstentions the section carries");
          }
          if (typeof coverage.truncated !== "boolean") {
            fail(`${at}.coverage.truncated`, "must be a boolean");
          }

          // State ↔ content agreement, which is what stops an empty section from reading as
          // an answer and a cut-short section from reading as a complete one.
          const observationCount = Array.isArray(section.observations)
            ? section.observations.length
            : -1;
          if (section.state === PRODUCTION_REPORT_STATES.UNKNOWN && section.established !== false) {
            fail(`${at}.state`, "cannot be unknown while the section claims an answer");
          }
          // `unsupported` is a statement about *this implementation*, so it needs a basis: the
          // section must name the domain it cannot interpret, and it cannot have answered.
          // An empty observation list is deliberately **not** a basis — a section that read
          // everything and found nothing is `complete` — and observations are not disqualifying
          // either: observing that a file exists is a different statement from interpreting it,
          // so a section may report the artifacts it observed while refusing to answer.
          if (section.state === PRODUCTION_REPORT_STATES.UNSUPPORTED) {
            if (section.established !== false) {
              fail(`${at}.state`, "cannot be unsupported while the section claims an answer");
            }
            const basis = PRODUCTION_UNSUPPORTED_REASONS[section.name] ?? [];
            const named = Array.isArray(section.unknown)
              ? section.unknown.some((record) => basis.includes(record?.reason))
              : false;
            if (!named) {
              fail(`${at}.unknown`, "cannot be unsupported without naming the unread domain");
            }
          }
          // `complete` may legitimately carry zero observations: an inspected, empty domain is
          // an answer ("this repository declares nothing here"), and calling it unsupported
          // would be the conflation this contract exists to reject.
          if (
            section.state === PRODUCTION_REPORT_STATES.COMPLETE &&
            (section.established !== true || coverage.truncated === true)
          ) {
            fail(`${at}.state`, "cannot be complete unless it answered an untruncated reading");
          }
          if (
            section.state === PRODUCTION_REPORT_STATES.PARTIAL &&
            section.established !== true
          ) {
            fail(`${at}.state`, "cannot be partial without an established answer");
          }
          if (
            section.state === PRODUCTION_REPORT_STATES.TRUNCATED &&
            coverage.truncated !== true
          ) {
            fail(`${at}.state`, "cannot be truncated without a bound that bit");
          }
          // A bound that bit is *recorded*, and a recorded bound is what makes it real.
          const sawTruncation = Array.isArray(section.unknown)
            ? section.unknown.some((record) => record?.reason === "section-observations-truncated")
            : false;
          if (sawTruncation && observationCount !== PRODUCTION_REPORT_LIMITS.maxObservationsPerSection) {
            fail(`${at}.unknown`, "cannot report truncation the section did not reach");
          }
        });
      }

      const reportCoverage = report.coverage;
      if (!isPlainObject(reportCoverage)) {
        fail("production.report.coverage", "must be a plain object");
      } else if (Array.isArray(report.sections)) {
        if (reportCoverage.state !== report.state) {
          fail("production.report.coverage.state", "must agree with the report state");
        }
        if (reportCoverage.established !== report.established) {
          fail("production.report.coverage.established", "must agree with the report state");
        }
        if (reportCoverage.complete !== (report.state === PRODUCTION_REPORT_STATES.COMPLETE)) {
          fail("production.report.coverage.complete", "must agree with the report state");
        }
        if (typeof reportCoverage.truncated !== "boolean") {
          fail("production.report.coverage.truncated", "must be a boolean");
        }
        if (reportCoverage.sections !== report.sections.length) {
          fail("production.report.coverage.sections", "must count the sections the report carries");
        }
        const observations = report.sections.reduce(
          (total, section) =>
            total + (Array.isArray(section?.observations) ? section.observations.length : 0),
          0,
        );
        if (reportCoverage.observations !== observations) {
          fail("production.report.coverage.observations", "must count every observation");
        }
        if (
          reportCoverage.inspected !== (observations > 0)
        ) {
          fail("production.report.coverage.inspected", "must say whether any observation was made");
        }
        const evidence = report.sections.reduce(
          (total, section) =>
            total + (Array.isArray(section?.evidenceIds) ? section.evidenceIds.length : 0),
          0,
        );
        if (reportCoverage.evidence !== evidence) {
          fail("production.report.coverage.evidence", "must count every cited observation");
        }
        // The census must be the sections' own abstentions, totalled, so the two views of
        // one fact cannot disagree.
        if (!isPlainObject(reportCoverage.unknownReasons)) {
          fail("production.report.coverage.unknownReasons", "must be a plain object");
        } else {
          const expected = {};
          for (const section of report.sections) {
            for (const entry of Array.isArray(section?.unknown) ? section.unknown : []) {
              if (!isPlainObject(entry) || typeof entry.reason !== "string") continue;
              expected[entry.reason] = (expected[entry.reason] ?? 0) + (entry.count ?? 0);
            }
          }
          const keys = Object.keys(reportCoverage.unknownReasons);
          if (keys.join("\u0000") !== keys.slice().sort().join("\u0000")) {
            fail("production.report.coverage.unknownReasons", "must be ordered by reason");
          }
          for (const key of keys) {
            if (reportCoverage.unknownReasons[key] !== expected[key]) {
              fail(
                `production.report.coverage.unknownReasons.${key}`,
                "must total the sections' own abstentions",
              );
            }
          }
          for (const key of Object.keys(expected)) {
            if (!(key in reportCoverage.unknownReasons)) {
              fail(
                `production.report.coverage.unknownReasons.${key}`,
                "must total the sections' own abstentions",
              );
            }
          }
        }
        if (productionArea.detected !== observations > 0) {
          fail("production.detected", "must say whether the report established anything");
        }

        // The report's own state must follow from its sections: complete only when every
        // domain answered, unknown only when none did. A section that could not answer (an
        // uninterpreted domain, or nothing established behind it) keeps the report `partial`
        // rather than letting it claim a completeness one of its domains does not have.
        const states = report.sections.map((section) => section?.state);
        const finalStates = states.every(
          (state) => state === PRODUCTION_REPORT_STATES.COMPLETE,
        );
        const truncatedStates = states.some(
          (state) => state === PRODUCTION_REPORT_STATES.TRUNCATED,
        );
        const establishedStates = report.sections.filter(
          (section) => section?.established === true,
        ).length;
        const expectedState = truncatedStates
          ? PRODUCTION_REPORT_STATES.TRUNCATED
          : finalStates
            ? PRODUCTION_REPORT_STATES.COMPLETE
            : establishedStates > 0
              ? PRODUCTION_REPORT_STATES.PARTIAL
              : PRODUCTION_REPORT_STATES.UNKNOWN;
        if (report.state !== expectedState) {
          fail("production.report.state", "must follow from the sections it summarises");
        }
      }
    }

    if (isPlainObject(productionArea.coverage) && isPlainObject(report?.coverage)) {
      for (const field of ["state", "established", "complete", "truncated", "inspected"]) {
        if (productionArea.coverage[field] !== report.coverage[field]) {
          fail(`production.coverage.${field}`, "must agree with the report it summarises");
        }
      }
      if (productionArea.coverage.sections !== report.coverage.sections) {
        fail("production.coverage.sections", "must agree with the report it summarises");
      }
      if (productionArea.coverage.observations !== report.coverage.observations) {
        fail("production.coverage.observations", "must agree with the report it summarises");
      }
      if (productionArea.coverage.evidence !== report.coverage.evidence) {
        fail("production.coverage.evidence", "must agree with the report it summarises");
      }
    }
  }

  // ── Production risk report (Phase 21) ──────────────────────────────────────
  //
  // The second report-shaped projection, validated as a document for the same reason the
  // first one is: its findings are what a consumer acts on, so a report that repeats a
  // finding, orders them non-deterministically, cites an observation the model does not
  // carry, states a classification or a severity its own kind does not declare, claims a
  // defect its kind is classified as an observation for, or renders prose that disagrees with
  // its data must be a **validation failure** rather than a finding.
  //
  // Six invariants carry the weight:
  //
  //   - the six domains appear **exactly once each, in their declared order**;
  //   - every finding's `kind` is in *its* section's vocabulary, and its classification,
  //     severity, confidence and basis are the ones the kind's own tables declare — so neither
  //     can be invented for a kind, a finding may claim a defect **only** where its kind is
  //     classified as one (an observation is `info` and may not be anything else), and there is
  //     no `high` or `critical` anywhere;
  //   - every finding's `statement` and `remediation` are **recomputed** here from its own
  //     record and must match, so a sentence cannot drift from the evidence it claims;
  //   - every cited evidence id resolves to an observation the model carries;
  //   - findings are ordered by a key unique within their section, and abstentions by
  //     `(reason, detail)`, so two reports of one repository state are byte-identical;
  //   - the report's own lists are the sections' lists, its coverage totals are the sections'
  //     totals, and its state follows from its sections — never the other way round.
  if (isPlainObject(model.productionRisk)) {
    const riskArea = model.productionRisk;
    const riskReport = riskArea.report;

    if (!PRODUCTION_RISK_STATE_VALUES.includes(riskArea.state)) {
      fail("productionRisk.state", "must be a documented report state");
    } else if (riskArea.established !== isEstablishedRiskState(riskArea.state)) {
      fail("productionRisk.established", "must agree with the state it reports");
    }

    /** A bounded, control-character-free detail token (or `null`). */
    const isRiskDetail = (value) =>
      value === null ||
      (typeof value === "string" &&
        value.length > 0 &&
        value.length <= 120 &&
        // eslint-disable-next-line no-control-regex
        !/[\u0000-\u001f]/.test(value));

    if (!isPlainObject(riskReport)) {
      fail("productionRisk.report", "must be a plain object");
    } else {
      if (riskReport.version !== PRODUCTION_RISK_REPORT_VERSION) {
        fail("productionRisk.report.version", "must be the report version this builder produces");
      }
      if (!PRODUCTION_RISK_STATE_VALUES.includes(riskReport.state)) {
        fail("productionRisk.report.state", "must be a documented report state");
      } else if (riskReport.state !== riskArea.state) {
        fail("productionRisk.report.state", "must agree with the area it belongs to");
      }
      if (riskReport.established !== riskArea.established) {
        fail("productionRisk.report.established", "must agree with the area it belongs to");
      }

      /** Every finding id the report carries, for the uniqueness check. */
      const findingIds = new Set();

      if (!Array.isArray(riskReport.sections)) {
        fail("productionRisk.report.sections", "must be an array");
      } else {
        if (riskReport.sections.length !== PRODUCTION_RISK_SECTIONS.length) {
          fail("productionRisk.report.sections", "must carry every audit domain exactly once");
        }

        riskReport.sections.forEach((section, index) => {
          const at = `productionRisk.report.sections[${index}]`;
          if (!isPlainObject(section)) {
            fail(at, "must be a plain object");
            return;
          }
          if (!PRODUCTION_RISK_SECTIONS.includes(section.name)) {
            fail(`${at}.name`, "must be a declared audit domain");
            return;
          }
          if (PRODUCTION_RISK_SECTIONS[index] !== section.name) {
            fail("productionRisk.report.sections", "must be ordered by domain and carry each once");
          }
          if (section.title !== PRODUCTION_RISK_SECTION_TITLES[section.name]) {
            fail(`${at}.title`, "must be the declared title of the domain it reports");
          }
          if (!PRODUCTION_RISK_STATE_VALUES.includes(section.state)) {
            fail(`${at}.state`, "must be a documented report state");
          }
          if (section.established !== isEstablishedRiskState(section.state)) {
            fail(`${at}.established`, "must agree with the state it reports");
          }

          const kinds = PRODUCTION_RISK_FINDING_KINDS[section.name] ?? [];
          const evidenceCited = new Set();
          if (!Array.isArray(section.findings)) {
            fail(`${at}.findings`, "must be an array");
          } else {
            if (section.findings.length > PRODUCTION_RISK_REPORT_LIMITS.maxFindingsPerSection) {
              fail(`${at}.findings`, "must stay within the report's finding bound");
            }
            let previousKey = null;
            section.findings.forEach((finding, position) => {
              const where = `${at}.findings[${position}]`;
              if (!isPlainObject(finding)) {
                fail(where, "must be a plain object");
                return;
              }
              if (finding.section !== section.name) {
                fail(`${where}.section`, "must be the section it is reported in");
              }
              if (!kinds.includes(finding.kind)) {
                fail(`${where}.kind`, "must be a finding kind this domain declares");
              }
              if (!isNonEmptyString(finding.key)) {
                fail(`${where}.key`, "must be a non-empty deterministic key");
              } else if (previousKey !== null && !(previousKey < finding.key)) {
                fail(`${at}.findings`, "must be sorted by key and carry each key once");
              }
              previousKey = isNonEmptyString(finding.key) ? finding.key : previousKey;
              if (finding.id !== `${section.name}:${finding.kind}:${finding.key}`) {
                fail(`${where}.id`, "must be derived from the section, kind and key");
              } else if (findingIds.has(finding.id)) {
                fail(`${where}.id`, "must be unique within the report");
              } else {
                findingIds.add(finding.id);
              }

              // The closed tables, each pinned to the kind rather than trusted. The
              // classification is checked first and the severity against it, because the whole
              // point of the pair is that a finding cannot claim a defect its kind does not:
              // an `observation` is `info` and nothing else, and a `risk` may not be silent.
              if (!PRODUCTION_RISK_CLASSIFICATION_VALUES.includes(finding.classification)) {
                fail(`${where}.classification`, "must be a classification this report declares");
              } else if (
                finding.classification !== PRODUCTION_RISK_CLASSIFICATION_BY_KIND[finding.kind]
              ) {
                fail(`${where}.classification`, "must be the classification its kind declares");
              } else if (
                finding.classification === PRODUCTION_RISK_CLASSIFICATIONS.OBSERVATION &&
                finding.severity !== PRODUCTION_RISK_SEVERITIES.INFO
              ) {
                fail(`${where}.severity`, "cannot claim a defect of a kind that observes");
              } else if (
                finding.classification === PRODUCTION_RISK_CLASSIFICATIONS.RISK &&
                finding.severity === PRODUCTION_RISK_SEVERITIES.INFO
              ) {
                fail(`${where}.severity`, "cannot leave a defect its kind declares unstated");
              }
              if (!PRODUCTION_RISK_SEVERITY_VALUES.includes(finding.severity)) {
                fail(`${where}.severity`, "must be a severity this report declares");
              } else if (finding.severity !== PRODUCTION_RISK_SEVERITY_BY_KIND[finding.kind]) {
                fail(`${where}.severity`, "must be the severity its kind declares");
              }
              if (!PRODUCTION_RISK_CONFIDENCE_VALUES.includes(finding.confidence)) {
                fail(`${where}.confidence`, "must be a confidence this report declares");
              }
              if (!isNonEmptyString(finding.basis)) {
                fail(`${where}.basis`, "must name what was read");
              } else if (finding.basis !== PRODUCTION_RISK_BASIS_BY_KIND[finding.kind]) {
                fail(`${where}.basis`, "must be the basis its kind declares");
              }

              // Prose is a pure function of the record: it is recomputed and compared, so a
              // sentence that claims more than its own data supports cannot survive.
              if (finding.statement !== renderRiskStatement(finding.kind, finding)) {
                fail(`${where}.statement`, "must be the statement its own record renders");
              }
              if (finding.remediation !== renderRiskRemediation(finding.kind, finding)) {
                fail(`${where}.remediation`, "must be the remediation its own record renders");
              }
              if (
                finding.remediation !== null &&
                (typeof finding.remediation !== "string" ||
                  finding.remediation.length > PRODUCTION_RISK_REPORT_LIMITS.maxRemediationLength)
              ) {
                fail(`${where}.remediation`, "must be null or a bounded sentence");
              }

              if (!Array.isArray(finding.evidenceIds) || finding.evidenceIds.length === 0) {
                fail(`${where}.evidenceIds`, "must cite at least one observation");
                return;
              }
              if (finding.evidenceIds.length > PRODUCTION_RISK_REPORT_LIMITS.maxEvidencePerFinding) {
                fail(`${where}.evidenceIds`, "must stay within the citation bound");
              }
              let previousEvidence = null;
              for (const id of finding.evidenceIds) {
                if (!evidenceIds.has(id)) {
                  fail(`${where}.evidenceIds`, "must name observations the model carries");
                }
                if (previousEvidence !== null && !(previousEvidence < id)) {
                  fail(`${where}.evidenceIds`, "must be sorted and unique");
                }
                previousEvidence = id;
                evidenceCited.add(id);
              }

              // Every optional domain field a finding may carry is checked for the shape its
              // statement's own rendering depends on: a count is a count, a bounded path list
              // says whether the bound bit, and a `class`, `detail` or `ecosystem` is a token.
              if ("count" in finding && !isNonNegativeInteger(finding.count)) {
                fail(`${where}.count`, "must be a non-negative integer");
              }
              if ("pathsTruncated" in finding && typeof finding.pathsTruncated !== "boolean") {
                fail(`${where}.pathsTruncated`, "must be a boolean");
              }
              if ("paths" in finding) {
                if (!Array.isArray(finding.paths)) {
                  fail(`${where}.paths`, "must be an array");
                } else if (finding.paths.length > PRODUCTION_RISK_REPORT_LIMITS.maxPathsPerFinding) {
                  fail(`${where}.paths`, "must stay within the path bound");
                }
              }
            });
          }

          if (!isPlainObject(section.counts)) {
            fail(`${at}.counts`, "must be a plain object");
          } else {
            const findings = Array.isArray(section.findings) ? section.findings : [];
            if (section.counts.findings !== findings.length) {
              fail(`${at}.counts.findings`, "must count the findings the section carries");
            }
            const expectedKinds = {};
            for (const kind of [...new Set(findings.map((entry) => entry?.kind))].sort()) {
              if (typeof kind !== "string") continue;
              expectedKinds[kind] = findings.filter((entry) => entry?.kind === kind).length;
            }
            if (
              JSON.stringify(section.counts.byKind ?? {}) !== JSON.stringify(expectedKinds)
            ) {
              fail(`${at}.counts.byKind`, "must census the findings the section carries");
            }
            const severities = section.counts.bySeverity;
            if (!isPlainObject(severities)) {
              fail(`${at}.counts.bySeverity`, "must be a plain object");
            } else {
              const keys = Object.keys(severities);
              if (keys.join("\u0000") !== [...PRODUCTION_RISK_SEVERITY_VALUES].join("\u0000")) {
                fail(`${at}.counts.bySeverity`, "must census every severity this report declares");
              }
              for (const severity of PRODUCTION_RISK_SEVERITY_VALUES) {
                if (!isNonNegativeInteger(severities[severity])) {
                  fail(`${at}.counts.bySeverity.${severity}`, "must be a non-negative integer");
                } else if (
                  severities[severity] !==
                  findings.filter((entry) => entry?.severity === severity).length
                ) {
                  fail(`${at}.counts.bySeverity.${severity}`, "must census the findings it names");
                }
              }
            }
          }

          if (!Array.isArray(section.evidenceIds)) {
            fail(`${at}.evidenceIds`, "must be an array");
          } else {
            let previousEvidence = null;
            for (const id of section.evidenceIds) {
              if (!evidenceIds.has(id)) {
                fail(`${at}.evidenceIds`, "must name observations the model carries");
              }
              if (previousEvidence !== null && !(previousEvidence < id)) {
                fail(`${at}.evidenceIds`, "must be sorted and unique");
              }
              previousEvidence = id;
            }
            const declared = [...evidenceCited].sort();
            if (declared.join("\u0000") !== section.evidenceIds.join("\u0000")) {
              fail(`${at}.evidenceIds`, "must be the union of its findings' citations");
            }
          }

          // The abstention vocabulary is the inventory section's own, plus the reasons this
          // report may add — so a risk section can neither invent a reason nor lose the
          // knowledge gaps it inherited.
          const reasons = [
            ...(PRODUCTION_UNKNOWN_REASONS[section.name] ?? []),
            ...(PRODUCTION_RISK_UNKNOWN_REASONS[section.name] ?? []),
          ];
          if (!Array.isArray(section.unknown)) {
            fail(`${at}.unknown`, "must be an array");
          } else {
            if (section.unknown.length > PRODUCTION_RISK_REPORT_LIMITS.maxUnknownReasonsPerSection) {
              fail(`${at}.unknown`, "must stay within the report's abstention bound");
            }
            let previousRecord = null;
            section.unknown.forEach((record, position) => {
              const where = `${at}.unknown[${position}]`;
              if (!isPlainObject(record)) {
                fail(where, "must be a plain object");
                return;
              }
              if (!reasons.includes(record.reason)) {
                fail(`${where}.reason`, "must be a reason this domain declares");
              }
              if (!isRiskDetail(record.detail)) {
                fail(`${where}.detail`, "must be a bounded token or null");
              }
              if (!Number.isInteger(record.count) || record.count < 1) {
                fail(`${where}.count`, "must be a positive integer");
              }
              const key = `${record.reason}\u0000${record.detail ?? ""}`;
              if (previousRecord !== null && !(previousRecord < key)) {
                fail(`${at}.unknown`, "must be sorted by (reason, detail) and carry each once");
              }
              previousRecord = key;
            });
          }

          const coverage = section.coverage;
          if (!isPlainObject(coverage)) {
            fail(`${at}.coverage`, "must be a plain object");
            return;
          }
          if (coverage.state !== section.state) {
            fail(`${at}.coverage.state`, "must agree with the section state");
          }
          if (coverage.established !== section.established) {
            fail(`${at}.coverage.established`, "must agree with the section state");
          }
          if (
            coverage.findings !== (Array.isArray(section.findings) ? section.findings.length : -1)
          ) {
            fail(`${at}.coverage.findings`, "must count the findings the section carries");
          }
          if (
            coverage.evidence !== (Array.isArray(section.evidenceIds) ? section.evidenceIds.length : -1)
          ) {
            fail(`${at}.coverage.evidence`, "must count the evidence the section cites");
          }
          if (
            coverage.unknownReasons !== (Array.isArray(section.unknown) ? section.unknown.length : -1)
          ) {
            fail(`${at}.coverage.unknownReasons`, "must count the abstentions the section carries");
          }
          if (typeof coverage.truncated !== "boolean") {
            fail(`${at}.coverage.truncated`, "must be a boolean");
          }

          // State ↔ content agreement. `unsupported` and `unknown` are the two states that
          // mean no answer, for two different reasons, and both need a basis: `unsupported`
          // names the uninterpreted domain, `unknown` names what was not established. A
          // `complete` section may carry zero findings — "this repository's evidence shows no
          // gap in this domain" is an answer, and it is exactly what a detection that found
          // nothing must read as.
          if (section.state === PRODUCTION_RISK_STATES.UNKNOWN && section.established !== false) {
            fail(`${at}.state`, "cannot be unknown while the section claims an answer");
          }
          if (section.state === PRODUCTION_RISK_STATES.UNSUPPORTED) {
            if (section.established !== false) {
              fail(`${at}.state`, "cannot be unsupported while the section claims an answer");
            }
            const basis = [
              ...(PRODUCTION_UNSUPPORTED_REASONS[section.name] ?? []),
              ...(PRODUCTION_RISK_UNSUPPORTED_REASONS[section.name] ?? []),
            ];
            const named = Array.isArray(section.unknown)
              ? section.unknown.some((record) => basis.includes(record?.reason))
              : false;
            if (!named) {
              fail(`${at}.unknown`, "cannot be unsupported without naming the unread domain");
            }
          }
          if (
            section.state === PRODUCTION_RISK_STATES.COMPLETE &&
            (section.established !== true || coverage.truncated === true)
          ) {
            fail(`${at}.state`, "cannot be complete unless it answered an untruncated reading");
          }
          if (
            section.state === PRODUCTION_RISK_STATES.PARTIAL &&
            section.established !== true
          ) {
            fail(`${at}.state`, "cannot be partial without an established answer");
          }
          if (
            section.state === PRODUCTION_RISK_STATES.TRUNCATED &&
            coverage.truncated !== true
          ) {
            fail(`${at}.state`, "cannot be truncated without a bound that bit");
          }
          const sawTruncation = Array.isArray(section.unknown)
            ? section.unknown.some((record) => record?.reason === "risk-findings-truncated")
            : false;
          if (
            sawTruncation &&
            (!Array.isArray(section.findings) ||
              section.findings.length !== PRODUCTION_RISK_REPORT_LIMITS.maxFindingsPerSection)
          ) {
            fail(`${at}.unknown`, "cannot report truncation the section did not reach");
          }
        });
      }

      // The report's own lists are the sections' lists, one level up: the flat `findings`,
      // `evidenceIds` and `unknowns` a consumer may read directly cannot disagree with the
      // sections they came from.
      if (Array.isArray(riskReport.sections)) {
        const flatFindings = riskReport.sections.flatMap((section) =>
          Array.isArray(section?.findings) ? section.findings : [],
        );
        if (!Array.isArray(riskReport.findings)) {
          fail("productionRisk.report.findings", "must be an array");
        } else if (riskReport.findings.length !== flatFindings.length) {
          fail("productionRisk.report.findings", "must carry every section's findings");
        } else {
          for (let index = 0; index < flatFindings.length; index += 1) {
            if (riskReport.findings[index]?.id !== flatFindings[index]?.id) {
              fail("productionRisk.report.findings", "must be the sections' findings in order");
              break;
            }
          }
        }

        const flatEvidence = [
          ...new Set(
            riskReport.sections.flatMap((section) =>
              Array.isArray(section?.evidenceIds) ? section.evidenceIds : [],
            ),
          ),
        ].sort();
        if (!Array.isArray(riskReport.evidenceIds)) {
          fail("productionRisk.report.evidenceIds", "must be an array");
        } else if (riskReport.evidenceIds.join("\u0000") !== flatEvidence.join("\u0000")) {
          fail("productionRisk.report.evidenceIds", "must be every citation the sections make");
        }

        const flatUnknowns = riskReport.sections.flatMap((section) =>
          (Array.isArray(section?.unknown) ? section.unknown : []).map((record) => ({
            section: section.name,
            reason: record.reason,
            detail: record.detail ?? null,
            count: record.count,
          })),
        );
        if (!Array.isArray(riskReport.unknowns)) {
          fail("productionRisk.report.unknowns", "must be an array");
        } else if (
          JSON.stringify(riskReport.unknowns) !== JSON.stringify(flatUnknowns)
        ) {
          fail("productionRisk.report.unknowns", "must be the sections' own abstentions");
        }

        const coverageReport = riskReport.coverage;
        if (!isPlainObject(coverageReport)) {
          fail("productionRisk.report.coverage", "must be a plain object");
        } else {
          if (coverageReport.state !== riskReport.state) {
            fail("productionRisk.report.coverage.state", "must agree with the report state");
          }
          if (coverageReport.established !== riskReport.established) {
            fail("productionRisk.report.coverage.established", "must agree with the report state");
          }
          if (
            coverageReport.complete !== (riskReport.state === PRODUCTION_RISK_STATES.COMPLETE)
          ) {
            fail("productionRisk.report.coverage.complete", "must agree with the report state");
          }
          if (typeof coverageReport.truncated !== "boolean") {
            fail("productionRisk.report.coverage.truncated", "must be a boolean");
          }
          if (coverageReport.sections !== riskReport.sections.length) {
            fail("productionRisk.report.coverage.sections", "must count the sections it carries");
          }
          if (coverageReport.findings !== flatFindings.length) {
            fail("productionRisk.report.coverage.findings", "must count every finding");
          }
          const sectionEvidence = riskReport.sections.reduce(
            (total, section) =>
              total + (Array.isArray(section?.evidenceIds) ? section.evidenceIds.length : 0),
            0,
          );
          if (coverageReport.evidence !== sectionEvidence) {
            fail("productionRisk.report.coverage.evidence", "must count every citation");
          }
          if (
            coverageReport.sectionsWithFindings !==
            riskReport.sections.filter((section) => (section?.findings?.length ?? 0) > 0).length
          ) {
            fail(
              "productionRisk.report.coverage.sectionsWithFindings",
              "must count the sections that carry a finding",
            );
          }
          const severities = coverageReport.severities;
          if (!isPlainObject(severities)) {
            fail("productionRisk.report.coverage.severities", "must be a plain object");
          } else {
            for (const severity of PRODUCTION_RISK_SEVERITY_VALUES) {
              if (severities[severity] !== flatFindings.filter((e) => e?.severity === severity).length) {
                fail(
                  `productionRisk.report.coverage.severities.${severity}`,
                  "must census the findings the report carries",
                );
              }
            }
          }
          const unknownReasons = coverageReport.unknownReasons;
          if (!isPlainObject(unknownReasons)) {
            fail("productionRisk.report.coverage.unknownReasons", "must be a plain object");
          } else {
            const expected = {};
            for (const record of riskReport.unknowns ?? []) {
              if (!isPlainObject(record) || typeof record.reason !== "string") continue;
              expected[record.reason] = (expected[record.reason] ?? 0) + (record.count ?? 0);
            }
            const keys = Object.keys(unknownReasons);
            if (keys.join("\u0000") !== keys.slice().sort().join("\u0000")) {
              fail("productionRisk.report.coverage.unknownReasons", "must be ordered by reason");
            }
            for (const key of [...new Set([...keys, ...Object.keys(expected)])]) {
              if (unknownReasons[key] !== expected[key]) {
                fail(
                  `productionRisk.report.coverage.unknownReasons.${key}`,
                  "must total the sections' own abstentions",
                );
              }
            }
          }
          if (!isPlainObject(coverageReport.limits)) {
            fail("productionRisk.report.coverage.limits", "must be a plain object");
          }

          // The report's state follows from its sections, exactly as the inventory report's
          // does: complete only when every domain answered, unknown only when none did.
          const states = riskReport.sections.map((section) => section?.state);
          const truncatedStates = states.some(
            (state) => state === PRODUCTION_RISK_STATES.TRUNCATED,
          );
          const expectedState = truncatedStates
            ? PRODUCTION_RISK_STATES.TRUNCATED
            : states.every((state) => state === PRODUCTION_RISK_STATES.COMPLETE)
              ? PRODUCTION_RISK_STATES.COMPLETE
              : riskReport.sections.some((section) => section?.established === true)
                ? PRODUCTION_RISK_STATES.PARTIAL
                : PRODUCTION_RISK_STATES.UNKNOWN;
          if (riskReport.state !== expectedState) {
            fail("productionRisk.report.state", "must follow from the sections it summarises");
          }
          if (coverageReport.truncated !== truncatedStates) {
            fail(
              "productionRisk.report.coverage.truncated",
              "must agree with the sections it summarises",
            );
          }
          if (riskArea.detected !== flatFindings.length > 0) {
            fail("productionRisk.detected", "must say whether the report established a gap");
          }
        }
      }
    }

    if (isPlainObject(riskArea.coverage) && isPlainObject(riskReport?.coverage)) {
      for (const field of [
        "state",
        "established",
        "complete",
        "truncated",
        "sections",
        "findings",
        "evidence",
        "sectionsWithFindings",
      ]) {
        if (riskArea.coverage[field] !== riskReport.coverage[field]) {
          fail(`productionRisk.coverage.${field}`, "must agree with the report it summarises");
        }
      }
      if (
        JSON.stringify(riskArea.coverage.severities ?? {}) !==
        JSON.stringify(riskReport.coverage.severities ?? {})
      ) {
        fail("productionRisk.coverage.severities", "must agree with the report it summarises");
      }
    }
  }

  // ── Policy and compliance (Phase 22) ──────────────────────────────────────
  //
  // The policy area is validated before the report that measures it, because the report's own
  // checks read the document the area publishes: an invalid document must fail as an invalid
  // *policy* rather than as a compliance item nobody can explain.
  collectPolicyAreaIssues(model, fail);
  collectComplianceIssues(model, fail);

  checkIndexCoverage(model, entityIds, evidenceIds, { fail });

  if (issues.length > 0) {
    throw new ValidationError("Invalid repository model graph", {
      details: { contract: "RepositoryModelGraph", issues },
    });
  }

  return model;
}
