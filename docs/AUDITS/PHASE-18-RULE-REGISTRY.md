# Phase 18 — Rule Registry (architectural decisions)

Official roadmap Phase 18 (`docs/ROADMAPS/Code Guardian — Long-Term Development Roadmap.md`, §22)
asks, once several analyzers exist, to **formalize the rule registry**:

```
RuleRegistry
Capabilities: register · lookup · version · filter · applicability ·
              enable/disable · category selection · configuration
Rule metadata becomes discoverable.
```

The repository already had a working registry (`src/rules/registry.js`, Phase 10) plus eight
domain packs each wrapping it with a namespace/completeness guarantee. Phase 18 does **not**
replace that architecture: it keeps the catalog/evaluator/engine separation and makes the catalog
carry the roadmap's full rule-management surface. This file records the decisions.

## 1. Why the Phase 10 registry was sufficient and insufficient

**Sufficient.** Registration, id uniqueness, descriptor validation, id-sorted listing and
`select(ids)` with unknown-id-as-error were correct and are depended on by the Rule Engine and by
every domain pack. None of that needed redesigning.

**Insufficient.** The catalog could register and list, but it could not be *managed*: there was no
metadata discovery, no filtering, no activation state, no configuration channel, and no
version/category surface. "Once several analyzers exist" — security, testing, code quality, CI/CD,
architecture, dependency analysis, API analysis, reliability analysis — a consumer needs to ask
*which rules exist, what they declare, and which of them should run*, without reaching into the
registry's private `Map`.

## 2. The layering is preserved (the central constraint)

```
Core            defines the Rule shape
RuleRegistry    catalogs · validates · selects · configures · exposes metadata · tracks enabled state
Applicability   evaluateRuleApplicability() decides whether a rule applies to a RepositoryModel
Rule Engine     executes rules · isolates failures · validates findings/evidence
Analyzer        composes rule execution for a domain
```

The registry never runs `detect()`, never evaluates selectors itself, and never aggregates
findings. `registry.evaluateApplicability(id, context)` is a **thin delegate** to the existing
`evaluateRuleApplicability` — exactly one semantic applicability implementation exists. The
registry is still "a catalog, not an evaluator."

## 3. New registry contract

All additions are **additive**; the Phase 10 methods keep their exact behavior.

| Method | Semantics |
| --- | --- |
| `register(rule)` / `registerAll(list)` | unchanged: validate, reject duplicates, freeze a structural copy |
| `get(id)` / `has(id)` | unchanged compatibility lookup |
| `lookup(id)` | canonical lookup name; a rule or `null` |
| `version(id)` | the rule's own declared version, or `null`; never a second registry version |
| `ids()` / `list()` | id-sorted; includes disabled rules |
| `filter(criteria)` | catalog entries matching metadata selectors (see §5) |
| `select(ids)` | execution candidates; unknown **or disabled** id is a configuration error |
| `selectCategories(categories)` | enabled rules in the given categories, id-sorted, deduped |
| `enabledIds()` / `activeRules()` | enabled registered ids/rules |
| `isEnabled(id)` / `enable(id)` / `disable(id)` | activation configuration |
| `configure(config)` / `configuration()` | the closed, data-only configuration channel |
| `describe(id)` / `describeAll()` | safe, deeply frozen metadata discovery (no `detect`) |
| `evaluateApplicability(id, context)` | delegate to the single applicability evaluator |
| `size` | unchanged: count of registered rules |

## 4. Registry immutability model

The public handle is `Object.freeze`d (unchanged). Registration and configuration are
**accumulated onto internal state** through that frozen handle, exactly as Phase 10 `register`
already worked — the frozen handle never becomes a mutable object, and no Rule descriptor is ever
mutated. `configuration()`, `describe()` and `describeAll()` return fresh, deeply frozen,
serializable snapshots. Callers cannot mutate what the registry will run, and mutating a returned
snapshot cannot reach the registry.

## 5. Filter semantics

`filter(criteria)` is a pure catalog query — it never executes a rule and never mutates state.

* Keys combine with **AND**; the values inside one key combine with **OR**.
* Recognized keys: `id`, `namespace` (`x` or `x.*`), `category`, `version`, `tags`,
  `deprecated`, `enabled`.
* An **unknown key is a configuration error**, never a silently ignored criterion.
* `deprecated`/`enabled` take booleans; the rest take strings or arrays of strings.
* Unknown *values* produce an empty result (a filter is a query, not a validation).
* The result is id-sorted and deeply frozen; disabled rules are ordinary catalog entries, so
  `filter` returns them unless `enabled` narrows the result.

`filter` (catalog) and `select` (execution candidates) are deliberately **not** synonyms: `filter`
answers *what matches*, `select` answers *what may run*.

## 6. Enable / disable semantics

* `disable(id)` adds the rule to the disabled set. `enable(id)` clears any disable/exclusion and
  marks the rule enabled — activation is last-write-wins configuration.
* `isEnabled(id)` throws for an unregistered id (no silent answer).
* Disabled is **configuration**, not a conclusion: it is never `pass`, never `unknown`, never
  `not-applicable`.
* A disabled rule stays **registered and discoverable** — `lookup`, `has`, `ids`, `list`,
  `version`, `filter`, `describe`, `configuration` all still see it. Disabling never unregisters.
* Execution selection honors it: `selectCategories` returns only enabled rules, and
  `select([disabledId])` throws rather than silently dropping or silently running it.
* The Rule Engine's `runAll` asks the registry for `enabledIds()` when available, so disabling a
  rule removes it from an all-rules run without changing engine semantics.

## 7. Category selection semantics

`rule.category` is the **single source of truth**; there is no parallel category table.
`selectCategories(categories)` derives the known categories from the registered rules, rejects a
category no rule declares, and returns registered **and enabled** rules in those categories,
id-sorted and deduplicated. It does not execute rules. Metadata discovery (`describe`) still shows
disabled rules, so *catalog* and *executable selection* stay distinct.

## 8. Configuration model

`configure(config)` accepts a **closed** top-level vocabulary; an unknown key, an unknown rule id,
an unknown category or a non-declarative value is an explicit `RuleConfigurationError`.

| Key | Meaning |
| --- | --- |
| `enabled` | explicit ids to enable (overrides category/include filters) |
| `disabled` | explicit ids to disable (wins over `enabled` and exclusions) |
| `includeRules` | when non-empty, only these ids stay enabled |
| `excludeRules` | these ids are disabled |
| `categories` | when non-empty, only rules in these categories stay enabled |
| `ruleOptions` | per-rule declarative data keyed by a registered rule id |

Configuration is **data only**: no `eval`, no function strings, no dynamic module loading, no
network. Values are validated against the existing bounded-declarative-data philosophy
(plain/JSON-safe, depth/key/length bounded, `__proto__`/`constructor`/`prototype` rejected), then
sanitized and deeply frozen. Configuration overlays registry state — it never mutates
`rule.detect`, `rule.version`, `rule.category`, `rule.applicability` or `rule.metadata`.
`configuration()` returns a deterministic, id-sorted, frozen snapshot. `ruleOptions` is exposed
as a data path; a host adapter that wants to hand it to a rule keeps using the existing
`AnalysisContext.configuration` channel — the registry is not a hidden global injection point.

## 9. Applicability integration

`evaluateRuleApplicability` remains the only authority. The registry adds a convenience
`evaluateApplicability(id, context)` that pairs the registered rule with the model and returns the
evaluator's frozen `{ applicable, reason, coverage }` under the rule id. It **preserves `unknown`**:
a rule whose selectors depend on uncovered repository facts stays `unknown`, never
`not-applicable` — "not observed" is not "absent". No selector language/framework/file/capability
logic is duplicated.

## 10. Metadata discovery shape

`describe(id)` returns `{ id, version, category, title, description, severity, applicability,
metadata, deprecated, enabled }` — purely declarative, deeply frozen, bounded plain data.
`describeAll()` returns the same records id-sorted. Neither exposes `detect`, host paths, runtime
handles or mutable internals. Core metadata keys (`references`, `tags`, `frameworks`,
`introducedIn`, `deprecated`, `falsePositives`) are surfaced as-is; the extra `deprecated`
boolean and `enabled` flag are registry-level facts, documented separately from Core metadata.
Declarative metadata never implies a finding: `falsePositives` is documentation, and
`deprecated: true` does **not** disable a rule — deprecation and enablement are separate concepts.

## 11. Determinism

Every list answer is id-sorted and derived from the canonical registered entries:

```
lookup    identity-based
list/ids  id-sorted
filter    id-sorted
categories id-sorted, deduplicated
describe  id-sorted
select    id-sorted, deduplicated
```

No answer depends on registration order, object key order, filesystem enumeration, Map insertion
order, timing or randomness. Configuration and metadata snapshots are byte-identical across runs.

## 12. Error semantics

No parallel error system: new failure kinds extend the existing `RULE_FAILURE_KINDS` /
`RULE_FAILURE_CODES` and reuse `RuleConfigurationError` (framework/configuration) and
`RuleRegistrationError` (invalid descriptor).

| Kind | Code | Raised when |
| --- | --- | --- |
| `unknown-rule` | `CG_RULE_UNKNOWN` | an id is selected/configured/queried that is not registered |
| `disabled-rule` | `CG_RULE_DISABLED` | an explicitly selected id is disabled |
| `unknown-category` | `CG_RULE_CATEGORY_UNKNOWN` | a category no registered rule declares is requested |
| `invalid-configuration` | `CG_RULE_CONFIGURATION_INVALID` | unknown key, malformed value, non-declarative data |

Nothing is silently ignored: no unknown rule id, category, configuration key, selector or
enable/disable target.

## 13. Security boundaries

The registry stays inside the Phase 10 boundary: it imports no `node:fs`/`child_process`/net
module, no MCP/CLI/tool-registry module, and adds no I/O. Configuration cannot smuggle code
(functions and class instances are rejected, not dropped) and cannot pollute prototypes
(`__proto__`/`constructor`/`prototype` keys are rejected). Returned metadata is sanitized copies,
so a rule's metadata can never become a mutation channel into execution.

## 14. Backward compatibility

The Rule Engine still uses `registry.list()`/`select()`, and every domain pack still wraps
`createRuleRegistry`. `get`, `has`, `ids`, `list`, `select`, `size` keep their exact Phase 10
behavior; `select` still treats an unknown id as a framework error. The only intentional behavior
change is that `select` now also treats an *explicitly selected disabled* id as a configuration
error (there were no disabled rules before Phase 18, so no existing caller is affected), and
`runAll` consults `enabledIds()` so disabling is honored. Per-pack registries were left intact.

## 15. Known limitations

* Rule-specific configuration (`ruleOptions`) is stored and discoverable but the registry does not
  itself hand it to a rule: that remains the Rule Engine / `AnalysisContext.configuration` path.
  This is deliberate layering, not a missing capability of the catalog.
* No analyzer-level or repository-level orchestration, risk calculation, aggregation or canonical
  `audit()` exists — those are official Phase 19 (`GuardianEngine`).
* `filter` intentionally does not accept arbitrary predicate functions (data-only configuration).
* ESLint is not runnable in this repository snapshot (ESLint 10 with no `eslint.config.*`); this is
  pre-existing and unrelated to Phase 18.

## 16. Scope

Phase 18 formalizes the registry only. No GuardianEngine, no canonical `audit()`, no aggregated
risk, no analyzer selection engine, no acquisition change, no MCP/CLI change, no Phase 19 work.
