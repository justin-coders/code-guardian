# Code Guardian
## Long-Term Development Roadmap

**Repository:** `justin-coders/code-guardian`  
**Package:** `@justin-coders/code-guardian`  
**Baseline:** v2.0.4  
**Roadmap type:** Architecture-driven implementation roadmap

---

# 1. Roadmap Objective

The objective is to evolve Code Guardian from its current MCP-oriented engineering checklist system into a reusable **repository intelligence, code analysis, engineering risk, and remediation platform**.

The roadmap deliberately prioritizes architectural foundations before feature expansion.

The development principle is:

```text
Foundation
    ↓
Repository Intelligence
    ↓
Analysis Engine
    ↓
Evidence + Findings
    ↓
Risk
    ↓
Remediation
    ↓
Verification
    ↓
Interfaces
    ↓
Advanced Intelligence
```

---

# 2. Current Baseline

The current release provides:

- 15 MCP tools
- stdio transport
- HTTP/SSE transport
- filesystem inspection
- Git checks
- test detection
- linting checks
- CI/CD detection
- security checks
- architecture checks
- production-readiness assessment
- industry-pattern knowledge
- static generators
- agent detection/guidance
- starter-repository recommendations
- npm publication
- GitHub Packages publication
- automated release testing

The current test suite contains approximately 83 tests.

The principal architectural constraint is the concentration of responsibilities in `src/tools.js`.

---

# 3. Roadmap Rules

Every phase must follow these rules:

1. Do not break existing public MCP tools unnecessarily.
2. Do not add architectural duplication.
3. New functionality must use the new Core where its contract exists.
4. Every major migration must have regression tests.
5. Security changes require dedicated boundary tests.
6. No silent scan failures.
7. No automatic repository mutation without explicit authorization.
8. No LLM-dependent correctness requirement.
9. No premature distributed/cloud architecture.
10. Do not advance a phase merely because code compiles.

A phase is complete only when its exit criteria are satisfied.

---

# 4. Phase 0 — Release and Baseline Stabilization

## Status

**Mostly complete / ongoing maintenance.**

Current public baseline:

```text
v2.0.4
```

Before major architectural work, preserve the current behavior as the reference point.

## Objectives

- establish reproducible baseline
- verify current tests
- document current public interfaces
- preserve current MCP behavior
- establish release discipline

## Deliverables

```text
baseline test report
public tool inventory
current response examples
release procedure
architecture baseline
```

## Gate

The existing release must remain reproducible.

---

# 5. Phase 1 — Deep Repository Audit

## Status

**COMPLETE**

This phase established the actual current architecture.

Completed:

- repository structure inspection
- `tools.js` responsibility analysis
- MCP transport analysis
- HTTP security analysis
- test architecture review
- generator analysis
- CI/CD analysis
- dependency analysis
- concrete implementation defect identification

## Gate

Complete.

---

# 6. Phase 2 — Behavioral and Contract Audit

## Status

**COMPLETE**

Completed:

- tool behavior analysis
- input/output behavior
- command execution behavior
- error behavior
- test behavior
- MCP interaction behavior
- incomplete scan behavior
- security boundary analysis

## Gate

Complete.

---

# 7. Phase 3 — Responsibility Decomposition

## Status

**COMPLETE**

The responsibilities currently concentrated in `tools.js` were decomposed into:

```text
repository
execution
analyzers
rules
core
remediation
generators
integrations
MCP
transport
CLI
```

## Gate

Complete.

---

# 8. Phase 4 — Internal Contract Design

## Status

**COMPLETE**

Defined:

```text
RepositoryModel
Evidence
Finding
Rule
Analyzer
AnalysisContext
ExecutionRequest
ExecutionResult
```

These contracts are the foundation for implementation.

## Gate

Complete.

---

# 9. Phase 5 — Architecture Specification

## Status

**COMPLETE**

Defined:

- target architecture
- module boundaries
- dependency direction
- repository intelligence
- analyzer architecture
- rule architecture
- evidence model
- finding model
- risk model
- remediation architecture
- compatibility strategy
- testing architecture
- security boundaries
- transport separation

## Gate

Complete.

---

# 10. Phase 6 — Core Contracts Implementation

## Status

**NEXT IMPLEMENTATION PHASE**

This is the first phase where production code should materially change.

## Objective

Implement the architectural contracts without changing the public behavior of existing tools.

## Build

```text
src/core/
```

with initial components:

```text
contracts/
engine/
findings/
evidence/
configuration/
version/
```

The exact directory naming can be adjusted during implementation, but the responsibility boundaries must remain.

## Implement

### RepositoryModel

Schema and validation.

### Evidence

Evidence identity, location and provenance.

### Finding

Finding schema, severity, confidence, fingerprint.

### Rule

Rule metadata and contract.

### Analyzer

Analyzer interface and result contract.

### AnalysisContext

Shared execution context.

### ExecutionRequest / Result

Structured command execution contracts.

---

## Testing

Add contract tests for:

- valid objects
- missing required fields
- invalid severity
- invalid confidence
- invalid evidence references
- malformed analyzer results
- invalid execution results

## Exit Criteria

The Core contracts can be imported independently by future modules.

No MCP transport should be required to use them.

---

# 11. Phase 7 — Infrastructure Extraction

## Objective

Remove low-level infrastructure responsibilities from `tools.js`.

Extract:

```text
filesystem
JSON/config parsing
process execution
Git operations
path handling
repository scanning primitives
```

## Critical fixes

### Path handling

Replace string concatenation:

```text
cwd + "/package.json"
```

with platform-safe path APIs.

### ESM require bug

Replace the incorrect bare `require()` usage in `tools.js`.

### JSON parsing

Distinguish:

```text
missing
valid
invalid
unsupported
```

rather than silently converting invalid JSON into fallback data.

### Process limits

Add:

```text
timeout
output limit
termination state
```

### Scan errors

Stop silently swallowing filesystem errors.

---

## Exit Criteria

Existing tools still pass their current regression suite while infrastructure has independent tests.

---

# 12. Phase 8 — Repository Intelligence Engine

## Objective

Create the first genuinely shared repository model.

Build scanners for:

```text
filesystem
manifest
language
framework
dependency
configuration
Git
tests
CI/CD
source structure
```

Result:

```text
RepositoryModel
```

---

## Important design rule

The scanner should collect facts.

It should not make security or architecture judgments.

For example:

```text
Found .env file
```

is repository intelligence.

```text
Potential secret exposure
```

is a security finding.

---

## Exit Criteria

At least two independent analyzers can consume the same RepositoryModel without independently rescanning the repository for basic facts.

---

# 13. Phase 9 — Dependency and Project Graph

## Objective

Build deeper repository understanding.

Add:

```text
dependency graph
workspace graph
module graph
import relationships
package relationships
```

For supported languages, gradually add AST-aware analysis.

Initial priority should remain on ecosystems with strong repository evidence and practical demand rather than attempting every programming language immediately.

---

## Exit Criteria

Code Guardian can answer structurally:

```text
What is this project?
What does it depend on?
What modules exist?
How are modules related?
Which files belong to which areas?
```

---

# 14. Phase 10 — First Production Analyzer: Security

## Objective

Create the first full analyzer using the new architecture.

Pipeline:

```text
RepositoryModel
      ↓
SecurityAnalyzer
      ↓
Applicable Rules
      ↓
Evidence
      ↓
Findings
```

Initial security rule families:

```text
secrets
authentication configuration
authorization configuration
unsafe CORS
insecure cookies
dangerous headers
dependency vulnerabilities
unsafe command execution
sensitive data exposure
debug endpoints
CI security
container security
```

The exact rules should be introduced incrementally and tested against fixtures.

---

## Security principles

Avoid rules that simply search for suspicious strings without context where better evidence is available.

Prefer:

```text
manifest
configuration
AST
data flow where feasible
dependency metadata
workflow parsing
```

---

## Exit Criteria

Security findings:

- have stable rule IDs
- contain evidence
- contain severity
- contain confidence
- have fingerprints
- distinguish unknown from clean
- have regression fixtures

---

# 15. Phase 11 — Testing Analyzer

Replace the current simplistic test detection with a real testing analyzer.

It should distinguish:

```text
detected
verified
failed
unknown
not_applicable
```

Analyze:

```text
test framework
test files
test configuration
test scripts
CI execution
coverage configuration
integration testing
E2E testing
test isolation
potential flaky patterns
```

The current Node built-in test runner omission should be corrected.

---

# 16. Phase 12 — Code Quality Analyzer

Expand beyond simple linter detection.

Analyze:

```text
linting
formatting
type checking
dead code indicators
complexity
duplication
unsafe patterns
maintainability
configuration consistency
```

Language-specific rules should remain modular.

---

# 17. Phase 13 — CI/CD Analyzer

The current presence checks become content-aware analysis.

Inspect:

```text
workflow triggers
permissions
secret handling
dependency installation
test execution
build execution
deployment
environment separation
artifact handling
caching
rollback
deployment protection
```

Do not treat:

```text
.github/workflows exists
```

as equivalent to:

```text
CI/CD is properly implemented.
```

---

# 18. Phase 14 — Architecture Analyzer

Move from directory inspection to actual structural analysis.

Analyze:

```text
module boundaries
dependency direction
circular dependencies
layer violations
coupling
cohesion indicators
large modules
boundary leakage
architecture patterns
```

The architecture analyzer should be evidence-driven.

It should not impose one universal architecture on every repository.

---

# 19. Phase 15 — Dependency Analyzer

Create a dedicated dependency analysis layer.

Inspect:

```text
outdated dependencies
known vulnerabilities
unused dependencies
duplicate versions
dependency concentration
lockfile integrity
package manager consistency
supply-chain risk indicators
```

External vulnerability information should be treated as time-sensitive data and clearly versioned.

---

# 20. Phase 16 — API Analyzer

For HTTP/API projects:

```text
APIAnalyzer
```

Analyze:

```text
input validation
schema validation
authentication
authorization
error handling
status codes
pagination
rate limiting
CORS
OpenAPI
request limits
logging
correlation IDs
```

Applicability is critical.

A CLI application should not receive HTTP API findings.

---

# 21. Phase 17 — Reliability Analyzer

Analyze:

```text
timeouts
retry behavior
circuit breaking
graceful shutdown
health checks
failure handling
resource cleanup
transaction handling
queue behavior
observability
```

This becomes especially useful for backend/service repositories.

---

# 22. Phase 18 — Rule Registry

Once several analyzers exist, formalize the rule registry.

Build:

```text
RuleRegistry
```

Capabilities:

```text
register
lookup
version
filter
applicability
enable/disable
category selection
configuration
```

Rule metadata becomes discoverable.

---

# 23. Phase 19 — Canonical Analysis Engine

At this point the independent analyzers should be unified under:

```text
GuardianEngine
```

Example conceptual API:

```text
guardian.audit(repository, options)
```

The engine should:

```text
1. load configuration
2. build RepositoryModel
3. select analyzers
4. determine applicable rules
5. run analyzers
6. collect evidence
7. aggregate findings
8. calculate risk
9. generate canonical result
```

---

# 24. Phase 20 — Production Readiness Rebuild

Now replace the current binary checklist.

The new system should derive readiness from:

```text
findings
risk
coverage
unknowns
critical blockers
```

The report should answer:

```text
What is wrong?
How serious is it?
How confident are we?
Where is the evidence?
What remains unknown?
What should be addressed?
```

---

# 25. Phase 21 — Legacy Tool Migration

Once the engine is stable, migrate the existing MCP tools.

Example:

```text
check_security
→ SecurityAnalyzer

check_tests
→ TestingAnalyzer

check_linting
→ CodeQualityAnalyzer

check_cicd
→ CICDAnalyzer

check_architecture
→ ArchitectureAnalyzer
```

Existing public tool names remain.

Their implementations become adapters.

---

# 26. Phase 22 — Audit Tool Rebuild

`audit_codebase` becomes the primary orchestration interface.

Instead of owning dozens of independent checks, it invokes the Guardian Engine.

Conceptually:

```text
audit_codebase
       ↓
GuardianEngine.audit()
       ↓
multiple analyzers
       ↓
canonical result
```

This is the point where `tools.js` should be dramatically reduced.

---

# 27. Phase 23 — MCP Modernization

Only after the Core is stable should transport modernization happen.

Goals:

```text
current MCP compatibility
structured tool schemas
structured outputs
modern HTTP transport
proper protocol negotiation
```

The current manual protocol implementation should be replaced or isolated behind an appropriate MCP SDK/adapter strategy.

Transport modernization must not alter analyzer behavior.

---

# 28. Phase 24 — HTTP Security Rebuild

Before supporting broader remote usage:

Implement:

```text
safe path containment
authentication modes
authorization
explicit CORS allowlist
request limits
command policy
resource limits
secure defaults
audit logging
```

Important rule:

```text
Remote mode != local mode
```

An HTTP server must not casually expose arbitrary repository command execution.

---

# 29. Phase 25 — Remediation Planner

Once findings are stable:

```text
Finding
   ↓
RemediationPlanner
   ↓
RemediationPlan
```

Plans should contain:

```text
problem
reason
recommended change
affected files
risk
verification requirements
```

Initially remediation can remain advisory.

---

# 30. Phase 26 — Repository-Aware Code Generation

Static templates should gradually become repository-aware.

Input:

```text
RepositoryModel
+
Finding
+
RemediationPlan
```

Output:

```text
Patch / proposed changes
```

The generator must understand:

```text
language
framework
package manager
existing architecture
existing configuration
project conventions
```

---

# 31. Phase 27 — Verification Engine

No automatic remediation should be considered successful without verification.

Pipeline:

```text
Generate change
     ↓
Apply in controlled context
     ↓
Run targeted checks
     ↓
Run relevant tests
     ↓
Re-run affected rules
     ↓
Compare findings
     ↓
Verification result
```

---

# 32. Phase 28 — Baseline and Regression Intelligence

Introduce:

```text
baseline
fingerprints
new findings
resolved findings
regressions
```

This enables practical CI adoption.

Example:

```text
Existing 100 findings
+
PR introduces 2 new high findings
```

The CI system can focus on the regression rather than forcing immediate resolution of historical debt.

---

# 33. Phase 29 — Incremental Analysis

Use Git changes and repository dependency relationships to avoid unnecessary work.

Pipeline:

```text
Git diff
   ↓
changed files
   ↓
affected modules
   ↓
affected analyzers/rules
   ↓
incremental analysis
```

Full audits remain available.

---

# 34. Phase 30 — CLI

The current CLI is minimal.

Once the Core exists, introduce meaningful commands:

```text
code-guardian audit
code-guardian security
code-guardian architecture
code-guardian test
code-guardian dependencies
code-guardian report
code-guardian baseline
code-guardian diff
```

The CLI should be a thin interface over the same Core.

---

# 35. Phase 31 — CI-Native Mode

Provide direct CI usage.

Possible conceptual operations:

```text
audit
diff
baseline
report
fail-on
```

Outputs may include:

```text
JSON
SARIF
human-readable terminal
CI annotations
```

The exact formats should be added based on real adoption needs.

---

# 36. Phase 32 — Golden Repository Benchmark Suite

Build a permanent benchmark corpus.

Example:

```text
fixtures/
  secure-node-api/
  insecure-node-api/
  secure-python-api/
  insecure-python-api/
  monorepo/
  malformed/
  large-repository/
  docker/
  kubernetes/
  frontend/
  backend/
```

Each fixture should have expected findings.

Track:

```text
true positives
false positives
false negatives
runtime
scan completeness
```

This becomes one of the project's most valuable engineering assets.

---

# 37. Phase 33 — Advanced Static Analysis

After the basic analyzer system is reliable:

```text
AST
control flow
data flow
taint analysis
dependency graph analysis
configuration flow
```

Priority should be driven by demonstrable engineering value.

---

# 38. Phase 34 — Semantic / LLM Assistance

Only after deterministic analysis is strong.

Potential uses:

```text
contextual explanation
finding correlation
remediation planning
architecture interpretation
documentation analysis
complex refactoring assistance
```

LLM-generated conclusions should remain distinguishable from deterministic evidence.

---

# 39. Phase 35 — Agent-Native Code Guardian

Agent integrations can then become substantially deeper.

Potential capabilities:

```text
agent receives findings
agent requests evidence
agent requests remediation plan
agent proposes patch
Guardian verifies patch
agent receives verification result
```

The interaction becomes:

```text
Agent
  ↓
Code Guardian
  ↓
Evidence
  ↓
Finding
  ↓
Remediation
  ↓
Verification
  ↓
Agent
```

This is where Code Guardian can become particularly useful inside coding-agent workflows.

---

# 40. Phase 36 — Ecosystem Expansion

Only after the architecture proves itself should language/ecosystem coverage expand aggressively.

Potential areas:

```text
JavaScript / TypeScript
Python
Go
Rust
Java
C#
PHP
Ruby
```

Expansion should happen through analyzer/rule plugins rather than special cases in the Core.

---

# 41. Phase 37 — Community Rule Ecosystem

Long-term possibility:

```text
official rules
community rules
organization rules
repository-local rules
```

A rule package could eventually define:

```text
rules
metadata
tests
documentation
version
compatibility
```

Rules must be sandboxed/validated before execution if third-party rules are supported.

---

# 42. Phase 38 — Advanced Repository Intelligence

Potential future capabilities:

```text
architectural dependency graph
service topology
data-flow map
security boundary map
deployment topology
ownership inference
change-risk analysis
```

These should only be built when underlying evidence quality supports them.

---

# 43. Phase 39 — Organizational Intelligence

Much later, Code Guardian could aggregate:

```text
repositories
teams
rules
baselines
technical debt
risk trends
```

This is intentionally a late-stage capability.

It must not distort the core repository analyzer into a SaaS dashboard prematurely.

---

# 44. Phase 40 — Cloud / Multi-Repository Platform

Only if real usage justifies it.

Potential architecture:

```text
Local Guardian
      ↓
optional cloud service
      ↓
repository history
      ↓
organization-wide analytics
```

This should remain separate from the local Core wherever practical.

---

# 45. Release Strategy

The architectural migration should use incremental releases.

Conceptually:

```text
2.x
Compatibility + infrastructure migration

3.x
Guardian Core + repository intelligence

4.x
Analyzer/rule platform

5.x
Remediation + verification

6.x+
Advanced intelligence/ecosystem
```

These are architectural milestones, not promises of exact semantic-version boundaries.

The actual versioning decision should be made based on API compatibility.

---

# 46. Migration Rule

At no point should the project require a "big bang" rewrite.

The preferred pattern is:

```text
old implementation
      ↓
new implementation
      ↓
compatibility adapter
      ↓
tests
      ↓
deprecate old path
      ↓
remove old path later
```

---

# 47. Definition of Done for Each Analyzer

Every production analyzer should eventually satisfy:

```text
[ ] common Analyzer contract
[ ] applicability detection
[ ] evidence generation
[ ] rule integration
[ ] severity
[ ] confidence
[ ] finding fingerprints
[ ] deterministic behavior where applicable
[ ] error handling
[ ] incomplete-scan handling
[ ] unit tests
[ ] integration tests
[ ] golden fixtures
[ ] performance measurement
```

---

# 48. Definition of Done for Each Rule

```text
[ ] unique rule ID
[ ] version
[ ] category
[ ] applicability
[ ] detection logic
[ ] evidence
[ ] severity rationale
[ ] confidence behavior
[ ] remediation guidance
[ ] positive fixture
[ ] negative fixture
[ ] regression fixture
```

---

# 49. Definition of Done for Remediation

```text
[ ] finding mapped to remediation
[ ] affected files identified
[ ] change plan generated
[ ] authorization required
[ ] patch generated
[ ] syntax validated
[ ] tests executed
[ ] affected rule rerun
[ ] regression checked
[ ] result reported
```

---

# 50. Critical Architectural Gates

Before moving forward from repository intelligence:

```text
RepositoryModel stable
```

Before adding many analyzers:

```text
Analyzer contract stable
```

Before large rule expansion:

```text
Evidence/Finding model stable
```

Before automatic remediation:

```text
Finding fingerprints + verification stable
```

Before remote execution:

```text
Execution security model stable
```

Before major MCP modernization:

```text
Guardian Core stable
```

Before cloud architecture:

```text
real-world adoption demonstrates need
```

---

# 51. Immediate Implementation Queue

The roadmap is intentionally long, but the immediate work should remain small.

The next engineering sequence is:

```text
1. Implement core contracts
2. Add contract tests
3. Extract filesystem/path utilities
4. Extract command execution
5. Fix execution limits
6. Build RepositoryModel
7. Build repository scanner
8. Build SecurityAnalyzer
9. Build Evidence/Finding pipeline
10. Add golden security fixtures
```

Do not jump directly to:

```text
LLM agent
dashboard
cloud
100 rules
automatic patching
```

---

# 52. First Major Milestone

The first meaningful architectural milestone is:

```text
Repository
     ↓
RepositoryModel
     ↓
SecurityAnalyzer
     ↓
Rule
     ↓
Evidence
     ↓
Finding
     ↓
Canonical Result
```

Once this works cleanly, the architecture has been proven.

The same pipeline can then support:

```text
Testing
Architecture
CI/CD
Dependencies
API
Reliability
Code Quality
```

---

# 53. Second Major Milestone

The second milestone is:

```text
Multiple analyzers
       ↓
Guardian Engine
       ↓
Risk Model
       ↓
Production Assessment
```

This replaces the current checklist architecture.

---

# 54. Third Major Milestone

The third milestone is:

```text
Finding
   ↓
Remediation
   ↓
Verification
```

This turns Code Guardian from an inspection system into an engineering feedback loop.

---

# 55. Fourth Major Milestone

The fourth milestone is:

```text
Guardian Core
   ↓
MCP
CLI
CI
HTTP
Agent integrations
```

Multiple interfaces now become relatively thin because the intelligence already exists underneath them.

---

# 56. Long-Term Product Shape

The mature product should expose a small number of conceptual capabilities rather than an ever-growing collection of unrelated functions.

At the center:

```text
AUDIT
ANALYZE
EXPLAIN
REMEDIATE
VERIFY
```

These can be surfaced through different interfaces without duplicating intelligence.

---

# 57. Final Roadmap

```text
CURRENT
v2.0.4
│
├── Phase 1  Deep Audit                  ✓
├── Phase 2  Behavior Audit              ✓
├── Phase 3  Responsibility Decomposition ✓
├── Phase 4  Contract Design             ✓
├── Phase 5  Architecture Specification  ✓
│
├── Phase 6  Core Contracts
├── Phase 7  Infrastructure Extraction
├── Phase 8  Repository Intelligence
├── Phase 9  Dependency / Project Graph
├── Phase 10 Security Analyzer
├── Phase 11 Testing Analyzer
├── Phase 12 Code Quality Analyzer
├── Phase 13 CI/CD Analyzer
├── Phase 14 Architecture Analyzer
├── Phase 15 Dependency Analyzer
├── Phase 16 API Analyzer
├── Phase 17 Reliability Analyzer
├── Phase 18 Rule Registry
├── Phase 19 Guardian Engine
├── Phase 20 Production Risk
├── Phase 21 Legacy Tool Migration
├── Phase 22 Audit Rebuild
├── Phase 23 MCP Modernization
├── Phase 24 HTTP Security
├── Phase 25 Remediation Planner
├── Phase 26 Repository-Aware Generation
├── Phase 27 Verification
├── Phase 28 Baselines / Regression
├── Phase 29 Incremental Analysis
├── Phase 30 CLI
├── Phase 31 CI-Native Mode
├── Phase 32 Benchmark Corpus
├── Phase 33 Advanced Static Analysis
├── Phase 34 Semantic / LLM Assistance
├── Phase 35 Agent-Native Workflow
├── Phase 36 Ecosystem Expansion
├── Phase 37 Community Rules
├── Phase 38 Advanced Repository Intelligence
├── Phase 39 Organizational Intelligence
└── Phase 40 Optional Cloud Platform
```

---

# 58. Final Strategic Direction

Code Guardian should not compete by simply accumulating more checks.

Its long-term technical advantage should come from the combination of:

```text
Repository understanding
+
deterministic analysis
+
executable rules
+
evidence
+
confidence
+
risk
+
remediation
+
verification
```

The resulting system is fundamentally different from the current checklist implementation.

The architecture should make this possible without sacrificing the existing MCP package or forcing users through a disruptive rewrite.