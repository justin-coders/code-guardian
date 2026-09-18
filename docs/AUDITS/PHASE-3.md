
# Phase 3 — `tools.js` Responsibility Decomposition

## 1. Current `tools.js` is actually 7 subsystems in one file

The file currently contains these distinct layers:

```text id="c0m7s5"
tools.js
│
├── A. Runtime / Infrastructure
│   ├── VERSION
│   ├── safeParseJSON()
│   ├── run()
│   ├── tryRead()
│   ├── listFiles()
│   ├── listDirs()
│   ├── findFilesRecursive()
│   └── findDirsRecursive()
│
├── B. Knowledge / Rules
│   ├── INDUSTRY_PATTERNS
│   └── AGENT_CONFIGS
│
├── C. Repository Analysis
│   ├── audit_codebase
│   ├── check_branch
│   ├── check_tests
│   ├── check_cicd
│   ├── check_linting
│   ├── check_security
│   └── check_architecture
│
├── D. Risk / Scoring
│   └── production_readiness
│
├── E. Generation
│   ├── generate_production_code
│   ├── generate_github_workflow
│   └── generate_starter_repo
│
├── F. Security Guidance
│   └── generate_security_checklist
│
└── G. Agent Integration
    ├── detect_agent
    └── get_agent_guidance
```

That confirms the architectural problem precisely.

---

# 2. Migration classification

Here is the migration map I would lock in.

| Current component                   | Decision            | Destination                            |
| ----------------------------------- | ------------------- | -------------------------------------- |
| `VERSION`                           | **MOVE**            | `core/version`                         |
| `safeParseJSON()`                   | **REWRITE**         | `repository/parsers`                   |
| `run()`                             | **REWRITE**         | `execution/command-runner`             |
| `tryRead()`                         | **REWRITE**         | `repository/filesystem`                |
| `listFiles()`                       | **MOVE + improve**  | `repository/scanner`                   |
| `listDirs()`                        | **MOVE + improve**  | `repository/scanner`                   |
| `findFilesRecursive()`              | **REPLACE**         | `repository/scanner`                   |
| `findDirsRecursive()`               | **REPLACE**         | `repository/scanner`                   |
| `INDUSTRY_PATTERNS`                 | **REPLACE**         | `rules/builtin`                        |
| `AGENT_CONFIGS`                     | **MOVE**            | `integrations/agents`                  |
| `audit_codebase`                    | **REWRITE**         | `analyzers/audit`                      |
| `check_branch`                      | **MOVE + rewrite**  | `analyzers/repository`                 |
| `check_tests`                       | **REWRITE**         | `analyzers/testing`                    |
| `check_cicd`                        | **REWRITE**         | `analyzers/cicd`                       |
| `check_linting`                     | **REWRITE**         | `analyzers/code-quality`               |
| `check_security`                    | **REBUILD**         | `analyzers/security`                   |
| `check_architecture`                | **REBUILD**         | `analyzers/architecture`               |
| `production_readiness`              | **REPLACE**         | `core/risk`                            |
| `generate_production_code`          | **REBUILD**         | `remediation/generator`                |
| `get_industry_patterns`             | **REBUILD**         | `rules/registry`                       |
| `generate_security_checklist`       | **REPLACE**         | `remediation/security`                 |
| `generate_github_workflow`          | **REBUILD**         | `generators/cicd`                      |
| `detect_agent`                      | **REWRITE**         | `integrations/agents`                  |
| `get_agent_guidance`                | **MOVE**            | `integrations/agents`                  |
| `generate_starter_repo`             | **DEFER + rebuild** | `generators/scaffold`                  |
| `detectStack()`                     | **REBUILD**         | `repository/project-model`             |
| `generateSecurityRecommendations()` | **REPLACE**         | `remediation/planner`                  |
| `getRecommendedStructure()`         | **REPLACE**         | `generators/scaffold`                  |
| `getEssentialPackages()`            | **REPLACE**         | `repository/project-model` + generator |
| `getProductionConfig()`             | **REPLACE**         | `rules` + generator                    |
| `generateGitHubWorkflow()`          | **REPLACE**         | `generators/cicd`                      |
| `getProductionTemplate()`           | **REPLACE**         | `remediation/generator`                |

---

# 3. Infrastructure layer

The first thing I'd extract is:

```text id="j1a9qx"
src/core/
src/repository/
src/execution/
```

### `run()` is especially important.

Current:

```text id="y5lq0n"
run(command, args, cwd, timeout)
```

is too primitive.

Future:

```text id="5z1tq6"
CommandRunner
│
├── command
├── args
├── cwd
├── timeout
├── stdout limit
├── stderr limit
├── environment policy
├── permission policy
├── cancellation
├── exit code
├── signal
├── timedOut
└── evidence
```

This becomes infrastructure that every analyzer can safely consume.

---

# 4. Repository scanner becomes foundational

Current tools independently do things like:

```text id="3qk6bd"
tryRead(package.json)
tryRead(tsconfig.json)
listFiles()
findFilesRecursive()
findDirsRecursive()
```

That causes repeated filesystem traversal.

Instead:

```text id="2v3q8x"
RepositoryScanner
       ↓
RepositoryModel
```

Example:

```json id="vl2nqy"
{
  "root": "...",
  "files": [],
  "directories": [],
  "languages": [],
  "frameworks": [],
  "packageManagers": [],
  "dependencies": {},
  "testFrameworks": [],
  "ciSystems": [],
  "containers": [],
  "infrastructure": [],
  "configurations": [],
  "git": {}
}
```

Then every analyzer consumes the same model.

This is probably the **single most important structural improvement after extracting `tools.js`.**

---

# 5. `safeParseJSON()` needs semantic states

Current:

```text id="x8f2nm"
invalid JSON
   ↓
fallback
```

Future:

```text id="u4n8j7"
parse()
│
├── missing
├── valid
├── invalid
└── unsupported
```

Example:

```json id="b3p0d5"
{
  "status": "invalid",
  "file": "tsconfig.json",
  "error": "Unexpected token ..."
}
```

This matters because an auditor must distinguish:

> “The project doesn't have configuration.”

from:

> “The project has configuration, but it is malformed.”

Those are completely different findings.

---

# 6. Industry patterns become a Rule Engine

The current `INDUSTRY_PATTERNS` is actually valuable source material.

We should preserve the knowledge, but change its representation.

Current:

```text id="g0e9gd"
security
 ├── description
 ├── checklist
 └── stack
```

Future:

```text id="qj1l6g"
Rule Registry
│
├── CG-SEC-...
├── CG-ARCH-...
├── CG-TEST-...
├── CG-CICD-...
├── CG-API-...
├── CG-DB-...
└── CG-OPS-...
```

Each rule should eventually define:

```text id="zv2d3c"
id
version
category
title
description
severity
confidence
applicability
prerequisites
detector
evidence
false-positive conditions
impact
remediation
references
fixtures
```

This changes Code Guardian from:

> a tool with opinions

into:

> an auditable rule platform.

---

# 7. Security should be rebuilt, not incrementally patched

I would **not** spend time turning the existing `check_security()` into a 500-line security function.

Instead:

```text id="3j7s7c"
analyzers/security/
│
├── secrets/
├── dependencies/
├── authentication/
├── authorization/
├── injection/
├── web/
├── crypto/
├── configuration/
├── ci-cd/
├── containers/
└── data-exposure/
```

Each detector generates evidence-backed findings.

Example:

```text id="f5o7ai"
CG-SEC-SECRET-001

severity: critical
confidence: 0.98

location:
  file: src/config/auth.ts
  line: 42

evidence:
  detected hard-coded credential-like value

impact:
  credential exposure

remediation:
  move secret to environment/secret manager
```

That is fundamentally different from:

```text
"Consider using helmet."
```

---

# 8. Architecture analyzer should start with a graph

Current:

```text id="whz1x2"
directories → warnings
```

Future:

```text id="2w4qae"
Files
  ↓
imports
  ↓
Dependency Graph
  ↓
Module Graph
  ↓
Architecture Rules
```

Then we can detect things like:

```text id="k5f2nd"
circular dependency
layer violation
forbidden import
high fan-in module
high fan-out module
dependency inversion violation
cross-domain coupling
god module
unstable dependency
```

Eventually this becomes one of Code Guardian's strongest capabilities.

---

# 9. Testing analyzer becomes evidence-driven

Instead of:

```text id="e1m7b0"
tests exist = true
```

we want:

```text id="a6c9z1"
Testing Model
│
├── framework
├── test files
├── unit tests
├── integration tests
├── e2e tests
├── coverage configuration
├── executed tests
├── failed tests
├── flaky tests
└── CI enforcement
```

Then a finding can say:

```text
Integration tests exist
but
CI does not execute them
```

That's far more valuable than merely detecting a Jest config.

---

# 10. CI/CD analyzer

Future flow:

```text id="m3v4ae"
CI configuration
       ↓
parse workflow
       ↓
workflow model
       ↓
rules
       ↓
findings
```

Potential rule examples:

```text id="1xk0z4"
CG-CI-PERM-001
Excessive GitHub token permissions

CG-CI-SEC-001
Untrusted PR executes privileged workflow

CG-CI-SUPPLY-001
Third-party action not pinned

CG-CI-TEST-001
Tests not enforced before deployment

CG-CI-DEPLOY-001
Production deployment lacks environment protection
```

This is much more useful than checking whether `ci.yml` exists.

---

# 11. Production readiness becomes a derived model

We should eliminate the current:

```text
10 checks
→ percentage
→ A-F
```

as the primary model.

Instead:

```text id="a4n4vp"
Repository
   ↓
Findings
   ↓
Risk Model
   ↓
Readiness Report
```

Possible dimensions:

```text
Security
Architecture
Reliability
Testing
Dependencies
Operations
CI/CD
Maintainability
Compliance
```

But the result should remain evidence-backed.

For example:

```json
{
  "status": "blocked",
  "blockingFindings": 2,
  "highRiskFindings": 5,
  "confidence": 0.91
}
```

rather than pretending:

```text
73% = production ready
```

---

# 12. Generation must become repository-aware

Current:

```text id="p9j3m8"
feature + stack
        ↓
template
```

Future:

```text id="1j5k8h"
Repository Model
        +
Findings
        +
Rules
        ↓
Remediation Plan
        ↓
Patch Generator
```

For example:

```text
Finding:
JWT secret is hard-coded

        ↓

Remediation:
1. introduce environment configuration
2. add startup validation
3. update tests
4. update example env
5. update documentation

        ↓

Patch
```

That's a much more compelling product.

---

# 13. Agent integration should remain outside the core

This is important for avoiding another architectural trap.

Don't do:

```text
core
 ├── Claude
 ├── Cursor
 ├── Gemini
 ├── Codex
 └── ...
```

Instead:

```text
core
   ↑
agent integrations
```

Code Guardian's core should not care which agent called it.

```text id="t4f5k2"
Claude
Cursor
Codex
Gemini
CI
CLI
       ↓
   same Guardian Core
```

This preserves the project's original cross-agent objective while making the implementation much cleaner.

---

# 14. The new directory structure is now becoming concrete

Based on the actual code, I'd currently target:

```text id="xk0p7m"
src/
│
├── core/
│   ├── engine/
│   ├── findings/
│   ├── evidence/
│   ├── rules/
│   ├── risk/
│   ├── configuration/
│   └── version/
│
├── repository/
│   ├── scanner/
│   ├── filesystem/
│   ├── parsers/
│   ├── git/
│   ├── project-model/
│   └── dependency-graph/
│
├── execution/
│   ├── command-runner/
│   ├── policies/
│   └── limits/
│
├── analyzers/
│   ├── audit/
│   ├── security/
│   ├── architecture/
│   ├── testing/
│   ├── code-quality/
│   ├── dependencies/
│   ├── cicd/
│   ├── api/
│   ├── reliability/
│   └── production/
│
├── rules/
│   └── builtin/
│
├── remediation/
│   ├── planner/
│   ├── generator/
│   └── verification/
│
├── generators/
│   ├── cicd/
│   └── scaffold/
│
├── integrations/
│   └── agents/
│
├── mcp/
│   ├── tools/
│   ├── schemas/
│   └── adapters/
│
├── transports/
│   ├── stdio/
│   └── http/
│
└── cli/
```

**This is still a target architecture, not something I recommend creating immediately.**

---

# 15. Migration order

This is where I want to be careful.

We should **not** start by moving every function into directories.

That would produce a cosmetic refactor without solving the architectural problem.

The correct migration sequence is:

```text
Phase 3A
Infrastructure extraction
        ↓
Phase 3B
Repository Model
        ↓
Phase 3C
Finding + Evidence contracts
        ↓
Phase 3D
Rule Engine
        ↓
Phase 3E
First analyzer migration
        ↓
Phase 3F
Remaining analyzers
        ↓
Phase 3G
Risk/readiness engine
        ↓
Phase 3H
Remediation engine
        ↓
Phase 3I
MCP modernization
        ↓
Phase 3J
CLI / CI interfaces
```

---

# 16. Which analyzer should migrate first?

I would **not start with security** despite security being the largest capability gap.

The first migrated analyzer should be:

```text
Repository / project detection
```

because everything else depends on it.

Then:

```text
Repository Model
      ↓
Security
Architecture
Testing
CI/CD
Dependencies
...
```

Otherwise every analyzer will independently rediscover:

```text
package.json
tsconfig
files
framework
language
package manager
git
```

and we'll recreate the same architectural problem in multiple files.

---

# 17. Critical rule: preserve v2 while migrating

We should use a compatibility strategy:

```text id="r6qz1e"
Existing MCP tool
       ↓
Compatibility wrapper
       ↓
New engine
```

For example:

```text
audit_codebase
   ↓
legacy-compatible adapter
   ↓
new AuditEngine
```

This means existing users don't suddenly lose the 15 tools.

The migration can happen internally.

---

# 18. Phase 3 current status

### Responsibility decomposition

* [x] Runtime helpers identified
* [x] Filesystem layer identified
* [x] Process execution layer identified
* [x] Rule/knowledge layer identified
* [x] Repository analyzers identified
* [x] Risk/scoring identified
* [x] Generator layer identified
* [x] Agent integration identified
* [x] Migration disposition assigned
* [x] Target module boundaries established
* [x] Migration order established

### The major architectural rule

> **Do not move functions one-for-one. Introduce the new contracts first, then migrate functionality behind those contracts.**

That prevents a “500-line `tools.js` split into 20 files” outcome—which would look cleaner but still be the same architecture underneath.

---

## Next step: Phase 4 — Contract design

Now we have enough evidence to define the **actual internal contracts** before writing the master architecture document.

Specifically, I want to define these five contracts from the current code outward:

```text
1. RepositoryModel
2. Evidence
3. Finding
4. Rule
5. Analyzer
```

Then we can prove that all future analyzers can plug into the same engine.

After that, we'll be in a good position to produce the two master documents you originally wanted:

**A. Code Guardian Architecture & Evolution Specification**

**B. Code Guardian Long-Term Development Roadmap**

without guessing about the current codebase.
