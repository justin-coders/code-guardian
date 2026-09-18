# Deep Code Guardian Architecture Audit — Phase 1

## 1. Current system is more mature than it looks

The current architecture is essentially:

```text
                    MCP CLIENT
                       │
          ┌────────────┴────────────┐
          │                         │
       stdio                    HTTP/SSE
          │                         │
          └────────────┬────────────┘
                       │
                tool-registry.js
                       │
                       ▼
                   tools.js
                       │
          ┌────────────┼────────────┐
          │            │            │
       Auditors     Patterns     Generators
          │            │            │
          └────────────┼────────────┘
                       ▼
                  JSON result
```

This is actually a **reasonable v2 prototype architecture**.

The important discovery is that `tool-registry.js` is already a single source of truth for tool definitions and dispatch.

So the old `UPCOMING_FEATURES.md` proposal saying to move toward a centralized registry is partially stale: **that central registry already exists.**

That means we shouldn't blindly follow the old roadmap.

---

# 2. The biggest architectural problem: `tools.js`

This is the biggest structural problem in the repository.

`tools.js` currently contains:

```text
IO primitives
        +
filesystem scanning
        +
industry standards
        +
agent configurations
        +
audit logic
        +
security logic
        +
architecture logic
        +
production scoring
        +
code templates
        +
starter-repo generation
        +
CI generation
```

That's too many responsibilities for one module.

The file is currently about **66 KB / ~1,400 lines** according to the repository's own roadmap.

But I would **not** simply split it into 15 smaller files.

That would reproduce the same architecture at a different scale.

### We need a proper domain architecture.

Eventually:

```text
src/
│
├── core/
│   ├── engine/
│   ├── findings/
│   ├── evidence/
│   ├── rules/
│   ├── scoring/
│   └── configuration/
│
├── repository/
│   ├── scanner/
│   ├── filesystem/
│   ├── git/
│   ├── manifest/
│   └── project-model/
│
├── analyzers/
│   ├── architecture/
│   ├── security/
│   ├── dependencies/
│   ├── testing/
│   ├── reliability/
│   ├── observability/
│   ├── api/
│   └── production/
│
├── rules/
│   ├── builtin/
│   ├── security/
│   ├── architecture/
│   └── ...
│
├── remediation/
│
├── generators/
│
├── integrations/
│
├── transports/
│   ├── stdio/
│   └── http/
│
├── mcp/
│
└── cli/
```

But **that is target architecture, not something we should implement now**.

---

# 3. Current audit engine isn't really a codebase auditor yet

This is probably the most important discovery.

`audit_codebase` sounds like:

> “Analyze my entire repository.”

But its actual implementation is primarily **presence/configuration checking**.

For example, it checks:

```text
package.json exists
README exists
.gitignore exists
ESLint config exists
tsconfig exists
test config exists
CI exists
lockfile exists
```

and optionally executes ESLint and TypeScript.

That is useful.

But it is not yet:

```text
architectural analysis
dependency graph analysis
data-flow analysis
security analysis
business-logic analysis
API contract analysis
concurrency analysis
database analysis
failure-mode analysis
observability analysis
deployment analysis
```

Therefore:

> **The current Code Guardian is a production-readiness checklist engine, not yet a deep codebase intelligence engine.**

This distinction needs to drive our entire roadmap.

---

# 4. Current `production_readiness` score has a serious conceptual limitation

Today it essentially evaluates ten binary dimensions:

```text
package.json
lock file
README
.gitignore
ESLint
TypeScript strict
tests
CI/CD
.env
build script
```

Then:

```text
passed / total
      ↓
percentage
      ↓
A-F grade
```

The code explicitly calculates the percentage from passed checks.

This creates a dangerous possibility:

```text
Excellent documentation
+
ESLint
+
README
+
.gitignore
+
tests
=
high score
```

while the actual application could still contain:

```text
SQL injection
broken authorization
race condition
data corruption
insecure JWT implementation
missing transaction boundary
```

That means **the score must eventually become an aggregation of evidence-backed findings**, rather than a checklist percentage.

This is a major architectural principle for the future.

---

# 5. Security is currently shallow

This one is explicitly documented by the project itself.

`check_security` currently:

* checks root `.env` files
* checks recent git history
* runs `npm audit`

It does **not inspect source contents for secrets**.

The current security architecture is therefore:

```text
.env presence
       +
npm audit
       +
basic metadata
```

rather than:

```text
Secrets
Dependencies
SAST
Injection
Auth
Authorization
Crypto
Configuration
Supply chain
Container
CI/CD
Infrastructure
Data exposure
```

So security needs to become an independent analyzer subsystem.

---

# 6. Architecture analysis is currently structural, not architectural

`check_architecture` currently looks primarily at:

```text
src/
tests/
dist/
docs/
workspaces
Nx
Lerna
```

and gives structural guidance.

That's not enough for the product vision.

A real architecture analyzer eventually needs to understand:

```text
Modules
    ↓
Imports
    ↓
Dependencies
    ↓
Layers
    ↓
Boundaries
    ↓
Cycles
    ↓
Coupling
    ↓
Dependency direction
    ↓
Domain relationships
```

For example:

```text
Controller
   ↓
Service
   ↓
Repository
   ↓
Database
```

versus:

```text
Controller
   ↓
Database
   ↑
Domain
```

The second might indicate an architectural boundary violation.

**This is where Code Guardian can become genuinely differentiated.**

---

# 7. The repository scanner itself needs to become a first-class subsystem

The current scanner uses recursive filesystem traversal with caps and skips directories such as:

```text
node_modules
.git
dist
build
```

and limits recursive results.

That's a good safety starting point.

But the future engine needs a proper:

```text
Repository Model
```

instead of each tool independently walking the filesystem.

Something like:

```text
Repository
│
├── files
├── directories
├── languages
├── frameworks
├── package managers
├── dependencies
├── test frameworks
├── CI systems
├── containers
├── infrastructure
├── git metadata
└── configuration
```

Then analyzers consume that model.

This avoids:

```text
audit_codebase → scan filesystem
check_tests → scan filesystem
check_security → scan filesystem
check_architecture → scan filesystem
...
```

over and over again.

---

# 8. Evidence needs to become a first-class object

This is the most important architectural addition I would make.

Currently findings are mostly generated directly as messages:

```text
message
severity
guidance
```

We need a formal model:

```text
Finding
├── id
├── ruleId
├── category
├── severity
├── confidence
├── location
├── evidence
├── explanation
├── impact
├── remediation
├── references
└── fingerprint
```

And evidence:

```text
Evidence
├── file
├── line
├── column
├── snippet
├── symbol
├── AST relationship
├── dependency relationship
└── command output
```

Then the engine can say:

```text
CG-AUTH-004

Authorization boundary violation

Evidence:
src/orders/controller.ts:84
→ ordersService.findById(id)

Missing:
ownership verification

Impact:
Authenticated user may access another user's order.

Confidence:
0.94
```

Now we're building an **auditing system**, rather than an LLM checklist.

---

# 9. We need deterministic + semantic analysis

I don't want Code Guardian to depend entirely on an LLM.

The future engine should have:

```text
                    Audit Engine
                        │
           ┌────────────┴────────────┐
           │                         │
      Deterministic              Semantic
        Analysis                 Analysis
           │                         │
      AST / regex              LLM reasoning
      dependency graph          contextual review
      manifests                 architecture inference
      configs                   remediation reasoning
      commands
           │                         │
           └────────────┬────────────┘
                        ▼
                  Evidence Fusion
                        │
                        ▼
                    Findings
```

That is much more robust.

---

# 10. Current MCP interface is too primitive for the future

The current tool definitions are manually represented with basic JSON schemas, and `tools/call` returns the result as serialized text:

```text
content:
[
  {
    type: "text",
    text: JSON.stringify(...)
  }
]
```

The registry has no meaningful `outputSchema` today.

Modern MCP supports richer tool schemas, output schemas and annotations such as:

```text
readOnlyHint
destructiveHint
idempotentHint
openWorldHint
```

and JSON Schema 2020-12. ([ModelContextProtocol][2])

Therefore future Code Guardian tools should expose machine-readable contracts.

For example:

```text
audit_repository
        ↓
outputSchema
        ↓
{
  summary,
  findings[],
  metrics,
  coverage,
  metadata
}
```

That allows agents to reason over results rather than parsing a giant text blob.

---

# 11. MCP transport needs modernization

The current HTTP implementation is explicitly a simplified HTTP/SSE transport. The project itself recognizes that it does not implement the complete modern Streamable HTTP behavior.

But now there is an even more important consideration:

The MCP specification has moved forward since the roadmap was written. The July 2026 MCP release introduced a **stateless protocol core**, header-based routing, authorization hardening, extensions, and other changes. ([Model Context Protocol Blog][1])

So we should **not implement the old `UPCOMING_FEATURES.md` Streamable HTTP design verbatim**.

The architecture roadmap must target the current MCP protocol family and maintain compatibility deliberately.

---

# 12. I found an actual code-level bug worth recording

At the beginning of `tools.js`, the code creates:

```js
const _require = createRequire(import.meta.url);
```

but `run()` later attempts:

```js
require("node:fs")
```

inside an ESM module.

Because the bare `require` isn't defined in this module, the exception is caught and ignored.

So the intended:

```text
Validate cwd exists
```

logic does not reliably execute.

That's not theoretical architecture criticism. That's a concrete implementation defect.

The correct architecture should eventually centralize filesystem/path validation rather than having subprocess helpers perform ad-hoc validation.

---

# 13. Another important issue: Windows path security

The HTTP server tries to enforce:

```text
cwd must be inside ALLOWED_ROOTS
```

which is good.

But the comparison uses:

```text
cwd.startsWith(root + "/")
```

while Node on Windows can produce backslash-separated resolved paths.

Therefore the authorization check is not truly cross-platform.

This is especially important because the project explicitly claims Windows support and CI tests Windows.

The security boundary should use canonical path comparison rather than string-prefix assumptions.

---

# 14. HTTP security model needs another redesign

The HTTP server has some good protections:

```text
127.0.0.1 default
1 MB body limit
optional bearer token
allowed roots
cwd validation
```

That's a good start.

But:

```text
if CODE_GUARDIAN_TOKEN isn't set
        ↓
authentication disabled
```

and the host can be changed through environment variables.

So a deployment could theoretically become:

```text
0.0.0.0
+
no token
+
filesystem inspection
+
command execution
```

That is unacceptable for a future remote production server.

We should eventually distinguish:

```text
Local mode
Remote mode
Trusted CI mode
Multi-user server mode
```

with different security policies.

---

# 15. CORS also needs proper policy

When authentication is enabled, the HTTP server currently derives:

```text
Access-Control-Allow-Origin
```

from the incoming `Origin`.

That's effectively reflection rather than an explicit origin allowlist.

For a production remote server, this should become:

```text
configured origins
       ↓
exact match
       ↓
allow
```

not:

```text
whatever origin the client supplied
       ↓
reflect it
```

---

# 16. CLI is barely a CLI today

`bin/cli.js` essentially launches the stdio server.

So:

```text
code-guardian
```

isn't yet a real developer CLI with commands such as:

```text
code-guardian audit
code-guardian security
code-guardian architecture
code-guardian production
code-guardian fix
code-guardian report
code-guardian baseline
code-guardian diff
```

That is a future opportunity.

But again: **don't build it yet**.

We first need the engine underneath.

---

# 17. The current generator architecture is also too static

The production-code generator mostly returns hard-coded templates.

For example, the project contains templates for:

```text
NestJS
Express
Fastify
Docker
GitHub Actions
Prisma
Jest
ESLint
Swagger
health checks
```

This is useful as a knowledge base, but it doesn't yet understand the actual target repository deeply.

Future evolution should be:

```text
Repository
   ↓
Detected stack
   ↓
Existing architecture
   ↓
Existing conventions
   ↓
Rules
   ↓
Generation plan
   ↓
Patch
```

rather than:

```text
feature + framework
       ↓
hardcoded template
```

That distinction will become extremely important.

---

# 18. The current test architecture is good for v2, insufficient for the future

The project has:

```text
57 unit tests
26 integration tests
= 83
```

and tests the MCP server and individual tools.

That's a solid foundation.

But future testing must add:

```text
golden repository fixtures
        +
known vulnerable repositories
        +
architecture violation fixtures
        +
multi-language fixtures
        +
large-repository benchmarks
        +
false-positive benchmarks
        +
MCP conformance tests
        +
security boundary tests
```

Especially:

## False-positive testing.

For an auditor, this is critical.

A tool that finds 1,000 “problems” isn't useful if 800 are wrong.

So we need:

```text
precision
recall
confidence
false positives
false negatives
```

as engineering metrics.

---

# 19. The existing industry patterns should NOT remain simple strings forever

Today a rule looks conceptually like:

```text
name
description
checklist[]
stack guidance
```

That is fine for v2.

But the future rule system should look more like:

```text
Rule
├── id
├── version
├── category
├── applicability
├── prerequisites
├── detection
├── evidence
├── severity
├── confidence
├── remediation
├── references
├── false-positive conditions
├── test fixtures
└── metadata
```

For example:

```text
CG-SEC-AUTH-001
```

rather than:

```text
"Use JWT with short expiry"
```

That enables a real community rules ecosystem.

---

# 20. The most important target architecture I see now

After inspecting the real implementation, I would evolve Code Guardian toward this:

```text
                         ┌─────────────────────┐
                         │    MCP / CLI / CI   │
                         └──────────┬──────────┘
                                    │
                           Interface Layer
                                    │
                    ┌───────────────▼───────────────┐
                    │       CODE GUARDIAN CORE       │
                    └───────────────┬───────────────┘
                                    │
                         Repository Intelligence
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
              ▼                     ▼                     ▼
        File/AST Model       Dependency Graph       Project Model
              │                     │                     │
              └─────────────────────┼─────────────────────┘
                                    ▼
                              Analyzer Engine
                                    │
        ┌───────────┬──────────┬────┴────┬───────────┬──────────┐
        ▼           ▼          ▼         ▼           ▼          ▼
   Security    Architecture  Testing  Reliability  API     Production
        │           │          │         │           │          │
        └───────────┴──────────┴────┬────┴───────────┴──────────┘
                                    ▼
                              Rule Engine
                                    │
                                    ▼
                            Evidence Engine
                                    │
                                    ▼
                             Finding Engine
                                    │
                              ┌─────┴─────┐
                              ▼           ▼
                         Risk Model   Confidence
                              │           │
                              └─────┬─────┘
                                    ▼
                           Remediation Engine
                                    │
                   ┌────────────────┼────────────────┐
                   ▼                ▼                ▼
                 Report            Patch            CI Gate
```

**This is the architecture we should design the future roadmap around.**

---

# Current maturity assessment

Not a score—because we're not trying to turn this audit into an arbitrary rating—but structurally:

| Area                | Current state         | Architectural implication            |
| ------------------- | --------------------- | ------------------------------------ |
| MCP interface       | Functional            | Needs modern schema/contracts        |
| Tool registry       | Good foundation       | Keep and evolve                      |
| Audit engine        | Basic                 | Major expansion required             |
| Repository scanner  | Basic but usable      | Needs central repository model       |
| Security            | Shallow               | Dedicated security subsystem         |
| Architecture        | Structural            | Needs graph/semantic analysis        |
| Rules               | Static knowledge      | Needs versioned rule engine          |
| Findings            | Informal              | Needs formal evidence model          |
| Scoring             | Binary checklist      | Needs evidence/risk model            |
| Generators          | Templates             | Needs context-aware remediation      |
| CLI                 | Minimal               | Can evolve after core engine         |
| HTTP                | Functional/local      | Needs modern MCP + security redesign |
| Tests               | Good v2 foundation    | Needs benchmark/conformance suite    |
| CI/CD               | Good                  | Needs audit-quality gates            |
| Documentation       | Strong prototype docs | Needs architecture/methodology docs  |
| Extensibility       | Limited               | Major opportunity                    |
| Community ecosystem | Not yet established   | Must be designed into architecture   |

---

# Most important conclusion

I **would not start implementing the existing `UPCOMING_FEATURES.md` roadmap**.

The current roadmap is too feature-oriented:

```text
Streamable HTTP
Secret scanning
Write mode
Python
tools.js refactor
score weights
```

Those are individual features.

We now need a **capability-oriented architecture**.

The evolution should instead be:

```text
                 CURRENT
                    │
                    ▼
          Repository Intelligence
                    │
                    ▼
             Evidence Model
                    │
                    ▼
               Rule Engine
                    │
                    ▼
             Analyzer Platform
                    │
                    ▼
             Finding / Risk
                    │
                    ▼
          Production Intelligence
                    │
                    ▼
             Remediation
                    │
                    ▼
           Continuous Guardian
                    │
                    ▼
           Community Ecosystem
```

And that is what will allow us to add Python, Go, Rust, Kubernetes, databases, cloud, security, architecture, etc. **without continually rewriting the core.**

---

## One thing I am deliberately NOT doing yet

I am **not writing the final Architecture document or Release Roadmap yet**.

We now have enough understanding to start designing them, but there is one more architecture-audit layer I want to complete first:

### **Phase 2 — Deep behavior + contract audit**

I want to map every existing tool:

```text
Tool
 ↓
Input
 ↓
Validation
 ↓
Dependencies
 ↓
Filesystem operations
 ↓
External commands
 ↓
Output
 ↓
Error handling
 ↓
Tests
 ↓
Known limitations
```

Then create the **current-state capability matrix**:

```text
15 tools
×
actual implementation
×
actual tests
×
security boundary
×
future role
```

That will tell us exactly which existing tools should survive unchanged, which should become wrappers, which should be deprecated, and which should become components of the new engine.

**After that, we can design the target architecture and only then write the two master documents:**

1. `CODE_GUARDIAN_EVOLUTION_ARCHITECTURE.md`
2. `CODE_GUARDIAN_EVOLUTION_ROADMAP.md`

That is the correct sequence if we're serious about making this a long-term engineering platform rather than just adding features to the current v2 codebase.

[1]: https://blog.modelcontextprotocol.io/posts/2026-07-28/?utm_source=chatgpt.com "The 2026-07-28 Specification | Model Context Protocol Blog"
[2]: https://apps.extensions.modelcontextprotocol.io/api/interfaces/server-helpers.ToolConfig.html?utm_source=chatgpt.com "ToolConfig | MCP Apps"
