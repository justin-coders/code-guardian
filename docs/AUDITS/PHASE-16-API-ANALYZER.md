# Phase 16 — API Analyzer: research and decisions (ADR)

Official roadmap Phase 16 asks for an `APIAnalyzer` over thirteen listed API domains, with the
explicit requirement that **applicability is critical — a CLI application should not receive HTTP
API findings**. This document records, before code, what each domain can and cannot establish
from the repository model this build already holds, so the analyzer states only what the evidence
supports and answers `unknown` when it cannot.

Source of truth order: repository source and tests, then the roadmap, then the model/query
contracts, then this record.

## 1. The evidence the model actually holds

Only two substrates exist, and this phase adds neither:

- **API graph** (`query.apiGraph`, `query.apiCoverage`) — route nodes declared by a supported
  framework receiver with a literal `/`-prefixed path; each route carries method, path,
  frameworks, declaring files and the evidence id of each declaring file's route scan. Coverage
  is `complete` / `partial` / `truncated` / `unsupported` / `unknown`.
- **Middleware graph** (`query.middlewareGraph`, `query.middlewareCoverage`) — middleware nodes,
  each with a `classification` derived **from the name alone** (`authentication`, `authorization`,
  `validation`, `cors`, `rate-limit`, `logging`, `parsing`, `unknown`), and per-route structural
  protection (`protected` / `unresolved` / `none-observed` / `unknown`).

The model establishes **no** fact about: request bodies, schemas, response statuses, pagination
parameters, error handlers, request size limits, or correlation-ID propagation. This is the
single most important input to the design: six of the thirteen domains have no evidence, and the
honest answer for them is `unknown`.

## 2. Applicability

- An API graph that was never established, or whose only sources are an uninterpreted format, is
  **`unknown`** — never `not_applicable`.
- A route-shaped occurrence the model could not turn into a route (a Koa receiver, a computed
  path) is **`unknown`** — the routes may exist.
- An established, complete graph with no routes and no unresolved occurrence is
  **`not_applicable`**. A CLI repository lands here and receives no finding.

This is the roadmap's central requirement, answered from model facts rather than a route count.

## 3. Domain decisions

For each ambiguous domain: the claim, the evidence, what is insufficient, and the expected false
positives.

### 3.1 Input validation — *structural gap*

- **Claim:** a body-carrying route (POST/PUT/PATCH) is reached by no `validation`-classified
  middleware.
- **Evidence:** the route's fully established middleware chain, and the file's middleware-source
  record.
- **Insufficient:** a middleware's name; a validator registered as a member call
  (`app.use(validator())`) the graph records as an unresolved registration.
- **Unknown:** chain unresolved/unknown/truncated, or a name-classified `unknown` middleware in it.
- **Not applicable:** no API subject.
- **Expected false positives:** validation performed inside the handler; a route that reads no body.

### 3.2 Schema validation — *unestablished*

- **Claim:** none. The model holds no request/response schema fact.
- **Insufficient:** a TypeScript type (a compile-time type is not a runtime schema); a middleware
  name.
- **Result:** `unknown` over an API subject, `not_applicable` when there is none.

### 3.3 Authentication — *structural gap*

- **Claim:** a route's established chain has no `authentication`-classified middleware.
- **Evidence:** route declaration + the file's middleware-source record + the chain.
- **Insufficient / abstain:** as 3.1. A route with unresolved middleware is never reported as
  unauthenticated.
- **Boundary:** this is the API-engineering contract over *every* route and makes no security
  claim; the Security Analyzer's `security.authorization.unprotected-privileged-route` keeps the
  privileged-path security conclusion.
- **Expected false positives:** intentionally public endpoints; authentication inside the handler.

### 3.4 Authorization — *structural gap*

- **Claim:** a route establishing an `authentication`-classified middleware establishes no
  `authorization`-classified middleware.
- **Evidence:** the measured relationship between two name-derived classifications.
- **Boundary:** distinct from authentication and from the Security Analyzer's rule.
- **Expected false positives:** authorization enforced inside the handler; intentionally readable
  by any authenticated caller.

### 3.5 Error handling — *unestablished*

- **Insufficient:** a `try`/`catch` anywhere in a file; the model does not read handler bodies and
  recognises no framework error-middleware signature.
- **Result:** `unknown` / `not_applicable`.

### 3.6 Status codes — *unestablished*

- **Insufficient:** a route's existence or its method. The model reads no `res.status(...)`,
  `res.sendStatus(...)` or `reply.code(...)`.
- **Result:** `unknown` / `not_applicable`.

### 3.7 Pagination — *unestablished (the most inference-sensitive domain)*

- **Insufficient:** a collection route; the literal word `page`; a returned array.
- **Result:** `unknown` / `not_applicable`. The roadmap flags this domain as the one most likely
  to be genuinely unknowable, and the analyzer does not pretend otherwise.

### 3.8 Rate limiting — *structural presence*

- **Claim:** a route's established chain contains a `rate-limit`-classified middleware.
- **Deliberately not a gap:** the repository establishes no baseline for how much rate limiting an
  API ought to have, and a name is not proof that enforcement works.
- **Expected false positives:** a middleware whose name suggests rate limiting but does otherwise;
  a limiter registered through an unestablished form (simply absent, never mis-reported).

### 3.9 CORS — *structural presence*

- **Claim:** a route's established chain contains a `cors`-classified middleware.
- **Deliberately silent on configuration:** origins, credentials and allow-lists are not in the
  model. `app.use(cors())` is a member call recorded as an unresolved registration, so the common
  form is deliberately *not* reported.

### 3.10 OpenAPI — *artifact*

- **Claim:** a file whose basename is a recognised OpenAPI/Swagger document is observed.
- **Explicitly not claimed:** that the API is described accurately or that the document is
  synchronised with the declared routes — the model establishes no relationship between a
  document and the API graph.
- **Absence:** claimed only over a complete file inventory; otherwise `unknown`.

### 3.11 Request limits — *unestablished*

- **Insufficient:** a server existing; a body parser existing. The model reads no parser options,
  server configuration or upload limits, and records `express.json()` as an unresolved member call.
- **Result:** `unknown` / `not_applicable`.

### 3.12 Logging — *structural gap*

- **Claim:** a route's established chain has no `logging`-classified middleware. Because the
  evidence is a middleware registration *on the request path*, this is a request-lifecycle
  statement.
- **Insufficient:** a generic `logger.info(...)` call; the model reads no handler bodies, so a
  non-middleware logger is invisible to the rule and neither satisfies nor violates it.
- **Result:** gap finding, or `unknown` when the chain is not established.

### 3.13 Correlation IDs — *unestablished*

- **Insufficient:** a `request.id` field; a middleware whose name mentions tracing. The model
  reads no request-context propagation and no response-header semantics.
- **Result:** `unknown` / `not_applicable`.

## 4. Absence, partial coverage and the boundary with Security

- **Absence is a claim.** Every gap rule gates on `routeCoverageGap` and `middlewareCoverageGap`:
  an unestablished, partial, truncated or unsupported graph, an unresolved route-shaped
  occurrence, a path that could not be read, or an incomplete inventory all yield `unknown`, never
  a clean pass.
- **Findings win.** A gap observed on a fully established route is reportable even when another
  unrelated source was incomplete; only the *absence* claim needs the complete coverage.
- **No second Security Analyzer.** This pack does not restate
  `security.authorization.unprotected-privileged-route` or `security.exposure.diagnostic-endpoint`.
  Its authentication and authorization rules use the broader, all-route, name-derived API
  contract; the security pack keeps the privileged-path security conclusion.

## 5. Severity and confidence

- Severity is tied to the claim: gaps low, presence/artifacts informational. No aggregate API
  score, grade, readiness percentage or remediation.
- Confidence is evidence strength: `OBSERVED_ARTIFACT` (0.9) for an observed file,
  `ESTABLISHED_STRUCTURE` (0.7) for a fully established structural fact, and `NAME_DERIVED` (0.5)
  for a middleware-name classification. It is never a probability that the API is secure.

## 6. Explicit non-goals

No RepositoryModel change, no acquisition change and no new detector. The pack reads the frozen
model through the Phase 11 query API and nothing else: no filesystem, no parser, no route
resolution, no server, no network, no LLM, no clock. Framework support stays exactly what the
substrate establishes (Express, Fastify); other frameworks are `unknown`, not guessed at.
