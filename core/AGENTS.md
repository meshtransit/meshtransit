# MeshTransit Core engineering instructions

## Purpose and scope

These instructions apply to everything under `core/`. The Core is
an original, open-source control plane. It must be secure by default, compatible
with supported MeshTransit clients, horizontally scalable, straightforward to
self-host, and maintainable by contributors who did not design the system.

The words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are
normative.

Before any Go coding, review, debugging, troubleshooting, or setup task, load
the `samber/cc-skills-golang@golang-how-to` skill first — it routes to whichever
other Go skills the task needs.

Respect system, user, and enclosing workspace instructions. In particular,
honor any command wrapper required by the current workspace, such as `rtk`.
Command examples in this file omit environment-specific wrappers.

## Sources of truth

Use sources in this order:

1. Approved product requirements, protocol specifications, and ADRs.
2. The topic-oriented architecture documents in `docs/architecture/`.
3. Versioned conformance fixtures and externally observable contract tests.
4. These repository instructions.
5. Implementation code and ordinary unit tests.

During repository bootstrap, the canonical architecture documents may still be
in the sibling directory `../core-docs`. Resolve architecture documentation in
this order:

1. `docs/architecture/README.md`, when present.
2. `../core-docs/README.md` in the development workspace.

Read the architecture README's routing table, then only the documents required
for the task. Before the first public release, move the canonical documents
into this repository so a standalone checkout is complete and reproducible.

When two authoritative sources conflict, do not guess and do not silently make
one pass. Stop the affected implementation, record the conflict, add a failing
contract test when possible, and resolve it through the relevant ADR or
protocol specification.

## Clean-room and compatibility boundaries

This repository MUST NOT copy, port, translate, or mechanically rewrite
Headscale source code. It MUST NOT depend on Headscale packages, schemas,
migrations, generated files, binaries, internal IDs, configuration models, or
runtime behavior.

The sibling `../headscale` checkout is a read-only interoperability reference.
It may be inspected to understand externally observable legacy behavior, but it
is not an architecture template. Never copy its files, comments, tests, SQL,
types, package layout, or control flow. Express a required observation first as
a product-owned specification or sanitized black-box fixture, then implement it
independently.

The MeshTransit client in `client/` (formerly the `meshd` repository) is the implementation reference
for currently supported client behavior. Before changing a client-facing
contract:

1. Read `client/AGENTS.md` and the relevant client architecture/security
   documents.
2. Pin and record the exact `meshd` commit or release artifact under test.
3. Trace the actual source and tests at the protocol boundary; do not infer a
   contract from type names or old documentation.
4. Convert the behavior into a versioned Core-owned protocol fixture and
   conformance requirement.
5. Run the same black-box case against the approved legacy `.87` oracle and the
   new Core when the behavior is intended to remain compatible.

`meshd` is evidence, not a substitute for a protocol specification. The Core
MUST NOT import `client/` packages (licence boundary and Go `internal`
rules); shared protocol code belongs in `shared/`. Checked-in specifications and sanitized fixtures
must make this repository independently buildable.

Core contains only MeshTransit protocol code; it never copies code from other
VPN products, and its dependencies come only from the reviewed
`hack/allowed-modules.txt` (`make check-boundaries`). No package, generated
API, database type, log field, metric, public identifier, or product-facing
documentation may expose another product's implementation names.

## Control protocol contract

Nodes speak MTCP v1 (`docs/protocol/mtcp-v1.md`) to Core and MTRP v1
(`docs/protocol/mtrp-v1.md`) to relays; `shared/mtcp` and `shared/mtrp` hold
the codecs both sides use. Whatever the protocol, Core must preserve:

- Registration supports enrollment-key and same-origin browser authorization
  flows. Duplicate and retried operations converge without consuming extra
  one-off uses, identities, or addresses.
- The first map on every stream contains the authenticated self Node and a
  complete, explicit peer set, including an empty set. A reconnect never starts
  with a delta and cannot resurrect stale peers. Duplicate, stale, malformed,
  or ambiguous updates must not partially mutate effective state.
- Endpoint candidates and the home relay are routing observations, never
  identity or authorization. Updates are bound to the authenticated Node,
  discovery key, session and Network scope.
- Every projected map contains only one Network plus explicit authorized share
  projections. The node never sends a trusted Network ID, and maps from
  different profiles are never unioned.
- The packet filter is Node-reduced and deny-by-default. Peer presence, routes,
  endpoints, and capabilities do not grant packet access.
- Relay directory and peer authorization derive from the same validated
  Network projection; relay reachability cannot grant peer visibility.
- Core never sends a node a URL it would fetch beyond the fixed same-origin
  approval URL of browser registration.

Compatibility tests compare semantics, not incidental JSON order, peer order,
timestamps within an approved tolerance, random nonces, or diagnostic text.
They MUST compare identity, scope, addresses, routes, policy, DNS, key expiry,
relay authority, revisions, and revocation outcomes exactly.

The production rollback floor is `.87-security-remediation`. No plan, test,
deployment, or migration may require rolling production below it.

## Repository and module layout

Use this initial shape unless an approved ADR changes it:

```text
meshcore/
├── cmd/meshcore/                 composition root and process lifecycle
├── internal/
│   ├── app/                      cross-module orchestration contracts
│   ├── workspace/                governance and deployment-profile scope
│   ├── network/                  Network identity, membership, and revision
│   ├── identity/                 principals and external identity bindings
│   ├── node/                     Device/Node identity and key epochs
│   ├── enrollment/               credentials, profiles, and registration
│   ├── ipam/                     realms, prefixes, leases, and quarantine
│   ├── group/                    typed identity/device/resource collections
│   ├── policy/                   intent, validation, compilation, explanation
│   ├── resource/                 private Resources and exports
│   ├── sharing/                  Trust Contracts and Private Endpoints
│   ├── route/                    advertisement, approval, and selection
│   ├── dns/                      canonical Network-scoped DNS intent
│   ├── control/                  sessions, maps, revisions, and presence
│   ├── relay/                    relay inventory and authorization
│   ├── audit/                    immutable security evidence
│   └── adapter/
│       ├── postgres/
│       ├── redis/
│       ├── httpapi/
│       ├── legacyadmin/
│       ├── controllistener/
│       ├── mtcp/
│       └── oidc/
├── api/openapi/                  versioned management contract
├── api/protocol/                 wire specifications and fixtures
├── migrations/                   reviewed expand/contract SQL
├── tests/                        cross-package contract and system tests
├── deployments/                 portable self-host and cloud examples
├── docs/
├── go.mod
├── LICENSE
├── SECURITY.md
└── THIRD_PARTY_NOTICES.md
```

The intended module is `meshtransit.net`; the binary is
`meshcore`. `cmd/meshcore` parses configuration, constructs dependencies,
selects runtime roles, handles signals, and coordinates shutdown. It contains
no domain policy.

Do not create `utils`, `common`, `helpers`, a giant `ports` package, or a public
`pkg` tree as a dumping ground. Extract shared code only after stable semantic
ownership is clear.

## Architecture and design patterns

Use a modular monolith with hexagonal boundaries and vertical-slice delivery.
The dependency direction is:

```text
cmd/composition -> adapters -> application/use cases -> domain
```

Domain code MUST NOT import HTTP frameworks, protocol codecs, database or Redis
drivers, Kubernetes clients, OIDC SDKs, global configuration, or adapters.
Adapters translate external representations at the boundary. They do not own
tenancy, authorization, policy, or lifecycle decisions.

Within a module:

- Keep entities, value objects, invariants, state transitions, and domain
  errors together.
- Put commands, queries, and orchestration in explicit application services.
- Define small interfaces where they are consumed, normally one to three
  methods. Accept interfaces and return concrete implementations.
- Prefer one vertical slice that reaches storage, audit, outbox, API, tests, and
  observability over many disconnected horizontal abstractions.
- A module owns its durable state. Another module uses its application
  contract; it does not query the owner's tables directly.
- Cross-module events announce already committed facts. They are not a hidden
  command channel and cannot become authorization evidence.

Use these patterns deliberately:

- **Explicit state machines** for registration, browser authorization, Node-key
  rotation, sessions, revocation, PolicyRelease, Trust Contracts, and recovery.
  Invalid transitions return typed errors and never partially mutate state.
- **Ports and adapters** for PostgreSQL, Redis, protocols, OIDC, clock, ID/key
  generation, KMS, event delivery, and external witnesses.
- **Immutable snapshots** for compiled policy and client projections. Build and
  validate a candidate completely before atomic publication.
- **Transactional outbox** for authority-changing side effects. Domain state,
  revisions, audit evidence, and outbox records commit together.
- **Idempotent consumers** keyed by public operation/event ID and authoritative
  revision. Delivery is at least once.
- **Strategy selection** only where behavior genuinely varies, such as protocol
  profile or route/source mode. Prefer a switch on a closed domain enum over a
  needless interface hierarchy.

Do not introduce event sourcing, CQRS infrastructure, service locators,
reflection-based dependency injection, global registries, or distributed
sagas without an approved ADR and measured need. Separating command and query
types is useful; adopting a framework is not required.

Construct dependencies manually. Constructors validate required inputs and
return explicit errors. No package may start goroutines, register handlers, read
environment variables, connect to dependencies, or mutate global state from
`init()`.

Application use cases own transaction boundaries. Repositories MUST NOT hide
independent transactions or commit internally. A multi-aggregate write is one
short, explicit transaction with deterministic lock order.

## Domain and tenancy rules

- `WorkspaceID`, `NetworkID`, `NodeID`, `ResourceID`, and similar identifiers
  are distinct typed values. Never exchange them as bare strings or integers at
  application/repository boundaries.
- Public IDs are stable, opaque, application-generated values. Internal
  sequence IDs never cross a trust boundary.
- A Workspace is the governance and address-realm boundary. A Network is the
  ordinary security, visibility, DNS, policy, and scale boundary.
- Cloud supports many Workspaces, each with many Networks. Self-host supports
  exactly one Workspace with many Networks. Enforce this in Core domain/API and
  entitlement logic, not only in Console routing or hidden UI controls.
- Network overlay Prefix Sets cannot overlap inside one Workspace. Different
  Workspaces may reuse identical overlay and routed CIDRs safely.
- Every Network-owned operation carries exact typed Workspace and Network
  scope. Do not expose an unscoped `FindByID`, `ListAll`, or bulk mutation to
  application code.
- Derive scope from the authenticated principal, enrollment, machine identity,
  and server-side membership. Client-supplied scope fields are filters at most;
  they never expand authority.
- A Network map is one Network plus explicit authorized sharing projections.
  Never union Networks to implement sharing.
- Routes provide reachability, never permission. Addresses, names, endpoints,
  presence, and Redis values are not identity.
- Cross-Workspace Resource sharing uses generation-bound Resource Alias and
  Consumer Source Alias projections with two-sided authorization, expiry,
  revocation, source enforcement, and quarantine. Never expose an ambiguous raw
  provider CIDR to a consumer with an overlapping address realm.
- Identity Groups, Device Groups, and Resource Groups are distinct types.
  Device ownership, registration actor, custodian, and group membership remain
  separate. A Device cannot self-assert a privileged group.

Use constructors to enforce invariants. The zero value of every enum is
`Unknown` or invalid. Never make zero mean a privileged/default state. Preserve
the semantic difference between absent, null, empty, and default values in
domain/API/protocol boundaries.

## Go implementation rules

- Prefer the standard library. Add a dependency only with a documented purpose,
  maintenance assessment, license review, vulnerability check, and removal
  cost. Pin tool and module versions reproducibly.
- Write clear code before clever code. Use early returns and small functions
  with one responsibility. When a function needs more than four meaningful
  parameters, use a named options/command struct.
- Use names from the MeshTransit domain. Avoid generic `Manager`, `Processor`,
  `Data`, `Info`, or `Util` when a precise role exists.
- Use `net/netip` for addresses and prefixes. Canonicalize at ingress and store
  canonical values.
- Use keyed composite literals. Return non-nil empty collections in public JSON
  APIs when the contract says empty; do not accidentally change absent/null
  semantics.
- Defensively copy slices, maps, byte arrays, and mutable inputs at ownership
  boundaries. Never return mutable internal state.
- Avoid `unsafe` and CGO. Either requires an ADR, threat analysis, portability
  impact, benchmarks, and dedicated tests.
- Every exported symbol has a useful Godoc comment. Comments explain intent,
  invariants, security constraints, and failure behavior, not syntax.
- TODOs identify an owner or issue, state the safe current behavior, and cannot
  defer authentication, authorization, bounds, cleanup, or error handling.

### Context and lifecycle

- `context.Context` is the first parameter for request-scoped work. Propagate it
  through every I/O boundary; do not store it in structs.
- Boundary handlers create explicit timeouts. Lower layers do not silently
  replace a caller's deadline with an unbounded background context.
- Always call cancellation functions. Cleanup that must outlive a canceled
  request uses a separately bounded lifecycle context and documented ownership.
- Every goroutine has one owner, a bounded/stoppable input, a cancellation path,
  and a join path. No fire-and-forget goroutines.
- Prefer `errgroup.WithContext` for related workers. Bound queues, worker counts,
  retries, fan-out, payload size, and per-tenant work.
- Never hold a mutex across network, database, Redis, filesystem, or user
  callback I/O. Document channel ownership and who closes it.
- Graceful shutdown stops admission, drains within a deadline, cancels workers,
  closes listeners/dependencies, and waits for owned goroutines.

### Errors and logging

- Check every error. Wrap with operation context using `%w`; use
  `errors.Is`/`errors.As` for classification.
- Translate infrastructure errors to stable domain/application errors before
  the API/protocol boundary.
- Expected invalid input and dependency failure return errors; they do not
  panic. Panic only for an impossible programmer invariant in process setup.
- An error is logged or returned, never both. Log once at the process/request
  boundary with the safe correlation and classification fields.
- Never branch on error strings. Public error bodies expose stable safe codes,
  not SQL, stack traces, object existence across scopes, topology, or secrets.
- `//nolint` must name the linter and explain why the suppression is safe.
  Security, resource-leak, or error-handling findings require exceptional
  justification and reviewer approval.

## PostgreSQL and Redis

PostgreSQL is the durable authority. Redis is required from Phase 1 for
consistent single-replica and HA behavior, but it is always non-authoritative.

PostgreSQL rules:

- Use explicit, parameterized SQL through the approved PostgreSQL driver. Do
  not use an ORM, auto-migration, hidden hooks, or schema creation at process
  startup.
- Repository methods accept exact typed scope and context. Every query has an
  explicit bounded timeout and an access-path/index rationale.
- Enforce uniqueness, foreign keys, lifecycle checks, address non-overlap, and
  immutable scope with database constraints where practical.
- Apply exact Workspace/Network RLS with both `USING` and `WITH CHECK` as
  defense in depth. Application authorization remains mandatory.
- Configure connection pools from a deployment-wide budget. A replica cannot
  assume it owns the database connection limit.
- Close rows, check iteration errors, distinguish not-found from failure, and
  map constraint errors to typed conflicts.
- Retry only a complete idempotent transaction on explicitly classified
  serialization/deadlock failures, with a strict attempt/time budget.
- Use the global deterministic lock order documented by the database contract.
- Authority state, revisions, immutable audit evidence, mutation coverage, and
  outbox/change records commit atomically.

Migrations are forward-only expand/backfill/validate/contract steps. They are
versioned SQL, independently reviewed, tested at qualification-scale, and
executed by a separate migration role/job. Do not contract a schema while the
supported rollback artifact still needs it. Never edit or reorder a released
migration.

Redis rules:

- Allowed uses include presence/session leases, generation-bound ownership
  hints, revision wakeups, cache invalidation, distributed rate limits,
  singleflight/coalescing hints, and bounded replayable queues.
- Redis MUST NOT hold the only copy of identity, policy, authorization,
  revision, audit, private keys, or durable work.
- A Redis lock cannot be required for authorization correctness. Loss, flush,
  failover, eviction, duplication, or reordering may reduce freshness or
  availability but cannot widen access.
- Keys are namespaced and versioned, use explicit TTLs, bounded values/scripts,
  command allowlists, TLS/authentication, memory limits, and documented
  eviction semantics.
- Reconcile authoritative PostgreSQL revisions periodically so missed Pub/Sub
  notifications and empty caches repair automatically.

## Management API and IaC

The versioned OpenAPI management API is the single product contract for
Console, CLI, Terraform, Pulumi, CI, and integrations. There are no UI-only
mutations, provider-only authorization paths, or duplicated business rules.

Every declarative resource defines:

- stable opaque ID and exact scope;
- canonical readable state and deterministic ordering;
- ETag/version and `If-Match` behavior;
- bounded idempotency behavior for create/action requests;
- pagination, filtering, import, and disambiguation rules;
- omitted/null/empty/default semantics;
- immutable and replacement-required fields;
- write-only secret fields and drift-safe fingerprints;
- stable error codes, correlation ID, retryability, and safe conflict details.

Policy authoring modifies typed draft resources. Only an immutable,
semantic-checksum-bound `PolicyRelease` can atomically activate client-visible
authority. A partial Console, Terraform, or Pulumi operation must leave the
previous active release unchanged.

Breaking API changes require a versioned migration and deprecation window.
OpenAPI compatibility and provider round-trip/no-perpetual-diff fixtures run in
CI.

## Security requirements

Before implementing a new boundary or authority flow, update its STRIDE threat
model and identify assets, attackers, trust transitions, abuse cases, limits,
and fail-closed behavior.

- Authenticate and authorize every operation server-side. Management RBAC,
  packet policy, group delegation, route approval, sharing approval, and
  enrollment authority are separate decisions.
- The embedded identity broker and its connectors are replaceable OIDC
  authentication components. Core owns stable identity, membership, RBAC,
  sessions, logout generations, and recovery quarantine. Provider roles,
  groups, and email domains never grant Core authority.
- Validate exact OIDC issuer, subject, audience, authorized party where
  applicable, nonce, state, PKCE, time, assurance, algorithm, and trusted key.
  Never link accounts by email alone.
- Generate bearer credentials with at least 256 bits of CSPRNG entropy. Store
  only versioned, domain-separated secret digests where possible; compare
  secret-derived values in constant time.
- Keep private/server signing keys in an approved secret manager or KMS seam.
  Define rotation, overlap, revocation, recovery epoch, and audit behavior
  before use.
- Validate and bound every external string, ID, address, prefix, port,
  protocol, selector, frame, list, request body, header, queue, session, retry,
  and concurrent operation at ingress and again before privileged effects.
- Use parameterized SQL, allowlisted dynamic identifiers, safe template
  escaping, no shell command construction, SSRF-resistant outbound clients,
  strict redirect policy, and explicit trusted-proxy configuration.
- Rate-limit by source, principal, credential, Workspace, Network, endpoint,
  and expensive operation as appropriate. Limits are bounded and observable.
- Do not log or expose private keys, auth/enrollment keys, bearer tokens,
  cookies, OIDC codes/state, complete registration URLs, session handles,
  policy bodies, packet payloads, DNS query names, raw public endpoints, or
  production topology.
- Do not store secrets in source, fixtures, command arguments, URLs, metrics,
  traces, panic output, environment dumps, support bundles, or examples.
- Fail closed on unknown identity/scope, stale generation, expired authority,
  invalid policy, ambiguous sharing, protocol downgrade, dependency ambiguity,
  or incomplete recovery evidence.

Runtime defaults are a minimal non-root container, read-only root filesystem,
explicit writable mounts, dropped capabilities, a seccomp profile, private
debug endpoints disabled, least-privilege service/database accounts, and
restricted network paths.

## HA, consistency, and performance

The v1 availability target is single-region active-active plus disaster
recovery. Runtime roles are `all`, `api`, `control`, `worker`, and `relay` in one
binary/image so roles can scale independently without changing domain logic.

- No correctness path depends on sticky sessions or process-local state. A
  reconnect to another replica reconstructs exact authority from PostgreSQL,
  authoritative revisions, and the authenticated session contract.
- Session generations, Network revisions, sub-revisions, and recovery epochs
  are monotonic and validated. A stale replica cannot renew or republish newer
  authority.
- Notifications are hints to read committed state. Reconciliation repairs
  missed, duplicated, delayed, reordered, or evicted notifications.
- Apply backpressure at every queue and streaming boundary. Slow clients have
  explicit bounded buffers, coalescing rules, deadlines, and disconnect/resync
  behavior.
- Authority commits in HA use the approved synchronous durability contract and
  fail instead of silently acknowledging asynchronous durability.
- Optimize only after a representative benchmark/profile identifies a
  bottleneck. Preserve a simple reference implementation for policy/IPAM
  correctness and compare it with optimized output.
- Performance changes include `benchstat` evidence, allocation results,
  workload shape, correctness tests, and documented trade-offs. Never trade
  exact scope or revocation latency for cache hit rate.

## Observability and operations

Use structured `log/slog`, Prometheus-compatible metrics, and OpenTelemetry
tracing. A feature is not complete until its success, failure, latency,
saturation, and security-relevant transitions can be observed safely.

- Use context-aware logs and traces. Stable operation names and bounded fields
  enable correlation across API, transaction, outbox, Redis, and projection
  work.
- Metrics use low-cardinality labels only. Never label with account, Workspace,
  Network, Node, Resource, hostname, full URL, address, or arbitrary error text.
- Prefer histograms for aggregatable latency and define SLO/alert queries with
  the metric.
- Audit events are immutable security evidence, not ordinary debug logs. Keep
  their access, retention, integrity, and redaction contracts separate.
- Liveness proves the process loop is alive. Readiness proves required
  dependencies, migrations, and role-specific admission are safe. Startup
  checks reject invalid or missing security configuration before listening.
- pprof/debug endpoints are disabled by default and, when enabled, bind to a
  separately authenticated private listener.
- Runbooks cover clean install, upgrade, dependency loss, Redis rebuild,
  database failover, backup/restore, key rotation, migration failure, canary
  abort, and rollback.

## Testing rules

Tests are executable specifications of observable behavior, not assertions
about incidental private implementation.

- Use named table-driven tests. Independent tests should use `t.Parallel()`;
  no test may depend on execution order, wall-clock sleeps, real production
  services, or another test's state.
- Inject clocks, entropy, ID generators, and external effects. Use deterministic
  time/concurrency facilities where supported.
- Name test files after the source file. Prefer black-box package tests for
  public contracts and focused same-package tests for invariants.
- Unit tests are fast and isolated. Integration tests use
  `//go:build integration`, disposable dependencies, isolated schemas/scopes,
  and `-count=1`.
- Concurrent packages use race tests and goroutine-leak detection. Fuzz every
  parser, protocol translation, policy/DNS compiler, key decoder, migration
  importer, and other attacker-controlled structured input.
- Golden files are reviewable, canonical, synthetic, bounded, and updated only
  by an explicit flag. Never regenerate them silently in ordinary tests.

Required test layers are:

1. Domain invariant and state-machine unit tests.
2. Repository/transaction/RLS integration tests.
3. OpenAPI and protocol contract tests, including absent/null/empty behavior.
4. MTCP v1 conformance tests (`shared/mtcp` vectors and the process-level
   registration test in `core/test/integration`).
5. Semantic differential tests against the isolated `.87` oracle.
6. Cross-Workspace/Network IDOR, overlapping-CIDR, hostname, DNS, policy,
   sharing, and non-transitive isolation tests.
7. Multi-replica registration, streaming, revocation, missed-notification,
   reconnect-storm, dependency-failure, and rolling-update tests.
8. Migration, qualification-scale query-plan/lock, backup, PITR, clean-restore,
   recovery-epoch, and supported rollback tests.
9. Disposable Linux end-to-end tests for registration, browser auth, full/delta
   maps, reconnect, direct path, forced relay, policy, DNS, expiry, and
   revocation.

Every requirement has a stable ID, owner, test/fixture, status, and evidence
bound to exact source, client, dependency, schema, and artifact digests.
Fixtures MUST NOT contain production keys, tokens, topology, domains, account
identifiers, database rows, or packet captures.

## Quality gates

Prefer repository-owned `make` targets that run the same pinned tools locally
and in CI. Until those targets exist, the bootstrap minimum for every Go change
is:

```text
gofmt/gofumpt check on changed Go files
go mod tidy -diff
go vet ./...
go test -race -shuffle=on ./...
golangci-lint run ./...
govulncheck ./...
```

Before merge, run all relevant gates plus:

- integration and conformance suites with test caching disabled;
- parser/compiler fuzz smoke tests and scheduled extended fuzzing;
- OpenAPI/protocol backward-compatibility and generated-file checks;
- import-boundary checks that reject Headscale and any module outside
  `hack/allowed-modules.txt`;
- migration lint, clean-install, upgrade, mixed-version, RLS/grant, query-plan,
  backup/restore, and rollback tests;
- Gitleaks against both the checked-out tree and complete Git history;
- SAST, dependency vulnerability, license, and third-party-notice checks;
- reproducible multi-platform binary and container builds;
- SBOM, provenance, signature, and High/Critical container vulnerability gates;
- Docker Compose and Helm render/install/upgrade tests where affected.

Do not claim a gate passed if it was skipped, unavailable, flaky, or run against
a different artifact. Document the exact failure and scope. Never weaken a
gate, add a broad exclusion, update a golden file, or suppress a finding merely
to make CI green.

## Open-source professionalism

- Keep `README.md`, `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  `SECURITY.md`, release notes/changelog, architecture/protocol docs, and
  `THIRD_PARTY_NOTICES.md` accurate and reviewable.
- Document supported versions, configuration, security defaults, threat model,
  compatibility matrix, upgrade/deprecation policy, and self-host operations.
- Public examples use reserved domains and documentation address ranges. Never
  publish personal paths, internal origins, infrastructure names, customer
  data, or production deployment topology.
- Preserve authorship and license headers. Generated files identify their
  source and generator and are never edited by hand.
- Keep PRs small and single-purpose. Explain motivation, invariants, security
  impact, compatibility impact, tests, operational impact, and rollback.
- Breaking behavior, schema, protocol, or API decisions require an ADR and
  migration plan before implementation.
- Releases are immutable and reproducible. Publish checksums, signed artifacts,
  SBOM, provenance, notices, compatibility data, and security contact details.
- Never force-push shared history, rewrite released tags/migrations, or commit
  secrets, generated binaries, local state, coverage files, or test evidence
  containing environment details.

## Required work sequence

For every task:

1. Inspect `git status`, current branch/HEAD, and relevant nested
   `AGENTS.md` files. Preserve existing and unrelated changes.
2. Classify the task by module, trust boundary, authoritative state, and
   client/API compatibility impact.
3. Read only the routed architecture, protocol, database, and operational
   documents required for that task.
4. State the invariant, state transition, failure behavior, resource bounds,
   concurrency ownership, and observable acceptance criteria before coding.
5. Add or identify the failing contract/security test. For compatibility work,
   pin the client/oracle artifacts and sanitize fixtures first.
6. Implement the smallest complete vertical slice with explicit construction,
   typed scope, audit/outbox, and observability.
7. Run focused tests while iterating, then the full applicable quality gates.
8. Inspect the final diff for architecture leakage, semantic widening, secrets,
   generated drift, missing docs, and accidental unrelated edits.
9. Report changed behavior, evidence, remaining risks, and deliberately deferred
   work. Do not commit, push, publish, migrate, or deploy unless explicitly
   requested.

Use patch-based edits for deliberate source changes. Do not discard a dirty
worktree, delete existing work, perform a broad mechanical rewrite, or use a
destructive Git command to recover from a local problem.

## Definition of done

A change is complete only when:

- intended behavior and invariants are explicit and tested;
- client, API, schema, security, HA, and self-host compatibility impacts are
  resolved;
- no Headscale dependency or legacy type leaks beyond the permitted adapter;
- exact scope, idempotency, transaction, revision, audit, outbox, and Redis-loss
  behavior are correct;
- failure, cancellation, retry, cleanup, and concurrency behavior are bounded;
- logs, metrics, traces, health, alerts, and runbooks are safe and sufficient;
- required docs, ADRs, specifications, fixtures, and compatibility matrices are
  updated;
- applicable local and CI gates pass against the exact reviewed artifacts;
- there is no unresolved Critical/High security finding, silent waiver, or
  ambiguous authority behavior.

Renaming Headscale concepts is not a rewrite. The Core is complete only when
MeshTransit owns its domain model, policy language, management API, database,
protocol contracts, security properties, HA behavior, performance envelope,
self-hosting experience, migration, and operational lifecycle.

## Forbidden shortcuts

Never:

- copy or mechanically translate Headscale code;
- import Headscale or any module outside `hack/allowed-modules.txt`;
- trust a client-provided Workspace, Network, role, group, route, endpoint, or
  capability as authority;
- implement sharing by merging Networks or exposing ambiguous overlapping
  prefixes;
- treat route, address, DNS name, endpoint, presence, or Redis state as
  authorization;
- hide transactions, use ORM auto-migration, or make Redis the source of truth;
- use mutable global state, side-effecting `init()`, service locators, or
  reflection DI;
- start an unowned goroutine, create an unbounded queue, or retry forever;
- store a context in a struct, ignore cancellation, or hold locks across I/O;
- swallow errors, branch on error strings, log and return the same error, or
  panic on attacker-controlled input;
- log secrets, sensitive topology, packet payloads, DNS queries, policy bodies,
  or unbounded user input;
- add a UI-only mutation or a provider-specific authority bypass;
- optimize without measurements or remove the simple reference evaluator;
- weaken validation, authorization, isolation, or a quality gate for legacy
  parity;
- perform a big-bang rewrite when a tested vertical slice can advance the same
  outcome;
- roll production back below `.87-security-remediation`.
