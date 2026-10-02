# Direct Device readiness checkpoint

## Scope

Migration 79 adds durable same-Workspace direct Device readiness. Management
activation now uses `activate_resource_share_v3`; revocation uses
`revoke_resource_share_v5`. This checkpoint does not enable live cross-Network
packets: the runtime map reader still supplies ordinary same-Network authority.

The new `mesh.direct_device_endpoint` is separate from alias endpoints. It binds
the exact contract/import versions, Resource version/target/hash, provider Device
session and machine/Node epochs, one current primary lease identity/generation,
both Network authority generations, deployment recovery epoch and traffic hash.
The exclusive proof deadline is no later than the contract or provider Device
deadline. The consumer access name remains reserved; direct DNS publication is
not part of this checkpoint.

## Transaction and isolation

Same-Workspace activation first uses the existing bilateral activation boundary
to lock both Network revision rows in deterministic order, recheck current
authorities and activate the contract/import. It then requires an active Device,
current active machine/Node epochs valid at evaluation time, and an active primary
lease before inserting ready evidence. Failure rolls back the complete mutation,
including revisions and idempotency claims. A ready row alone grants no traffic.

Terminal Trust Contract transitions withdraw direct evidence in the same
transaction. The explicit contract trigger is covered by the existing change ID,
mutation coverage, both audit streams and both revision outbox records. Runtime
DML on direct endpoints is absent; FORCE RLS restricts ordinary reads to the
exact consumer Network. The NOLOGIN sharing writer uses the exact two-scope
boundary. Cross-Workspace activation retains federation provisioning, readiness,
DNS publication and withdrawal requirements.

The operator-only ownership step must run after the existing sharing ownership
steps, before enabling the new writer. Legacy v2 activation and v4 revocation
entry points remain available for supported generation-1 rollback writers.
Legacy terminal transitions also invoke direct withdrawal. This is an expanding
migration; previous migration files and checksums are unchanged. A complete old
binary rollout/rollback rehearsal is still a release gate.

## Verification

Disposable PostgreSQL migration integration covers schema 1 through 79 and the
complete Resource Sharing management lifecycle (final run: 21.102 seconds).
Core `make quality` passed: format/tidy, vet, unit/race with shuffle, regular and
integration lint, reachable-symbol vulnerability scan and workflow lint. New
staged secret scanning passed; this is not a clean whole-history scan claim.
The pre-existing Dex patch findings remain recorded in the protocol checkpoint.

The database integration checks direct proof bindings,
activation replay, rollback for expired/revoked Devices and missing current Node
epochs, ordinary consumer/provider/third-Network/absent-scope RLS, endpoint
withdrawal with contract/import/name state, and bilateral audit/outbox evidence.
A rollback-only runtime call to legacy `revoke_resource_share_v4` after direct
activation checks endpoint withdrawal and exact one-step advancement of both
Network revisions; the normal service then commits v5 revocation with evidence.
Both SQL and adapter federation publication regressions still run on separate
cross-Workspace fixtures, including automatic recovery-epoch invalidation.

The first run rejected an older Resource fixture targeting an expired Node
epoch. The test now creates a separate Resource through the normal Resource
service, bound to a Device with current active keys. Application validation was
retained. Fault injection is confined to the disposable integration administrator;
production roles cannot disable lifecycle or evidence triggers.

## Remaining runtime gates

- Authenticate and bound a bilateral map read using machine fingerprint and Node
  key in the existing read-only repeatable-read snapshot.
- Resolve current active consumer Imported Resource policy plus export, direct
  proof, Resource, Device, key, lease, expiry and both revision vectors.
- Define explicit evidence for absent/configured traffic Guardrails and Resource
  constraints. The database currently has no independent persisted traffic
  Guardrail definitions; copying contract traffic into every independent ceiling
  would not prove their authority.
- Deliver both Network changes through Redis hints and repair lost/reordered
  hints through PostgreSQL reconciliation.
- Package the client deadline gate, refresh normal SSO enrollments, and qualify
  real IPv4/IPv6 allow/deny, reverse initiation, third-Device isolation,
  non-transitive access, revoke, expiry and missed wakeups.

No image was published, migration applied to POC, or live share enabled for this
checkpoint. Router and SSH remain deferred.
