# Guarded Device alias worker qualification

Schema 85 introduces reserve and readiness entry points owned by an isolated
NOLOGIN, NOSUPERUSER, NOBYPASSRLS role without memberships. The worker login
receives only EXECUTE on these two guarded operations. Runtime receives none.
Direct table access, internal allocator and scope/proof helpers stay private.
The existing pool cursor has no RLS; its capability is confined to the NOLOGIN
owner and its allocator explicitly binds the selected Deployment and pool.

A typed intent selects one public Deployment, endpoint, consumer Device and
expected generation/key epochs. It cannot choose addresses, packet policy,
Workspace scope, expiry or revision. The functions clear all closed authority
GUCs, derive scope from the exact endpoint and restore caller context on exit.
Both Network revision locks precede endpoint/contract/target, Device/key and
allocation locks. Audit heads are last. No external effect runs under locks.

Reserve rechecks accepted bilateral consent, current export pins and both
client version claims after allocation locks. Readiness requires previously
committed leases and the complete authenticated map-reader predicate, including
current consumer rule and all live pins. Reservation alone grants no packets.
Mutation, both revisions, exact audit batch and outbox evidence commit together.
PostgreSQL generates canonical payload bytes; Go computes the standard audit
hash locally and finalization rederives and checks every evidence field.
Missing, modified or repeated evidence fails. An uncertain commit is never
retried inside the operation. Exact readiness replay emits no extra event.

## Verification

- Full make quality: tidy, vet, shuffled tests, race, normal and integration
  lint, reachability vulnerability scan and actionlint passed.
- Disposable PostgreSQL 18.6/Redis 8.8, migrations 1–85, uncached race
  integration passed in 32.878 seconds.
- Actual mesh_worker role: direct tables and internal allocator denied;
  runtime entry point denied; poisoned scope restored. Changed accepted offer,
  export semantics, missing client claim, stale key and missing rule rejected.
- Missing audit/outbox evidence rolls back; changed payload rejected;
  complete reservation and readiness accepted; duplicate finalization rejected;
  exact readiness replay produces no mutation/evidence. Both maps match.
- Adapter tests cover bounded ownership, strict proof decoding, cancellation,
  cleanup errors and unknown commit without retry.

## Remaining activation gates

This is a guarded storage capability, not a deployed worker loop. Map feature
remains off by default. Withdrawal/quarantine, bounded candidate pagination,
owned runtime composition and client claim advertisement are still required.
Genuine Core/SSO enrollment and encrypted two-host qualification remain pending.
The earlier client fixture PASS does not prove this runtime integration.
No POC database, profile, membership or packet rule changed in this increment.
