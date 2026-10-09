# Authorized publisher direct policy publication

Date: 2026-10-01

Status: product decision explicitly requested by the owner; implementation and qualification in progress.

## Decision

A human with current `policy.publish` authority in the exact Workspace and Network can author and activate a valid Policy Release directly. Independent approval is not a prerequisite for the ordinary policy editor. `policy.validate` permits preview only; `policy.approve` does not permit publication. No role or membership is granted by this change.

This supersedes the unconditional production approval requirement in the M4c2b implementation. Canonical RBAC describes separation of duties as optional enterprise governance. The default runtime now uses an explicit authenticated-publisher mode, distinct from the offline qualification mode. Unknown modes and enabling trusted actors in authenticated-publisher mode fail construction. A supplied approval Evidence ID still invokes every existing approval validation and single-use consumption check; invalid, null, empty or expired evidence is never silently ignored.

## Contract and rollout

The existing publish endpoint accepts omission of `approval_evidence_id`. It continues to require an AccountSession, exact scope, fresh browser CSRF/Origin, `If-Match`, valid bounded rules and audit reason. Existing approved clients remain compatible. Deploy Core before enabling the direct Console action. No released migration is edited and no database schema change is needed.

Console previews the replacement, displays additions and removals, and requires an explicit reviewed replacement confirmation before Apply. It submits the same stable rule IDs once. An ambiguous result disables further submission until the active release is reconciled. The existing approval APIs remain available for deliberate reviewed workflows; the ordinary editor does not create an approval request.

## Authority and threats

- Spoofing and elevation: the transaction freshly authorizes `policy.publish` against current Session, identity, Workspace membership and exact Network RoleBinding. Preview permission or an approver role alone cannot activate access.
- Scope substitution: compiler and transaction retain typed Workspace/Network boundaries and current Device/Resource provenance. Sharing continues to require its own two-sided authority.
- Tampering and races: recompile on the server; retain policy revision CAS, immutable semantic hashes, deterministic locks and candidate provenance revalidation.
- Repudiation: release, revisions, publisher authorization, hash-chained audit and outbox commit atomically. Direct releases contain no invented approval evidence.
- Replay and uncertainty: existing bounded commit resolution must distinguish releases with and without approval evidence. Supplied evidence cannot be downgraded to direct mode during replay.
- Availability: preserve all body/rule, query/lock, retry, cancellation and rollback bounds.

## Acceptance

Test direct authenticated publication, exact `policy.publish` authorization, denied/revoked/expired publisher, missing Session, invalid optional evidence, required approval composition, supplied-evidence consumption, stale revision, cross-scope selectors, audit/outbox atomicity and commit replay. Run Core and Console gates and verify the two enrolled POC clients with only reciprocal ICMP access.
