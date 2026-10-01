# Active policy reader and Device rule form

The product GET `/api/v1/workspaces/{workspace_id}/networks/{network_id}/policy`
requires current exact-scope `policy.read`. Console cookie transport and bearer
transport use the same application/storage contract. Source and Session rate
limits, bounded admission, request/SQL/lock timeouts and no-store responses apply.
Read access does not grant `policy.validate` or `policy.publish`.

Migration 75 adds a read-only PostgreSQL function and exposes existing
`policy.read` bindings in the Console navigation projection. It grants no user
membership, binding or packet access. Current Session generations, membership,
RBAC and Network revision are checked under repeatable-read and authority locks.
Rows contain only local selectors; Imported Resource destinations expose the
consumer-local ID and no provider Workspace, Network, Resource or Trust Contract.

At most 1,000 compiled rows are returned with a total count and completeness flag.
Resource provenance remains typed. The Device form cannot edit an incomplete or
Resource-based policy; it never turns Resource selectors into Device intent.
Stable Device rule IDs, protocols and ports are preserved when appending rules.
Strong ETags supply the base revision automatically. The Console requires a
complete fresh preview with zero removals. Publication still reauthorizes
`policy.publish`, validates the compiled candidate and commits audit/outbox/CAS.
Conflicts require refreshed review; uncertain responses are never retried silently.

## STRIDE

Session spoofing and scope tampering fail current Session/RBAC/RLS checks. The
read function checks exact public scope and cannot expand authorization. Reads
expose only bounded authorized local policy data and create no authority. Existing
publish audit/outbox handles repudiation. Rate, row, body, SQL and lock bounds
limit denial of service. Separate read/validate/publish permissions prevent
elevation. A missing artifact, malformed selector, timeout or dependency failure
releases no editable snapshot.

Verification covers HTTP scope/ETag/permission failure, strict bounded decoding,
parser fuzz seeds, PostgreSQL runtime role reads and denied approver reads, plus
Console retention of rule IDs/ports, revision binding, duplicate rejection and
create/cancel behavior. Older migrations and existing policy authority are retained.
