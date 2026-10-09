# Consumer Trust Contract read

`GET /api/v1/workspaces/{workspace_id}/networks/{network_id}/trust-contracts/{trust_contract_id}`
returns current consumer-local metadata for lifecycle review and lost-response
reconciliation. A read never activates a contract, publishes DNS or grants packets.

The caller needs a freshly authorized Account Session and `share.read` in the exact
Consumer Network. A provider-side offer locator does not authorize reading local
Imported Resource metadata. Provider and unrelated Network reads fail closed.
The private Console profile requires the existing cookie and browser channel;
the read accepts no mutation proof, request body, query, If-Match or idempotency key.

One bounded repeatable-read transaction sets exact RLS scope, checks current
membership and administrative authority, resolves the accepted offer and contract,
and joins the exact Imported Resource and Access Name. No new SECURITY DEFINER
function, role, RLS policy, grant or migration is introduced. Existing unique IDs
and consumer-local indexes bound the lookups.

The strong ETag is the current Contract version. Local Imported Resource version,
label, retained access name, bilateral scope, Resource binding, traffic ceiling
and exclusive expiry are returned together. Historical or expired metadata may
remain readable; lifecycle state, naming intent and peer presence grant no access.
Activate and Revoke still recheck authoritative scope, current version, expiry,
permission and readiness atomically with audit/outbox. Never derive a current
Contract version from the accepted Offer version.

Threat cases covered by the boundary tests include foreign-side scope, wrong
contract identity from a repository, cancelled reads, mutation headers on a GET,
unexpected queries and accidental offer-token disclosure. PostgreSQL qualification
reads activating, active and revoked versions and denies provider-local scope.
Redis is not an authorization source for this read.
