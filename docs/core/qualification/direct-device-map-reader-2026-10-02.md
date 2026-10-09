# Authenticated direct Device map reader qualification

Date: 2026-10-02. This checkpoint extends direct readiness migration 79 with
migration 80 and a runtime PostgreSQL map reader. It is not live packet evidence.

## Boundary implemented

The ordinary peer and packet-policy queries remain exactly Network scoped.
After constructing that base map, the adapter reads a separate bounded sharing
projection in the same read-only repeatable-read transaction. A failure rejects
the whole candidate map; it never commits partial sharing state. A stream with
direct grants sends terminal withdrawal on an authority read failure even before
its sharing deadline, rather than retaining a previously allowed grant.

`load_direct_share_map_edges_v1` authenticates the current machine fingerprint
and Node key inside the installed self scope. It discards a caller-supplied
remote-scope setting, derives each remote Network from a ready same-Workspace
endpoint, and restores the setting on success and failure. The isolated
`mesh_direct_map_reader` NOLOGIN role has SELECT privileges and exact local/derived
remote RLS policies. Application roles receive EXECUTE only and no membership in
that role. Ordinary cross-Network inventory remains unavailable after the call.

Both perspectives must agree on current export, accepted offer, contract,
import, Resource target, endpoint version/generation, current Device session and
key epochs, the pinned primary lease, both authority generations and recovery
epoch. Only the consumer's active immutable release at its current policy
revision can select a consumer Device. Provider maps receive that exact consumer
peer and the directed inbound tuple. Consumer maps receive the exact provider
peer without an opposite initiation rule. Versions, hashes and deadlines are
validated again by domain constructors before attaching a projection.

Work is bounded to 256 ready endpoints and 256 output grants per self map, with
limit-plus-one rejection, a 64 KiB per-edge decode bound and existing combined
peer, rule and encoded frame bounds. There is no ordinary remote inventory scan.

## Explicit absence of additional traffic ceilings

The present schema has no independently configured Guardrail or Resource traffic
ceiling authority. Migration 80 records this capability explicitly in
`deployment.direct_sharing_ceiling_profile`, rather than copying contract traffic
into three supposedly independent ceilings. The only supported profile is
`no-additional-traffic-ceilings-v1`; `blocked`, missing and unknown profiles grant
no sharing access.

For the supported profile, the additional ceiling is the intersection identity:
TCP and UDP ports 1–65535 and the supported ICMP shape. This value is not an
Access Rule. A current export, contract, endpoint and exact consumer rule remain
mandatory. Empty new policy still denies every sharing edge. Installing
configured ceilings must disable this profile atomically until a replacement
authority reader and profile resolve them. This checkpoint does not claim that
Guardrail or Resource constraint authoring is implemented.

## Operator order

1. Provision the isolated role using
   `migrations/operator/000080_direct_device_map_role.sql` as the database
   operator before migration 80. Do not grant membership to any application role.
2. Apply the forward migration catalog through the normal migration job.
3. Apply existing sharing ownership hardening, then migration 79 ownership, then
   `000080_direct_device_map_function_ownership.sql` as the operator.
4. Verify the function owner and runtime EXECUTE privileges before serving the
   new reader. Ownership hardening is tested twice for idempotence.

No new reader or writer application generation is introduced. An older binary
does not call the new reader. Direct runtime rollout still requires the client
packet-deadline gate and bilateral notification qualification.

## Verification

- Full Core quality gate passed: formatting, tidy, vet, whole-tree unit and race
  tests, ordinary and integration lint, reachable vulnerability scan, actionlint.
- Disposable PostgreSQL 18.6 and Redis 8.8 TLS integration passed with migrations
  1–80. The final run including bilateral SQL probes completed in 21.152 seconds.
- Both reader perspectives preserved consumer source identity and TCP 443;
  ordinary foreign Device reads returned no rows after the call.
- Resource retarget, consumer release change, provider Node epoch/session/expiry,
  lease generation, authority generation, recovery and import version changes
  removed the edge. A blocked ceiling profile also removed it.
- Mismatched keys, spoofed Network scope and unsafe bounds rejected the request.
  Caller remote-scope state was restored.
- Adapter tests cover immutable separation from ordinary inventory, precise
  provider inbound direction, deadline capping, malformed/oversized evidence,
  unknown profiles, output overflow and whole-map rollback on reader failure.

## Remaining live gates

The stream still watches its local Network. Add bounded subscriptions for both
participating revision/connectivity scopes and dependency discovery when a ready
share currently has no consumer rule. Repair dropped hints by authoritative
reconciliation; notifications must never grant access. Publish/deploy the Core
and the client deadline gate only after those tests pass. Then re-enroll two real
clients normally into distinct Networks and qualify exact encrypted packet
direction, ports, expiry and revocation. DNS remains the next feature slice.
