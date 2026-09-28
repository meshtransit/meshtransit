# Phase 2 M4a Access Graph active-policy explanation design

Status: implemented and locally qualified for bounded active-policy explanation.

Date: 2026-09-29

## Scope

M4a answers one exact question: may one Device initiate `network.connect` to
one Device or Device-backed Resource for a specific TCP/UDP destination port or
for ICMP? The answer is derived from the active compiled policy and its durable
authoring provenance. It does not create a second authorization model.

PostgreSQL remains the relational authority. Access Graph is a revision-bound
projection computed on demand; no graph database, Redis authority, background
graph materializer, or client-side evaluator is introduced.

## Query and decision semantics

- Every query has one exact Workspace-qualified Network, one source Device,
  exactly one destination Device or Resource, one protocol, and one TCP/UDP
  port. ICMP carries no port.
- A Resource query resolves its current active Device target in the same
  repeatable-read transaction as the active policy lookup. A Device-authored,
  Resource-authored, or Resource-Group-authored edge may therefore explain the
  effective Device path, while the path retains its original selector kind.
- Only the release whose revision equals the current policy revision and whose
  state is `active` is considered. Only active source and destination Devices
  and, for Resource queries, an active current Resource target participate.
- At least one matching compiled edge yields `allow` with
  `matching_active_rule`. No matching edge, no active release, or an unavailable
  active target yields `deny` with `no_matching_active_rule`.
- This is explanation of configured effective policy, not proof that a packet
  traversed the data plane.

## Revision-bound evidence

One repeatable-read snapshot returns the Network, inventory, group, policy,
DNS, route, sharing, and isolation revisions. When an active release exists it
also returns its immutable release ID, compiler format, and semantic hash.

Each matching path carries:

- immutable compiled projection and authoring Access Rule IDs;
- source and resolved destination Device IDs;
- protocol and canonical destination-port ranges;
- authoring selector kind: Device, Resource, or Resource Group; and
- Resource and Resource Group IDs when those selectors produced the edge.

The domain rejects malformed, duplicate, non-canonical, cross-query, or
revision-inconsistent evidence. Results are sorted deterministically and capped
at 64 paths; a 65th row sets `truncated=true` without returning unbounded
topology.

## Authorization and database boundary

Migration 45 adds the read-only security-definer function
`mesh_ops.explain_active_policy_v1`. It cross-checks the transaction's exact
Network scope and revalidates the complete Account Session authority vector
through `policy.explain` at the supplied evaluation time before reading graph
evidence.

Only `mesh_runtime` may execute the function. Public, worker, observer, audit,
and share roles cannot execute it; no new table or direct write capability is
granted. Parameters are typed, path limits are checked in PostgreSQL, statement
and lock waits are bounded, and all queries are parameterized.

## Management API

The versioned route is:

```text
POST /api/v1/workspaces/{workspace_id}/networks/{network_id}/access-graph/actions/explain
```

Bearer and private-cookie Console transports use the same handler and service.
The Console path additionally requires the existing origin, channel, and CSRF
proof admission. The endpoint uses the standard source/session rate limits,
request deadline, strict JSON decoding, opaque UUIDv7 identities, safe errors,
and `Cache-Control: no-store`.

Successful output contains the decision, stable reason, exact action, subject,
queried target, revision/release evidence, bounded paths, truncation flag,
correlation ID, and a strong ETag for the policy revision. It exposes no display
names, account attributes, raw database keys, credentials, or unrelated graph
neighbors.

## Failure behavior

- Invalid or ambiguous input returns `400` before an authority read.
- Missing current `policy.explain` authority returns the same safe `403` shape.
- An inconsistent authoritative snapshot fails closed as `500`.
- Dependency unavailability returns retryable `503`; deadline expiry returns
  retryable `504`.
- A syntactically valid unknown Device or Resource is a default-deny result,
  avoiding existence disclosure through `404` distinctions.

## STRIDE review

| Threat | Control |
| --- | --- |
| Spoofing | Fresh Account Session vector, exact scope, current `policy.explain`, and private Console proof. |
| Tampering | Active-release revision equality, immutable projection/provenance IDs, and domain evidence validation. |
| Repudiation | Correlation ID plus immutable release identity/hash; this read does not claim packet execution. |
| Information disclosure | Exact query only, opaque identifiers, safe deny semantics, 64-path cap, and `no-store`. |
| Denial of service | Body, port-range, path, connection, concurrency, transaction, and request-time bounds. |
| Elevation of privilege | Read-only runtime function; no graph writes, policy mutation, or client enforcement authority. |

## Acceptance and non-claims

Executable evidence is recorded in
`docs/qualification/phase2-m4a-access-graph-policy-explanation-2026-09-29.md`.

This is non-production engineering evidence. M4a does not implement draft or
proposed-change simulation, before/after impact diffs, human approval, approval
quorum, historical graph traversal, reverse reachability, principal-to-Device
identity mapping, enforcement receipts, packet telemetry, a Resource Console
UI, deployed HA qualification, production SLOs, or GA.

## Next order

1. M4b: compiler-identical draft simulation and deterministic before/after
   impact, bound to the complete source revision vector.
2. M4c: durable human approval evidence over the unchanged candidate and impact
   hash before protected publication.
3. M5: routed/service Resource resolution and trusted gateway enforcement.
