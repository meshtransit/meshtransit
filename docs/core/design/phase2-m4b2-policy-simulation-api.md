# Phase 2 M4b2 policy simulation persistence and API design

Status: implemented engineering slice, pending deployed-environment qualification.

Date: 2026-09-29

## Scope

M4b2 exposes the M4b1 compiler-identical simulation domain through the
management API and adds the PostgreSQL adapter required to reconstruct the
complete active compiled baseline. PostgreSQL remains the only authority.
There is no graph database, Redis authority, policy mutation, durable approval,
or alternate policy evaluator in this slice.

The operation is:

`POST /api/v1/workspaces/{workspace_id}/networks/{network_id}/policy/actions/simulate`

It requires an authenticated Account Session, fresh `policy.validate`
authorization, exact Workspace/Network scope, and a strong `If-Match` carrying
the active policy revision. The request contains the same bounded rule schema
used by publication, without an audit reason or idempotency key because the
operation is read-only.

## Authoritative baseline read

Migration 46 adds the least-privileged
`mesh_ops.read_policy_simulation_baseline_v1` security-definer function. The
runtime role can execute the function but receives no direct table grant. The
function:

1. verifies transaction-local Workspace and Network scope;
2. resolves the complete Account Session authority vector for
   `policy.validate` at the application-supplied evaluation time;
3. reads all eight Network authority revisions;
4. selects only the active release at the current policy revision; and
5. returns all compiled rules plus exact direct Resource and expanded Resource
   Group provenance, capped at 10,001 rows so corrupted over-limit authority is
   detectable.

The adapter executes this function inside a repeatable-read transaction. It
reconstructs publication format 1, 2, or 3 candidates with the existing domain
constructors, recomputes the candidate semantic hash, and requires it to equal
the durable release hash. Missing, mixed, malformed, over-limit, or
format-inconsistent evidence fails closed.

Before the first release, the only accepted state is policy revision 1 with no
release metadata and no compiled rules. The adapter reconstructs the canonical
empty format-v1 default-deny candidate.

## Stability and authorization

The simulation service obtains a fresh application-clock timestamp for each
of its two baseline reads. This prevents a permission that expires during
compilation from being treated as still current. The first read must match the
strong policy precondition. Any revision mismatch returns stale-input evidence
before compiler invocation. Any baseline or authority drift across compilation
returns no successful result.

PostgreSQL authorization failures are mapped only to the opaque simulation
`ErrForbidden`; database details and object existence are not disclosed.

## Management response

The successful response is non-cacheable and returns:

- current and proposed eight-field revision vectors;
- active release presence, identity, compiler format, and semantic hash;
- proposed compiler format, semantic hash, and compiled rule count;
- complete counts and bounded canonical lists for added/removed effective
  relationships and explanation paths;
- bounded affected Device, Resource, and Resource Group identities;
- the complete untruncated impact hash;
- explicit unsupported capabilities; and
- `truncated`, `stale_inputs`, and `uncertain` flags.

`stale_inputs` and `uncertain` are always false on a successful result. Stale
input is an HTTP 412 failure, never a successful best-effort preview.

Both Bearer management and the private Console source use the same operation
contract. Private Console dispatch keeps its existing cookie, origin,
continuation-proof, CSRF, rate-limit, and fresh browser-admission validation.

## Security and operational bounds

- Request bodies are limited to 8 MiB, 10,000 authoring rules, and the existing
  per-rule port-range limit.
- Unknown JSON fields, ambiguous selectors, weak/wildcard preconditions, query
  strings, alternate paths, and unsupported methods are rejected.
- Public evidence lists are capped at 256 while counts and the impact hash bind
  the full result.
- Simulation never inserts a release, advances a revision, emits audit/outbox
  evidence, or writes an idempotency record.
- All success and error responses preserve the existing management security,
  correlation, rate-limit, and safe-error envelope behavior.

## Non-claims and next order

M4b2 does not provide durable human approval, publication-time complete-vector
CAS, deployed browser/API qualification, graph materialization, Principal
projection, Guardrails, sharing, cross-scope relationships, routed/service
Resources, production SLOs, HA, or GA.

M4c is next: persist an approval bound to the unchanged candidate semantic
hash, complete baseline vector, and impact hash; require a distinct authorized
human decision; and revalidate the complete vector atomically at publication.
