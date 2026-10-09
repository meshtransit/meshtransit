# Phase 2 M4b1 compiler-identical policy simulation domain design

Status: implemented engineering slice, pending runtime/API integration and
production availability qualification.

Date: 2026-09-29

## Scope

M4b1 introduces the read-only domain and application boundary for deterministic
before/after packet-policy simulation. It does not add a second evaluator. The
simulation service accepts the existing `compilation.Request` and invokes the
same `Compiler` contract that produces `publication.Candidate` artifacts for
normal policy publication.

This slice adds no database migration, graph database, Redis authority, public
endpoint, policy mutation, approval workflow, or client-side enforcement
change. PostgreSQL remains the intended baseline authority for the subsequent
adapter slice.

## Authority-stability protocol

One simulation performs:

1. a freshly authorized read of the complete current authority vector and
   active compiled release;
2. exactly one invocation of the publication compiler for the proposed draft;
3. a second freshly authorized read of the complete current authority vector
   and active release; and
4. impact derivation only when both reads are exactly equal.

Equality binds Workspace and Network scope, all eight authority counters,
active-release presence and identity, compiler format, and the current compiled
semantic hash. A change in any input returns `ErrStaleInputs`; a stale or mixed
snapshot never produces successful simulation evidence.

The current vector contains Network, Resource inventory, Resource Group,
policy, DNS, route, sharing, and isolation revisions. The proposed vector is
the exact expected single-policy-publication successor: Network and policy
advance once while every other input remains unchanged. M4c must repeat CAS
against the complete current vector before accepting this expected successor.

Before the first publication, the baseline is represented by a canonical empty
format-v1 candidate at policy revision 1. This preserves explicit default-deny
semantics and gives bootstrap simulation the same hash and diff machinery.

## Effective and explanatory diffs

The simulator keeps two concepts separate:

- Effective relationships are directional source Device, destination Device,
  protocol, and exact destination-port intervals. Rules contributing the same
  packet authority are unioned before comparison. Overlapping intervals are
  subtracted, so a change from TCP `80-90` to `85-95` reports only removed
  `80-84` and added `91-95`.
- Explanation paths retain Access Rule identity, Device/Resource/Resource Group
  selector kind, normalized packet intent, and exact Resource/Group version,
  generation, revision, and semantic-hash provenance. A provenance-only change
  is therefore visible without falsely reporting a packet-authority change.

Affected Device, Resource, and Resource Group identities are derived from both
diff classes and sorted canonically. Public relationship, explanation, and
entity lists return at most 256 values each, include complete counts, and mark
truncation. The impact hash is computed over the complete untruncated sets.

## Evidence binding

The domain-separated SHA-256 impact hash binds:

- exact Workspace and Network identities;
- current and proposed complete revision vectors;
- active-release presence and identity;
- current and proposed compiler formats and semantic hashes;
- complete added and removed effective relationships;
- complete added and removed explanation paths with Resource/Group provenance;
- complete affected Device, Resource, and Resource Group sets; and
- the canonical unsupported-capability set.

The candidate semantic hash is the draft semantic hash. It remains the existing
publication hash; simulation does not define an alternative policy digest.

## Explicit capability boundary

The current publication compiler covers same-Network Device-backed packet
policy, including Device, Resource, and Resource Group destinations. Every
successful M4b1 result explicitly declares these unsupported dimensions:

- Principal-to-Device projection;
- sensitive Resource classification;
- cross-Network or cross-Workspace relationships;
- Guardrail evaluation;
- share intersection; and
- routed/service Resources.

Within the supported compiler dimensions, a successful result is deterministic
and not uncertain. Unsupported dimensions are never interpreted as empty,
allowed, or denied. M4b2 must expose the same distinction in the management
contract.

## Security properties

- Invalid draft, baseline, compiler result, or revision evidence fails closed.
- Resource and Resource Group provenance cannot reference revisions newer than
  the stable baseline vector.
- All collections are bounded by existing compiler limits; disclosed lists are
  additionally capped without weakening the full impact hash.
- Returned values own their slices, preventing caller mutation of evidence.
- Simulation performs no policy publication or other authority side effect.

## Acceptance and non-claims

Executable evidence is recorded in
`docs/qualification/phase2-m4b1-policy-simulation-domain-2026-09-29.md`.

M4b1 does not implement the PostgreSQL full-baseline reader, management HTTP
contract, OpenAPI schema, durable simulation record, protected-change approval,
publication-time complete-vector CAS, Resource Console UI, deployed HA
qualification, production SLOs, or GA.

## Next order

1. M4b2: PostgreSQL repeatable-read baseline adapter plus strict management API
   and OpenAPI contract for bounded simulation results.
2. M4c: durable human approval over unchanged candidate and impact hash, with
   publication-time complete-vector CAS.
3. Extend publication and simulation together for Principal projection,
   Guardrails, sharing, cross-scope paths, and routed/service Resources.
