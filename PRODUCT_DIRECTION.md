# MeshTransit Product Direction

## Position

MeshTransit targets **Zero Trust Access Assurance for private infrastructure**.
The Secure Private Resource Fabric is the architecture and connectivity
foundation. The MeshTransit Access Graph is the product's authorization,
explanation, simulation, and assurance model.

The product promise is:

> Know who can reach what — and prove it.

The supporting sharing principle is:

> Share access, not networks.

WireGuard, NAT traversal, relay, DNS, routing, SSO, ACLs, and posture are
essential capabilities. They are not the product category or differentiation by
themselves.

## Core loop

```text
DEFINE
  -> SIMULATE
  -> PUBLISH
  -> DISTRIBUTE
  -> ENFORCE
  -> VERIFY
  -> OBSERVE
  -> EXPLAIN
  -> IMPROVE
```

MeshTransit must keep each state separate:

- **Intended:** approved immutable policy and Resource intent.
- **Effective:** deterministic compiled authorization for exact inputs.
- **Distributed:** a revision-bound projection reached a client.
- **Enforced:** a trusted destination agent or gateway reports the semantic hash
  active within a bounded validity window.
- **Observed:** passive flow metadata or active verification evidence is bound
  to the same identities, path, and revisions.

Delivery is not proof of enforcement. One observed flow is not proof that every
deny works. An enforcement receipt from a compromised endpoint has limited
assurance. Product language and UI must expose evidence quality and uncertainty.

## Authorization model

```text
authorize(Principal, DeviceOrWorkload, Action, Resource, Context)
  -> ALLOW or DENY plus Explanation
```

The v1 packet action remains `network.connect(protocol, port)`. Identity,
Device, Resource, posture, and context are typed inputs. The five-field Access
Rule stays simple; trusted group selectors, assurance baselines, Guardrails,
Resource constraints, and future Access Leases own conditions.

Resource identity is stable. IP addresses, DNS names, routes, endpoints, and
Connectors are locators or paths, never authority. IP/CIDR selectors remain for
compatibility and explicit routed-address intent, but the Console should prefer
a known Resource.

Control-plane RBAC and data-plane policy remain separate. Workspace
administration does not grant production packet access.

## Access Graph

The Access Graph is a revision-bound read model derived from canonical
PostgreSQL state. PostgreSQL remains authoritative. A graph database is not a
prerequisite.

Initial product queries are:

- Can this Principal/Device perform this action on this Resource?
- Why is the decision allow or deny?
- Who can access this Resource?
- What can this Principal or Device access?
- What changes if this draft is published?
- What is the blast radius of a compromised Principal, Device, group, or
  Connector?

Every result uses stable IDs, exact revisions, provenance, bounded pagination,
and topology-view authorization.

## Digital Twin and verification

Policy simulation uses the same schema, validator, reference evaluator,
optimized compiler, Resource resolution, Guardrails, and share intersection as
publication. A separate permissive simulator is forbidden. Preview evidence
binds the draft semantic hash and exact input revisions; stale evidence cannot
publish.

Managed destinations or trusted Resource gateways are primary enforcement
points. Source filtering and map trimming are defense in depth. Routed-resource
authorization occurs before SNAT or translation removes source provenance.

Verification combines immutable policy evidence, signed projections, delivery
ACKs, enforcement receipts where supported, controlled positive/negative probes,
and privacy-bounded observed-flow rollups. Timeout, offline target, path failure,
unknown, confirmed allow, and confirmed deny remain distinct outcomes.

No packet payload, raw DNS stream, secret, or unbounded topology is collected.
Policy intelligence follows:

```text
observe -> explain -> suggest -> human approve -> simulate -> publish
```

Observation or AI never publishes authority directly.

## Delivery order

Current Phase 1 remains unchanged: platform spine, initial real Google SSO
through Keycloak, and supported Core/client qualification.

Later delivery order:

1. Stable Resources, Resource Groups, typed Principal/Device inputs, and
   endpoint-generation seams.
2. Access Graph v1, Policy Explain, and compiler-identical digital twin.
3. Routed/service Resources, controlled discovery, sharing, and trusted
   destination/gateway enforcement.
4. HA/scale convergence, enforcement receipts, and bounded verification pilot.
5. MTCP signed projection and enforcement evidence.
6. Historical graph, drift, blast radius, Access Leases, cloud/Kubernetes
   discovery, federation, and human-approved policy intelligence.

## Deliberate deferrals

- Public Rego or arbitrary boolean policy language.
- Universal mixed-object Group.
- Generic explicit-deny priority tree.
- Per-packet central authorization calls.
- Application-level authorization and complex PAM.
- Graph database requirement.
- Automatic AI policy application.
- Broad posture catalogs before provenance and freshness contracts.

The normative architecture and acceptance requirements are maintained during
bootstrap in
[`../core-docs/30-access-graph-and-assurance-strategy.md`](../core-docs/30-access-graph-and-assurance-strategy.md).
