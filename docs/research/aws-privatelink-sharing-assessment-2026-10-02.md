# AWS PrivateLink applicability to MeshTransit sharing

## Status and recommendation

Research assessment dated 2026-10-02. This is a proposal, not an approved ADR,
implementation change, or claim of live sharing qualification.

Adopt the Resource Configuration / consumer Endpoint product model for named
Device and service sharing. Preserve MeshTransit's existing typed authority,
directional packet rules, encrypted client transport and revocation contract.
An AWS connectivity adapter can be evaluated separately when an actual AWS VPC
integration is requested; this assessment does not provision AWS resources.

## AWS models examined

| AWS model | Published target | Relevance |
| --- | --- | --- |
| Interface endpoint and endpoint service | Service behind an NLB; GWLB has a distinct appliance use case | Future service or application export |
| Resource endpoint and resource gateway | Explicit IP, domain or supported resource configuration; no load balancer required | Closest model for a named Device or database export |
| Tunnel endpoint | Explicit shared CIDR ranges, using GENEVE | Future subnet work, outside the current Device-sharing slice |

AWS distinguishes these endpoint types. Interface endpoints can carry TCP or
UDP to endpoint services; resource endpoints do not require a load balancer.
These are separate capabilities, not interchangeable protocol profiles.
[PrivateLink concepts](https://docs.aws.amazon.com/vpc/latest/privatelink/concepts.html).

Resource endpoints currently support TCP and consumer-initiated connections.
Providers cannot initiate connections into the consumer endpoint VPC. Endpoint
interfaces supply consumer-side addresses and DNS directs traffic to them.
[Resource access](https://docs.aws.amazon.com/vpc/latest/privatelink/privatelink-access-resources.html).

AWS introduced tunnel endpoints on 2026-09-18.
[Launch announcement](https://aws.amazon.com/about-aws/whats-new/2026/9/privatelink-tunnel-endpoint/).
Their outer transport is GENEVE over UDP/6081. Application traffic inside the
tunnel is TCP; inner UDP is limited to DNS. This does not provide the general
UDP and ICMP contract required by MeshTransit Device sharing.
[Tunnel endpoint contract](https://docs.aws.amazon.com/vpc/latest/privatelink/privatelink-access-cidr-ranges.html).

## Authority and product mapping

The following mappings are design inferences, not AWS-enforced semantics in
MeshTransit:

| AWS concept | MeshTransit concept | Scope |
| --- | --- | --- |
| Provider VPC | Provider Network | Owns the actual Device or service |
| Consumer VPC | Consumer Network | Owns the local sources allowed to connect |
| Resource Configuration | Resource plus ResourceExport | Target, allowed consumer, protocol and port maximum |
| RAM resource share and acceptance | ShareOffer and TrustContract | Bilateral agreement and lifecycle |
| Consumer resource endpoint | ImportedResource and logical PrivateEndpoint | Local stable destination used by policy and DNS |
| Endpoint-side security controls | Consumer Access Rule | Explicit source-to-imported-destination permission |
| Resource gateway or service target enforcement | Provider client or future authorized gateway | Enforces the exact consumer identity and traffic intersection |

An AWS resource configuration specifies accepted port ranges and can be shared
through AWS RAM. Its service-network association settings can prevent subsequent
cross-account sharing through a shareable service network.
[Resource configuration](https://docs.aws.amazon.com/vpc/latest/privatelink/resource-configuration.html).

A consumer of a cross-account resource configuration accepts its RAM share and
creates a resource endpoint in the chosen VPC, with security groups attached.
[Create a resource endpoint](https://docs.aws.amazon.com/vpc/latest/privatelink/use-resource-endpoint.html).

### Recommended post-accept flow

1. Provider selects one Device, consumer Workspace/Network, allowed services and
   optional expiry, and sends the offer.
2. Consumer accepts. Core validates current bilateral authority and endpoint
   readiness. The consumer receives a typed imported destination.
3. Console opens an optional Create rule form with that destination selected.
   The consumer chooses local sources and services within the provider maximum.
4. Saving with the required management permission publishes the consumer rule.
   Rule creation does not need a second human approval under the current product
   requirement. Core still performs validation and atomic publication internally.
5. Core derives both packet projections from the same current grant. Provider
   initiation remains denied; established response traffic follows the existing
   stateful packet policy.

Acceptance and permission to originate traffic are separate states. An accepted
share without a current consumer rule remains unavailable for packet access.
An explicit combined Accept and create rule action may present both effects in
one workflow. It must not silently grant every consumer Device access.

Example: provider exports server-01 TCP/443. Consumer permits laptop-01 to that
import on TCP/443. TCP/22 remains denied. A local broad destination selector must
not expand to foreign imported Resources merely because their IP is known.

Console labels should expose target name, provider Network and allowed services,
with stable scoped IDs retained internally. Users should not enter revisions,
internal endpoint generations, alias addresses or contract hashes.

## MeshTransit implementation choices

Within one Workspace, validated non-overlapping overlay prefixes permit the
existing direct Device path. The endpoint is a logical imported destination;
introducing a mandatory gateway hop for this case is unnecessary.

Across Workspaces, the existing architecture requires consumer-local Resource
and source aliases plus an authenticated provider agent or gateway, even when
current prefixes happen not to overlap. The AWS endpoint model is a useful
analogy for this isolation. Aliases, forwarding, return routing and their client
capability are still MeshTransit implementation work; an imported UI row alone
does not deliver this path.

DNS should identify the imported destination in the consumer's namespace and
follow that endpoint's lifecycle. It must not import the provider's complete
private zone or expose unrelated Devices. AWS recommends DNS rather than
endpoint IPs and offers private DNS integration.
[Resource endpoint DNS](https://docs.aws.amazon.com/vpc/latest/privatelink/privatelink-access-resources.html).

## Security semantics to retain explicitly

### Endpoint IAM policy is not packet ACL

AWS endpoint policies control AWS principals accessing supported AWS services.
They do not replace identity or service resource policies. For a non-AWS endpoint
service, AWS allows full access at that endpoint policy layer; network and
application controls still matter. Therefore a generic endpoint IAM JSON editor
cannot replace MeshTransit's Device/group and protocol/port Access Rules.
[Endpoint policies](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html).

### Revocation must remove an existing grant

For an AWS endpoint service, removing an allowed principal does not affect
previously accepted endpoint connections. Permission management and connection
acceptance are separate controls.
[Endpoint service permissions](https://docs.aws.amazon.com/vpc/latest/privatelink/configure-endpoint-service.html).

MeshTransit should implement Revoke as durable withdrawal of the active contract
and endpoint grant, both Network revisions/audit/outbox, peer/filter removal and
invalidation of tracked flows. Deleting an invitation permission alone is not a
sufficient revoke operation. Redis remains a hint; PostgreSQL reconciliation and
exclusive client deadlines bound stale authority.

### Preserve authenticated consumer provenance

An AWS resource sees the resource gateway's source IP; its gateway security
groups control gateway-to-resource outbound traffic.
[Resource gateway](https://docs.aws.amazon.com/vpc/latest/privatelink/resource-gateway.html).

NLB-backed endpoint services similarly present load-balancer source IPs unless
application handling consumes the supported proxy protocol metadata.
[Endpoint service considerations](https://docs.aws.amazon.com/vpc/latest/privatelink/create-endpoint-service.html).

MeshTransit enforcement must bind the real consumer Device key/session and
source address or source alias before forwarding. A shared gateway identity or
unbound SNAT address must not collapse several consumers into one authorization
principal. Imported Resources remain non-exportable through this slice.

## Engineering sequence

1. Retain the implemented same-Workspace direct authority reader and packet
   deadline gate. Verify consumer source controls and provider maxima with
   positive and negative protocol fixtures.
2. Extend policy authoring to typed imported destinations; keep ordinary Device
   inventory and local destination selectors exactly Network-scoped.
3. Discover bounded share dependencies even when no consumer rule exists, and
   subscribe to both revision/connectivity hint streams. Re-read authoritative
   state and repair missed notifications through reconciliation.
4. Qualify first-rule creation, removal, foreign target changes, revoke and
   expiry against two real encrypted clients before enabling live sharing.
5. Complete scoped DNS. Cross-Workspace alias/gateway delivery and subnet work
   require separate capability and packet qualification.

Relevant current design:
[Same-Workspace direct Device sharing](../design/same-workspace-direct-device-sharing.md).
The cross-Workspace and policy contracts remain defined by the canonical
architecture set. This research introduces no migration, packet grant, AWS
service dependency or live deployment change.
