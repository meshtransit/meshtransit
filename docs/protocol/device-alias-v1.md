# Device alias v1

> MTCP v1 carries this grant as typed fields of a peer's `alias`
> ([mtcp-v1 §7.4](mtcp-v1.md)). The semantics below are normative for it. The
> JSON capability encoding under "Wire grant" was the form used by the retired
> legacy control protocol; its fields map one to one onto the MTCP fields and
> it is no longer served.

## Boundary and admission

A qualified client advertises version 1 on its authenticated map request
(MTCP capability `device-alias.v1`). The control plane must bind that declaration
to the current Device session and machine/Node key epochs, and require both
peers' current declarations before delivery. A declaration grants no permission.
Unknown versions or incomplete evidence fail closed. This encoder increment
provides no runtime admission, allocator worker or reader.

The pinned client implementation is `meshd bbe1ec7b77ea35e7217e53694bbe9f5201d82d89`.
The participating clients translate the packet; Core and relays do not decrypt
or translate it. An additional gateway is not part of this contract.

## Wire grant

Each alias peer carries exactly one JSON object under Node CapMap capability
`https://meshtransit.io/cap/device-alias-v1`. It includes exact `version:1`,
`contract_id`, `endpoint_id`, positive `generation`, `grant_revision`,
`recovery_epoch`, exact `self_key`, `peer_key`, `role` (`consumer` or `provider`),
exclusive finite `expires_at`, and ordered disjoint `services`. Each service has
numeric `protocol`, `port_from`, and `port_to`: TCP6/UDP17 ports1–65535;
ICMPv4 1 and ICMPv6 58 echo grants use zero ports and the corresponding family.

Peer Addresses and AllowedIPs are identical exact remote alias host routes.
SelfNodeV4MasqAddrForThisPeer / SelfNodeV6MasqAddrForThisPeer contain the matching
local aliases. The self Node retains canonical addresses and no peer binding.
Aliases are required for every enabled family; no raw remote address fallback.
Both Workspaces may use identical canonical addresses.

The document is at most8192 bytes, at most64 services, and one map has at
most256 authorized peers when aliases are present. The complete encoded map
must also fit the current256KiB server envelope. Excess fails the whole map.
One peer key cannot carry incompatible contracts/endpoints/generations.
Multiple compatible current consumer rules are canonicalized into one grant.
A provider Resource Alias may serve multiple distinct consumer source aliases
only within the exact same contract/endpoint/generation/recovery epoch.

## Packet policy and lifetime

The provider PacketFilter source is the Consumer Source Alias. Its destination
is the provider canonical address, because the client validates the original
local alias and normalizes the destination before applying the filter. The
consumer receives no reverse allow rule. Replies require an admitted tracked
flow; provider initiation is denied by the role even with a local wildcard.

Each grant is the exact intersection of current export maximum, consumer rule,
both Guardrails, Resource constraints and endpoint grant. Peer and grant
deadlines are bounded by both Device key deadlines, contract, endpoint and
lease expiry. Every packet enforces the exclusive deadline.

The grant revision is the sum of the positive provider and consumer Network
revisions. Their signed64-bit bounds make this sum fit uint64; neither may
regress. A grant-only change forces a complete peer replacement in the atomic
policy delta even when key/address/deadline remain identical. Connectivity
deltas preserve the complete grant. Removal clears peer and filter together.

## Fixtures and threat cases

`fixtures/device-alias-v1/` contains six synthetic Core-encoded full maps for
TCP8443, UDP8443 and both-family ICMP echo, in each direction, with identical
canonical addresses. They contain public test keys and reserved example names.
Generate only with the explicit adapter test output flag; ordinary tests never
rewrite fixtures. The same bytes must pass the pinned client decoder.

Tests cover exact scope/keys/sessions, expiry extension, generation/recovery
mismatch, raw peer addresses, alias collisions, incomplete families, no ordinary
inventory union, no reverse filter, immutable grant copies, service limits and
atomic grant replacement. Runtime SQL authority, notifications and live
encrypted packet qualification remain separate required evidence.

## Authenticated compatibility metadata — schema82

The declaration is the exact root map-request field `DeviceAliasVersion`.
Omission or numeric zero means unsupported; numeric one means v1. Null,
strings, fractions, alternate casing, duplicates and unknown versions are
invalid. The claim is authenticated only as coming from the current Noise
machine/Node pair; it does not attest a trusted binary or grant packet access.

The opt-in map store records one metadata row per Device through a separately
owned NOLOGIN, NOBYPASSRLS observer. It derives scope from the authenticated
pair, matches current session and key epochs, locks those identities and checks
fresh expiry after waits. Caller scope is ignored and restored. Ordinary
serving roles have no table access. The observer exposes only acceptance, never
foreign identity or scope. Exact repeated claims cause no row mutation.

Version changes remain compatibility observations, not authority mutations.
They never allocate an alias, advance packet policy, create membership, or
publish DNS. Future alias readers must match both current claims to the exact
Device session and key epochs and independently validate every sharing
permission. Node-key rotation cannot transfer a previous epoch's declaration.
The feature remains disabled by default and is not yet advertised by the
qualified client or connected to live alias projection.
