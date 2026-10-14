# Relay (MeshTransit Interchange)

`meshrelay` forwards traffic between two nodes that have no direct path yet,
or never will. It is the only component that forwards packets; Core never
does. Its wire protocol is [MTRP v1](../protocol/mtrp-v1.md). Code: `relay/`
(AGPL-3.0), protocol codecs in `shared/mtrp` and `shared/stun`.

A relay is trusted for availability and for enforcing who may reach whom
through it. It is not trusted with traffic: it forwards WireGuard ciphertext
and encrypted disco messages, and holds no key that decrypts them.

## Listeners

| Listener | Default | Purpose |
|---|---|---|
| UDP | `0.0.0.0:3479` | MTRP over UDP |
| STUN | `0.0.0.0:3478`, alternate `0.0.0.0:3480` | Binding requests; with `--public-ip` (and `--public-ipv6`) also the RFC 5780 attributes nodes use to classify their NAT |
| TLS | off (`--tls`) | MTRP over TCP: ALPN `mtrp/1` carries length-prefixed frames; ALPN `http/1.1` carries WebSocket at `/mtrp/v1` |
| Admin | `127.0.0.1:9479` | `/metrics` (Prometheus) and `/healthz` |

TLS needs version 1.3. Its certificate comes from files, from ACME (TLS-ALPN-01
on the TLS port itself, so port 80 is not needed), or is self-signed for
tests. TLS only gets traffic through networks that block UDP; the Noise
handshake inside MTRP, not TLS, authenticates the relay.

## Sessions and authorization

A node opens a session with a Noise IK handshake to the relay's static key,
which it learns from the relay map. The handshake carries a **relay ticket**
that Core signed for this node:

- the node key and disco key it was issued to (the disco key must be the
  Noise peer key);
- the **zones** the node belongs to: its Network and every
  [Trust Contract](../glossary.md) that shares with it;
- a lifetime of at most 15 minutes, a bandwidth cap and a route cap.

The relay checks the signature against the signing keys it trusts, the time
window and the revocation list. It keeps one session per node key and per
disco key; a new one replaces the old.

A node asks the relay to open a route to a peer. The relay opens it only when
the peer also has a session there and the two tickets share a live,
unrevoked zone. A peer that is absent and one that is not authorized get the
same answer, so a node cannot probe who is connected.

Data frames are forwarded unchanged to the peer. They are not authenticated by
MTRP, because they already carry WireGuard ciphertext; the relay only checks
that a frame comes from the address the session is bound to. Control frames
are encrypted and authenticated per session, and only they can move a
session's binding to a new address. Until the new address answers a path
challenge, traffic to it is capped at 16 KiB/s, so a relay cannot be used to
flood a third party.

## State from Core

The relay long-polls Core (`--core-url`) for a signed **relay state**: the
trusted signing keys with their expiry, revocations and a drain list.
Revocations are hashes of ticket IDs, node keys, disco keys or zones, so the
relay never holds a plaintext list of what was revoked. The relay accepts only
a newer, unexpired state; if every signing key it trusts has expired, it
refuses all sessions. A new revocation closes the affected sessions and
routes within seconds.

`--trusted-signing-keys` (required) bootstraps trust before the first state
arrives. Sockets are bound at start but not read until the first state is
applied, or 20 seconds pass.

A **Private Interchange** relay (`--private-interchange`) is one a Workspace
runs for some of its Networks. It also fetches a grant, sealed to its own key,
that names those Networks. Without a valid grant it admits no session, and it
admits only the granted Networks' zones; Trust Contract zones do not admit
sessions there.

## Limits

The main limits, each per relay node; control frames, route opens and zones
have their own rate and size limits.

| Limit | Default |
|---|---|
| Sessions | 100,000 |
| Routes per session | 4,096, or fewer if the ticket says so |
| Handshakes | 1,000/s, and 10/s per source address (IPv6 per /64) |
| Packets per session | 50,000/s |
| Bytes per session | 1 Gbit/s, or less if the ticket says so |
| Bytes per Network | 500 Mbit/s (`--network-bandwidth-mbit`), charged to the sender's Network |
| TLS connections | 10,000, and 64 per source address |

Under handshake load a UDP client must first echo a cookie, and stream clients
are refused as overloaded. Dropped frames are counted by reason
(`no_route`, `rate_limited`, `network_rate_limited`, `unverified_peer`, …);
metrics and logs carry outcome names only, never keys, tickets, endpoints or
zones.

## Drain

On `SIGTERM`, or when Core puts the relay on the drain list, the relay stops
admitting sessions and tells every session to move to another relay within
the drain timeout (`--drain-timeout`, 5 s); existing sessions keep forwarding
meanwhile. After `SIGTERM` the process exits once the timeout has passed; a
drain from Core leaves it running without admitting new sessions.

## Keys

| Key | Where | Use |
|---|---|---|
| Relay key (`mtrelay:`) | `--key-file`, mode 0600; `meshrelay genkey` creates it | Noise responder key, published in the relay map |
| Core signing keys (`mtsign:`) | Core | Sign tickets, the relay map and the relay state |

The signing keys belong to Core's `control` role (the relay authority); see
[Core](core.md). Core's `relay` role is unrelated to `meshrelay`: it only
serves health and metrics.
