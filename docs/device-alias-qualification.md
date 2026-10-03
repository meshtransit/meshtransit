# Device alias packet qualification

The opt-in Linux integration test `TestDeviceAliasEncryptedPeer` runs the owned
control decoder, privileged helper, kernel TUN and encrypted engine with
Core-owned v1 fixtures. This proves the client packet path; it does not prove
live Core enrollment, publication, Redis delivery or DNS.

## Operator inputs

Build the test with `go test -tags=integration -c ./internal/compat/ts2021` for
Linux. Run on two disposable hosts as root. Both use the owned `meshqual0`
interface and encrypted UDP port 42642. Existing daemon interfaces must remain
separate. Supply two absolute, owner-only regular files:

- `MESHD_ALIAS_QUAL_PRIVATE`: exactly 32 raw bytes of a disposable X25519
  private key. Never reuse a production key.
- `MESHD_ALIAS_QUAL_CONTROL`: at most 4096 bytes of JSON. Fields are `role`
  (`consumer` or `provider`), the other host's public `peer_key` and
  `peer_endpoint`, finite `expires_at`, positive `grant_revision`, enabled
  `tcp`, `udp`, `icmp`, `peer`, and `stop` booleans.

Replace control files atomically. Self creation time and key deadline stay
fixed across grant changes. Set `stop: true` before the ten-minute test deadline
and require PASS plus interface/route cleanup on both hosts. Remove disposable
keys and listeners afterwards.

## Verified matrix

The 2026-10-03 qualification used identical canonical IPv4/IPv6 addresses on the
two hosts and distinct Resource/Consumer aliases from the checked-in fixtures.
Actual encrypted TCP/UDP port 8443 and ICMP worked in both families. TCP/UDP
8444 and provider-initiated TCP/UDP/ICMP were denied. A higher grant revision
removed TCP while UDP/ICMP continued. Peer removal denied all three protocols;
reinstalling a finite grant restored permitted packets, and its expiry denied
all three protocols. Both tests ended with PASS and the owned interface was
absent after shutdown.

Raw spoof probes, a third Network, key rotation, reconnect, live Core authority,
bilateral notification latency and imported DNS remain separate required gates.
