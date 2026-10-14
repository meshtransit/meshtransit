# MeshTransit Interchange (`meshrelay`)

Interchange forwards encrypted node traffic when no direct path exists yet or
ever. It speaks MTRP v1 ([spec](../docs/protocol/mtrp-v1.md)) over UDP, admits
clients with Core-signed tickets, and serves STUN with the RFC 5780
attributes nodes use to classify their NAT. It sees only WireGuard ciphertext
and encrypted disco messages.

## Run

```bash
meshrelay genkey --out /etc/meshrelay/relay.key     # prints the public key for the relay map
meshrelay serve \
  --key-file /etc/meshrelay/relay.key \
  --trusted-signing-keys mtsign:... \
  --public-ip 203.0.113.10
```

| Flag | Default | Purpose |
|---|---|---|
| `--udp` | `0.0.0.0:3479` | MTRP UDP |
| `--stun`, `--stun-alt` | `0.0.0.0:3478`, `0.0.0.0:3480` | STUN and its alternate port |
| `--public-ip` | none | Address advertised in RFC 5780 attributes |
| `--public-ipv6` | none | IPv6 address advertised to IPv6 clients in RFC 5780 attributes. To serve IPv6, listen on `[::]` (for example `--udp [::]:3479 --stun [::]:3478 --stun-alt [::]:3480 --tls [::]:443`); a `[::]` socket also accepts IPv4 on Linux |
| `--admin` | `127.0.0.1:9479` | `/metrics` (Prometheus) and `/healthz` |
| `--drain-timeout` | `5s` | Time clients get to move away on SIGTERM |
| `--tls` | off | TLS listen address (for example `0.0.0.0:443`): ALPN `mtrp/1` for framed MTRP, `http/1.1` for WebSocket at `/mtrp/v1` |
| `--acme-host`, `--acme-cache` | none | Let's Encrypt certificate via TLS-ALPN-01 on the TLS port |
| `--tls-cert`, `--tls-key` | none | Certificate files instead of ACME |
| `--tls-self-signed` | off | Ephemeral certificate, for labs |
| `--network-bandwidth-mbit` | `500` | Mbit/s that all sessions of one Network forward through this relay together; past it the relay drops that Network's DATA, counted as `meshrelay_data_frames_total{result="network_rate_limited"}` |
| `--core-url` | none | Core control URL; the relay polls `/relay/v1/state` for trusted signing keys, revocations and drain (with it, `--trusted-signing-keys` only bootstraps trust) |

Every flag can be set as `MESHRELAY_<FLAG>` (upper case, `_` for `-`). The key
file must be mode 0600. A key handed over with systemd `LoadCredential=` may be
group-readable (systemd writes it 0440), because only the service can open
`$CREDENTIALS_DIRECTORY`; point `--key-file` at `${CREDENTIALS_DIRECTORY}/<name>`.

TLS is not part of MTRP's trust model: clients authenticate the relay with
the Noise handshake. A publicly trusted certificate still matters, because
middleboxes and proxies pass it.
