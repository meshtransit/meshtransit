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
| `--admin` | `127.0.0.1:9479` | `/metrics` (Prometheus) and `/healthz` |
| `--drain-timeout` | `5s` | Time clients get to move away on SIGTERM |

Every flag can be set as `MESHRELAY_<FLAG>` (upper case, `_` for `-`). The key
file must be mode 0600.

TLS and WebSocket transports, and the Core link for signing keys and
revocations, are being added (see the protocol roadmap).
