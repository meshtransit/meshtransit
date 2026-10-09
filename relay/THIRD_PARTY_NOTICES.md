# Third-party notices: relay

`meshrelay` uses these direct dependencies:

- `github.com/flynn/noise` (Noise Protocol Framework), BSD 3-Clause License.
- `golang.org/x/crypto` (BLAKE2s, ChaCha20-Poly1305, Curve25519), BSD 3-Clause
  License.
- `github.com/prometheus/client_golang` (metrics), Apache License 2.0.
- `github.com/coder/websocket` (WebSocket transport), ISC License.
- `golang.org/x/crypto/acme/autocert` (ACME certificates), BSD 3-Clause License.

Product names and documentation must not imply endorsement by any
dependency's copyright holders or contributors. Before a release, regenerate
the module graph, verify `go.sum`, scan reachable dependencies, and update this
notice if the dependency set or license obligations change.
