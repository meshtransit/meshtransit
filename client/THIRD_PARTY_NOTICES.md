# Third-party notices: client

`meshd` and `meshctl` contain only MeshTransit code and the modules below.

| Module | Used for | License |
| --- | --- | --- |
| `golang.zx2c4.com/wireguard` | Linux encrypted data plane | MIT |
| `github.com/vishvananda/netlink`, `github.com/vishvananda/netns` | Linux routes, addresses and namespaces | Apache-2.0 |
| `github.com/flynn/noise` | MTCP v1 Noise handshake | BSD-3-Clause |
| `github.com/coder/websocket` | MTCP and relay WebSocket fallback | ISC |
| `github.com/klauspost/compress` | MTCP message compression | BSD-3-Clause, parts Apache-2.0 |
| `google.golang.org/protobuf` | MTCP messages | BSD-3-Clause |
| `golang.org/x/crypto`, `golang.org/x/net`, `golang.org/x/sys` | peer-probe cryptography, DNS messages, system calls | BSD-3-Clause |

The complete direct-dependency license texts are reproduced under `client/third_party/licenses/`. Product commands, API names, and documentation must not imply endorsement by any dependency's copyright holders or contributors.

Before a release, regenerate the module graph, verify `go.sum`, scan reachable dependencies, and update this notice if the dependency set or license obligations change.
