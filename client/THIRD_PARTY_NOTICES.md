# Third-party notices: client

`meshd`, `meshnetd` and `meshctl` contain only MeshTransit code and the modules below. So will the planned Kubernetes gateway `meshgw` (not yet built; only its tests link the rows marked `meshgw` today).

| Module | Used for | License |
| --- | --- | --- |
| `golang.zx2c4.com/wireguard` | Linux encrypted data plane | MIT |
| `gvisor.dev/gvisor` | the userspace TCP/IP stack behind `golang.zx2c4.com/wireguard/tun/netstack`, used only by `meshgw` | Apache-2.0, parts BSD-3-Clause and MIT |
| `github.com/google/btree` | TCP selective-acknowledgement bookkeeping inside `gvisor.dev/gvisor` (`meshgw`) | Apache-2.0 |
| `github.com/vishvananda/netlink`, `github.com/vishvananda/netns` | Linux routes, addresses and namespaces | Apache-2.0 |
| `github.com/google/nftables` | Linux subnet router packet rules (`meshnetd`) | Apache-2.0 |
| `github.com/mdlayher/netlink`, `github.com/mdlayher/socket` | netlink sockets used by `github.com/google/nftables` | MIT |
| `github.com/flynn/noise` | MTCP v1 Noise handshake | BSD-3-Clause |
| `github.com/coder/websocket` | MTCP and relay WebSocket fallback | ISC |
| `github.com/klauspost/compress` | MTCP message compression | BSD-3-Clause, parts Apache-2.0 |
| `google.golang.org/protobuf` | MTCP messages | BSD-3-Clause |
| `golang.org/x/crypto`, `golang.org/x/net`, `golang.org/x/sync`, `golang.org/x/sys`, `golang.org/x/text` | peer-probe cryptography, DNS messages, concurrency helpers, system calls, text handling used by these modules | BSD-3-Clause |
| `golang.org/x/exp`, `golang.org/x/time` | generic constraints and rate limiting inside `gvisor.dev/gvisor`, and the rate of the gateway's token mints (`meshgw`) | BSD-3-Clause |
| `golang.org/x/mobile` | the Java and Objective-C bindings of `client/mobile` that the Android and iOS apps embed (ADR-052) | BSD-3-Clause |

`golang.org/x/mod` and `golang.org/x/tools` (BSD-3-Clause) are required by the `gomobile` and `gobind` build tools pinned in `go.mod`; they run at build time and are not part of any shipped binary.

The license texts of every module in the table above are reproduced under `client/third_party/licenses/`. Product commands, API names, and documentation must not imply endorsement by any dependency's copyright holders or contributors.

Before a release, regenerate the module graph, verify `go.sum`, scan reachable dependencies, and update this notice if the dependency set or license obligations change.

## Code adapted from other projects

| Source | Adapted into | License |
| --- | --- | --- |
| Kubernetes `k8s.io/apiserver@v0.35.1` `pkg/endpoints/request/requestinfo.go` and its tests; `k8s.io/apimachinery@v0.35.3` `pkg/fields/selector.go`, and the rules of its `pkg/runtime/conversion.go` (`Convert_Slice_string_To_bool`) and `pkg/api/validation/path/name.go` (Copyright The Kubernetes Authors) | `client/internal/kubereq`, used only by `meshgw`: reading a Kubernetes API request as the API server does. Each adapted file keeps its copyright header and says what changed | Apache-2.0 |

The Apache-2.0 text is `LICENSES/Apache-2.0.txt` at the repository root.
