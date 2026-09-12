# Third-party notices

`meshd` uses selected packages from `tailscale.com v1.102.3` inside isolated TS2021 and relay wire compatibility adapters. That dependency is licensed under the BSD 3-Clause License.

The Linux encrypted data plane uses `golang.zx2c4.com/wireguard`, licensed under the MIT License, and `github.com/vishvananda/netlink`, licensed under the Apache License 2.0. The compatible peer-probe cryptography uses `golang.org/x/crypto`, licensed under the BSD 3-Clause License.

The complete direct-dependency license texts are reproduced under `third_party/licenses/`. Product commands, API names, and documentation must not imply endorsement by any dependency's copyright holders or contributors.

Before a release, regenerate the module graph, verify `go.sum`, scan reachable dependencies, and update this notice if the dependency set or license obligations change.
