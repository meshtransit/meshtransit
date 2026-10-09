<p align="center"><strong>MeshTransit</strong></p>
<p align="center">Zero Trust access to private infrastructure: a WireGuard® mesh with an<br>explainable access graph, sealed audit history and sovereign addressing.</p>

<p align="center">
  <a href="https://github.com/meshtransit/meshtransit/actions/workflows/core.yml"><img alt="Core" src="https://github.com/meshtransit/meshtransit/actions/workflows/core.yml/badge.svg"></a>
  <a href="https://github.com/meshtransit/meshtransit/actions/workflows/client.yml"><img alt="Client" src="https://github.com/meshtransit/meshtransit/actions/workflows/client.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License: AGPL-3.0 / Apache-2.0" src="https://img.shields.io/badge/license-AGPL--3.0%20%7C%20Apache--2.0-blue"></a>
</p>

---

MeshTransit connects devices, servers and shared services across networks and
organisations with end-to-end encrypted WireGuard tunnels. Every connection is
allowed by an explicit rule, can be explained ("why can A reach B?"), replayed
at any past moment, and is recorded in a tamper-evident audit trail.

> **Status:** pre-release. The control plane and the Linux client run a
> public proof of concept; APIs and protocols may still change.

## Features

- **Access Graph and Policy Explain:** see every allowed connection, ask why a
  connection is allowed or blocked, and preview the impact of a change.
- **Connection history:** answer who could reach what at any moment, since
  when, with a sealed record per change.
- **Policy distribution status:** know which devices already run the current
  rules.
- **Groups, user groups and tags** resolved live, without republishing rules.
- **Trust Contracts:** share a device with another organisation with explicit,
  expiring terms and address sovereignty on both sides.
- **Guardrails:** organisation-wide rules that block risky changes.
- **Sealed audit history** with export and offline verification.
- **Direct paths first:** NAT traversal with relay fallback through
  MeshTransit Interchange.

## Repository layout

| Path | What | License |
|---|---|---|
| [`core/`](core/) | MeshTransit Core: control plane (API, control, worker, identity roles) | AGPL-3.0 |
| [`relay/`](relay/) | MeshTransit Interchange (`meshrelay`), the relay | AGPL-3.0 |
| [`client/`](client/) | `meshd` node daemon, `meshnetd`, `meshcred` helpers and the `meshctl` CLI | Apache-2.0 |
| `shared/` | Protocol libraries used by the client, the relay and Core (in development) | Apache-2.0 |
| [`api/`](api/) | Management API (OpenAPI) and protocol contracts | Apache-2.0 |
| `test/` | Shared test infrastructure, including the NAT traversal lab (`test/natlab`) | Apache-2.0 |
| [`packaging/`](packaging/) | Linux packages (deb) and service units | Apache-2.0 |
| [`docs/`](docs/) | Architecture, protocol and operations documents | Apache-2.0 |
| [`hack/`](hack/) | Development, CI and supply-chain scripts | Apache-2.0 |

The web Console, the Helm chart and the website live in separate repositories.

## Building

Requires the Go version declared in [`go.mod`](go.mod).

```bash
make build            # bin/meshcore, bin/meshd, bin/meshnetd, bin/meshcred, bin/meshctl
make test             # unit tests for every component
make quality          # formatting, vet, race tests, lint, vulnerabilities, boundaries
make integration-platform-container   # Core integration tests on PostgreSQL and Redis
make package-deb      # Linux packages for meshd and meshctl (Linux only)
make container-build  # Core container image
```

See [`core/README.md`](core/README.md) and [`client/README.md`](client/README.md)
for component details.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and our
[Code of Conduct](CODE_OF_CONDUCT.md). Report security issues privately as
described in [SECURITY.md](SECURITY.md); never in a public issue.

## License

Core and Interchange are licensed under the
[GNU AGPL v3.0](LICENSES/AGPL-3.0.txt), with a
[commercial license](COMMERCIAL-LICENSING.md) available. The client, the shared
protocol libraries and the API contracts are licensed under the
[Apache License 2.0](LICENSES/Apache-2.0.txt). See [LICENSE](LICENSE) for the
per-directory details.

WireGuard is a registered trademark of Jason A. Donenfeld.
