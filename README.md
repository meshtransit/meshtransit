# MeshTransit Core

MeshTransit Core is the product-owned MeshTransit control plane. This checkout
currently contains the first Phase 1 platform-spine slice: validated process
configuration, runtime role selection, bounded lifecycle management, safe JSON
logging, and health/readiness endpoints.

The module path is `github.com/meshtransit/meshtransit`; the process binary
is `meshcore`. Development and security gates run with Go 1.26.8.

## Runtime configuration

Configuration is read once at process startup. An explicitly set empty or
invalid value stops startup before a listener is opened.

| Environment variable | Default | Contract |
| --- | --- | --- |
| `MESHTRANSIT_ROLE` | `all` | One of `all`, `api`, `control`, `worker`, or `relay`. |
| `MESHTRANSIT_HEALTH_ADDRESS` | `127.0.0.1:8081` | TCP host and non-zero port for the operator health listener. |
| `MESHTRANSIT_SHUTDOWN_TIMEOUT` | `15s` | Drain deadline from 1 second through 5 minutes. |
| `MESHTRANSIT_LOG_LEVEL` | `info` | One of `debug`, `info`, `warn`, or `error`. |

`all` expands to the `api`, `control`, `worker`, and `relay` responsibilities.
This slice deliberately does not implement their business protocols yet; role
selection changes the declared process responsibility without creating empty
domain packages.

## Health surface

The operator listener exposes:

- `GET /live`: process listener is responsive;
- `GET /ready`: configured work may be admitted;
- `GET /health`: redacted runtime component summary.

Readiness opens only after the listener starts and closes before graceful
draining begins. The listener defaults to loopback and should not be exposed on
public client ingress.

## Development gates

Run individual gates with `make fmt-check`, `make tidy-check`, `make vet`,
`make test`, `make test-race`, `make lint`, and `make vuln`. `make quality` runs
the complete bootstrap set. The lint and vulnerability commands pin tool
versions pinned for reproducible execution with the module's Go 1.26.8
baseline.
