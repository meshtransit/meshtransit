# Agent instructions: relay (Interchange, meshrelay)

Before any Go coding, review, debugging, troubleshooting, or setup task, load
the `samber/cc-skills-golang@golang-how-to` skill first.

- Licensed AGPL-3.0-only (`relay/LICENSE`). The relay may import `shared/` and
  `relay/`; it must not import `core/` or `client/` (`relay/.golangci.yml`
  enforces this).
- The wire contract is `docs/protocol/mtrp-v1.md`; codecs and the session
  layer live in `shared/mtrp` so nodes and the relay share one implementation.
- Forwarding decisions use in-memory state only; the DATA path must not
  allocate or perform I/O other than the forwarded send.
- Metrics labels are outcome names only. Logs carry no keys, tickets,
  endpoints or zones.
- Lint with `golangci-lint run --config relay/.golangci.yml ./relay/...`.
