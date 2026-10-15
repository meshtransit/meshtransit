# Agent instructions

This is the MeshTransit monorepo. Each component has its own instructions;
read the one for the code you change before editing:

- `core/AGENTS.md`: control plane (AGPL-3.0).
- `client/AGENTS.md`: meshd, meshnetd, meshcred, meshctl (Apache-2.0).

Before any Go coding, review, debugging, troubleshooting, or setup task, load
the `samber/cc-skills-golang@golang-how-to` skill first.

## Repository-wide rules

- Licensing is per directory (see `LICENSE`). Code under `client/`, `shared/`,
  `api/` and `test/` MUST NOT import `core/` or `relay/`. `make check-boundaries`
  enforces this in CI.
- MeshTransit speaks its own MTCP/MTRP protocols; never copy code from other
  VPN products. Dependencies come only from the reviewed
  `hack/allowed-modules.txt`, which `make check-boundaries` enforces.
- Never copy third-party control-plane source code, schemas or migrations.
- Shared protocol code (MTCP, MTRP, disco, keys) belongs in `shared/` with a
  language-independent specification under `docs/`.
- Cryptography uses standard constructions only (Noise, Ed25519, X25519,
  ChaCha20-Poly1305, WireGuard). Never invent primitives.
- Product-facing names use MeshTransit terminology.
- Commits use conventional commit messages and carry no AI attribution.
