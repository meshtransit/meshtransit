# Agent instructions

This is the MeshTransit monorepo. Each component has its own instructions;
read the one for the code you change before editing:

- `core/AGENTS.md`: control plane (AGPL-3.0).
- `client/AGENTS.md`: meshd, meshnetd, meshcred, meshctl (Apache-2.0).

Before any Go coding, review, debugging, troubleshooting, or setup task, load
the `samber/cc-skills-golang@golang-how-to` skill first.

## Repository-wide rules

- Licensing is per directory (see `LICENSE`). Code under `client/`, `shared/`
  and `api/` MUST NOT import `core/` or `relay/`. `make check-boundaries`
  enforces this in CI.
- `tailscale.com` may be imported only by the compatibility adapters
  (`client/internal/compat`, `core/internal/adapter/legacyts2021`) until they
  are removed. Do not add new uses.
- Never copy Headscale source code, schemas or migrations.
- Shared protocol code (MTCP, MTRP, disco, keys) belongs in `shared/` with a
  language-independent specification under `docs/`.
- Cryptography uses standard constructions only (Noise, Ed25519, X25519,
  ChaCha20-Poly1305, WireGuard). Never invent primitives.
- Product-facing names use MeshTransit terminology.
- Commits use conventional commit messages and carry no AI attribution.
