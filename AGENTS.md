# Agent instructions

## Go development

Before any Go coding, review, debugging, troubleshooting, or setup task, load the `samber/cc-skills-golang@golang-how-to` skill first — it routes to whichever other Go skills the task needs.

Read `docs/architecture.md` and `docs/security-model.md` before changing protocol, profile, persistence, local API, privilege, or data-plane behavior.

Do not copy source files from compatibility references into this repository. Keep protocol-specific code behind internal adapters and keep upstream product names out of public commands, API fields, log fields, and paths.
