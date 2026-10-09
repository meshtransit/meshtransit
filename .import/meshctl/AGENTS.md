# Agent instructions

## Go development

Before any Go coding, review, debugging, troubleshooting, or setup task, load the `samber/cc-skills-golang@golang-how-to` skill first — it routes to whichever other Go skills the task needs.

Keep `meshctl` an unprivileged client of the versioned `meshd` local API. It must not read daemon state files, configure TUN/routes/DNS, hold node private keys, or import protocol and tunnel-engine packages.

Public commands, flags, output, paths, API fields, and log fields use MeshTransit terminology. Never add a client-supplied network identifier to registration or profile commands.
