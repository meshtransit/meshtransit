# Linux runtime recovery rc5 sample 1

- Runtime: `0.1.0~rc5+35a452b`
- Runtime commit: `35a452b639cef650e11a24aaba3f668da6b33233`
- Source archive SHA-256: `399e554c78903cbd837c80d7864af16ba92bc24994735783e32169dc0f2855c7`
- Scenario: temporary helper socket permission failure during the first map application
- Targets: Ubuntu 26.04 x86_64 and aarch64
- Outcome: both passed without a daemon or helper generation change

Reports:

- `ubuntu26-amd64.json`
- `ubuntu26-arm64.json`

The reports contain aggregate platform, artifact, timing, generation, and
recovery-state evidence only. They omit process IDs, addresses, socket paths,
network names, fingerprints, identity material, and error text.
