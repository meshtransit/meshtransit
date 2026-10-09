## Summary

<!-- What changes and why. Link the issue. -->

## Component

- [ ] Core (`core/`, AGPL-3.0)
- [ ] Client (`client/`, Apache-2.0)
- [ ] Interchange (`relay/`, AGPL-3.0)
- [ ] Shared protocol (`shared/`, `api/`)
- [ ] Packaging, CI or docs

## Checklist

- [ ] Tests cover the observable behaviour (fuzz tests for new network parsers)
- [ ] `make test lint check-boundaries` pass locally
- [ ] Security-sensitive changes update the threat model / security docs
- [ ] No secrets, keys, tokens or production data in code, tests or logs
- [ ] Documentation updated where behaviour changes
