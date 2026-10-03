# OIDC creation clock qualification

Login start samples PostgreSQL clock_timestamp() in a bounded, owned read-only
transaction before sealing pending evidence. The graph requires this explicit
CreationClock port; production binds it to AuthTransactionStore. The local clock
continues to reject release beyond the existing 30-second positive skew allowance
or at the exclusive expiry deadline. No SQL, cookie, nonce, AEAD or expiry check
is relaxed. Failed query, cancellation, commit or cleanup releases no timestamp.

This fixes intermittent first reads rejected by PostgreSQL when the application
creation time led the DB clock by milliseconds. The pending hash and ciphertext
are created only after time sampling, so persisted and sealed times still agree.

Verification: full make quality passed (unit, race, shuffle, both lint profiles,
vet, module consistency, vulnerability scan and actionlint). Disposable PostgreSQL
18.6/Redis 8.8 migrations 1–84 with uncached race integration passed in 38.057
seconds. A real DB test starts with the application clock one second ahead and
immediately verifies the committed browser proof. Unit tests cover application
clock behind/ahead, unsafe skew, exclusive expiry, DB errors and cleanup.

Sampling adds one short read transaction per login start. It occurs before write
locks and external redirects. No deployed POC database or image was changed by
this qualification.
