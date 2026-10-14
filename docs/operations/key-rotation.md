# Key rotation

Which keys a deployment holds, how long they live, and how to replace each
without breaking nodes, relays or sessions. The key types are defined in
[keys](../protocol/keys.md); the settings in [configuration](configuration.md).

| Key | Lives | Rotation |
|---|---|---|
| MTCP control key | Until `MESHTRANSIT_CONTROL_MTCP_KEY_NOT_AFTER` (at most 5 years) | Planned, with a next key, below |
| Relay signing key | Until replaced | Planned, with a next key |
| A relay's key | Until replaced | New relay map revision |
| Identity broker signing keys | `MESHTRANSIT_IDENTITY_SIGNING_KEY_ROTATION` (6 h) | Automatic |
| Enrollment and Account Session digest keys | Until replaced | Active and previous key |
| Console login purpose keys | Until replaced | `subject` has an active and a previous key; the others have one key each |
| Idempotency and rate-limit digest keys | Until replaced | Replaced at once |
| TLS certificates | Their validity | Replace the files; restart Core |

## MTCP control key

Nodes pin this key when they first trust a deployment, so it cannot simply be
swapped. Core announces its keys, and nodes keep the announced next key.

1. **Generate** a next key and set `MESHTRANSIT_CONTROL_NOISE_NEXT_PRIVATE_KEY_FILE`
   and `MESHTRANSIT_CONTROL_MTCP_NEXT_KEY_NOT_AFTER` on every control replica.
   Restart them.
2. **Wait** until every node has connected at least once. Core accepts
   handshakes to both keys and sends each node both public keys
   (`KeyUpdate`, MTCP §11); the node stores the next one. Core does not
   record which nodes have it, so leave enough time for Devices that are often
   offline.
3. **Promote:** make the next key the current one (and its expiry the current
   expiry), remove the next key settings, restart. Nodes that never learned the
   new key must trust the deployment again.

Core logs a warning at start when less than 60 days remain before the current
key's expiry, and refuses to start once it has passed. Alert on
`meshtransit_mtcp_control_key_not_after_timestamp_seconds - time() < 60*86400`;
note that during a rotation the metric shows the next key's expiry, not the
current key's.
Extending the expiry without a new key only means changing
`MESHTRANSIT_CONTROL_MTCP_KEY_NOT_AFTER`: nodes read the expiry from Core.

## Relay signing key

The key signs relay tickets, the relay map and the relay state.

1. Set `MESHTRANSIT_RELAY_NEXT_SIGNING_KEY_FILE` on every control replica and
   restart. Core publishes both public keys: to nodes in `KeyUpdate`, to relays
   in the relay state they poll.
2. Wait until every relay has polled (seconds) and every node has connected.
3. Swap the files (the next key becomes the current one), remove the next key,
   restart.

A published key is valid for 7 days after Core last lists it, so a replica
that still signs with the old key during the change does not break anything.
Relays started with `--trusted-signing-keys` keep only the keys the relay state
lists once they have one; update the flag for relays that start later.

## A relay's key

A relay node has one key in the map, so nodes cannot reach it between the two
changes below; drain it first.

1. Add the relay's key to `MESHTRANSIT_RELAY_DRAIN` and restart the control
   replicas; its sessions move elsewhere.
2. `meshrelay genkey --out <new file>` on the relay host, and restart the relay
   with the new key file.
3. Put the new public key in the relay's entry in the relay map, increase
   `revision`, update `MESHTRANSIT_RELAY_MAP_SHA256`, remove the drain entry,
   restart the control replicas.

## Digest keys

The HMAC keys Core uses for digests of secrets have a key ID, and most accept a
previous key while digests made with it are still in use:

- **Enrollment keys** (`MESHTRANSIT_ENROLLMENT_DIGEST_…`) and **Account
  Sessions** (`MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_…`): set the new key as
  active with a new ID, keep the old one as previous, restart. Remove the
  previous key once every credential or session digested with it has expired
  or been replaced.
- **OIDC subjects** (`subject_active`, `subject_previous` in the Console login
  profile): stored subject digests are never recomputed, so an Account bound
  under a key matches only while that key is active or previous. Keep the
  previous key for as long as such Accounts exist; there is no tool to move
  them to the new key, so a second rotation locks out Accounts of the first
  key.
- **Idempotency and rate-limit keys** have no previous slot: replacing one
  forgets idempotency records in flight and resets rate-limit counters.

Every key needs its own file and ID; Core refuses to start if two settings
share either.

## TLS certificates

Core reads its listener certificates at start: replace the files and restart
the replicas one by one. `meshrelay` rereads `--tls-cert`/`--tls-key` when the
certificate file changes (checked at most once a minute, on a handshake;
replace both files and touch the certificate), and renews ACME certificates
itself; alert on `meshrelay_tls_certificate_expiry_timestamp_seconds` (it is 0
until the first TLS handshake). Core has no certificate
expiry metric; monitor its certificates from outside.
