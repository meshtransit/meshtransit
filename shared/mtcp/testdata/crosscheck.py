#!/usr/bin/env python3
"""Independent check of the MTCP v1 test vectors (docs/protocol/mtcp-v1.md).

Recomputes, without the Go implementation, the Noise_IK_25519_ChaChaPoly_BLAKE2s
handshake (Noise revision 34) with the fixed keys of vectors.json, the
transport records, the proofs of possession, the control key fingerprint and
the key ID. Requires the `cryptography` package.

Usage: python3 crosscheck.py vectors.json
"""

import hashlib
import hmac
import json
import struct
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

PROTOCOL = b"Noise_IK_25519_ChaChaPoly_BLAKE2s"
PROLOGUE = b"MeshTransit MTCP v1"


def blake2s(data):
    return hashlib.blake2s(data).digest()


def public(private):
    return X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def dh(private, peer):
    secret = X25519PrivateKey.from_private_bytes(private).exchange(X25519PublicKey.from_public_bytes(peer))
    assert secret != bytes(32), "low-order key"
    return secret


def hkdf(chaining_key, ikm):
    temp = hmac.new(chaining_key, ikm, hashlib.blake2s).digest()
    out1 = hmac.new(temp, b"\x01", hashlib.blake2s).digest()
    out2 = hmac.new(temp, out1 + b"\x02", hashlib.blake2s).digest()
    return out1, out2


def aead(key, nonce, ad, plaintext):
    return ChaCha20Poly1305(key).encrypt(b"\x00" * 4 + struct.pack("<Q", nonce), plaintext, ad)


class Symmetric:
    def __init__(self):
        self.h = PROTOCOL + bytes(32 - len(PROTOCOL)) if len(PROTOCOL) <= 32 else blake2s(PROTOCOL)
        self.ck = self.h
        self.k = None
        self.n = 0

    def mix_hash(self, data):
        self.h = blake2s(self.h + data)

    def mix_key(self, ikm):
        self.ck, self.k = hkdf(self.ck, ikm)
        self.n = 0

    def encrypt_and_hash(self, plaintext):
        ciphertext = aead(self.k, self.n, self.h, plaintext)
        self.n += 1
        self.mix_hash(ciphertext)
        return ciphertext

    def split(self):
        return hkdf(self.ck, b"")


def handshake(v):
    machine = bytes.fromhex(v["machine_private"])
    control = bytes.fromhex(v["control_private"])
    client_e = bytes.fromhex(v["client_ephemeral_private"])
    server_e = bytes.fromhex(v["server_ephemeral_private"])
    rs = public(control)

    state = Symmetric()
    state.mix_hash(PROLOGUE)
    state.mix_hash(rs)  # IK pre-message: <- s

    # INIT: e, es, s, ss, payload
    init = public(client_e)
    state.mix_hash(public(client_e))
    state.mix_key(dh(client_e, rs))
    init += state.encrypt_and_hash(public(machine))
    state.mix_key(dh(machine, rs))
    init += state.encrypt_and_hash(bytes.fromhex(v["client_hello"]))

    # RESPONSE: e, ee, se, payload
    response = public(server_e)
    state.mix_hash(public(server_e))
    state.mix_key(dh(server_e, public(client_e)))
    state.mix_key(dh(server_e, public(machine)))
    response += state.encrypt_and_hash(bytes.fromhex(v["server_hello"]))

    initiator_to_responder, responder_to_initiator = state.split()
    return init, response, state.h, initiator_to_responder, responder_to_initiator


def proof(private, control_public, handshake_hash):
    secret = dh(private, control_public)
    data = b"meshtransit/mtcp-key-proof/v1\x00" + handshake_hash + public(private)
    return hashlib.blake2s(data, key=secret).digest()


def main(path):
    with open(path, encoding="utf-8") as handle:
        v = json.load(handle)
    failures = []

    def check(name, got, want):
        if got != want:
            failures.append(f"{name}: got {got}, want {want}")

    control_public = public(bytes.fromhex(v["control_private"]))
    check("machine_public", "mtmachine:" + public(bytes.fromhex(v["machine_private"])).hex(), v["machine_public"])
    check("control_public", "mtcontrol:" + control_public.hex(), v["control_public"])
    check("control_key_id", blake2s(b"meshtransit/key-id/v1\x00" + control_public)[:8].hex(), v["control_key_id"])
    check("control_fingerprint", blake2s(b"meshtransit/mtcp-control-fp/v1\x00" + control_public)[:16].hex(),
          v["control_fingerprint"])

    init, response, handshake_hash, to_core, to_node = handshake(v)
    check("init", init.hex(), v["init"])
    check("response", response.hex(), v["response"])
    check("handshake_hash", handshake_hash.hex(), v["handshake_hash"])

    counters = {"node_to_core": 0, "core_to_node": 0}
    keys = {"node_to_core": to_core, "core_to_node": to_node}
    for index, record in enumerate(v["records"]):
        direction = record["direction"]
        sealed = aead(keys[direction], counters[direction], b"", bytes.fromhex(record["plaintext"]))
        counters[direction] += 1
        check(f"record {index}", sealed.hex(), record["record"])

    proofs = v["proofs"]
    check("node_public", "mtnode:" + public(bytes.fromhex(proofs["node_private"])).hex(), proofs["node_public"])
    check("disco_public", "mtdisco:" + public(bytes.fromhex(proofs["disco_private"])).hex(), proofs["disco_public"])
    check("node_proof", proof(bytes.fromhex(proofs["node_private"]), control_public, handshake_hash).hex(),
          proofs["node_proof"])
    check("disco_proof", proof(bytes.fromhex(proofs["disco_private"]), control_public, handshake_hash).hex(),
          proofs["disco_proof"])

    # Fragment headers: msg_type, flags (no MORE, no ZSTD) for single fragments.
    check("ping fragment header", v["fragments"]["ping"][:4], "0200")
    check("lifecycle fragment header", v["fragments"]["lifecycle"][:4], "5000")

    if failures:
        print("\n".join(failures))
        return 1
    print(f"ok: handshake, {len(v['records'])} records, 2 proofs, fingerprint and key ID match")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "vectors.json"))
