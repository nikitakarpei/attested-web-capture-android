#!/usr/bin/env python3
"""
TEST HELPER ONLY. Emulates Android Keystore on a desktop: a fake root and a chain shaped like a real one
(RKP: root → "Droid CA2" → "O=StrongBox|TEE" → leaf; factory: root → serial-numbered intermediates → leaf), whose
leaf carries a key-attestation extension with the given challenge. Verifiers accept it only when told to trust
the fake root.
"""
import argparse
import base64
import datetime as dt
import json
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from asn1 import boolean, enum, explicit, integer, null, octets, seq, set_  # noqa: E402

OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")


def name(cn, org=None, serial=None, title=None):
    attrs = []
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    if cn:
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    if serial:
        attrs.append(x509.NameAttribute(NameOID.SERIAL_NUMBER, serial))
    if title:
        attrs.append(x509.NameAttribute(NameOID.TITLE, title))
    return x509.Name(attrs)


def make_cert(subject, issuer, pub, signer_key, ca, ext=None):
    now = dt.datetime.now(dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(pub)
         .serial_number(x509.random_serial_number())
         .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=3650))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ext is not None:
        b = b.add_extension(x509.UnrecognizedExtension(OID, ext), critical=False)
    return b.sign(signer_key, hashes.SHA256())


def key_description(a):
    app_id = seq(set_(seq(octets(a.package.encode()), integer(a.version_code))),
                 set_(octets(bytes.fromhex(a.signer))))
    software = seq(explicit(701, integer(1762130000000)), explicit(709, octets(app_id)))
    root_of_trust = seq(octets(bytes.fromhex(a.boot_key)), boolean(a.locked), enum(a.boot_state), octets(b"\x11" * 32))
    hardware = seq(
        explicit(1, set_(integer(2))),          # purpose: SIGN
        explicit(2, integer(3)),                # algorithm: EC
        explicit(3, integer(256)),              # keySize
        explicit(5, set_(integer(4))),          # digest: SHA-256
        explicit(10, integer(1)),               # ecCurve: P-256
        explicit(503, null()),                  # noAuthRequired
        explicit(702, integer(0)),              # origin: GENERATED
        explicit(704, root_of_trust),
        explicit(705, integer(160000)),         # osVersion
        explicit(706, integer(a.os_patch)),     # osPatchLevel
        explicit(718, integer(20261005)),       # vendorPatchLevel
        explicit(719, integer(20261005)),       # bootPatchLevel
    )
    return seq(integer(300), enum(a.level), integer(300), enum(a.level),
               octets(bytes.fromhex(a.challenge)), octets(b""), software, hardware)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--challenge", required=True)
    p.add_argument("--data-file", required=True)
    p.add_argument("--state-dir", required=True)
    p.add_argument("--package", default="io.github.nikitakarpei.attestedwebcapture")
    p.add_argument("--version-code", type=int, default=1)
    p.add_argument("--signer", default="d66a722561948c23fca5f90a758008dc4b2a11100db466e75e58d4f3ee4ffb99",
                   help="app signing certificate the fake attestation claims (a fixed test value)")
    p.add_argument("--boot-key", default="d8f879d10419eddc9fcda6280718be763f6bf12299e1f72df3ea8ad8a8eb7f80")
    p.add_argument("--boot-state", type=int, default=1)
    p.add_argument("--locked", type=int, default=1)
    p.add_argument("--level", type=int, default=2)
    p.add_argument("--os-patch", type=int, default=202610)
    p.add_argument("--root-alg", choices=["ec", "rsa"], default="ec")
    p.add_argument("--provisioning", choices=["rkp", "factory"], default="rkp")
    a = p.parse_args()

    os.makedirs(a.state_dir, exist_ok=True)
    root_key = (rsa.generate_private_key(public_exponent=65537, key_size=2048) if a.root_alg == "rsa"
                else ec.generate_private_key(ec.SECP256R1()))
    root = make_cert(name("FAKE Attestation Root (TEST ONLY)"), name("FAKE Attestation Root (TEST ONLY)"),
                     root_key.public_key(), root_key, True)
    level = {1: "TEE", 2: "StrongBox"}.get(a.level, "TEE")
    if a.provisioning == "rkp":
        top_name, attest_name = name("Droid CA2", org="Google LLC"), name(os.urandom(16).hex(), org=level)
    else:
        top_name = name(None, serial=os.urandom(8).hex(), title=level)
        attest_name = name(None, serial=os.urandom(8).hex(), title=level)
    top_key = ec.generate_private_key(ec.SECP256R1())
    top = make_cert(top_name, root.subject, top_key.public_key(), root_key, True)
    attest_key = ec.generate_private_key(ec.SECP256R1())
    attest = make_cert(attest_name, top.subject, attest_key.public_key(), top_key, True)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = make_cert(name("Android Keystore Key"), attest.subject, leaf_key.public_key(), attest_key, False,
                     key_description(a))
    with open(os.path.join(a.state_dir, "fake_root.pem"), "wb") as f:
        f.write(root.public_bytes(serialization.Encoding.PEM))
    with open(a.data_file, "rb") as f:
        sig = leaf_key.sign(f.read(), ec.ECDSA(hashes.SHA256()))
    print(json.dumps({
        "chain": [c.public_bytes(serialization.Encoding.PEM).decode() for c in (leaf, attest, top, root)],
        "signature": base64.b64encode(sig).decode(),
        "publicKey": base64.b64encode(leaf_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode(),
        "privateKey": base64.b64encode(leaf_key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())).decode(),
    }))


if __name__ == "__main__":
    main()
