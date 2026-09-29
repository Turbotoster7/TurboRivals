#!/usr/bin/env python3
"""Stand-in certificate generator for the server that replaces the EA redirector.

Context: the NFS Rivals online service was shut down on 2025-10-07. We run our
own stand-in server, which our own, legally purchased client connects to. The
server has to present an SSL certificate - that is its own identity, not an
impersonation of a live service (the EA service no longer exists).

Why a self-made certificate is enough - and why not on its own:
the old ProtoSSL (DirtySDK) of this era DOES verify the cert signature (memcmp
over the hash), so a plain self-signed cert would be rejected. We use a known
parser bug (Aim4kill/Bug_OldProtoSSL): if the signature algorithm OID is set to
`rsaEncryption` (ASN_OBJ_RSA_PKCS_KEY, 1.2.840.113549.1.1.1), the parser falls
into the `default` branch, sets iHashSize = 0, and then memcmp(...,0)==0 - the
verification "passes" without checking the signature. Tested on BF3/BF4
(Frostbite 2013, the same DirtySDK generation as Rivals). That is why after
generating the cert we PATCH its DER: we swap the signature OID for
rsaEncryption. EA's private key is neither needed nor used - we generate our
own; the cert with CN `gosredirector.ea.com` is the identity of our stand-in
server (one CN for the whole environment table).

IMPORTANT - the issuer MUST be the OTG3 DN, not self-signed. This was the source
of the RST in round 1: before verifying the signature, ProtoSSL picks a built-in
CA certificate by the leaf's issuer DN. Our previous self-signed cert had
issuer=CN gosredirector.ea.com, which is NOT in the client's CA store - the parser
failed on the CA lookup BEFORE it reached the patched OID, and the client dropped
the connection (RST without an Alert) right after our Certificate. So instead of
a self-signed cert we issue the leaf under our own throwaway CA whose subject =
the EXACT OTG3 DN (`docs/recon/capture/120822-003-server-cert0.der`). The CA key
does not matter - the leaf signature is not verified anyway.

DN fields must be encoded as PrintableString (email as IA5String) - EXACTLY like
the EA original. UTF8String (a different tag: 0x0c instead of 0x13) would change
the DN bytes, and DirtySDK compares the issuer byte by byte - RST again.

The leaf extensions mirror what actually WORKS (the multiplayer session of
2026-09-16): basicConstraints CA:FALSE, subjectKeyIdentifier and
authorityKeyIdentifier - all non-critical. An earlier version of this file
claimed in a comment that AKI was deliberately omitted, but openssl 3.x added it
by itself and the resulting cert passed; the cert is the reference, not the comment.

Does not require `openssl` in PATH - uses the `cryptography` library, so the same
code works in the packaged launcher for someone who has neither Python nor
openssl. The output goes to proto-lab/pki/, which is in .gitignore - the private
key goes neither into the repository nor into the distributed .exe.

Usage:
    python proto-lab/make_stub_cert.py
    python proto-lab/make_stub_cert.py --cn gosredirector.ea.com --bits 1024
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import NameOID

# Subject fields mirrored from the original EA cert (docs/protocol.md, section
# 5). The original had a 1024-bit RSA key and a CN without "online" - one cert for
# the whole environment table. The client does not validate these fields; we keep
# them for consistency with what the game "saw" on the live service.
SUBJECT = [
    (NameOID.COUNTRY_NAME, "US"),
    (NameOID.STATE_OR_PROVINCE_NAME, "California"),
    (NameOID.ORGANIZATION_NAME, "Electronic Arts, Inc."),
    (NameOID.ORGANIZATIONAL_UNIT_NAME, "Global Online Studio"),
    (NameOID.COMMON_NAME, "gosredirector.ea.com"),
]

# Issuer DN EXACTLY as in the original EA cert - the client matches its built-in
# CAs by it (see the docstring, cause of the RST in round 1). The field order
# mirrors the original (docs/recon/capture/120822-003-server-cert0.der). This DN
# becomes the subject of our throwaway CA, so leaf.issuer = this DN.
ISSUER_OTG3 = [
    (NameOID.COMMON_NAME, "OTG3 Certificate Authority"),
    (NameOID.COUNTRY_NAME, "US"),
    (NameOID.STATE_OR_PROVINCE_NAME, "California"),
    (NameOID.LOCALITY_NAME, "Redwood City"),
    (NameOID.ORGANIZATION_NAME, "Electronic Arts, Inc."),
    (NameOID.ORGANIZATIONAL_UNIT_NAME, "Online Technology Group"),
    (NameOID.EMAIL_ADDRESS, "dirtysock-contact@ea.com"),
]

SERIAL = 962          # 0x3C2, like the original (cosmetic)

# AlgorithmIdentifier OIDs (just the OID content bytes, no TLV header). All the
# signature variants have the same 9-byte length as rsaEncryption, so swapping
# them does not change the DER length. rsaEncryption (1.2.840.113549.1.1.1) is
# our target - it hits the `default` branch of the ProtoSSL parser and zeroes iHashSize.
OID_RSA_ENCRYPTION = bytes.fromhex("2a864886f70d010101")   # rsaEncryption (target)
SIG_OIDS = {
    "sha256WithRSA": bytes.fromhex("2a864886f70d01010b"),
    "sha1WithRSA":   bytes.fromhex("2a864886f70d010105"),
    "md5WithRSA":    bytes.fromhex("2a864886f70d010104"),
}


def build_name(pairs: list[tuple[x509.ObjectIdentifier, str]]) -> x509.Name:
    """DN with forced PrintableString (email: IA5String) - like the EA original.

    By default `cryptography` encodes most fields as UTF8String. A different tag
    means different DN bytes, and DirtySDK compares the issuer byte by byte.
    """
    attrs = []
    for oid, value in pairs:
        asn1 = (_ASN1Type.IA5String if oid == NameOID.EMAIL_ADDRESS
                else _ASN1Type.PrintableString)
        attrs.append(x509.NameAttribute(oid, value, _type=asn1))
    return x509.Name(attrs)


def patch_sig_oid(der: bytes) -> bytes:
    """Swaps the signature algorithm OID for rsaEncryption (ProtoSSL bug).

    In an X.509 certificate the signature OID appears twice: in tbsCertificate
    (the `signature` field) and in the outer `signatureAlgorithm`. ProtoSSL reads
    the outer one, but the signature is not verified anyway, so we swap EVERY
    occurrence - both positions stay consistent, and the DER lengths are unchanged.
    """
    hits = 0
    for name, oid in SIG_OIDS.items():
        if oid in der:
            count = der.count(oid)
            der = der.replace(oid, OID_RSA_ENCRYPTION)
            hits += count
            print(f"  patch OID: {name} -> rsaEncryption ({count}x)")
    if hits == 0:
        raise SystemExit("no known signature OID found in the DER - cert "
                         "generated with an algorithm other than sha256/sha1/md5?")
    # Assertions: the target is present, none of the source OIDs is left.
    assert OID_RSA_ENCRYPTION in der, "no rsaEncryption in the DER after the patch"
    for name, oid in SIG_OIDS.items():
        assert oid not in der, f"OID {name} still in the DER after the patch"
    return der


def der_to_pem(der: bytes) -> bytes:
    import base64
    import textwrap
    b64 = base64.b64encode(der).decode("ascii")
    body = "\n".join(textwrap.wrap(b64, 64))
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n".encode("ascii")


def generate(out: Path, cn: str = "gosredirector.ea.com", bits: int = 1024,
             days: int = 7300) -> dict:
    """Creates pki/ with the leaf key and the patched cert. Returns the paths."""
    out.mkdir(parents=True, exist_ok=True)

    subject = build_name([(oid, cn if oid == NameOID.COMMON_NAME else val)
                          for oid, val in SUBJECT])
    issuer = build_name(ISSUER_OTG3)

    now = dt.datetime.now(dt.timezone.utc)
    not_after = now + dt.timedelta(days=days)

    # 1. Throwaway CA. Only its SUBJECT (= the OTG3 DN) matters, because it becomes
    #    the leaf's issuer. The key does not matter - the signature is not verified.
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    ca_cert = (x509.CertificateBuilder()
               .subject_name(issuer)
               .issuer_name(issuer)
               .public_key(ca_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now)
               .not_valid_after(not_after)
               .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                              critical=True)
               .sign(ca_key, hashes.SHA256()))

    # 2. Leaf: our own key, subject like the EA original, issuer = the OTG3 DN.
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(SERIAL)
            .not_valid_before(now)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False)
            .sign(ca_key, hashes.SHA256()))

    # 3. Patch the signature OID -> rsaEncryption (ProtoSSL bug). Without it the old
    #    client would reject the cert, because it verifies the signature.
    patched = patch_sig_oid(cert.public_bytes(serialization.Encoding.DER))

    paths = {
        "key": out / "server.key",
        "crt": out / "server.crt",
        "der": out / "server.der",
        "pem": out / "server.pem",
        "ca_crt": out / "ca.crt",
    }
    paths["key"].write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    paths["der"].write_bytes(patched)
    paths["crt"].write_bytes(der_to_pem(patched))
    paths["pem"].write_bytes(paths["key"].read_bytes() + paths["crt"].read_bytes())
    paths["ca_crt"].write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    return paths


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cn", default="gosredirector.ea.com",
                    help="Common Name of the cert (default: like the EA original)")
    ap.add_argument("--bits", type=int, default=1024,
                    help="RSA key size; 1024 = like the original, the old client "
                         "will definitely accept it.")
    ap.add_argument("--days", type=int, default=7300,
                    help="validity in days (default ~20 years)")
    ap.add_argument("-o", "--out", type=Path,
                    default=Path(__file__).parent / "pki",
                    help="directory for the key and cert (gitignored)")
    args = ap.parse_args()

    print(f"generating stand-in cert: CN={args.cn}, RSA-{args.bits}, {args.days} days")
    paths = generate(args.out, args.cn, args.bits, args.days)

    cert = x509.load_der_x509_certificate(paths["der"].read_bytes())
    print(f"\n  leaf key:   {paths['key']}")
    print(f"  cert (PEM): {paths['crt']}")
    print(f"  cert (DER): {paths['der']}")
    print(f"  combined:   {paths['pem']}")
    print("\n--- verification ---")
    print(f"  subject: {cert.subject.rfc4514_string()}")
    print(f"  issuer:  {cert.issuer.rfc4514_string()}")
    print(f"  serial:  {cert.serial_number}")
    print(f"  valid:   {cert.not_valid_before_utc.date()} -> {cert.not_valid_after_utc.date()}")
    print(f"  sig OID: {cert.signature_algorithm_oid.dotted_string} "
          f"({'OK - rsaEncryption' if cert.signature_algorithm_oid.dotted_string == '1.2.840.113549.1.1.1' else 'ERROR'})")
    print("  ^ issuer MUST be the OTG3 DN (CN=OTG3 Certificate Authority ...), "
          "otherwise the client will drop the connection after Certificate.")
    print("\nDone. The stand-in TLS-terminating server will present this cert.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
