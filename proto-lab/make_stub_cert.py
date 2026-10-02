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

Plain Python, no `openssl` and no `cryptography`: the RSA keys, the DER and the
signatures are built here (a few dozen lines), so the packaged launcher does not
carry a 10 MB library for a file it makes once per machine. The output is byte
for byte what the earlier `cryptography` version produced from the same keys and
times - tests/test_stub_cert.py builds both and compares them. The output goes to
proto-lab/pki/, which is in .gitignore - the private key goes neither into the
repository nor into the distributed .exe.

Usage:
    python proto-lab/make_stub_cert.py
    python proto-lab/make_stub_cert.py --cn gosredirector.ea.com --bits 1024
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import math
import secrets
import textwrap
from dataclasses import dataclass
from pathlib import Path

OID_C, OID_ST, OID_L = "2.5.4.6", "2.5.4.8", "2.5.4.7"
OID_O, OID_OU, OID_CN = "2.5.4.10", "2.5.4.11", "2.5.4.3"
OID_EMAIL = "1.2.840.113549.1.9.1"

# Subject fields mirrored from the original EA cert (docs/protocol.md, section
# 5). The original had a 1024-bit RSA key and a CN without "online" - one cert for
# the whole environment table. The client does not validate these fields; we keep
# them for consistency with what the game "saw" on the live service.
SUBJECT = [
    (OID_C, "US"),
    (OID_ST, "California"),
    (OID_O, "Electronic Arts, Inc."),
    (OID_OU, "Global Online Studio"),
    (OID_CN, "gosredirector.ea.com"),
]

# Issuer DN EXACTLY as in the original EA cert - the client matches its built-in
# CAs by it (see the docstring, cause of the RST in round 1). The field order
# mirrors the original (docs/recon/capture/120822-003-server-cert0.der). This DN
# becomes the subject of our throwaway CA, so leaf.issuer = this DN.
ISSUER_OTG3 = [
    (OID_CN, "OTG3 Certificate Authority"),
    (OID_C, "US"),
    (OID_ST, "California"),
    (OID_L, "Redwood City"),
    (OID_O, "Electronic Arts, Inc."),
    (OID_OU, "Online Technology Group"),
    (OID_EMAIL, "dirtysock-contact@ea.com"),
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

OID_BASIC_CONSTRAINTS, OID_SKI, OID_AKI = "2.5.29.19", "2.5.29.14", "2.5.29.35"
DER_NULL = b"\x05\x00"
DIGEST_INFO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")   # RFC 8017 9.2


# ------------------------------------------------------------------------------- DER

def _tlv(tag: int, body: bytes) -> bytes:
    size = len(body)
    if size < 0x80:
        head = bytes([size])
    else:
        raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
        head = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + head + body


def _seq(*parts: bytes) -> bytes:
    return _tlv(0x30, b"".join(parts))


def _int(value: int) -> bytes:
    return _tlv(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big"))   # room for the sign bit


def _oid(dotted: str) -> bytes:
    first, second, *rest = (int(part) for part in dotted.split("."))
    body = bytearray([40 * first + second])
    for arc in rest:
        chunk = [arc & 0x7F]
        while arc > 0x7F:
            arc >>= 7
            chunk.append(0x80 | (arc & 0x7F))
        body += bytes(reversed(chunk))
    return _tlv(0x06, bytes(body))


def _name(pairs: list[tuple[str, str]]) -> bytes:
    """DN with PrintableString (email: IA5String) - like the EA original, one attribute per RDN."""
    return _seq(*(_tlv(0x31, _seq(_oid(oid), _tlv(0x16 if oid == OID_EMAIL else 0x13,
                                                    value.encode("ascii"))))
                  for oid, value in pairs))


def _time(moment: dt.datetime) -> bytes:
    """UTCTime up to 2049, GeneralizedTime after (RFC 5280 4.1.2.5), whole seconds."""
    if moment.year < 2050:
        return _tlv(0x17, moment.strftime("%y%m%d%H%M%SZ").encode("ascii"))
    return _tlv(0x18, moment.strftime("%Y%m%d%H%M%SZ").encode("ascii"))


def _pem(label: str, der: bytes) -> bytes:
    body = "\n".join(textwrap.wrap(base64.b64encode(der).decode("ascii"), 64))
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n".encode("ascii")


def der_to_pem(der: bytes) -> bytes:
    return _pem("CERTIFICATE", der)


# ------------------------------------------------------------------------------- RSA

@dataclass(frozen=True)
class RsaKey:
    n: int
    e: int
    d: int
    p: int
    q: int

    def public_der(self) -> bytes:
        """RSAPublicKey - the value of subjectPublicKeyInfo's BIT STRING."""
        return _seq(_int(self.n), _int(self.e))

    def key_id(self) -> bytes:
        """SHA-1 of the public key BIT STRING's value (RFC 5280 4.2.1.2, method 1)."""
        return hashlib.sha1(self.public_der()).digest()

    def sign_sha256(self, data: bytes) -> bytes:
        """RSASSA-PKCS1-v1_5 with SHA-256 - deterministic, which is what makes the output testable."""
        size = (self.n.bit_length() + 7) // 8
        digest = DIGEST_INFO_SHA256 + hashlib.sha256(data).digest()
        block = b"\x00\x01" + b"\xff" * (size - len(digest) - 3) + b"\x00" + digest
        return pow(int.from_bytes(block, "big"), self.d, self.n).to_bytes(size, "big")

    def pkcs8_pem(self) -> bytes:
        private = _seq(_int(0), _int(self.n), _int(self.e), _int(self.d), _int(self.p), _int(self.q),
                       _int(self.d % (self.p - 1)), _int(self.d % (self.q - 1)),
                       _int(pow(self.q, -1, self.p)))
        return _pem("PRIVATE KEY", _seq(_int(0), _seq(_oid("1.2.840.113549.1.1.1"), DER_NULL),
                                        _tlv(0x04, private)))


_SMALL_PRIMES = [n for n in range(3, 2000, 2) if all(n % k for k in range(3, math.isqrt(n) + 1, 2))]


def _probably_prime(n: int, rounds: int = 40) -> bool:
    for small in _SMALL_PRIMES:
        if n % small == 0:
            return n == small
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):                       # Miller-Rabin
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits: int, e: int) -> int:
    while True:
        # the top two bits set, so that two of these multiply to exactly 2 * bits bits
        candidate = secrets.randbits(bits) | (3 << (bits - 2)) | 1
        if math.gcd(e, candidate - 1) == 1 and _probably_prime(candidate):
            return candidate


def generate_key(bits: int = 1024, e: int = 65537) -> RsaKey:
    while True:
        p, q = _prime(bits - bits // 2, e), _prime(bits // 2, e)
        if p != q and (p * q).bit_length() == bits:
            p, q = max(p, q), min(p, q)
            return RsaKey(p * q, e, pow(e, -1, math.lcm(p - 1, q - 1)), p, q)


# ------------------------------------------------------------------------------ X.509

SHA256_WITH_RSA = _seq(_oid("1.2.840.113549.1.1.11"), DER_NULL)


def _extension(oid: str, value: bytes, critical: bool = False) -> bytes:
    return _seq(_oid(oid), b"\x01\x01\xff" if critical else b"", _tlv(0x04, value))


def _certificate(serial: int, issuer: bytes, subject: bytes, subject_key: RsaKey,
                 not_before: dt.datetime, not_after: dt.datetime,
                 extensions: list[bytes], signer: RsaKey) -> bytes:
    spki = _seq(_seq(_oid("1.2.840.113549.1.1.1"), DER_NULL),
                _tlv(0x03, b"\x00" + subject_key.public_der()))
    tbs = _seq(b"\xa0\x03\x02\x01\x02",              # [0] version: v3
               _int(serial), SHA256_WITH_RSA, issuer,
               _seq(_time(not_before), _time(not_after)), subject, spki,
               _tlv(0xA3, _seq(*extensions)))
    return _seq(tbs, SHA256_WITH_RSA, _tlv(0x03, b"\x00" + signer.sign_sha256(tbs)))


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


def generate(out: Path, cn: str = "gosredirector.ea.com", bits: int = 1024,
             days: int = 7300, *, now: dt.datetime | None = None,
             keys: tuple[RsaKey, RsaKey] | None = None, ca_serial: int | None = None) -> dict:
    """Creates pki/ with the leaf key and the patched cert. Returns the paths.
    now, keys (leaf, CA) and ca_serial are for the test that compares this with its reference."""
    out.mkdir(parents=True, exist_ok=True)
    now = (now or dt.datetime.now(dt.timezone.utc)).replace(microsecond=0)
    not_after = now + dt.timedelta(days=days)
    key, ca_key = keys or (generate_key(bits), generate_key(1024))
    issuer = _name(ISSUER_OTG3)
    subject = _name([(oid, cn if oid == OID_CN else value) for oid, value in SUBJECT])

    # 1. Throwaway CA. Only its SUBJECT (= the OTG3 DN) matters, because it becomes
    #    the leaf's issuer. The key does not matter - the signature is not verified.
    ca_cert = _certificate(
        ca_serial if ca_serial is not None else secrets.randbits(160) >> 1, issuer, issuer, ca_key,
        now, not_after, [_extension(OID_BASIC_CONSTRAINTS, _seq(b"\x01\x01\xff"), critical=True)],
        ca_key)

    # 2. Leaf: our own key, subject like the EA original, issuer = the OTG3 DN.
    cert = _certificate(
        SERIAL, issuer, subject, key, now, not_after,
        [_extension(OID_BASIC_CONSTRAINTS, _seq()),
         _extension(OID_SKI, _tlv(0x04, key.key_id())),
         _extension(OID_AKI, _seq(_tlv(0x80, ca_key.key_id())))],
        ca_key)

    # 3. Patch the signature OID -> rsaEncryption (ProtoSSL bug). Without it the old
    #    client would reject the cert, because it verifies the signature.
    patched = patch_sig_oid(cert)

    paths = {
        "key": out / "server.key",
        "crt": out / "server.crt",
        "der": out / "server.der",
        "pem": out / "server.pem",
        "ca_crt": out / "ca.crt",
    }
    paths["key"].write_bytes(key.pkcs8_pem())
    paths["der"].write_bytes(patched)
    paths["crt"].write_bytes(der_to_pem(patched))
    paths["pem"].write_bytes(paths["key"].read_bytes() + paths["crt"].read_bytes())
    paths["ca_crt"].write_bytes(_pem("CERTIFICATE", ca_cert))
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
    der = paths["der"].read_bytes()
    print(f"\n  leaf key:   {paths['key']}")
    print(f"  cert (PEM): {paths['crt']}")
    print(f"  cert (DER): {paths['der']}")
    print(f"  combined:   {paths['pem']}")
    print("\n--- verification ---")
    print(f"  issuer is the OTG3 DN: {_name(ISSUER_OTG3) in der}")
    print(f"  signature OID rsaEncryption in both places: {der.count(OID_RSA_ENCRYPTION) >= 2}")
    print("  ^ issuer MUST be the OTG3 DN (CN=OTG3 Certificate Authority ...), "
          "otherwise the client will drop the connection after Certificate.")
    print("\nDone. The stand-in TLS-terminating server will present this cert.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
