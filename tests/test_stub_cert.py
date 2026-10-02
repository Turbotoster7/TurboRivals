"""make_stub_cert.py builds the stand-in certificate without `cryptography`. The game's ProtoSSL
accepts it only because of particular bytes (the OTG3 issuer in PrintableString, the patched
signature OID), so the reference is the earlier version: the certificate it built with
`cryptography`, from the same keys, time and serials, has to come out byte for byte the same."""
import support

import datetime as dt
import math
import tempfile
import unittest
from pathlib import Path

import make_stub_cert as msc
import tls_terminator

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.x509.name import _ASN1Type
    from cryptography.x509.oid import NameOID
except ImportError:                     # the reference is optional; the launcher does not need it
    x509 = None

NOW = dt.datetime(2026, 10, 2, 12, 30, 45, tzinfo=dt.timezone.utc)
CA_SERIAL = 0x5DEECE66D1F2B3A4C5D6E7F8091A2B3C4D5E6F7      # 159 bits, like a random one


def reference(leaf: msc.RsaKey, ca: msc.RsaKey) -> dict:
    """The earlier make_stub_cert.generate, with the keys, time and CA serial fixed."""
    def private(k):
        return rsa.RSAPrivateNumbers(k.p, k.q, k.d, k.d % (k.p - 1), k.d % (k.q - 1), pow(k.q, -1, k.p),
                                     rsa.RSAPublicNumbers(k.e, k.n)).private_key()

    oids = {msc.OID_C: NameOID.COUNTRY_NAME, msc.OID_ST: NameOID.STATE_OR_PROVINCE_NAME,
            msc.OID_L: NameOID.LOCALITY_NAME, msc.OID_O: NameOID.ORGANIZATION_NAME,
            msc.OID_OU: NameOID.ORGANIZATIONAL_UNIT_NAME, msc.OID_CN: NameOID.COMMON_NAME,
            msc.OID_EMAIL: NameOID.EMAIL_ADDRESS}

    def name(pairs):
        return x509.Name([x509.NameAttribute(
            oids[oid], value,
            _type=_ASN1Type.IA5String if oid == msc.OID_EMAIL else _ASN1Type.PrintableString)
            for oid, value in pairs])

    key, ca_key = private(leaf), private(ca)
    issuer, not_after = name(msc.ISSUER_OTG3), NOW + dt.timedelta(days=7300)
    ca_cert = (x509.CertificateBuilder()
               .subject_name(issuer).issuer_name(issuer).public_key(ca_key.public_key())
               .serial_number(CA_SERIAL).not_valid_before(NOW).not_valid_after(not_after)
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
               .sign(ca_key, hashes.SHA256()))
    cert = (x509.CertificateBuilder()
            .subject_name(name(msc.SUBJECT)).issuer_name(issuer).public_key(key.public_key())
            .serial_number(msc.SERIAL).not_valid_before(NOW).not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))
    return {"key": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()),
            "der": msc.patch_sig_oid(cert.public_bytes(serialization.Encoding.DER)),
            "ca": ca_cert.public_bytes(serialization.Encoding.PEM)}


class StubCertificate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key, cls.ca_key = msc.generate_key(1024), msc.generate_key(1024)
        cls.paths = msc.generate(Path(tempfile.mkdtemp(dir=support.HOME)), now=NOW,
                                 keys=(cls.key, cls.ca_key), ca_serial=CA_SERIAL)

    def test_the_key_is_a_sound_rsa_key(self):
        k = self.key
        self.assertEqual((k.n.bit_length(), k.e, k.p * k.q), (1024, 65537, k.n))
        self.assertEqual(k.e * k.d % math.lcm(k.p - 1, k.q - 1), 1)
        message = 0x1234567890ABCDEF
        self.assertEqual(pow(pow(message, k.e, k.n), k.d, k.n), message)

    def test_the_server_reads_the_key_it_writes(self):
        n, d, size = tls_terminator.load_rsa_priv(self.paths["key"])
        self.assertEqual((n, d, size), (self.key.n, self.key.d, 128))

    def test_what_protossl_looks_at(self):
        der = self.paths["der"].read_bytes()
        self.assertIn(msc._name(msc.ISSUER_OTG3), der)
        self.assertIn(b"\x13\x1aOTG3 Certificate Authority", der)          # PrintableString
        self.assertIn(b"\x16\x18dirtysock-contact@ea.com", der)            # IA5String
        self.assertEqual(der.count(msc.OID_RSA_ENCRYPTION), 3)             # the key + both signature fields
        for oid in msc.SIG_OIDS.values():
            self.assertNotIn(oid, der)
        self.assertTrue(self.paths["crt"].read_bytes().startswith(b"-----BEGIN CERTIFICATE-----\n"))

    def test_a_fresh_pair_each_time(self):
        other = msc.generate(Path(tempfile.mkdtemp(dir=support.HOME)))
        self.assertNotEqual(other["key"].read_bytes(), self.paths["key"].read_bytes())
        self.assertEqual(tls_terminator.load_rsa_priv(other["key"])[2], 128)

    @unittest.skipUnless(x509, "cryptography (the reference) is not installed")
    def test_byte_for_byte_what_the_cryptography_version_made(self):
        expected = reference(self.key, self.ca_key)
        self.assertEqual(self.paths["key"].read_bytes(), expected["key"])
        self.assertEqual(self.paths["der"].read_bytes(), expected["der"])
        self.assertEqual(self.paths["ca_crt"].read_bytes(), expected["ca"])

    @unittest.skipUnless(x509, "cryptography (the reference) is not installed")
    def test_the_ca_signature_verifies_before_the_patch(self):
        ca = x509.load_pem_x509_certificate(self.paths["ca_crt"].read_bytes())
        ca.public_key().verify(ca.signature, ca.tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256())
        self.assertTrue(ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)


if __name__ == "__main__":
    unittest.main()
