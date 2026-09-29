#!/usr/bin/env python3
"""Generator certyfikatu zastepczego dla serwera zastepujacego redirector EA.

Kontekst: usluga online NFS Rivals zostala wylaczona 2025-10-07. Stawiamy
wlasny serwer zastepczy, do ktorego laczy sie nasz wlasny, legalnie kupiony
klient. Serwer musi przedstawic certyfikat SSL - to jego wlasna tozsamosc,
nie podszywanie sie pod dzialajaca usluge (uslugi EA juz nie ma).

Dlaczego samodzielnie podpisany cert wystarcza - i dlaczego nie sam z siebie:
stary ProtoSSL (DirtySDK) tej epoki JEDNAK weryfikuje podpis certu (memcmp po
haszu), wiec zwykly self-signed zostalby odrzucony. Wykorzystujemy znany blad
parsera (Aim4kill/Bug_OldProtoSSL): jesli OID algorytmu podpisu ustawic na
`rsaEncryption` (ASN_OBJ_RSA_PKCS_KEY, 1.2.840.113549.1.1.1), parser wpada w
galaz `default`, ustawia iHashSize = 0, a wtedy memcmp(...,0)==0 - weryfikacja
"przechodzi" bez sprawdzania podpisu. Testowane na BF3/BF4 (Frostbite 2013, ta
sama generacja DirtySDK co Rivals). Dlatego po wygenerowaniu certu PATCHUJEMY
jego DER: podmieniamy OID podpisu na rsaEncryption. Klucz prywatny EA nie jest
potrzebny ani uzywany - generujemy wlasny; cert o CN `gosredirector.ea.com` to
tozsamosc naszego serwera zastepczego (jeden CN na cala tablice srodowisk).

WAZNE - issuer MUSI byc DN OTG3, nie self-signed. To bylo zrodlo RST w rundzie 1:
przed weryfikacja podpisu ProtoSSL wybiera wbudowany certyfikat CA po issuer DN
leafa. Nasz poprzedni self-signed mial issuer=CN gosredirector.ea.com, ktorego w
magazynie CA klienta NIE MA - parser wywalal sie na dopasowaniu CA, ZANIM doszedl
do zpatchowanego OID, i klient zrywal polaczenie (RST bez Alertu) tuz po naszym
Certificate. Dlatego zamiast certu self-signed wystawiamy leaf pod wlasnym
throwaway CA, ktorego subject = DOKLADNY DN OTG3
(`docs/recon/capture/120822-003-server-cert0.der`). Klucz CA jest nieistotny -
podpis leafa i tak nie jest weryfikowany.

Pola DN musza byc kodowane jako PrintableString (email jako IA5String) -
DOKLADNIE jak oryginal EA. UTF8String (inny tag: 0x0c zamiast 0x13) zmienilby
bajty DN, a DirtySDK porownuje issuera bajtowo - znowu RST.

Rozszerzenia leafa odwzorowuja to, co realnie DZIALA (sesja multiplayer z
2026-09-16): basicConstraints CA:FALSE, subjectKeyIdentifier i
authorityKeyIdentifier - wszystkie niekrytyczne. Wczesniejsza wersja tego pliku
twierdzila w komentarzu, ze AKI jest celowo pomijane, ale openssl 3.x dodawal je
sam i tak wygenerowany cert przeszedl; wzorcem jest cert, nie komentarz.

Nie wymaga `openssl` w PATH - korzysta z biblioteki `cryptography`, zeby ten sam
kod dzialal w spakowanym launcherze u kogos, kto Pythona ani openssl nie ma.
Wynik trafia do proto-lab/pki/, ktory jest w .gitignore - klucz prywatny nie
idzie do repozytorium ani do rozdawanego pliku .exe.

Uzycie:
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

# Pola podmiotu odwzorowane z oryginalnego certu EA (docs/protocol.md, sekcja
# 5). Oryginal mial klucz RSA 1024-bit i CN bez "online" - jeden cert na cala
# tablice srodowisk. Klient tych pol nie waliduje; trzymamy je dla zgodnosci
# z tym, co gra "widziala" na zywej usludze.
SUBJECT = [
    (NameOID.COUNTRY_NAME, "US"),
    (NameOID.STATE_OR_PROVINCE_NAME, "California"),
    (NameOID.ORGANIZATION_NAME, "Electronic Arts, Inc."),
    (NameOID.ORGANIZATIONAL_UNIT_NAME, "Global Online Studio"),
    (NameOID.COMMON_NAME, "gosredirector.ea.com"),
]

# DN wystawcy (issuer) DOKLADNIE jak w oryginalnym certcie EA - to po nim klient
# dopasowuje wbudowane CA (patrz docstring, powod RST w rundzie 1). Kolejnosc pol
# odwzorowuje oryginal (docs/recon/capture/120822-003-server-cert0.der). Ten DN
# staje sie subjectem naszego throwaway CA, wiec leaf.issuer = ten DN.
ISSUER_OTG3 = [
    (NameOID.COMMON_NAME, "OTG3 Certificate Authority"),
    (NameOID.COUNTRY_NAME, "US"),
    (NameOID.STATE_OR_PROVINCE_NAME, "California"),
    (NameOID.LOCALITY_NAME, "Redwood City"),
    (NameOID.ORGANIZATION_NAME, "Electronic Arts, Inc."),
    (NameOID.ORGANIZATIONAL_UNIT_NAME, "Online Technology Group"),
    (NameOID.EMAIL_ADDRESS, "dirtysock-contact@ea.com"),
]

SERIAL = 962          # 0x3C2, jak oryginal (kosmetyka)

# OID-y AlgorithmIdentifier (same bajty tresci OID, bez naglowka TLV). Wszystkie
# sygnaturowe warianty maja te sama dlugosc 9 bajtow co rsaEncryption, wiec
# podmiana nie zmienia dlugosci DER. rsaEncryption (1.2.840.113549.1.1.1) to
# nasz cel - trafia w galaz `default` parsera ProtoSSL i zeruje iHashSize.
OID_RSA_ENCRYPTION = bytes.fromhex("2a864886f70d010101")   # rsaEncryption (cel)
SIG_OIDS = {
    "sha256WithRSA": bytes.fromhex("2a864886f70d01010b"),
    "sha1WithRSA":   bytes.fromhex("2a864886f70d010105"),
    "md5WithRSA":    bytes.fromhex("2a864886f70d010104"),
}


def build_name(pairs: list[tuple[x509.ObjectIdentifier, str]]) -> x509.Name:
    """DN z wymuszonym PrintableString (email: IA5String) - jak oryginal EA.

    Domyslnie `cryptography` koduje wiekszosc pol jako UTF8String. Inny tag to
    inne bajty DN, a DirtySDK porownuje issuera bajtowo.
    """
    attrs = []
    for oid, value in pairs:
        asn1 = (_ASN1Type.IA5String if oid == NameOID.EMAIL_ADDRESS
                else _ASN1Type.PrintableString)
        attrs.append(x509.NameAttribute(oid, value, _type=asn1))
    return x509.Name(attrs)


def patch_sig_oid(der: bytes) -> bytes:
    """Podmienia OID algorytmu podpisu na rsaEncryption (bug ProtoSSL).

    W certyfikacie X.509 OID podpisu wystepuje dwukrotnie: w tbsCertificate
    (pole `signature`) i w zewnetrznym `signatureAlgorithm`. ProtoSSL czyta ten
    zewnetrzny, ale podpis i tak nie jest weryfikowany, wiec podmieniamy KAZDE
    wystapienie - obie pozycje zostaja spojne, a dlugosci DER bez zmian.
    """
    hits = 0
    for name, oid in SIG_OIDS.items():
        if oid in der:
            count = der.count(oid)
            der = der.replace(oid, OID_RSA_ENCRYPTION)
            hits += count
            print(f"  patch OID: {name} -> rsaEncryption ({count}x)")
    if hits == 0:
        raise SystemExit("nie znalazlem znanego OID podpisu w DER - cert "
                         "wygenerowany innym algorytmem niz sha256/sha1/md5?")
    # Asercje: cel obecny, zaden zrodlowy OID juz nie zostal.
    assert OID_RSA_ENCRYPTION in der, "po patchu brak rsaEncryption w DER"
    for name, oid in SIG_OIDS.items():
        assert oid not in der, f"po patchu zostal OID {name} w DER"
    return der


def der_to_pem(der: bytes) -> bytes:
    import base64
    import textwrap
    b64 = base64.b64encode(der).decode("ascii")
    body = "\n".join(textwrap.wrap(b64, 64))
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n".encode("ascii")


def generate(out: Path, cn: str = "gosredirector.ea.com", bits: int = 1024,
             days: int = 7300) -> dict:
    """Tworzy pki/ z kluczem leafa i zpatchowanym certem. Zwraca sciezki."""
    out.mkdir(parents=True, exist_ok=True)

    subject = build_name([(oid, cn if oid == NameOID.COMMON_NAME else val)
                          for oid, val in SUBJECT])
    issuer = build_name(ISSUER_OTG3)

    now = dt.datetime.now(dt.timezone.utc)
    not_after = now + dt.timedelta(days=days)

    # 1. Throwaway CA. Liczy sie tylko jego SUBJECT (= DN OTG3), bo to on staje
    #    sie issuerem leafa. Klucz nieistotny - podpis nie jest weryfikowany.
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

    # 2. Leaf: wlasny klucz, subject jak oryginal EA, issuer = DN OTG3.
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

    # 3. Patch OID podpisu -> rsaEncryption (bug ProtoSSL). Bez tego stary klient
    #    odrzucilby cert, bo weryfikuje podpis.
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
                    help="Common Name certu (domyslnie jak oryginal EA)")
    ap.add_argument("--bits", type=int, default=1024,
                    help="rozmiar klucza RSA; 1024 = jak oryginal, stary klient "
                         "na pewno przyjmie.")
    ap.add_argument("--days", type=int, default=7300,
                    help="waznosc w dniach (domyslnie ~20 lat)")
    ap.add_argument("-o", "--out", type=Path,
                    default=Path(__file__).parent / "pki",
                    help="katalog na klucz i cert (gitignore)")
    args = ap.parse_args()

    print(f"generuje cert zastepczy: CN={args.cn}, RSA-{args.bits}, {args.days} dni")
    paths = generate(args.out, args.cn, args.bits, args.days)

    cert = x509.load_der_x509_certificate(paths["der"].read_bytes())
    print(f"\n  klucz leafa: {paths['key']}")
    print(f"  cert (PEM): {paths['crt']}")
    print(f"  cert (DER): {paths['der']}")
    print(f"  razem: {paths['pem']}")
    print("\n--- weryfikacja ---")
    print(f"  subject: {cert.subject.rfc4514_string()}")
    print(f"  issuer:  {cert.issuer.rfc4514_string()}")
    print(f"  serial:  {cert.serial_number}")
    print(f"  waznosc: {cert.not_valid_before_utc.date()} -> {cert.not_valid_after_utc.date()}")
    print(f"  sig OID: {cert.signature_algorithm_oid.dotted_string} "
          f"({'OK - rsaEncryption' if cert.signature_algorithm_oid.dotted_string == '1.2.840.113549.1.1.1' else 'BLAD'})")
    print("  ^ issuer MUSI byc DN OTG3 (CN=OTG3 Certificate Authority ...), "
          "inaczej klient zerwie po Certificate.")
    print("\nGotowe. Cert poda serwer zastepczy terminujacy TLS.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
