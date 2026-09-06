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
Certificate. Dzialajacy exploit Aim4kill zachowywal oryginalny issuer=OTG3 i
patchowal tylko OID. Dlatego zamiast `req -x509` (self-signed, issuer=subject)
wystawiamy leaf pod wlasnym throwaway CA, ktorego subject = DOKLADNY DN OTG3
(`docs/recon/capture/120822-003-server-cert0.der`). Klucz CA jest nieistotny
(podpis leafa i tak nie jest weryfikowany). CELOWO nie dodajemy Authority Key
Identifier - prawdziwy AKI zawiera keyid OTG3, ktorego nie odtworzymy; brak AKI
zmusza klienta do dopasowania CA po issuer DN (nasza sciezka), nie po keyid.

Pola podmiotu leafa odwzorowuja oryginal tylko dla porzadku - klient ich nie
sprawdza; liczy sie issuer.

Wymaga w PATH `openssl` (testowane na 3.5). Wynik trafia do proto-lab/pki/,
ktory jest w .gitignore - klucz prywatny nie idzie do repozytorium.

Uzycie:
    python proto-lab/make_stub_cert.py
    python proto-lab/make_stub_cert.py --cn gosredirector.ea.com --bits 1024
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

# Pola podmiotu odwzorowane z oryginalnego certu EA (docs/protocol.md, sekcja
# 5). Oryginal mial klucz RSA 1024-bit i CN bez "online" - jeden cert na cala
# tablice srodowisk. Klient tych pol nie waliduje; trzymamy je dla zgodnosci
# z tym, co gra "widziala" na zywej usludze.
SUBJECT = [
    ("C", "US"),
    ("ST", "California"),
    ("O", "Electronic Arts, Inc."),
    ("OU", "Global Online Studio"),
    ("CN", "gosredirector.ea.com"),
]

# DN wystawcy (issuer) DOKLADNIE jak w oryginalnym certcie EA - to po nim klient
# dopasowuje wbudowane CA (patrz docstring, powod RST w rundzie 1). Kolejnosc pol
# odwzorowuje oryginal (docs/recon/capture/120822-003-server-cert0.der). Ten DN
# staje sie subjectem naszego throwaway CA, wiec leaf.issuer = ten DN.
ISSUER_OTG3 = [
    ("CN", "OTG3 Certificate Authority"),
    ("C", "US"),
    ("ST", "California"),
    ("L", "Redwood City"),
    ("O", "Electronic Arts, Inc."),
    ("OU", "Online Technology Group"),
    ("emailAddress", "dirtysock-contact@ea.com"),
]


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


def pem_to_der(pem: bytes) -> bytes:
    import base64
    lines = pem.decode("ascii").splitlines()
    b64 = "".join(l for l in lines if l and not l.startswith("-----"))
    return base64.b64decode(b64)


def der_to_pem(der: bytes) -> bytes:
    import base64, textwrap
    b64 = base64.b64encode(der).decode("ascii")
    body = "\n".join(textwrap.wrap(b64, 64))
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n".encode("ascii")


def build_dn(pairs: list[tuple[str, str]]) -> str:
    """Sklada string -subj dla openssl z listy par (klucz, wartosc).

    Delimiter '/' (wiec przecinki w wartosciach, np. w O, sa ok). Kolejnosc par
    zachowana - istotne dla issuera OTG3, ktory klient moze porownywac bajtowo.
    """
    return "/" + "/".join(f"{key}={val}" for key, val in pairs)


def build_subj(cn: str) -> str:
    """DN podmiotu leafa: SUBJECT z podmienionym CN."""
    return build_dn([(k, cn if k == "CN" else v) for k, v in SUBJECT])


def openssl(*args: str) -> None:
    cmd = ["openssl", *args]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(f"openssl {args[0]} nie powiodlo sie:\n{proc.stderr}\n")
        raise SystemExit(1)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cn", default="gosredirector.ea.com",
                    help="Common Name certu (domyslnie jak oryginal EA)")
    ap.add_argument("--bits", type=int, default=1024,
                    help="rozmiar klucza RSA; 1024 = jak oryginal, stary klient "
                         "na pewno przyjmie. Nowszy serwer moze wymagac 2048.")
    ap.add_argument("--days", type=int, default=7300,
                    help="waznosc w dniach (domyslnie ~20 lat)")
    ap.add_argument("-o", "--out", type=Path,
                    default=Path(__file__).parent / "pki",
                    help="katalog na klucz i cert (gitignore)")
    args = ap.parse_args()

    if which_openssl() is None:
        sys.stderr.write("Nie znalazlem 'openssl' w PATH.\n")
        return 1

    args.out.mkdir(parents=True, exist_ok=True)
    key = args.out / "server.key"
    crt = args.out / "server.crt"          # cert PEM (po patchu OID)
    der = args.out / "server.der"          # cert DER (po patchu) - czyta terminator
    pem = args.out / "server.pem"          # klucz + cert razem, wygodne dla serwerow
    ca_key = args.out / "ca.key"           # klucz throwaway CA (nieistotny, zostaje)
    ca_crt = args.out / "ca.crt"           # cert throwaway CA (subject = DN OTG3)
    csr = args.out / "server.csr"          # CSR leafa (posrednik, zostaje w pki/)
    ext = args.out / "leaf.ext"            # rozszerzenia leafa dla `x509 -req`
    cnf = args.out / "openssl.cnf"         # wymusza PrintableString w DN (nizej)

    subj = build_subj(args.cn)
    ca_subj = build_dn(ISSUER_OTG3)
    print(f"generuje cert zastepczy: CN={args.cn}, RSA-{args.bits}, {args.days} dni")
    print(f"  subject (leaf): {subj}")
    print(f"  issuer  (CA):   {ca_subj}")

    # Konfiguracja openssl z `string_mask = nombstr`: wymusza kodowanie pol DN
    # jako PrintableString (ASCII) / IA5String (email) - DOKLADNIE jak oryginalny
    # cert EA. Domyslnie openssl 3.x koduje je jako UTF8String (inny tag: 0x0c vs
    # 0x13), co przy bajtowym porownaniu issuera przez DirtySDK znow daloby RST
    # (fallback #1 z planu). Dlugosci pol i tak sie zgadzaja, wiec rozniil tylko tag.
    cnf.write_text(
        "[req]\ndistinguished_name = dn\nstring_mask = nombstr\nprompt = no\n[dn]\n",
        encoding="ascii")

    # 1. Throwaway CA. Subject = DOKLADNY DN OTG3 => leaf.issuer = DN OTG3, po
    #    ktorym klient dopasowuje wbudowane CA. Klucz CA nieistotny (podpis leafa
    #    nie jest weryfikowany) - RSA-1024. -nodes: bez hasla.
    openssl("req", "-x509", "-newkey", "rsa:1024", "-nodes",
            "-keyout", str(ca_key), "-out", str(ca_crt), "-config", str(cnf),
            "-days", str(args.days), "-sha256", "-subj", ca_subj)

    # 2. Leaf: wlasny klucz (server.key) + CSR o subject jak dotad. -nodes: klucz
    #    bez hasla (serwer laduje go bez interakcji).
    openssl("req", "-newkey", f"rsa:{args.bits}", "-nodes",
            "-keyout", str(key), "-out", str(csr), "-config", str(cnf),
            "-sha256", "-subj", subj)

    # 3. Podpisz leaf naszym CA => leaf.issuer = DN OTG3. Serial 0x3C2 (962) jak
    #    oryginal (kosmetyka). Rozszerzenia: TYLKO basicConstraints=CA:FALSE jak
    #    oryginal - CELOWO bez Authority Key Identifier (patrz docstring), zeby
    #    klient dopasowywal CA po issuer DN, nie po keyid.
    ext.write_text("basicConstraints=CA:FALSE\n", encoding="ascii")
    openssl("x509", "-req", "-in", str(csr),
            "-CA", str(ca_crt), "-CAkey", str(ca_key),
            "-set_serial", "962", "-days", str(args.days),
            "-sha256", "-extfile", str(ext), "-out", str(crt))

    # Patch OID podpisu -> rsaEncryption (bug ProtoSSL). Bez tego stary klient
    # odrzucilby cert, bo weryfikuje podpis. Podmieniamy na DER, potem zapisujemy
    # i DER (dla terminatora), i przepisany PEM (dla openssl/serwerow).
    print("\n--- patch OID podpisu (bug ProtoSSL) ---")
    patched = patch_sig_oid(pem_to_der(crt.read_bytes()))
    der.write_bytes(patched)
    crt.write_bytes(der_to_pem(patched))

    pem.write_bytes(key.read_bytes() + crt.read_bytes())

    print(f"\n  klucz leafa: {key}")
    print(f"  cert (PEM): {crt}")
    print(f"  cert (DER): {der}")
    print(f"  razem: {pem}")
    print(f"  throwaway CA: {ca_crt} / {ca_key} (do regeneracji; terminator go nie uzywa)")
    print("\n--- weryfikacja ---")
    subprocess.run(["openssl", "x509", "-in", str(crt), "-noout",
                    "-subject", "-issuer", "-dates"], check=False)
    print("  ^ issuer MUSI byc DN OTG3 (CN=OTG3 Certificate Authority ...), "
          "inaczej klient zerwie po Certificate.")
    print("\nGotowe. Cert poda serwer zastepczy terminujacy TLS (Tor B).")
    return 0


def which_openssl() -> str | None:
    from shutil import which
    return which("openssl")


if __name__ == "__main__":
    raise SystemExit(main())
