# Protokol NFS Rivals - stan wiedzy

Dokument zywy. Kazde ustalenie ma zapisane zrodlo: albo wyciag z binarki,
albo obserwacja z zywego klienta. Rzeczy niepotwierdzone sa oznaczone
jako hipotezy.

Badana binarka: `NFS14.exe`, wersja Steam (app 1262600, build 10351327),
x64, image base `0x140000000`.

---

## 1. Endpointy backendu

Wyciagniete z `.rdata` (`tools/dump_strings.py`). Offsety sa pozycjami w pliku.

| host | offset | rola |
| --- | --- | --- |
| `gosredirector.online.ea.com` | `0x016ce2a0` | **redirector produkcyjny** - glowny cel |
| `gosredirector.stest.ea.com` | `0x016ce2c0` | srodowisko testowe |
| `gosredirector.scert.ea.com` | `0x016ce2e0` | srodowisko certyfikacyjne |
| `gosredirector.ea.com` | `0x016ce300` | srodowisko deweloperskie |
| `https://gosca.ea.com:44125/redirector` | `0x0170d9b0` | redirector po HTTPS (wariant alternatywny) |
| `demangler.ea.com` | `0x0170d300` | **NAT punch-through** (DirtySDK ProtoMangle) |
| `peach.online.ea.com` | `0x016eab10` | telemetria |
| `https://reports.tools.gos.ea.com/bugsentry` | `0x016768f8` | raporty crashy |

Cztery warianty `gosredirector` to standardowa tablica srodowisk BlazeSDK
(ten sam uklad co w Dead Space 2). Klient wybiera jeden wg `BlazeEnvironment`.

**Port redirectora: 42127/TCP** - wartosc standardowa dla tej epoki Blaze,
do potwierdzenia obserwacja.

### Warstwa P2P (DirtySDK)

Sekcja `dirtysdk` zrzutu stringow potwierdza, ze rozgrywka nie idzie przez
serwer:

```
netgamelink          warstwa polaczenia miedzy graczami
commudp-global       transport UDP
protoadvt            rozglaszanie w LAN
protossl session     SSL
User-Agent: ProtoHttp %d.%d/DS %d.%d.%d.%d.%d (Windows)
```

Demangler ma proste API HTTP - format zapytania jest w binarce doslownie:

```
http://%s:%d/getPeerAddress?myIP=%s&myPort=%d&version=1.0
myIP=%s&myPort=%d&version=1.0&status=%s&gameFeatureID=%s
```

To znaczy, ze **NAT traversal da sie zaemulowac prostym serwerem HTTP** -
nie trzeba niczego lamac. Istotne dla fazy 5.

---

## 2. Komponenty Blaze

Binarka zawiera nazwy typow TDF dla wszystkich uzywanych komponentow.
Liczba typow na komponent (`docs/recon/strings_NFS14.md`):

| komponent | typow | uwagi |
| --- | --- | --- |
| `GameManager` | 124 | sesje AllDrive, matchmaking, migracja hosta |
| `GameReporting` | 89 | raportowanie wynikow |
| `NFS` | 51 | **komponent wlasny Ghost Games** |
| `Authentication` | 29 | logowanie, persony, entitlements |
| `Util` | 21 | preAuth/postAuth/ping/konfiguracja |
| `ByteVault` | 20 | przechowywanie danych gracza |
| `Stats` | 19 | statystyki |
| `Playgroups` | 14 | grupy graczy |
| `Redirector` | 13 | |
| `Association` | 10 | listy znajomych |
| `Rooms` | 8 | |
| `Clubs` | 5 | |
| `Authentication2` | 4 | nowszy wariant logowania |
| `Messaging` | 3 | |
| `DynamicInetFilter` | 3 | |
| `CensusData` | 1 | |

Pelna lista typow: `docs/recon/strings_NFS14_all.txt`.

Komponent `Blaze::NFS::` jest specyficzny dla Rivals i obsluguje m.in.
geolokalizacje, rekomendacje rywali, Overwatch, rich presence i speed walls.
Zawiera tez `NotifyBlazeTwoWayCommunication` - generyczny kanal
notyfikacji z listami parametrow (int32/uint64/float/string).

### Sekwencja startowa (hipoteza)

Na podstawie logow BlazeSDK z innych tytulow tej epoki. Do potwierdzenia
obserwacja na zywym kliencie:

```
Util::preAuth        [0x0009::0x0007]
Authentication::login[0x0001::0x0028]  / loginPersona [0x0001::0x006E]
Util::postAuth       [0x0009::0x0008]
UserSessions::updateNetworkInfo [0x7802::0x0014]
GameManager::createGame / joinGame [0x0004::...]
```

Identyfikatory komponentow i komend nie sa jeszcze potwierdzone dla Rivals -
w binarce mamy nazwy typow, nie numery. Numery ustalimy z ruchu.

---

## 3. Format TDF - **potwierdzony**

### Kodowanie tagu

Tag to 4 znaki spakowane w 24 bity, po 6 bitow na znak. Wartosc 0 oznacza
spacje (tagi krotsze niz 4 znaki sa dopelniane).

```python
def decode_tdf_tag(raw: int) -> str:          # raw = 24 bity
    return "".join(" " if (c := (raw >> s) & 0x3F) == 0 else chr(c + 0x20)
                   for s in (18, 12, 6, 0))
```

Implementacja: `tools/pe_probe.py::decode_tdf_tag`.

**Weryfikacja:** algorytm zastosowany do metadanych w `.rdata` daje pary,
ktore zgadzaja sie z nazwami pol - to nie moze byc przypadek:

| tag | pole |
| --- | --- |
| `BID ` | `mBlazeId` |
| `MAIL` | `mEmail` |
| `PASS` | `mPassword` |
| `PNAM` | `mPersonaName` |
| `NLST` | `mEntitlements` |
| `GID ` | `mGameId` |
| `GSET` | `mGameSettings` |
| `ATTR` | `mAttributes` / `mGameAttributes` |
| `STTE` | `mGameStateField` |

### Slownik pol

`tools/extract_tdf_meta.py` wyciagnal z `.rdata`:

- **2 864** par (tag, nazwa pola)
- **1 152** unikalnych tagow
- 121 ciaglych blokow rekordow

Wynik: `docs/recon/tdf_members.md` i `docs/recon/tdf_members.json`.

To znaczy, ze **kazdy przechwycony pakiet bedziemy umieli wypisac z nazwami
pol**, zamiast patrzec na surowe bajty. To zmienia charakter fazy 1 -
zamiast zgadywac, czytamy.

### Uklad rekordu metadanych

```
+0   uint64   bajty 1..3 = tag TDF, bajty 4..7 = metadane typu
+8   ptr      nazwa pola ("m" + CamelCase)
+16  ...      ogon zalezny od typu (pola tekstowe maja 2 qwordy wiecej)
```

Bajt `meta[0]` ma maly, dyskretny zbior wartosci - to kandydat na kod typu TDF:

```
0x05 (638x)  0x15 (334x)  0x02 (310x)  0x0a (249x)  0x17 (225x)
0x01 (218x)  0x14 (172x)  0x13 (163x)  0x18 (149x)  0x0e  (84x)
```

Przypisanie tych kodow do typow (varint / string / blob / struct / list /
map / union / float) jest **otwarte** - rozstrzygniemy je, porownujac
metadane z faktycznymi bajtami w przechwyconym pakiecie.

---

## 4. Ochrona binarki - **blokada analizy kodu**

Entropia sekcji obu plikow wykonywalnych:

| sekcja | entropia | stan |
| --- | --- | --- |
| `.text` | 1.000 | zaszyfrowana |
| `.data` | 1.000 | zaszyfrowana |
| `typeinfo` | 1.000 | zaszyfrowana |
| `fieldinf` | 1.000 | zaszyfrowana |
| `ctr` | 1.000 | zaszyfrowana (prawdopodobnie sam protektor) |
| `.rdata` | 0.579 | **czytelna** |

Konsekwencje:

1. **Statyczna analiza kodu odpada.** Skan instrukcji `lea rip+disp32`
   znalazl 15 trafien w 19 MB - czyli szum. Zeby czytac kod, trzeba by
   zrzucic pamiec procesu po odszyfrowaniu.
2. **Mapowanie klasa -> tablica pol odlozone.** Granice tablic sa
   zakodowane w kodzie, nie w danych. Mamy slownik tagow, ale nie wiemy,
   ktore pola naleza do ktorej klasy. Do odzyskania z ruchu albo ze zrzutu
   pamieci.
3. **Patchowanie exe jest drogie.** Tym bardziej oplaca sie podejscie
   z certyfikatem zastepczym, ktore nie rusza binarki.
4. Dane zostaly czytelne, wiec caly powyzszy dorobek jest wazny.

---

## 5. Handshake SSL redirectora - **potwierdzony**

Sonda `proto-lab/ssl_probe.py` przeciw `159.153.51.18:42127` - redirector
nadal zyje mimo wylaczenia gry online. Recznie sklecony ClientHello, i w
wersji SSLv3, i w TLS 1.2, dostaje pelna sekwencje
`ServerHello -> Certificate -> ServerHelloDone` (ogon rekordu to
`16 03 03 00 04 0e 00 00 00` - ServerHelloDone). To odpowiada na pytania
otwarte 1-3.

### Certyfikat redirectora - wzor dla zamiennika

```
subject   C=US, ST=California, O=Electronic Arts, Inc.,
          OU=Global Online Studio, CN=gosredirector.ea.com
issuer    CN=OTG3 Certificate Authority, C=US, ST=California,
          L=Redwood City, O=Electronic Arts, Inc.,
          OU=Online Technology Group, emailAddress=dirtysock-contact@ea.com
waznosc   2015-05-07 .. 2035-05-02   (wg daty wciaz wazny)
serial    0x03C2
podpis    md5WithRSAEncryption, klucz 1024-bit
```

Dwa fakty przesadzaja o strategii:

1. **CN to `gosredirector.ea.com`, nie `...online.ea.com`.** Jeden certyfikat
   obsluguje cala tablice srodowisk z sekcji 1, wiec stary ProtoSSL nie robi
   scislego dopasowania hosta. Nasz **cert zastepczy** ma miec dokladnie ten CN.
2. **Podpis MD5-RSA, 1024 bity, wystawca to wewnetrzne EA "OTG3 CA".** Stary
   ProtoSSL nie weryfikuje lancucha do zaufanego CA, wiec **serwer zastepczy
   moze przedstawic wlasny, samodzielnie podpisany cert z tym samym CN** -
   generujemy go z wlasnym kluczem. Nie potrzebujemy - i nie mamy - klucza
   prywatnego EA; to tozsamosc naszego wlasnego serwera, nie podszywanie sie
   pod dzialajaca usluge (usluga EA jest wylaczona). Ostateczny test to podanie
   go zywemu klientowi.

### Wybrany szyfr i wersja (z `.bin` przez `parse_records`)

Wszystkie trzy sondy dostaly ten sam ServerHello:

| sonda | wersja serwera | wybrany szyfr |
| --- | --- | --- |
| SSLv3   | SSLv3   | `TLS_RSA_WITH_AES_256_CBC_SHA` (0x0035) |
| TLS 1.0 | TLS 1.0 | `TLS_RSA_WITH_AES_256_CBC_SHA` (0x0035) |
| TLS 1.2 | TLS 1.2 | `TLS_RSA_WITH_AES_256_CBC_SHA` (0x0035) |

Trzy wnioski:

- **Serwer odbija wersje klienta**, nie wymusza swojej. Realna wersja
  handshake'u zalezy wiec od tego, co zaoferuje gra - do ustalenia
  `tcp_proxy.py` na zywym kliencie.
- **Wymiana kluczy to RSA** (brak ServerKeyExchange, brak ECDHE/forward
  secrecy). To najlepszy przypadek dla certu zastepczego: klient szyfruje
  premaster naszym kluczem publicznym z certu, a my odszyfrowujemy go swoim
  prywatnym - nic tu nie wymaga klucza prywatnego EA.
- Serwer wybral AES-256-CBC-SHA, choc nasza lista zaczynala sie od RC4 -
  **RC4 nie jest potrzebny**. Minimalny serwer musi umiec: RSA kx +
  AES-256-CBC + HMAC-SHA1.

### Zywy klient - potwierdzone proxy (Tor A)

`proto-lab/tcp_proxy.py` miedzy gra a prawdziwym EA (`159.153.51.18:42127`),
sesja `120822-003`. **Klient laczy sie i przechodzi caly handshake** - pytanie
otwarte 1 rozstrzygniete. Jego ClientHello:

- warstwa rekordu: **SSLv3** (`0x0300`), wersja w ciele ClientHello: **TLS 1.1**
  (`0x0302`). Typowe dla DirtySDK/ProtoSSL - stary stos owinięty w rekord SSLv3.
- oferowane szyfry (4): `RC4_128_SHA`, `RC4_128_MD5`, `AES_128_CBC_SHA`,
  `AES_256_CBC_SHA`. Serwer wybral `AES_256_CBC_SHA` - zgodnie z sondami.
- po handshake klient od razu slal `ApplicationData` (256 B) - to pierwszy
  zaszyfrowany pakiet Blaze. Proxy pasywne go nie odczyta; do tego potrzebny
  serwer zastepczy terminujacy TLS wlasnym certem (Tor B).

Cel terminatora jest wiec ustalony: **TLS 1.1 (0x0302), RSA kx,
AES-256-CBC-SHA**. RC4 pomijamy. Uwaga w ServerHello EA: 8 ostatnich bajtow
losowosci to sentinel `DOWNGRD\x00` (ochrona przed downgrade) - nasz serwer
nie musi go odtwarzac, stary klient go ignoruje.

---

## 6. Otwarte pytania

Kolejnosc = kolejnosc rozstrzygania.

1. ~~**Czy klient nadal probuje sie polaczyc?**~~ **TAK, rozstrzygniete
   (sekcja 5).** Zywy klient laczy sie z redirectorem przez `hosts` i wykonuje
   pelny handshake TLS 1.1.
2. ~~**SSLv3 czy nowszy TLS?**~~ **Rozstrzygniete (sekcja 5).** Klient oferuje
   TLS 1.1 (w rekordzie SSLv3) i szyfry RC4/AES; negocjuje sie
   `TLS_RSA_WITH_AES_256_CBC_SHA`.
3. **Czy klient przyjmie cert zastepczy?** *Narzedzie gotowe, czeka na test na
   zywym kliencie.* Research (sekcja 8) skorygowal zalozenie: stary ProtoSSL
   JEDNAK weryfikuje podpis certu, wiec zwykly self-signed zostalby odrzucony.
   `make_stub_cert.py` patchuje teraz DER - podmienia OID podpisu na
   `rsaEncryption` (bug Aim4kill/Bug_OldProtoSSL: iHashSize=0 -> memcmp
   przechodzi). Terminator `proto-lab/tls_terminator.py` poda ten cert i
   przeprowadzi handshake. Ostateczny test: `hosts` -> `127.0.0.1`, uruchomic
   terminator, wystartowac gre. Jesli klient odrzuci cert (Alert
   `bad_certificate`) - sprobowac patchu tylko zewnetrznego OID / md5 zamiast
   sha256; dopiero potem hook DLL (drogie przy zaszyfrowanej binarce).
4. **Framing: Fire czy Fire2?** Ustalimy z pierwszego pakietu po handshake.
5. **Numery komponentow i komend** dla Rivals.
6. **Kody typow TDF** (mapowanie `meta[0]` na typ).
7. **Czy ruch rozgrywki jest szyfrowany** kluczem z Blaze. Najwieksze
   ryzyko projektu, odpowiedz dopiero w fazie 2.

---

## 7. Zrodla zewnetrzne

- [Aim4kill/Bug_OldProtoSSL](https://github.com/Aim4kill/Bug_OldProtoSSL) - bug weryfikacji certyfikatu w starym ProtoSSL
- [jacobtread/tdf](https://github.com/jacobtread/tdf), [blaze-ssl](https://github.com/jacobtread/blaze-ssl) - biblioteki Rust
- [PocketRelay/Server](https://github.com/PocketRelay/Server) - wzorzec architektury + [tunelowanie NAT](https://jacobtread.com/blog/pocket-relay-tunnel/)
- [grid-leak/blaze](https://github.com/grid-leak/blaze) - Blaze dla Mirror's Edge Catalyst
- [open-ds2-server](https://github.com/lowlevelmetal/open-ds2-server) - notatki o przeplywie polaczenia

---

## 8. Tor B - serwer terminujacy TLS (zbudowany, smoke-test OK)

Cel: zobaczyc pierwszy pakiet Blaze otwartym tekstem. `proto-lab/tls_terminator.py`
prowadzi wlasny handshake, odszyfrowuje premaster naszym kluczem prywatnym i
zrzuca `ApplicationData` do `docs/recon/capture/blaze-first-*.bin`.

### Korekta zalozenia: ProtoSSL JEDNAK weryfikuje podpis

Pierwotnie zakladalismy, ze stary ProtoSSL nie sprawdza podpisu i wystarczy
zwykly self-signed. Research ([Aim4kill/Bug_OldProtoSSL](https://github.com/Aim4kill/Bug_OldProtoSSL))
pokazal inaczej: parser **porownuje hasz podpisu** (`memcmp` po `iHashSize`
bajtach), wiec zwykly self-signed **zostalby odrzucony**. Obejscie to bug: gdy
OID algorytmu podpisu w certyfikacie ustawic na `rsaEncryption`
(`2a 86 48 86 f7 0d 01 01 01`, ASN_OBJ_RSA_PKCS_KEY), parser trafia w galaz
`default`, ustawia `iHashSize = 0`, a wtedy `memcmp(...,0) == 0` - weryfikacja
przechodzi bez sprawdzania. Testowane pierwotnie na BF3/BF4 (Frostbite 2013, ta
sama generacja DirtySDK co Rivals). `make_stub_cert.py` robi ten patch na DER
(podmienia oba wystapienia OID, dlugosc bez zmian) i zapisuje `pki/server.der`.

### RC4 zamiast AES

EA negocjowalo AES-256-CBC-SHA, ale klient **oferowal tez `RC4_128_SHA`**
(sekcja 5, Tor A). Nasz serwer wybiera RC4 - klient to przyjmie. RC4 nie ma IV
ani paddingu, wiec ochrona rekordow (RC4 + HMAC-SHA1 na tekscie jawnym) jest
trywialna. To samo uproszczenie stosuje [jacobtread/blaze-ssl](https://github.com/jacobtread/blaze-ssl).

### Parametry i weryfikacja

- Negocjacja: ServerHello `0x0302`, szyfr `0x0005`, brak session id, kompresja
  null; RSA kx; PRF TLS 1.0/1.1 (P_MD5 XOR P_SHA1); MAC HMAC-SHA1.
- Krypto czysto w Pythonie (RC4, PRF, RSA-decrypt PKCS#1v1.5) - bez zaleznosci;
  klucz `(n, d)` z `openssl rsa -text`. (Plan zakladal `cryptography`, ale nie
  jest w env - pure-Python jest spojniejsze z reszta proto-lab.)
- **Smoke-test** (klient testowy w czystym Pythonie, mirror handshake'u):
  Finished w obie strony `verify_data` OK, `ApplicationData` odszyfrowany 1:1.
  Caly tor kryptograficzny potwierdzony. Czego test nie obejmuje: czy PRAWDZIWY
  ProtoSSL przyjmie patchowany cert i uzyje dokladnie tej krypto - to test na
  zywym kliencie (pytanie otwarte 3).
