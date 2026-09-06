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
   z podrobionym certyfikatem, ktore nie rusza binarki.
4. Dane zostaly czytelne, wiec caly powyzszy dorobek jest wazny.

---

## 5. Otwarte pytania

Kolejnosc = kolejnosc rozstrzygania.

1. **Czy klient nadal probuje sie polaczyc?** Serwery sa martwe; DNS moze
   juz nie rozwiazywac. Wpis w `hosts` to obchodzi.
2. **SSLv3 czy nowszy TLS?** Decyduje o tym, czy minimalna implementacja
   SSLv3 + RC4 wystarczy. Odpowiedz da pierwszy ClientHello.
3. **Czy dziala bug ProtoSSL z certyfikatem?** Jesli nie - potrzebny hook
   DLL, co przy zaszyfrowanej binarce jest znacznie trudniejsze.
4. **Framing: Fire czy Fire2?** Ustalimy z pierwszego pakietu po handshake.
5. **Numery komponentow i komend** dla Rivals.
6. **Kody typow TDF** (mapowanie `meta[0]` na typ).
7. **Czy ruch rozgrywki jest szyfrowany** kluczem z Blaze. Najwieksze
   ryzyko projektu, odpowiedz dopiero w fazie 2.

---

## 6. Zrodla zewnetrzne

- [Aim4kill/Bug_OldProtoSSL](https://github.com/Aim4kill/Bug_OldProtoSSL) - bug weryfikacji certyfikatu w starym ProtoSSL
- [jacobtread/tdf](https://github.com/jacobtread/tdf), [blaze-ssl](https://github.com/jacobtread/blaze-ssl) - biblioteki Rust
- [PocketRelay/Server](https://github.com/PocketRelay/Server) - wzorzec architektury + [tunelowanie NAT](https://jacobtread.com/blog/pocket-relay-tunnel/)
- [grid-leak/blaze](https://github.com/grid-leak/blaze) - Blaze dla Mirror's Edge Catalyst
- [open-ds2-server](https://github.com/lowlevelmetal/open-ds2-server) - notatki o przeplywie polaczenia
