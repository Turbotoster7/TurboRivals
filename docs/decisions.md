# Dziennik decyzji i odkryc

Zapis tego, co probowalismy i czego sie dowiedzielismy - zeby nie wracac
do slepych uliczek.

---

## 2026-09-06 - faza 0, rekonesans

### Punkt wyjscia

Serwery NFS Rivals zgasly 7 pazdziernika 2025. Nie istnieje zaden publiczny
projekt przywracajacy je do zycia (sprawdzone: GitHub, fora NFS, Steam
Discussions). Istnieja emulatory Blaze dla BF3/BF4, Mass Effect 3,
Mirror's Edge Catalyst, Dead Space 2 i Skate 3 - to nasze wzorce.

**Ograniczenie definiujace projekt:** skoro serwery sa martwe, nikt juz nie
nagra ruchu serwer->klient. Nie robimy "podsluchaj i odtworz", tylko
"prowokuj klienta i rekonstruuj odpowiedzi".

### Co poszlo lepiej, niz zakladal plan

Plan zakladal, ze binarka bedzie pomocnicza - w praktyce okazala sie
glownym zrodlem. Sekcja `.rdata` zawiera pelne tablice metadanych TDF:
tag protokolu lezy w pamieci tuz obok nazwy pola.

Sciezka odkrycia:

1. `dump_strings.py` pokazal 511 stringow ze slowem "Blaze" i komplet nazw
   typow TDF (`Blaze::GameManager::CreateGameRequest` itd.).
2. Nazwy pol (`mBlazeId`) mialy po ~75 wskaznikow z `.rdata` - czyli lezaly
   w tablicach, a nie w kodzie.
3. Zrzut sasiedztwa pokazal rekordy o kroku 24 bajtow: 8 bajtow metadanych,
   wskaznik na nazwe, ogon.
4. Zastosowanie znanego z BlazeSDK kodowania tagow (4 znaki po 6 bitow) do
   bajtow 1..3 metadanych dalo pary `BID `->`mBlazeId`, `MAIL`->`mEmail`,
   `PASS`->`mPassword`. Zgodnosc semantyczna wyklucza przypadek.
5. `extract_tdf_meta.py` wyciagnal 2 864 pary i 1 152 unikalne tagi.

Efekt: przechwycone pakiety bedziemy czytac z nazwami pol, zamiast zgadywac.

### Slepa uliczka: statyczna analiza kodu

Proba zmapowania klas TDF na ich tablice pol przez skan instrukcji
`lea r64, [rip+disp32]` zwrocila 15 trafien w 19 MB kodu - czyli nic.

Powod: **sekcja `.text` jest zaszyfrowana**. Entropia 1.000, rozklad bajtow
idealnie rownomierny, brak typowych wzorcow x64. To samo dotyczy `.data`,
`typeinfo` i `fieldinf`. Obecna jest nietypowa sekcja `ctr` - prawdopodobnie
sam protektor. Dotyczy obu plikow (`NFS14.exe` i `NFS14_x86.exe`).

`.rdata` pozostala czytelna, wiec dorobek z metadanych jest wazny.

Wnioski:

- mapowanie klasa -> pola wymaga zrzutu pamieci procesu po odszyfrowaniu;
  odkladamy to, bo z zywego ruchu mozemy dostac to samo taniej,
- patchowanie exe (plan B dla SSL) jest drogie - tym mocniej stawiamy na
  certyfikat zastepczy, ktory binarki nie rusza.

### Niespodzianka: NAT do zaemulowania

W binarce jest doslowny format zapytania do demanglera:

```
http://%s:%d/getPeerAddress?myIP=%s&myPort=%d&version=1.0
```

Czyli NAT punch-through EA to zwykle API HTTP. Faza 5 (dzialanie bez VPN)
jest wyraznie tansza, niz zakladal plan - nie trzeba pisac wlasnego relaya
UDP, wystarczy odtworzyc ten serwis.

### Decyzje

- **Kolejnosc rozstrzygania**: najpierw czy klient w ogole nawiazuje
  polaczenie, potem jaka wersja SSL, dopiero potem framing i komendy.
  Kazdy krok tanszy od poprzedniego, gdy poprzedni odpadnie.
- **`hosts` zamiast DNS**: proste, odwracalne, nie wymaga infrastruktury.
  Skrypt trzyma wpisy w oznaczonym bloku i robi kopie zapasowa.
- **Przekierowujemy na start tylko `gosredirector.online.ea.com`**.
  Kazdy dodatkowy wpis to dodatkowa zmienna przy diagnozie.

---

## 2026-09-06 - faza 1, handshake SSL redirectora

### Sonda potwierdzila, ze redirector zyje

`ssl_probe.py` przeciw `159.153.51.18:42127` dostaje pelny
`ServerHello -> Certificate -> ServerHelloDone` i dla SSLv3, i dla TLS 1.2.
Nie musimy czekac na klienta, zeby poznac parametry SSL - serwer sam je
zdradza. Rozstrzyga to pytania otwarte 2 i 3.

### Kluczowe: certyfikat jest podatnej klasy

Rozbior certyfikatu (`strings` + `openssl x509`):

- podpis **md5WithRSAEncryption**, klucz **1024-bit** - z hexdumpu OID
  `1.2.840.113549.1.1.4` i 129-bajtowy podpis (`03 81 81 00`),
- wystawca: wewnetrzne EA **OTG3 Certificate Authority**,
- subject CN: **`gosredirector.ea.com`** (nie `...online.`), jeden cert na
  cala tablice srodowisk,
- waznosc do 2035-05-02, wiec wg daty wciaz wazny.

To konfiguracja, w ktorej stary ProtoSSL nie weryfikuje lancucha do zaufanego
CA. **Wniosek dla strategii: nie potrzebujemy klucza prywatnego EA.** Nasz
serwer zastepczy przedstawia wlasny, samodzielnie podpisany **cert zastepczy**
o CN `gosredirector.ea.com` - to tozsamosc naszego serwera, nie podszywanie
sie pod dzialajaca usluge (usluga EA jest wylaczona od 2025-10-07). Podejscie
to nie rusza zaszyfrowanej binarki.

### Nazewnictwo (decyzja)

Nie piszemy "podrobiony/sklonowany cert" - to mylace ramy. Uzywamy
**"certyfikat zastepczy"** / **"serwer zastepczy"**: stawiamy wlasny serwer
zastepujacy wylaczona usluge, do ktorego laczy sie nasz wlasny, legalnie
kupiony klient. Zadnego lamania zabezpieczen ani redystrybucji plikow gry.

### Tor A - proxy potwierdzilo strone klienta

`tcp_proxy.py` miedzy gra a EA (sesja `120822-003`): **klient laczy sie i
robi pelny handshake** (pytanie otwarte 1 - TAK). Oferuje TLS 1.1 w rekordzie
SSLv3, szyfry RC4+AES; negocjuje `AES_256_CBC_SHA`. Zaraz po handshake slal
zaszyfrowany `ApplicationData` (256 B) - pierwszy pakiet Blaze, ktorego proxy
pasywne nie odczyta. Cel terminatora: **TLS 1.1, RSA kx, AES-256-CBC-SHA**.

### Co zostaje do zrobienia

- ~~Odczytac wybrany szyfr z `.bin`.~~ Zrobione: `TLS_RSA_WITH_AES_256_CBC_SHA`
  (RSA kx, AES-256-CBC, HMAC-SHA1). RC4 niepotrzebny; przy RSA kx cert
  zastepczy wystarczy do odszyfrowania premastera.
- ~~Sprawdzic, czy klient inicjuje polaczenie.~~ Zrobione w Torze A: tak.
- Zbudowac **cert zastepczy** (`make_stub_cert.py`) i serwer terminujacy TLS,
  potem podac go zywemu klientowi (pytanie otwarte 3, test ostateczny) - da
  pierwszy odszyfrowany pakiet Blaze.

---

## 2026-09-06 - faza 1, Tor B: terminator TLS zbudowany i przetestowany

### Research zmienil dwa zalozenia

1. **Self-signed nie wystarczy - trzeba patchu OID.** Zakladalismy, ze stary
   ProtoSSL nie weryfikuje podpisu. Nieprawda: parser robi `memcmp` po haszu.
   Bug [Aim4kill/Bug_OldProtoSSL](https://github.com/Aim4kill/Bug_OldProtoSSL):
   OID podpisu = `rsaEncryption` -> galaz `default` -> `iHashSize = 0` ->
   `memcmp(...,0)==0` -> weryfikacja przechodzi. `make_stub_cert.py` patchuje
   teraz DER (oba wystapienia OID `sha256WithRSA` -> `rsaEncryption`, dlugosc
   bez zmian), zapisuje `pki/server.der`. Potwierdzone: `openssl x509 -text`
   pokazuje `Signature Algorithm: rsaEncryption`.
2. **RC4 zamiast AES.** Klient oferowal `RC4_128_SHA`; nasz serwer go wybiera.
   RC4 (brak IV/paddingu) upraszcza ochrone rekordow do RC4 + HMAC-SHA1. Tak
   samo robi jacobtread/blaze-ssl. AES-CBC niepotrzebny.

### Decyzja implementacyjna: pure-Python, bez `cryptography`

Plan zakladal `cryptography` do RSA-decrypt, ale nie ma go w env. Zamiast
dokladac zaleznosc - RSA-decrypt (PKCS#1v1.5), RC4 i PRF sa czysto w Pythonie,
spojnie z reszta proto-lab (ssl_probe tez recznie sklada TLS). Klucz `(n, d)`
wyciagany raz przez `openssl rsa -text`. Terminator reuzywa `hexdump`/
`parse_records` z `tcp_proxy.py`.

### Smoke-test przeszedl

Wlasny klient testowy (mirror handshake'u w czystym Pythonie) przeciw
`tls_terminator.py`: **Finished w obie strony `verify_data` OK**, `ApplicationData`
odszyfrowany 1:1. Caly tor kryptograficzny (RSA-decrypt premastera, PRF TLS
1.0/1.1, keyblock, RC4, MAC, sekwencjonowanie CCS) potwierdzony bez zywego
klienta.

### Co zostaje: jedyny test, ktorego nie da sie zrobic bez gry

Czy PRAWDZIWY ProtoSSL Rivals przyjmie patchowany cert i uzyje tej krypto -
pytanie otwarte 3, rozstrzygane dopiero podaniem certu zywemu klientowi
(`hosts` -> `127.0.0.1`, uruchomic terminator, wystartowac gre). Sukces =
powstaje `blaze-first-*.bin` z czytelnym pierwszym pakietem Blaze.
