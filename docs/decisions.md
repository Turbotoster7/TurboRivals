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

---

## 2026-09-10 - QoS: zla hipoteza formatu, naprawiona dezasemblacja

### Objaw

Gra przechodzila cala sekwencje logowania (redirector -> preAuth z CONF+QOSS ->
ping -> login -> notyfikacje UserSessions -> postAuth) i **sama** wolala nasz
ping-site po HTTP: `GET /qos/qos?vers=1&qtyp=1&prpt=3659`. Odpowiedz odczytywala
w calosci (130 B, widac w hookach `recv`), ale **nie wysylala ani jednej sondy
UDP** - dalej tylko `Util.ping`, ekran "Laczenie".

### Co bylo zle

Klucze `.numprobes`, `.probesize`, `.qosport`, `.requestid`, `.reqsecret`
wyciagniete ze stringow binarki sa prawdziwe, ale zinterpretowalismy je jako
pary `klucz=wartosc` w formacie TagField (`qos.numprobes=1 qos.probesize=64 ...`).
To byl domysl z nazwy funkcji, nie z kodu.

Dezasemblacja rozstrzygnela: funkcja brana za `TagFieldFind` (`0xfee910`) to
**`XmlFind`** z `xmlparse` DirtySDK. Dowod w samym kodzie: skanuje do znaku `<`,
pomija `<?..?>` i `<!..>`, przerywa na `</`, a maska dopuszczalnych terminatorow
nazwy to `0x40008001FFFFFFFF` = `{0x00-0x20, '/', '>'}` - **nie ma w niej `=`**,
wiec dopasowywane sa nazwy ELEMENTOW, a nie klucze przypisan ani atrybuty.
Towarzyszaca jej `0xfee6a0` to `XmlContentGetInteger` (po `<` skacze do `>`).

Nasza odpowiedz nie zawierala ani jednego `<`, wiec wszystkie trzy `XmlFind`
(`"firewall"`, `"firetype"`, `"qos"`) zwracaly NULL i
`_QosApiParseResponse` @`0xfdb070` konczyl sie kodem `-2`, nie robiac nic. Stad
cisza na UDP przy poprawnie odczytanej odpowiedzi.

### Wniosek metodyczny

Dwa razy z rzedu (uklad `QosConfigInfo` wziety z BF3, teraz format odpowiedzi
QoS) kosztowal nas domysl przez analogie. Zrzut pamieci z odszyfrowana `.text` +
capstone daja odpowiedz w kilka minut - **gdy istnieje kod do przeczytania, nie
zgadujemy**. Ta sama zasada dala przy okazji numery komend UserSessions z
tablicy skokow `getCommandName` (`updateNetworkInfo` = `0x14`), zamiast czekac,
az komenda pojawi sie w logu jako "brak handlera".

### Zmiany

- `_qos_body` w `tls_terminator.py` odpowiada teraz XML-em dla `/qos/qos`,
  `/qos/firetype`, `/qos/firewall`; `Content-Type: text/xml`. Flagi A/B:
  `--qos-numprobes`, `--qos-probesize`, `--qos-firetype`.
- `hook_origin.js`: hook na `0xfdb070` wypisuje bufor odpowiedzi i kod powrotu
  (`0` / `-1` / `-2`) oraz odczytany stan QoS - diagnoza bez domyslow.
- `_dispatch_blaze`: puste potwierdzenia dla `0x7802` cmd `0x14`
  (updateNetworkInfo), `0x08` (updateHardwareFlags), `0x1A`
  (setUserInfoAttribute).
- Format, reguly walidacji, uklad sondy UDP i tablica komend: `docs/protocol.md`
  sekcja 9.

### Czego ta zmiana nie przesadza

Responder UDP zostaje zwyklym echem - z kodu wynika, ze to wystarcza (odbior
sondy porownuje `requestid`/`reqsecret`/`numprobes` odczytane z pakietu, a echo
zwraca je niezmienione), ale **nie bylo jeszcze testowane na zywo**. Nieznana
zostaje tez semantyka `<firetype>` (typ NAT): wartosc trafia do `[conn+0x1b0]`,
a `== 5` wylacza callback, wiec 5 to sentinel "nieznany"; domyslnie odsylamy 1.

### Uzupelnienie tego samego dnia - sonda UDP tez nie jest echem

Po przejsciu XML-a gra **wyslala sondy UDP** (`QosApiParseResponse = 0`,
potwierdzone hookiem), ale nadawala cztery identyczne sondy co ~1 s i ponawiala
`GET /qos/qos` - czyli odrzucala nasze odpowiedzi. Przyczyna w tym samym
odbiorniku: `0xfdb777` wymaga **`len >= 0x1e` (30 B)**, a odbijalismy 20 B
sondy. Dalej kod czyta z odpowiedzi zewnetrzny IP (`+0x14`) i port (`+0x18`)
klienta oraz dlugosc ogona (`+0x1a`) - pol, ktorych w echu fizycznie nie ma.

Korekta wczesniejszego wpisu: teza "echo bajt w bajt spelnia wszystkie warunki"
byla sluszna tylko dla sciezki pasma (`ntohl(+0x04) >= 2`), gdzie kod porownuje
requestid/reqsecret i zlicza bajty. Sciezka latencji, ktorej gra uzywa przy
`qtyp=0`, wymaga zbudowania odpowiedzi. Wniosek do zapamietania: **zanim uznam
echo za wystarczajace, mam przeczytac CALA sciezke odbioru, nie tylko miejsce,
w ktorym porownywane sa pola, ktore znam.**

---

## 2026-09-12 - blokada przeniosla sie do bramki aktywacji EA (ActivationUI)

### Objaw

Do 2026-09-11 gra przechodzila caly lancuch logowania do naszego Blaze (redirector
-> preAuth -> login tokenem z EA App -> notyfikacje -> postAuth -> QoS), a jedynym
otwartym problemem bylo rozlaczenie + access violation zaraz po naszej odpowiedzi
na postAuth. W przebiegu 2026-09-12 13:24 gra przestala w ogole dochodzic do menu:
po "Graj" w Steamie odpala sie `EASteamLauncher` -> `Core/ActivationUI.exe` (bramka
aktywacji EA, Qt, korzysta z `Core/Activation.dll`/`Activation64.dll`) i pokazuje
okno logowania/aktywacji. `NFS14.exe` startuje (Frida lapie proces, hook tokenu
`0xec3c80` sie zaklada), ale stoi za bramka - terminator nie widzi zadnego
polaczenia Blaze.

### Przyczyna (ze zrzutu ActivationUI)

Zrzut pamieci bezczynnego okna aktywacji zawiera blok srodowiska startowego, ktory
launcher EA podaje grze - a w nim `EAAuthCode=NeedsAFreshAuthCode`. EA App nie
zdobylo swiezego auth code (usluga `accounts.ea.com` zyje, w odroznieniu od
`gos.ea.com`), wiec ActivationUI nie potrafi zweryfikowac entitlementu i spada do
okna logowania. To jest PRZED calym Origin SDK / LSX, wiec zbudowane wstrzykiwanie
tokenu (hook w NFS14.exe) nie ma jak zadzialac, dopoki gra nie ruszy. `hosts`
przekierowuje tylko `gosredirector.ea.com`, wiec to nie my blokujemy accounts.ea.com.

### Wniosek dla dalszej pracy - gra sama NIE waliduje entitlementu

Z calego bloku zmiennych EA* `NFS14.exe` ma w sobie JAKO STRING tylko
`EALaunchOfflineMode` (`tools/xref.py --str`, brak odwolan `lea` - uzywane przez
wskaznik/tabele). Reszte (`EALaunchUserAuthToken`, `EALicenseToken`, `EAAuthCode`,
`EASecureLaunchTokenTemp`) konsumuje LAUNCHER, nie gra. Czyli entitlement waliduje
ActivationUI, a nie NFS14.exe. Stad Tor B: odpalic `NFS14.exe` bezposrednio z
odtworzonym srodowiskiem EA* (przy dzialajacym EA App dla LSX 3216), z pominieciem
ActivationUI - gra powinna pojsc prosto do LSX, gdzie hook `0xec3c80` podmienia
token. Prototyp: `proto-lab/launch_direct.py` (+ szablon `ea_launch_env.example.txt`;
`ea_launch_env.txt` z sekretami jest gitignore).

### Zmiany w tej sesji

- `proto-lab/frida_run.py`: domyslny `--settle` = 8 s. W przebiegu 13:24 kilka
  hookow padlo z "unable to intercept function" (`0xebd140`, `0xebd800`, `0xf66220`,
  `0xf8a0d0`) - `.text` gry jest szyfrowana i nie byla jeszcze rozpakowana, gdy
  Frida podpiela sie tuz po starcie procesu. `replace` na `0xec3c80` (token) i
  `0xec1880` (IsCoreConnected) zaladowaly sie mimo to.
- `proto-lab/launch_direct.py`: nowy launcher Tora B (opis wyzej).

### Sekrety - swiadoma decyzja

Zrzuty ActivationUI zawieraja ZYWY JWT konta EA (`EALaunchUserAuthToken`) i sesyjne
tokeny. Repo jest docelowo publiczne, wiec do `docs/` idzie architektura i NAZWY
zmiennych, a wartosci sekretow sa zredagowane (placeholder `<...>`). Oba pliki
zrzutu usuniete po wyciagnieciu findings.

---

## 2026-09-13 - zerwanie Blaze: wartosci czasu w CONF bez jednostek

### Objaw

Odkad CONF w preAuth jest niepusty (2026-09-09), klient zrywa polaczenie Blaze
bledem `0x800e0000` w ciagu sekund: w run-13 zaraz po postAuth, w run-14 (trzy
proby) juz po preAuth, zanim zdazyl wyslac login. Hook stanu pokazywal za kazdym
razem `[conn+0x2fc]=0`, czyli prog bezczynnosci. 2026-09-07, przy pustym CONF, to
samo polaczenie zylo 50 minut na samych pingach.

### Przyczyna (dezasemblacja zrzutu)

Warunek zerwania w `0xf3a580` to "cisza > `[conn+0x2fc]` ms". Pole zapisuja tylko
konstruktor (40000) i czytnik configu `0xf419b0` (`wartosc/1000`). Czytnik bierze
wartosc przez getter `0xf39dc0`, a ten przez parser TimeValue `0xf79d60`, ktory
wymaga jednostki (`90s`, `15000ms`, `1m`). My wysylalismy `"90"`: parser zwraca
false i nic nie zapisuje, getter ten wynik ignoruje i melduje "znaleziony", wiec
czytnik zapisuje 0. To samo dotyczylo `defaultRequestTimeout="30"` (timeout RPC 0 ms).
Format opisany w `protocol.md`, sekcja 11.

### Falszywe tropy po drodze

- "Keepalive od serwera" (2026-09-12): klient nie czekal na ruch, mial prog 0 ms,
  wiec zaden ping by nie zdazyl.
- "Klient nie znajduje klucza, format mapy zly": mapa jest dobra i klucz jest
  znajdowany. Zly byl format WARTOSCI. Nasz round-trip enkoder/dekoder tego nie
  wykryje, bo sprawdza tylko nasz wlasny format, nie semantyke u konsumenta.

### Zmiany

- `blaze.DEFAULT_CLIENT_CONFIG`: `connIdleTimeout=90s`, `defaultRequestTimeout=30s`,
  `pingPeriod=15s`.
- `hook_origin.js`: hooki gettera `0xf39dc0` (klucz, wynik w us), parsera `0xf79d60`
  (tekst -> OK/BLAD) i migawka pol polaczenia w `0xf3a580` (loguje tylko zmiany).

### Otwarte

Hook na wejsciu `0xf419b0` nie wypisal w run-14 nic, choc to jedyny zapis zera do
`[conn+0x2fc]` poza konstruktorem. Hooki gettera i parsera pokaza wprost, czy i kiedy
czytnik dziala.

Wniosek do zapamietania: **wartosci wysylane klientowi sprawdzamy u konsumenta
(parser w kodzie), nie tylko round-tripem naszego enkodera.**

### Wynik - run-15 (12:53), fix POTWIERDZONY

- Parser przyjal wartosci: `'15s' -> 15000000 us`, `'30s' -> 30000000 us`,
  `'90s' -> 90000000 us`. Getter czyta klucze w kolejnosci pingPeriod ->
  defaultRequestTimeout -> connIdleTimeout (dokladnie jak `0xf419b0`), a migawka
  polaczenia pokazuje `idle[+0x2fc]=90000ms req[+0x1c4]=30000ms`.
- Drugie polaczenie Blaze przeszlo preAuth -> ping -> login 1/152 -> notyfikacje ->
  postAuth 9/8, a klient **po raz pierwszy zdekodowal nasza odpowiedz postAuth**
  (`PostAuthResponse` `0xf211e0`) i NIE zamknal polaczenia. Potem pingi 9/2 co ok.
  15 s, polaczenie ESTABLISHED, zero wyjatkow, brak wpisu crasha w Event Log.
- Pierwsze polaczenie w tym przebiegu i tak zerwalo sie (`0x800e0000`,
  `prog=90000`). Gra nie byla restartowana po run-14, a migawka na starcie
  pokazywala `idle=0ms` - obiekt polaczenia mial stary prog zero do chwili
  przyjscia nowego configu. Najpewniej pozostalosc; do sprawdzenia na swiezym procesie.
- Hook na wejsciu `0xf419b0` znow nic nie wypisal, choc czytnik wyraznie dziala
  (sekwencja kluczy z gettera). Przyczyna nieznana, dla diagnozy juz nieistotna.
- Na swiezym procesie gry (13:00) juz PIERWSZE polaczenie przechodzi login i postAuth
  i zyje (idle 40000 -> 90000 ms po preAuth). Zerwanie pierwszej proby wyzej bylo
  wiec pozostaloscia po run-14.

### Crash 12:59:58 - to Frida, nie gra

Event Log wskazuje `frida-agent.dll`, kod `0xc0000409` (fail-fast 7 = `abort()`),
offset `0xfc891d`. Identyczny podpis ma zgon z 01:58:36 (proces run-12). Minidumpy
WER (`%LOCALAPPDATA%\CrashDumps\NFS14.exe.<PID>.dmp`) pokazuja, ze abortuje wlasny
watek agenta Fridy: na stosie tylko `frida-agent.dll` i start watku, zero ramek gry,
a na zadnym stosie nie ma pierwotnego rekordu wyjatku (`0xc0000005` itp.). Oba zgony
wypadly przy restartowaniu `frida_run.py` na dzialajacej grze, ktora miala Fride
podpinana wiecej niz raz. To korelacja, nie dowod.

Konsekwencje:
- Hook co klatke `0xf3a580` (migawka polaczenia) domyslnie wylaczony
  (`CONN_SNAPSHOT=false`) - swoje zadanie spelnil, a zmniejsza ryzyko przy odpinaniu.
- Przebieg konczymy, **zamykajac najpierw gre**, potem Fride i terminator.
- Przy kazdym crashu najpierw sprawdzic w Event Log modul (id 1000): `frida-agent.dll`
  to artefakt narzedzia, `NFS14.exe`/`unknown` to realny blad gry.

---

## 2026-09-13 (popoludnie) - "Logowanie": gra dostawala usera z ID=0

### Objaw

Po naprawie configu (run-15..19) login i postAuth przechodzily, sesja Blaze zyla, ale
na ekranie wisialo "Logowanie", a po postAuth gra wysylala tylko pingi.

### Jak to rozlozylismy

- Obserwator stanu menedzera online gry (`0xa1bb00`, stan w `[obj+0x20]`) pokazal
  2 -> 5 -> 6 i nigdy 9.
- Hooki zdarzen pokazaly, ze obiekt online gry to `BlazeStateEventHandler` (vtable
  `0x15cc938`: dtor, onConnected -> 6, onDisconnected, onAuthenticated -> 9,
  onDeAuthenticated, onIncompatibleServerVersion). Stan 6 to "polaczony" (onConnected
  po preAuth), a onAuthenticated nie przychodzilo nigdy.
- Notyfikacja UserAdded (`0x7802/2`) ma pola `DATA mExtendedData` i `USER mUserInfo`.
  W binarce jest klasa UserIdentification (`@0x1416d78c0`: AID ALOC EXBB EXID ID NAME
  ORIG PIDI). My wysylalismy w USER tagi UserSessionLoginInfo (BUID DSNM KEY ...), z
  ktorych zgadzal sie tylko ALOC - gra tworzyla lokalnego usera z `ID=0`.

### Zmiana i wynik (run-20)

`USER` = UserIdentification z `ID` = BlazeId z loginu. Wynik: onAuthenticated, stan
online gry 9 -> 10, inicjalizacja ByteVault i seria nowych RPC (userSettingsLoad,
getLists, Stats, komponent 2050).

### Falszywe tropy po drodze (zeby do nich nie wracac)

- Pusta notyfikacja UserAuthenticated (cmd 8) - wypelnilismy ja wg klasy z binarki
  (`@0x141a2f160`), ale sama nie zmienila zachowania.
- `0xf40570` to `Game::setGameState` (GameManager; wartosci 1, 4, 7, 8, 130, 131 to enum
  GameState), a nie stan logowania. Sloty thunkow dyspozytorow (`0xf6c5f0`, `0xefde70`)
  sa generyczne - numer slotu nie mowi, jaki to interfejs listenera.
- ByteVault i klucze `bytevault*` - nie blokowaly logowania (czytane dopiero po stanie 9).

### Blad znaleziony przy okazji - mapy musza byc posortowane

Lookup configu (`0xf39cb0`) szuka klucza binarnie w posortowanym wektorze. Klucze
`bytevault*` dopisane na koncu CONF byly przez to nieznajdowane i ByteVault poszedl
na domyslny host `bytevault.test.gameservices.ea.com`. `blaze.f_map_str` sortuje
teraz klucze.

### Zmiany w narzedziach

- `tls_terminator.py`: na RPC bez handlera domyslnie wysylamy puste potwierdzenie
  (err=0), zeby zapytanie gry sie konczylo; `--no-ack-unknown` wylacza. Flagi A/B:
  `--legacy-user-added`, `--empty-user-auth`, `--no-bytevault`.
- `hook_origin.js`: obserwator stanu online gry, hooki zdarzen listenera, lookup i
  getter configu, DNS przez `gethostbyname`, init ByteVault.

## 2026-09-13 (wieczor) - run-23: rozgrywka na naszym serwerze

### Wynik

Po odpowiedzi na `GameManager.createGame` (odpowiedz z `GID` + `NotifyGameSetup` z graczem
jako hostem) gra przeszla sama: `updateMeshConnection` -> `finalizeGameCreation` ->
`advanceGameState` PRE_GAME (130) -> IN_GAME (131). Jazda w otwartym swiecie, bez crasha,
bez Fridy. ByteVault (REST po HTTPS na porcie Blaze) dostal odpowiedzi i je przyjal.
Zmiana gry w trakcie (`leaveGameByGroup` -> nowy `createGame` -> `removePlayer` starej gry)
tez przeszla, choc na te komendy odpowiadamy samym potwierdzeniem.

### Co przyszlo w trakcie jazdy

- 429 raportow `GameReporting` (komponent 28, cmd 2) w ok. 2 minuty: Collectables,
  DistanceDriven*, Racer_Completed_Objective_*, CarCustomization, LicensesPart1/2. To stan
  postepu gracza - kandydat do zapisu po stronie serwera.
- `Util.filterForProfanity`, `NFS.getInGameSpeedWalls`, `UserSessions.lookupUsers`,
  `Authentication.listUserEntitlements2`, `NFS.getSpecialGuestInfo`,
  `NFS.getOverwatchStatsConfig`, `NFS.getAutologPlaylist`, `NFS.getInGameRecommendations`.
- Gra uzywa dwoch identyfikatorow: BlazeId z loginu i drugiego id (persona) w
  `listUserEntitlements2`, `lookupUsers` i naglowku `X-USER-ID` ByteVault. Skad bierze to
  drugie - nie ustalone.

### Nazwy komend z binarki

Emulacja 13 funkcji `getCommandName` na zrzucie pamieci daje pelne tablice numer -> nazwa
(Authentication, GameManager, Stats, Util, AssociationLists, NFS 2050, UserSessions, ByteVault,
Messaging, Playgroups oraz notyfikacje). Sa w `blaze._RPC_TABLES` i trafiaja do logu przez
`blaze.rpc_name()`. Komponent 28 nie ma tablicy nazw; nazwe GameReporting daje uklad klasy
zadania `{FNSH PRVT RPRT}` (`@0x141a32ad0`).

### Zmiany w narzedziach

- `tls_terminator.py`: nazwy komend w logu; znane RPC bez handlera bez hexdumpu; raporty 28
  jedna linia + potwierdzenie (surowe ramki zostaja w capture); `filterForProfanity` odsyla
  teksty z wynikiem `FILTER_RESULT_PASSED` (enum z `.rdata`, klient wysyla `UNPROCESSED` = 2);
  sesja HTTP konczy sie po `Connection: Close`.
- Zweryfikowane offline na ramkach run-23, nie na zywo.

## 2026-09-13 (wieczor) - zapis postepu gracza z raportow GameReporting

### Decyzja

Po run-24 (logowanie, swiat, zmiana kariery - wszystko dziala) wybralismy zapis postepu przed
multiplayerem, bo da sie go zrobic i sprawdzic w pojedynke.

### Co jest w raportach

Dekoder dostal typ `variable` (bajt obecnosci, id klasy, pola). Wszystkie 473 raporty z run-24
rozkladaja sie tak samo: `RPRT.GTYP` = kategoria + 8 znakow hex, a w `RPRT.GAME` mapa
`gracz -> {ENTI, STAI, STAF, STAS}` (id obiektu i mapy statystyk int/float/string).

Raporty niosa **stan**, nie przyrost - kolejne raporty `PlayerStats` powtarzaja te same liczby
(kupione auta, zlote medale, kredyty, rangi, postep shotlist). Zapisujemy wiec ostatnia wartosc
kazdej statystyki, a obok pelny dziennik raportow, zeby stan dalo sie odtworzyc na nowo, gdyby ten
model okazal sie zly.

Nazwy kategorii (poza `MetaData` i `VehicleStatisticsData`) nie wystepuja w kodzie - pochodza z
danych gry. Koncowki hex to najpewniej hashe (`0xaaa040`: sprintf nazwy + hash djb2a).

### Gdzie i jak

`proto-lab/player_store.py`, dane w `%LOCALAPPDATA%\TurboRivals\data` - poza repo i poza OneDrive
(podmiana pliku kilka razy na sekunde w synchronizowanym folderze grozi blokada pliku). Blad
parsowania lub zapisu nie wstrzymuje gry: potwierdzenie raportu idzie przed zapisem.

### Otwarte

Odczyt: gra pyta Stats tylko o grupy `MetaData` i `PlayerStats`. Zanim zaczniemy odsylac wartosci,
trzeba z kodu ustalic, jak klient mapuje wartosci `EntityStats.STAT` na nazwy - nie zgadujemy.
Id speed walli w `getInGameSpeedWalls` pokrywaja sie z `ENTI` z raportow, wiec wlasne wyniki da
sie podawac z zapisanego stanu.

### Poprawka po run-25: katalog danych

Zapis dzialal (465/465), ale plikow nie bylo pod `%LOCALAPPDATA%\TurboRivals`. Python ze Sklepu
Microsoft (`WindowsApps\python.exe`) wirtualizuje zapisy do AppData\Local i kieruje je do
`Packages\PythonSoftwareFoundation.Python.*\LocalCache`. Domyslny katalog to teraz
`~\TurboRivals\data` (katalog domowy nie jest wirtualizowany), a terminator wypisuje go na starcie.

## 2026-09-13 (wieczor) - speed walle z zapisanych wynikow

### Jak ustalilismy uklad

Automatyczne wiazanie tablic pol z nazwami klas zawiodlo (brak wskaznikow w danych, brak `lea` do
nazw w tych samych funkcjach). Zadzialaly stringi `Klasa::mPole` w binarce, np.
`InGameSpeedWallResponseRow::mStatsFlt` - nazwy pol wskazuja jedna tablice:

- `InGameSpeedWallResponseRow` = `{BLUS mBlazeUser, STAF mStatsFlt, STAI mStatsInt, STAS mStatsStr}`
- `InGameSpeedWallResponseSpeedWall` = `{ROWS mSpeedWall, SWID mSpeedWallId}`
- `{RILI, SPWA}`, brane wczesniej za odpowiedz speed walli, to `InGameRecommendationsResponse`.

Wiersz speed walla ma dokladnie te same mapy co wpis gracza w raporcie GameReporting, a id speed
walla to `ENTI` z raportu: serwer odsylal zapisane statystyki obiektu (fotoradar - `speed`, strefa
predkosci - `AverageSpeed`).

### Niepewnosc, ktora obchodzimy

`InGameSpeedWallResponse::mSpeedwalls` pasuje do dwoch tablic: lista pod tagiem `ROWS` albo `SPWA`.
Wysylamy oba pola z ta sama lista - dekoder klienta pomija tagi nieznane swojej klasie.

### Zmiany

`blaze.build_in_game_speed_walls_response`, mapy int/float, `PlayerStore.rows_for_entity`, handler
2050/20 w terminatorze (`--no-speed-walls` wraca do pustego potwierdzenia). Sprawdzone offline na
46 zapytaniach z run-25: 9 speed walli dostaje wiersze, wartosci zgodne z zapisanym stanem.

## 2026-09-13 (wieczor) - gra publiczna: matchmaking tworzy gre

### Objaw (run-26)

"Wyszukaj sesje" w grze konczylo sie samymi pingami. Gra wysylala `GameManager.leaveGameByGroup`, a
potem `GameManager.startMatchmaking` z trybem `MODE=3` (szukaj i utworz), czasem sesji 6000 ms i
regula `gameMembershipRule = Public`. Na oba odpowiadalismy pustym potwierdzeniem. Wynik matchmakingu
serwer dostarcza notyfikacja, wiec gra czekala bez konca.

### Co wzielismy z binarki

- `StartMatchmakingRequest` (stringi `StartMatchmakingRequest::m...`) - uklad zadania.
- Enum `MatchmakingResult` z tablicy `{nazwa, wartosc}`: `SUCCESS_CREATED_GAME=0` ...
  `SESSION_TIMED_OUT=3` ... `SESSION_ERROR_GAME_SETUP_FAILED=6`.
- `MatchmakingSetupContext {FIT MAXF MSID RSLT USID}` jako wariant 3 unii powodu setupu gry
  (kolejnosc tablic czlonkow; wariant 0 dziala od run-23 przy `createGame`).
- `NotifyMatchmakingFailed {MAXF MSID RSLT USID}`.

### Decyzja

Innych graczy na serwerze nie ma, wiec robimy to, co serwer w trybie "szukaj i utworz" robi przy
braku gier: tworzymy nowa gre z graczem jako hostem. Odpowiedz `{MSID}`, potem `NotifyGameSetup` z
kontekstem matchmakingu i wynikiem `SUCCESS_CREATED_GAME`. Parametry gry kopiujemy z zadania, a
regule `Public` zapisujemy jako atrybut gry (nazwa atrybutu przyjeta z `createGame`), zeby w
przyszlosci drugi gracz mogl te gre znalezc. `--mm-fail` wysyla zamiast tego porazke
`SESSION_TIMED_OUT` - do porownania, gdyby gra nie przyjela utworzonej gry.

### Otwarte

Prawdziwe "znajdz" (dolaczanie do gier innych graczy) wymaga wspolnej listy gier miedzy
polaczeniami - to juz multiplayer. Stara gra po `leaveGameByGroup` nie dostaje
`NotifyPlayerRemoved`/`NotifyGameRemoved`.

### Wynik (run-27)

Gra publiczna dziala: gra wyslala `startMatchmaking` zaraz po wejsciu, przyjela utworzona gre i
przeszla do IN_GAME (przy grze z matchmakingu klient pomija `updateMeshConnection` i
`finalizeGameCreation`). Speed walle z zapisanymi wynikami (fotoradar, strefa, skok) tez przyjete.
Na koncu przebiegu crash gry (wykonanie spod adresu stosu) - log serwera urwany przy otwartym
polaczeniu, wiec najpewniej ten sam problem gry przy utracie polaczenia z serwerem, tylko z innym
podpisem; minidump WER nie ma ramek NFS14, wiec nie da sie tego potwierdzic z samego zrzutu.
Uzytkownik potwierdzil pozniej, ze zamknal terminal przed gra.

## 2026-09-13 (wieczor) - serwer dla kilku graczy

### Dlaczego teraz

Tryb dla jednego gracza dziala od poczatku do konca, a uzytkownik testuje z kolega w tej samej
sieci. Serwer zakladal jednego gracza: stala tozsamosc, gry jako liczniki bez listy graczy,
notyfikacje tylko do wlasnego polaczenia i adres zewnetrzny `127.0.0.1` z QoS.

### Decyzje

- **Rejestr w osobnym module** (`proto-lab/lobby.py`): sesje i gry pod jedna blokada, a kazda
  sesja z wlasna blokada wysylki. `Wire.send_record` zmienia stan RC4 i licznik MAC, a
  notyfikacje do gracza B wysyla watek gracza A - bez blokady rekordy by sie przeplataly.
- **Tozsamosc po adresie IP.** Login niesie tylko token Origin, ktorego nie weryfikujemy i z
  ktorego nie odczytamy pelnego id. W LAN adres rozroznia komputery; gracz lokalny zachowuje
  BlazeId z EA App, pod ktorym jest zapisany jego postep. Nick EA drugiego gracza serwer
  poznaje z nazwy gry, ktora klient sam tworzy, i zapamietuje.
- **Matchmaking najpierw szuka, potem tworzy** - jak serwer w trybie `MODE=3`.
- **Adres zewnetrzny gracza lokalnego = adres komputera w sieci** (`--public-ip`, domyslnie
  wykryty). Bez tego host melduje `127.0.0.1` i kolega laczylby sie sam ze soba. Topologia
  gry to polaczenia bezposrednie; relay EA nie istnieje.
- **Notyfikacja o wyjsciu tylko dla pozostalych graczy.** W run-23..27 klient wychodzil z gry
  bez tej notyfikacji i dzialal; wyslanie jej o wlasnym wyjsciu grozi podwojnym sprzataniem gry.
- **Bez migracji hosta:** gdy host wychodzi (tez przy zmianie kariery), gra znika i pozostali
  dostaja `NotifyGameRemoved`.
- **Licencje DLC pominiete:** Steam Complete Edition ma DLC lokalnie, a w binarce nie ma tagow
  licencji, ktore dalo sie odeslac.

### Weryfikacja

Offline na ramkach run-27: dwie symulowane sesje (lokalna i z LAN) - utworzenie gry
publicznej, dolaczenie drugiego gracza z rosterem dwoch graczy, zakonczenie dolaczania po
`updateMeshConnection`, wyjscie, rozlaczenie hosta, solo `createGame` bez zmian, adresy QoS
per klient. Regresja zapisu postepu i speed walli. Test na zywo z drugim komputerem w toku.

## 2026-09-16 - multiplayer na zywo: run-38 do run-40

### Run-38 (20:51) - pierwsze udane dolaczenie

Drugi gracz po raz pierwszy wszedl do gry pierwszego. `startMatchmaking` dolaczajacego trafil
w `find_public_game`, mesh zestawil sie w obie strony (`STAT=2`), poszedl `addAdminPlayer`,
a w UI hosta pojawila sie ikonka kolegi "w garazu". Wczesniej (run-36/37) klient dolaczajacego
w ogole nie matchmakowal - wysylal `resetDedicatedServer` (4/25), na co nie bylo handlera.

Sesja rozpadla sie przy przejsciu z garazu do swiata: klient wyslal drugi `startMatchmaking`,
dostal NOWA gre, a `removePlayer` ze starej przyszedl klatke pozniej. Skutek: dwie gry zamiast
jednej i dwoch samotnych graczy.

### Run-39 (21:21) - zamiana rol i znaleziona przyczyna

Kluczowa zmiana metodyczna: **Frida na maszynie DOLACZAJACEGO** (do tej pory chodzila u hosta,
ktory niczego nie tracil). Dopiero to pokazalo mechanizm:

```
19:19:52.711  [mm-status] edx=2  SUCCESS_JOINED_EXISTING_GAME, obiekt gry 0xd3ab4680
19:19:59.542  [gra-utracona] rdx=0xd3ab4680 sledzona=0xd3ab4680 r8=0x80
19:19:59.610  [mm-ponow] licznik=1
19:20:01.210  [mm-status] edx=0  -> wlasna nowa gra
```

**6,83 s** od dolaczenia do zniszczenia obiektu gry po stronie klienta. W calym tym oknie
dolaczajacy wyslal 11 zadan - nie odpytywal, nie ponawial, czekal. To wyklucza brakujaca
ODPOWIEDZ na RPC. Ponowny matchmaking i wyjscie z gry sa SKUTKIEM utraty obiektu, nie przyczyna.

Slepa uliczka po drodze: `--mm-delay` (odroczenie decyzji matchmakingu, zeby zdazyl dojsc
`removePlayer`). Nie moglo zadzialac - klient wysyla `removePlayer` dopiero PO otrzymaniu wyniku
matchmakingu. Kod zostaje z domyslnym `0`; przyda sie, gdy klient kiedys wyjdzie z gry przed
szukaniem. Przy okazji doszedl handler `cancelMatchmaking` (4/14), wczesniej bez obslugi.

### Przyczyna

Serwer ustawial dolaczajacemu `ACTIVE_CONNECTED` tylko we wlasnym rejestrze i wysylal
`NotifyPlayerJoinCompleted` (4/30). To **dwie rozne notyfikacje**: 30 mowi "dolaczanie
zakonczone", a stan gracza niesie `NotifyGamePlayerStateChange` (4/116), ktorej nie wysylalismy
nigdy. Obiekt gracza u dolaczajacego zostawal w `ACTIVE_CONNECTING` i timeout sprawdzany po
wczytaniu swiata kasowal gre.

### Co wzielismy z binarki

`NotifyGamePlayerStateChange` @0x141a30660 `{GID mGameId, PID mPlayerId, STAT mPlayerState}` -
klasa wyodrebniona z `tdf_members.json` miedzy `{GID, PID}` a `{GID, PID, ROLE, SLOT}`. Klasy
leza w tej samej kolejnosci co numery notyfikacji (116 GamePlayerStateChange,
117 GamePlayerTeamRoleSlotChange), co domyka identyfikacje. Mapowanie `meta[0]` -> typ TDF
wyprowadzone z `build_in_game_speed_walls_response`, zweryfikowanego wczesniej na kliencie:
4/21/22/23/24 -> int, 5 -> string, 2 -> lista, 1 -> mapa, 10 -> struktura.

### Decyzja

`Lobby.mesh()` przy przejsciu gracza na `ACTIVE_CONNECTED` wysyla do wszystkich graczy gry
**116 przed 30**. `--no-player-state-notify` wraca do zachowania do run-39 wlacznie (A/B).

### Wynik (run-40, 21:52)

| | run-39 | run-40 |
|---|---|---|
| czas w grze | 6,83 s | **14 min 42 s** |
| `[gra-utracona]` | 2x | **0** |
| `[mm-ponow]` | licznik=1 | brak ponowienia |
| gry w rejestrze | 2 (rozpad) | **1** |

`cmd=116` poszlo do obu graczy, nikt nie wyszedl, zero Tracebackow, rozlaczenie na koniec
przez uzytkownika. Multiplayer w LAN dziala.

### Otwarte

- **Nietestowane na zywo:** wyjscie hosta w trakcie sesji (poprawka `remove_player` z 15.09:
  samo `NotifyGameRemoved`, bez `NotifyPlayerRemoved`), 3+ graczy, sciezka timera
  `--mm-delay > 0`.
- **RPC bez handlera widoczne dopiero przy dluzszej sesji:** `UserSessions.lookupUsers` (14x),
  `NFS.getInGameRecommendations` (4x), `NFS.getAutologPlaylist` (4x). Dalej bez handlera:
  `getSpecialGuestInfo` (42x, uklad odpowiedzi odtworzony @0x141a2c0d0 - `BLIS mSpecialGuests`,
  `STAI mSpecialGuestRealNames`, `SPGT`, `SPGN`, `SPLA`), `getOverwatchStatsConfig`,
  `getAccount`, `createWalUserSession`.
- **Nieustalone:** znaczenie `r8` w `[gra-utracona]` (`0x80` przy pierwszej utracie, `0x40` przy
  drugiej) - do dezasemblacji `0xa1b770`, gdyby wrocil podobny objaw. Typ TDF `0x70`
  (`blaze.py:1423`) wciaz nieznany dekoderowi.
