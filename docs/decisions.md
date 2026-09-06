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
  podrobiony certyfikat, ktory binarki nie rusza.

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
