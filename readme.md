# TurboRivals

Prywatne serwery multiplayer dla **Need for Speed Rivals**.

EA wylaczylo online 7 pazdziernika 2025. Gra dziala offline, ale AllDrive -
wspolny swiat do szesciu graczy - jest martwy. Cel projektu: postawic wlasny
serwer i zaprosic znajomego linkiem.

Projekt nie kopiuje ani nie redystrybuuje plikow gry i nie obchodzi
zabezpieczen. Kazdy gracz uzywa wlasnej, legalnie kupionej kopii; my
dostarczamy tylko serwer zastepujacy wylaczona usluge.

## Stan

Faza 0 (rekonesans) zamknieta. Ustalone:

- adresy backendu, w tym redirector `gosredirector.online.ea.com`
- **potwierdzony algorytm kodowania tagow TDF**
- **slownik 1 152 tagow protokolu** wyciagniety z binarki (2 864 par tag/pole)
- mapa 16 komponentow Blaze uzywanych przez gre
- binarka ma zaszyfrowana sekcje kodu - analiza kodu wymaga zrzutu pamieci

Szczegoly: [docs/protocol.md](docs/protocol.md). Dziennik: [docs/decisions.md](docs/decisions.md).

## Uklad repozytorium

```
tools/       narzedzia recon (analiza binarki, przelacznik hosts)
proto-lab/   laboratorium protokolu - nasluch, dekodery, prototyp serwera
docs/        specyfikacja protokolu i surowe wyniki recon
server/      docelowy serwer w Rust (faza 3)
launcher/    launcher i linki zapraszajace (faza 4)
```

## Narzedzia

```bash
# zrzut stringow z binarki gry
python tools/dump_strings.py "<sciezka>/NFS14.exe" --all --tags

# metadane TDF: pary tag <-> nazwa pola
python tools/extract_tdf_meta.py "<sciezka>/NFS14.exe"

# sonda PE: naglowki, wyszukiwanie, referencje, zrzut tablic
python tools/pe_probe.py "<sciezka>/NFS14.exe" info

# przekierowanie backendu EA na siebie (konsola jako administrator)
python tools/hosts_switch.py on
python tools/hosts_switch.py off        # zawsze po sesji

# pasywny nasluch - co gra wysyla
python proto-lab/tcp_tap.py -p 42127

# logujace proxy miedzy gra a prawdziwym EA (handshake jawnym tekstem)
python proto-lab/tcp_proxy.py --upstream 159.153.51.18 --port 42127

# certyfikat zastepczy dla naszego serwera (klucz do proto-lab/pki/)
python proto-lab/make_stub_cert.py
```

## Plan

| faza | zakres | stan |
| --- | --- | --- |
| 0 | rekonesans binarki i endpointow | zrobione |
| 1 | rozgryzienie protokolu (Python) | w toku |
| 2 | prototyp serwera, pierwsza wspolna sesja przez VPN | |
| 3 | serwer produkcyjny w Rust | |
| 4 | launcher i zaproszenia linkiem | |
| 5 | dzialanie bez VPN (relay / demangler) | |
