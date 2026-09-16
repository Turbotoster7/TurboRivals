// Frida - podglad WEWNETRZNYCH logow Origin SDK w NFS14.exe.
// Odkrycie: funkcje 0xee2370 i 0xec1880 to LOGGERY (rcx=poziom, rdx=wskaznik na
// tekst). Podpinamy je i wypisujemy tekst logu -> widzimy cala sekwencje wywolan
// Origin SDK w czasie proby online i moment decyzji "offline".
//
// Uruchom: python proto-lab/frida_run.py

const MOD = "NFS14.exe";
let base = null;
try {
  if (typeof Process.getModuleByName === "function") base = Process.getModuleByName(MOD).base;
  else if (typeof Process.findModuleByName === "function") { const m = Process.findModuleByName(MOD); base = m && m.base; }
  else if (typeof Module.getBaseAddress === "function") base = Module.getBaseAddress(MOD);
} catch (e) { console.log("[!] blad szukania bazy: " + e); }

// Szum do odfiltrowania (wolane co klatke) - nie wypisujemy tych.
const SPAM = ["OriginUpdate entered", "OriginReadEnumeration", "OriginGetEnumerateStatus",
              "OriginRegisterEventCallback", "OriginUpdate"];

function isSpam(s) {
  for (const w of SPAM) if (s.indexOf(w) >= 0) return true;
  return false;
}

if (!base) {
  console.log("[!] nie znalazlem modulu " + MOD + " - czy gra dziala?");
} else {
  console.log("[*] " + MOD + " base = " + base);

  // ================= HANDLER WYJATKOW - PIERWSZY =================
  // Ustawiany PRZED hookami: gdyby ktorykolwiek hook sie nie zalozyl, handler i
  // tak dziala. (Wczesniej byl na koncu pliku i nieudany Interceptor.attach
  // przerywal caly skrypt, wiec crashu nie mial kto zlapac.)
  const MOD_SPAN = 0x2000000;
  function inMod(a) {
    return a.compare(base) >= 0 && a.compare(base.add(MOD_SPAN)) < 0;
  }
  // Raportowanie wyjatkow. UWAGA na pulapke, ktora nas juz raz zmylila:
  // wczesniej logowalismy WYLACZNIE pierwszy wyjatek, a gra rzuca na starcie
  // niegrozne wyjatki first-chance spoza modulu (SEH/C++, np. 0x7ffc...). Taki
  // wyjatek zjadal jedyny slot i prawdziwy access-violation NIE BYL pokazywany -
  // w przebiegu A/B 2026-09-12 wygladalo to tak, jakby wariant A wcale nie
  // crashowal, choc konczyl sie identycznie jak B. Teraz: kazdy
  // access-violation jest raportowany (do LIMIT_AV), a wyjatki innego typu
  // tylko raz i jednolinijkowo, zeby nie zaglusaly logu.
  let avLogged = 0, otherLogged = 0;
  const LIMIT_AV = 5;
  Process.setExceptionHandler(function (details) {
    const isAV = details.type === "access-violation";
    if (!isAV) {
      if (otherLogged++ === 0) {
        console.log("[wyjatek first-chance, typ=" + details.type + " @ " +
                    details.address + " - zwykle niegrozny, loguje tylko raz]");
      }
      return false;
    }
    if (avLogged++ >= LIMIT_AV) return false;
    const addr = details.address;
    console.log("\n########## WYJATEK #" + avLogged + " ##########");
    console.log("  typ:    " + details.type);
    console.log("  adres:  " + addr +
                (inMod(addr) ? "  (base+0x" + addr.sub(base).toString(16) + ")"
                             : "  (POZA modulem gry)"));
    if (details.memory) {
      console.log("  pamiec: operacja=" + details.memory.operation +
                  " adres=" + details.memory.address);
    }
    try {
      const c = details.context;
      console.log("  rcx=" + c.rcx + " rdx=" + c.rdx + " r8=" + c.r8 + " r9=" + c.r9);
      console.log("  rax=" + c.rax + " rbx=" + c.rbx + " rsp=" + c.rsp + " rip=" + c.rip);
    } catch (e) {}
    try {
      const bt = Thread.backtrace(details.context, Backtracer.ACCURATE)
        .map(a => a + (inMod(a) ? "  (base+0x" + a.sub(base).toString(16) + ")" : ""))
        .join("\n     ");
      console.log("  STOS:\n     " + bt);
    } catch (e) { console.log("  bt err " + e); }
    console.log("#############################\n");
    return false;                          // przepusc dalej - gra i tak padnie
  });
  console.log("[+] handler wyjatkow uzbrojony (pokaze adres crasha)");

  function hookLogger(rva) {
    try {
      hookLoggerUnsafe(rva);
    } catch (e) {
      console.log("[!] nie podpialem loggera @ base+0x" + rva.toString(16) +
                  " (" + e.message + ")");
    }
  }
  function hookLoggerUnsafe(rva) {
    const addr = base.add(rva);
    Interceptor.attach(addr, {
      onEnter() {
        let s = null;
        try { s = this.context.rdx.readCString(); } catch (e) {}
        if (s && s.length > 0 && !isSpam(s)) {
          const lvl = this.context.rcx.toUInt32().toString(16);
          // poziom 0xa0.... = blad Origin -> oznaczamy
          const mark = lvl.indexOf("a0") === 0 ? "  <<< ERROR" : "";
          console.log("[log lvl=" + lvl + "] " + s + mark);
        }
      }
    });
    console.log("[+] logger @ " + addr);
  }

  hookLogger(ptr("0xee2370"));

  // 0xec1880 NIE JEST loggerem - to sprawdzenie "czy Core (EA App) odpowiada":
  // bez argumentow, wynik w al. OriginRequestTicket (0xebd169) wola je zaraz po
  // logu i przy al==0 idzie w sciezke bledu. Podpiete tu wczesniej jako logger
  // czytalo rdx, w ktorym po poprzednim wywolaniu wciaz lezal TEN SAM tekst -
  // stad kazda linia logu Origin wychodzila w naszych logach PODWOJNIE.
  let coreChecks = 0, coreFails = 0;
  try {
    Interceptor.attach(base.add(0xec1880), {
      onLeave(ret) {
        const ok = (ret.toInt32() & 0xff) !== 0;
        if (coreChecks++ < 6 || (!ok && coreFails++ < 6)) {
          console.log("[core] EA App podlaczone? " + (ok ? "TAK" : "NIE"));
        }
      }
    });
    console.log("[+] IsCoreConnected @ base+0xec1880");
  } catch (e) { console.log("[!] nie podpialem IsCoreConnected: " + e.message); }

  // Dodatkowo: kluczowe funkcje auth/online - sygnalizacja wejscia + wynik.
  // Backtrace: JEDEN raz NA HOOK, nie jeden raz na caly skrypt. Wczesniej byla
  // tu wspolna flaga i pierwszy hook z backtrace=true (ServerInstanceRequest,
  // ktory odpala sie juz przy redirectorze) zabieral jedyny zrzut stosu -
  // FullLoginResponse nigdy swojego nie wypisal, choc to wlasnie jego backtrace
  // mial nam dac RVA generycznego dekodera heat2 (TDF_READER_RVA nizej).
  const btDone = {};
  function hookFn(rva, name, backtrace) {
    // Kazdy hook w try/catch: Frida potrafi odmowic ("unable to intercept
    // function"), gdy podepniemy sie zanim gra rozpakuje kod. Bez tego JEDEN
    // nieudany hook przerywal caly skrypt i reszta sond nie powstawala.
    try {
      hookFnUnsafe(rva, name, backtrace);
    } catch (e) {
      console.log("[!] nie podpialem " + name + " @ base+0x" + rva.toString(16) +
                  " (" + e.message + ")");
    }
  }
  function hookFnUnsafe(rva, name, backtrace) {
    const addr = base.add(rva);
    Interceptor.attach(addr, {
      onEnter() {
        this.n = name;
        console.log("\n>>> " + name);
        if (backtrace && !btDone[name]) {
          btDone[name] = true;
          try {
            const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
              .map(a => {
                const off = a.sub(base);
                return a + "  (base+" + off + ")";
              }).join("\n     ");
            console.log("   BACKTRACE:\n     " + bt);
          } catch (e) { console.log("   bt err " + e); }
        }
      },
      onLeave(ret) { console.log("<<< " + name + " rax=" + ret + " al=" + (ret.toInt32() & 0xff)); }
    });
    console.log("[+] fn " + name + " @ " + addr);
  }
  // Wstrzykiwanie tokenu Origin - WYLACZONE (dead end na teraz).
  // Ustalona sygnatura z wolajacego 0x9574c0:
  //   OriginRequestTicket(rcx=Core, rdx=callback @0x140955a90, r8=context)
  // czyli funkcja jest ASYNCHRONICZNA: token NIE jest zapisywany do bufora, tylko
  // dostarczany przez WYWOLANIE callbacku (0x140955a90) z obiektem tokenu, gdy
  // przyjdzie odpowiedz LSX. Nasza proba pisania do "bufora" trafiala we wskaznik
  // callbacku (kod) -> blad. Poprawne wstrzykniecie = zbudowac obiekt-token i
  // wywolac callback z wlasciwym kontekstem - zlozone, odlozone. Na razie polegamy
  // na realnym tokenie z EA App (login przechodzi, gdy token przyjdzie na czas).
  const INJECT_TOKEN = false;
  // OriginRequestTicket (0xebd140) NIE hookujemy przez attach, gdy INJECT_TOKEN:
  // ta funkcja konczy sie TAIL-JMP do 0xec3c80, ktora PODMIENIAMY. Rownoczesny
  // attach na 0xebd140 przeklamywal rejestry przy tail-jmp (crash 12.09, outTok
  // wskazywal w kod). LSX request/response i tak loguje logger 0xee2370.
  if (!INJECT_TOKEN)
    hookFn(ptr("0xebd140"), "OriginRequestTicket");

  // ============ raport bledow Origin SDK ===================================
  // 0xebd800(rcx = kod, rdx = opis, r8 = plik, r9 = linia) sklada
  // '%s(%d) Origin Error: 0x%08X'. To JEDYNE miejsce, w ktorym widac, czym
  // skonczylo sie zadanie Origin: sciezki bledu z OriginRequestTicket
  // (0xebd1e0) i z ticketu LSX (0xec3d8c) skacza wlasnie tutaj. Bez tego hooka
  // porazka byla dla nas cisza w logu.
  try {
    Interceptor.attach(base.add(0xebd800), {
      onEnter(args) {
        let opis = "", plik = "";
        try { opis = args[1].readCString() || ""; } catch (e) {}
        try { plik = args[2].readCString() || ""; } catch (e) {}
        console.log("\n!!! ORIGIN ERROR 0x" + args[0].toUInt32().toString(16) +
                    "  " + opis + "   (" + plik + ":" + args[3].toUInt32() + ")");
      }
    });
    console.log("[+] raport bledow Origin @ base+0xebd800");
  } catch (e) { console.log("[!] nie podpialem raportu bledow: " + e.message); }

  // ============ WSTRZYKNIECIE TOKENU ORIGIN (obejscie EA App) ==============
  // Po co: gdy EA App uzna gre za nieaktywowana, NIE odpowiada na LSX
  // GetAuthToken. Gra nie dostaje ticketu, nigdy nie wysyla Blaze login (1/152)
  // i pokazuje okno aktywacji - tak skonczyl przebieg 2026-09-12 12:39.
  // Nasz serwer tokenu NIE WALIDUJE (przyjmuje dowolny AUTH), wiec wystarczy
  // podac grze ten sam string, ktory EA App wydalo, gdy jeszcze dzialalo.
  //
  // Gdzie (z dezasemblacji zrzutu, nie z domyslu): OriginRequestTicket 0xebd140
  // sprawdza Core i skacze do
  //     0xec3c80(rcx=Core, rdx=uchwyt uzytkownika, r8=char** out, r9=size_t* outLen)
  // ktora alokuje kontekst 0x1a8 B, wpisuje w niego r8/r9 oraz callback 0xec3dd0
  // i CZEKA w 0xec1770 z timeoutem -1 na odpowiedz LSX. Caly callback to:
  //     mov [r8], [rax]        ; *out    = char* token
  //     mov [r9], [rax+0x10]   ; *outLen = dlugosc
  //     xor eax, eax           ; 0 = sukces
  // Token wraca WSKAZNIKIEM na tekst, wiec nie podrabiamy ani LSX, ani jego
  // szyfrowania, ani zdarzenia w kontekscie - podajemy wskaznik i zero.
  //
  // Dlaczego replace, a nie attach: original czeka z timeoutem -1, wiec przy
  // milczacym EA App onLeave nigdy by sie nie odpalil, a gra by wisiala.
  //
  // Token: dokladnie ten base64, ktory EA App wydalo 2026-09-11 21:54. W udanym
  // logowaniu gra przekazala go do Blaze BEZ ZMIAN (log-login.txt:66
  // AUTH='QVQx...'), wiec nie ma tu zadnego kodowania do odtworzenia.
  // Wygasniecie nie ma znaczenia - przyjmuje go NASZ serwer.
  // WYLACZONE 2026-09-12 popoludnie. Przebieg 13:59 (uruchomienie przez EA App)
  // pokazal DWIE rzeczy: (1) EA App znow dziala - gra przeszla bramke aktywacji,
  // wiec token GetAuthToken plynie normalnie i wstrzykiwanie jest zbedne; (2) samo
  // wstrzykiwanie jest ZEPSUTE - callback rzucil "access violation accessing
  // 0x140955a90" (adres KODU, nie bufor) w linii z outTok.writePointer, zwrocil
  // smieci (rax=0xeb00000000) i najpewniej to ONO wywolalo crash. Przyczyna:
  // Interceptor.replace na 0xec3c80 koliduje z attach na OriginRequestTicket
  // (0xebd140), ktora konczy sie TAIL-JMP do 0xec3c80 - rejestry z argumentami
  // (r8/r9 = bufory wyjsciowe) wychodza przeklamane. Do naprawy dla Tora B trzeba
  // albo zdjac attach z 0xebd140, albo zamiast replace hookowac callback ukonczenia
  // 0xec3dd0. Na teraz opieramy sie na dzialajacym EA App (jak w udanym logowaniu
  // 11.09), zeby dojsc do blokady postAuth.
  const ORIGIN_TOKEN =
    "QVQxOjMuMDozLjA6MjQwOnd4VWwxOHRXOHNxQ1JTZFU5cU9UM1kyZTMwamxSSjZqdVczOjc0NzA0OnNlMGcw";
  let tokenBuf = null;          // referencje MUSZA byc globalne: bufor i callback
  let ticketCb = null;          // zwolnione przez GC = gra czytalaby smieci
  let ticketHits = 0;
  if (INJECT_TOKEN) {
    try {
      tokenBuf = Memory.allocUtf8String(ORIGIN_TOKEN);
      ticketCb = new NativeCallback(function (core, user, outTok, outLen) {
        ticketHits++;
        // ODPORNOSC NA CRASH (nauczka z 12.09): przy pierwszym wywolaniu argumenty
        // bywaja inne (init), a outTok wskazywal w KOD -> zapis wywalal gre. Kazdy
        // zapis w try/catch: gdy wskaznik nie jest zapisywalny, NIE piszemy i
        // zwracamy blad a2000004 (tak jak original 0xec3cc0 przy braku bufora) -
        // gra to obsluguje, zamiast crashowac. Przy prawdziwym wywolaniu outTok/
        // outLen sa zapisywalne i token wchodzi.
        if (outTok.isNull() || outLen.isNull())
          return 0xa2000004 | 0;
        try {
          outTok.writePointer(tokenBuf);
          outLen.writeU64(ORIGIN_TOKEN.length);
        } catch (e) {
          if (ticketHits <= 3)
            console.log("[token] wywolanie #" + ticketHits + " ma nizapisywalny " +
                        "bufor (" + outTok + ") - pomijam, zwracam blad");
          return 0xa2000004 | 0;
        }
        if (ticketHits <= 3) {
          console.log("\n[token] PODSTAWIAM token Origin (" + ORIGIN_TOKEN.length +
                      " B) zamiast pytac EA App   [wywolanie #" + ticketHits + "]");
        }
        return 0;
      }, "int", ["pointer", "pointer", "pointer", "pointer"]);
      Interceptor.replace(base.add(0xec3c80), ticketCb);
      console.log("[+] WSTRZYKIWANIE TOKENU aktywne (0xec3c80 podmieniona)");
    } catch (e) {
      console.log("[!] nie podmienilem 0xec3c80: " + e.message);
    }
  } else {
    console.log("[*] wstrzykiwanie tokenu WYLACZONE (INJECT_TOKEN=false)");
  }

  // ============ parser odpowiedzi koordynatora QoS (DirtySDK qosapi) ========
  // _QosApiParseResponse @0xfdb070(rcx = struct polaczenia, rdx = QosApiRef).
  // Bufor odpowiedzi HTTP lezy pod *(QosApiRef+0x128) + 0x112, a kod powrotu
  // mowi JEDNOZNACZNIE, czy gra przyjela nasz XML:
  //    0  -> przyjety, powinny polecic sondy UDP na <qosport>
  //   -1  -> XmlFind trafil, ale padla walidacja (0xfdb3f1): qosport == 0 albo
  //          requestid == 0, albo dla qtyp==2 probesize == 0 / numprobes < 2
  //   -2  -> nie znalazl zadnego z elementow <firewall>/<firetype>/<qos>
  //          (tak bylo, gdy odsylalismy format TagField "qos.numprobes=1 ...")
  function hookQosParse(rva) {
    try {
      const addr = base.add(rva);
      Interceptor.attach(addr, {
        onEnter(args) {
          this.ref = args[1];
          let txt = "(nie odczytalem)";
          try {
            txt = this.ref.add(0x128).readPointer().add(0x112).readCString(512);
          } catch (e) { txt = "(blad czytania buforu: " + e.message + ")"; }
          console.log("");
          console.log(">>> QosApiParseResponse, bufor odpowiedzi:");
          console.log("    " + txt);
        },
        onLeave(ret) {
          const rc = ret.toInt32();
          const why = rc === 0 ? "XML PRZYJETY - sondy UDP powinny polecic"
                    : rc === -1 ? "walidacja odrzucila (qosport/requestid == 0?)"
                    : rc === -2 ? "nie znalazl elementu <qos>/<firetype>/<firewall>"
                    : "nieznany kod";
          console.log("<<< QosApiParseResponse = " + rc + "  (" + why + ")");
          try {
            const st = this.ref.add(0x128).readPointer();
            console.log("    stan QoS: qtyp=" + st.add(0x1118).readU32() +
                        " probesize=" + st.add(0x111c).readU32() +
                        " numprobes=" + st.add(0x1124).readU32() +
                        " requestid=" + st.add(0x1130).readU32() +
                        " reqsecret=" + st.add(0x1134).readU32() +
                        " qosport=" + this.ref.add(0x124).readU16());
          } catch (e) {}
        }
      });
      console.log("[+] fn QosApiParseResponse @ " + addr);
    } catch (e) {
      console.log("[!] nie podpialem QosApiParseResponse (" + e.message + ")");
    }
  }
  hookQosParse(ptr("0xfdb070"));

  // ================= KROK A: sledzenie dekodera TDF (heat2) =================
  // Cel: logowac KAZDY tag, ktory dekoder czyta z naszej odpowiedzi. Ostatni
  // tag przed bledem = brakujace/zle pole. Teraz crasha nie ma, wiec sluzy do
  // potwierdzenia, KTORE pola gra realnie czyta z postAuth/login.
  //
  // Dekoder jest wolany posrednio (vtable), wiec jego adres ustalamy z BACKTRACE
  // sondy decode (nizej). Gdy go poznamy, wpisujemy RVA tutaj i skrypt zacznie
  // logowac tagi. Do tego czasu backtrace z sond decode wskaze wlasciwa funkcje.
  const TDF_READER_RVA = null;   // np. ptr("0xf8a200") - ustaw z backtrace

  function decodeTag(raw) {
    // 24-bitowy tag -> 4 znaki (6 bitow/znak, 0=spacja). Lustro pe_probe.
    let s = "";
    for (const sh of [18, 12, 6, 0]) {
      const c = (raw >>> sh) & 0x3f;
      s += (c === 0) ? " " : String.fromCharCode(c + 0x20);
    }
    return s;
  }
  function tagFromU32(v) {
    // Tag na drucie to 3 bajty; w rejestrze bywa surowy (0x00TTTTTT) albo <<8.
    const a = decodeTag(v & 0xffffff);
    const b = decodeTag((v >>> 8) & 0xffffff);
    const ok = t => /^[ -~]{4}$/.test(t) && t.trim().length > 0;
    if (ok(a)) return a + "  (raw)";
    if (ok(b)) return b + "  (<<8)";
    return "?(" + v.toString(16) + ")";
  }
  function traceTdfReader(rva) {
    const addr = base.add(rva);
    Interceptor.attach(addr, {
      onEnter(a) {
        // Nie znamy sygnatury - logujemy kandydatow na tag z rejestrow arg.
        const cands = [];
        for (const [nm, reg] of [["rcx", this.context.rcx], ["rdx", this.context.rdx],
                                 ["r8", this.context.r8], ["r9", this.context.r9]]) {
          const lo = reg.toUInt32();
          const t = tagFromU32(lo);
          if (t.indexOf("?(") !== 0) cands.push(nm + "=" + t);
        }
        console.log("[TDF tag] " + (cands.length ? cands.join("  ") : "brak czytelnego taga"));
      }
    });
    console.log("[+] TDF reader trace @ " + addr);
  }
  if (TDF_READER_RVA !== null) traceTdfReader(TDF_READER_RVA);

  // Sonda przeplywu redirectora: getTypeDescription klas zadania i odpowiedzi.
  // Jesli "ServerInstanceInfo::getTypeDescr" sie odpala -> gra DEKODUJE nasza
  // odpowiedz (framing Fire2 OK). Jesli nie -> odrzuca juz na ramce/msgId.
  hookFn(ptr("0xf8a0f0"), "ServerInstanceRequest (encode zadania)", true);
  hookFn(ptr("0xf8a0e0"), "ServerInstanceInfo (decode?)");
  hookFn(ptr("0xf8a0c0"), "ServerInstance (decode?)");
  hookFn(ptr("0xf8a0d0"), "ServerInstanceError (decode?)");
  hookFn(ptr("0xf8a090"), "ServerAddressInfo (decode?)");
  // login / postAuth / notyfikacja po loginie.
  // backtrace=true na FullLoginResponse decode: stos ujawni GENERYCZNY dekoder
  // heat2 (funkcja tuz nad ta w stosie, w module NFS14). Jej RVA wpisz do
  // TDF_READER_RVA powyzej, by logowac kazdy tag.
  hookFn(ptr("0xf0c0a0"), "FullLoginResponse (decode odp. login) <- BACKTRACE do dekodera", true);
  hookFn(ptr("0xf211d0"), "PostAuthRequest (encode -> gra wysyla postAuth!)");
  // backtrace=true (run-20): stos przy dekodzie odpowiedzi postAuth pokaze handler
  // odpowiedzi Util i callback zakonczenia postAuth - stamtad powinno isc onAuthenticated.
  hookFn(ptr("0xf211e0"), "PostAuthResponse (decode naszej odp. postAuth?)", true);
  // backtrace=true: w przebiegu 14:07 getTypeDescr FullLoginResponse (0xf0c0a0)
  // sie NIE odpalil, ale TA notyfikacja i NotifyUserAdded DEKODUJA TDF i odpalaja
  // sie na pewno. Backtrace z ktorejkolwiek ujawni generyczny dekoder heat2
  // (ramka tuz nad w module) -> TDF_READER_RVA.
  hookFn(ptr("0xf66220"), "UserSessionExtendedDataUpdate (decode notyfikacji)", true);
  hookFn(ptr("0xf65f90"), "NotifyUserAdded (decode UserAdded)", true);

  // ============ decyzja dolaczajacego o wyjsciu z gry (15.09) =====================
  // log-30..32: gracz, ktory dolaczyl do cudzej gry, ~230 ms po sprawdzeniu entitlementow wysyla
  // startMatchmaking z AGAM.GIDL = [ta gra] i removePlayer - niezaleznie od tego, kto jest hostem.
  // getTypeDescription klasy zadania odpala sie przy jego kodowaniu, wiec backtrace KAZDEGO
  // wywolania (do limitu) pokazuje kod NFS, ktory o wyjsciu zdecydowal. Pierwszy
  // StartMatchmakingRequest to dolaczenie - ciekawy jest nastepny. Entitlements = dekod odpowiedzi
  // listUserEntitlements2, czyli kod, ktory te uprawnienia sprawdza.
  const btCount = {};
  function hookBtEach(rva, name, limit) {
    try {
      Interceptor.attach(base.add(rva), {
        onEnter() {
          const n = (btCount[name] = (btCount[name] || 0) + 1);
          if (n > limit) return;
          let bt;
          try {
            bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
              .map(a => inMod(a) ? "base+" + a.sub(base) : String(a)).join("\n     ");
          } catch (e) { bt = "bt err " + e; }
          console.log("\n[decyzja] " + name + " #" + n + " (" +
                      new Date().toISOString().substr(11, 12) + ")\n     " + bt);
        }
      });
      console.log("[+] backtrace kazdego wywolania (max " + limit + "): " + name +
                  " @ base+0x" + rva.toString(16));
    } catch (e) {
      console.log("[!] nie podpialem " + name + " @ base+0x" + rva.toString(16) + " (" + e.message + ")");
    }
  }
  hookBtEach(ptr("0xf66100"), "StartMatchmakingRequest (encode 4/13)", 8);
  hookBtEach(ptr("0xf66010"), "RemovePlayerRequest (encode 4/11)", 6);
  hookBtEach(ptr("0xf0c060"), "Entitlements (decode odp. 1/29)", 8);

  // ============ maszyna stanow matchmakingu NFS (frida-33 + dezasemblacja) =========
  // 0xa3b590 buduje kryteria i wola SDK startMatchmaking z callbackiem wyniku 0xa3c5f0
  // (this=rcx: [+0x98] id sesji MM, callback zapisuje [+0x9d]=1 koniec, [+0xa0]=edx wynik,
  // [+0xb0]=r9). 0xa3c1a0 sprawdza "skonczone i OK" ([+0x9d] != 0 && [+0xa0] == 0).
  // 0xa11400 = wejscie w stan "ponow matchmaking": licznik [[this+0x110]+0x40], tryb
  // [[this+0x130]+0x418], limit z tweakable "matchmaking_retries". 0xa6dfe0(rcx=maszyna,
  // rdx=klucz stanu) = przejscie stanu - logujemy wolajacego, zeby znalezc warunek.
  function hookSafe(rva, name, cb) {
    try { Interceptor.attach(base.add(rva), cb); console.log("[+] " + name + " @ base+0x" + rva.toString(16)); }
    catch (e) { console.log("[!] nie podpialem " + name + " (" + e.message + ")"); }
  }
  hookSafe(ptr("0xa3c5f0"), "MM wynik (callback NFS)", {
    onEnter(args) {
      const c = this.context;
      let jid = "?", mine = "?";
      try { jid = c.r8.readU32(); mine = c.rcx.add(0x98).readU32(); } catch (e) {}
      console.log("\n[mm-wynik] edx(wynik)=" + (c.rdx.toInt32()) + " r9=" + c.r9 + " jobId=" + jid +
                  " oczekiwany=" + mine + " this=" + c.rcx + " (" + new Date().toISOString().substr(11, 12) + ")");
    }
  });
  const mmSeen = {};
  // 0xa3c1a0 = aktualizacja stanu MM: [+0x9d] koniec && [+0xa0] != 0 -> porazka (klucz +0x428);
  // inaczej gdy [+0x9e] != 0: [+0xa4] <= 2 -> sukces (+0x410), > 2 -> porazka (+0x428).
  // Wolane co klatke - logujemy tylko zmiane czworki 9d/9e/a0/a4.
  hookSafe(ptr("0xa3c1a0"), "MM aktualizacja stanu (0xa3c1a0)", {
    onEnter(args) {
      const o = this.context.rcx;
      let k = "?";
      try {
        k = "9d=" + o.add(0x9d).readU8() + " 9e=" + o.add(0x9e).readU8() + " a0=" + o.add(0xa0).readS32() +
            " a4=" + o.add(0xa4).readS32();
      } catch (e) {}
      const key = String(o);
      if (mmSeen[key] !== k) {
        mmSeen[key] = k;
        console.log("[mm-stan] " + o + " " + k + " wolajacy base+" + this.returnAddress.sub(base) +
                    " (" + new Date().toISOString().substr(11, 12) + ")");
      }
    }
  });
  hookSafe(ptr("0xa11400"), "MM ponow (0xa11400)", {
    onEnter(args) {
      const t = this.context.rcx;
      let n = "?", mode = "?";
      try { n = t.add(0x110).readPointer().add(0x40).readU32(); mode = t.add(0x130).readPointer().add(0x418).readU32(); } catch (e) {}
      console.log("\n[mm-ponow] licznik=" + n + " tryb=" + mode + " this=" + t + " (" +
                  new Date().toISOString().substr(11, 12) + ")");
    }
  });
  // 0xa3c570 = drugi callback tego obiektu: gdy r8 == [this+0xb0] (gra z wyniku MM) zeruje
  // [+0x98], zapisuje [+0x9e]=1 i [+0xa4]=edx (status). 0xa3c1a0 uznaje dolaczenie za udane tylko
  // przy statusie <= 2 - tu widac, jaki status gra dostaje i kto go podaje (backtrace).
  let st2 = 0;
  hookSafe(ptr("0xa3c570"), "MM status gry (0xa3c570)", {
    onEnter(args) {
      const c = this.context;
      let gra = "?";
      try { gra = c.rcx.add(0xb0).readPointer(); } catch (e) {}
      console.log("\n[mm-status] edx(status)=" + c.rdx.toInt32() + " r8(gra)=" + c.r8 + " oczekiwana=" + gra +
                  " r9=" + c.r9 + " this=" + c.rcx + " (" + new Date().toISOString().substr(11, 12) + ")");
      if (++st2 <= 4) {
        try {
          console.log("     " + Thread.backtrace(c, Backtracer.ACCURATE)
            .map(a => inMod(a) ? "base+" + a.sub(base) : String(a)).join("\n     "));
        } catch (e) { console.log("     bt err " + e); }
      }
    }
  });
  // 0xa1b770 = obsluga "gra utracona" (frida-34): gdy rdx == [this+0x388] (sledzona gra) wychodzi ze
  // stanu (vfunc+8 -> przejscie +0x660 -> "ponow MM"), wyrejestrowuje sie z gry i zeruje wskaznik.
  // U dolaczajacego odpala sie po wczytaniu swiata - stos pokaze, co w SDK usunelo gre.
  let lostBt = 0;
  hookSafe(ptr("0xa1b770"), "gra utracona (0xa1b770)", {
    onEnter(args) {
      const c = this.context;
      let tracked = "?";
      try { tracked = c.rcx.add(0x388).readPointer(); } catch (e) {}
      console.log("\n[gra-utracona] rdx(gra)=" + c.rdx + " sledzona=" + tracked + " r8=" + c.r8 + " r9=" + c.r9 +
                  " this=" + c.rcx + " (" + new Date().toISOString().substr(11, 12) + ")");
      if (++lostBt <= 3) {
        try {
          console.log("     " + Thread.backtrace(c, Backtracer.ACCURATE)
            .map(a => inMod(a) ? "base+" + a.sub(base) : String(a)).join("\n     "));
        } catch (e) { console.log("     bt err " + e); }
      }
    }
  });
  let trCount = 0, trBt = 0;
  hookSafe(ptr("0xa6dfe0"), "przejscie stanu (0xa6dfe0)", {
    onEnter(args) {
      if (++trCount > 400) return;
      const c = this.context;
      const rel = c.rdx.sub(c.rcx).toInt32();
      console.log("[stan] maszyna=" + c.rcx + " klucz=+0x" + rel.toString(16) +
                  " wolajacy base+" + this.returnAddress.sub(base) + " (" + new Date().toISOString().substr(11, 12) + ")");
      // frida-34: przejscie +0x660 (00:44:51.581, przez delegata 0xa1b770) konczylo udane dolaczenie i
      // prowadzilo do "ponow MM" - pelny stos pokaze, kto je zlecil. Do 3 zrzutow.
      if ((rel === 0x660 || rel === 0x188) && (trBt = (trBt || 0) + 1) <= 3) {
        try {
          console.log("     STOS +0x" + rel.toString(16) + ":\n     " + Thread.backtrace(c, Backtracer.ACCURATE)
            .map(a => inMod(a) ? "base+" + a.sub(base) : String(a)).join("\n     "));
        } catch (e) { console.log("     bt err " + e); }
      }
    }
  });

  // ============ zdejmowanie komponentu (teardown) ==========================
  // base+0xf4de00(rcx = hub, edx = indeks komponentu): czyta tablice komponentow
  // spod [hub+0x310], indeksuje po edx, wola dwie metody przez vtable i ZERUJE
  // slot (mov qword ptr [r15+rax], 0 @0xf4decd). Indeks jest maly - @0xf4def0
  // stoi cmp edi,0x10 i uzycie jako numeru bitu w masce.
  //
  // Po co: w crashu 2026-09-11 (rip=0, operacja=execute pod adresem 0) najglebsza
  // ramka powrotu to base+0xf4df22, czyli wnetrze WLASNIE tej funkcji - gra
  // sprzatala komponent i skoczyla pod wskaznik, ktorego nikt nie ustawil. Ten
  // hook odpowiada na dwa pytania naraz: KTORY komponent jest zdejmowany i KTO
  // to zlecil. Jesli teardown pojawi sie PRZED crashem i zlecony z obslugi
  // naszej odpowiedzi postAuth - rozlaczenie jest przyczyna, a crash skutkiem.
  let teardownSeen = 0;
  function hookTeardown(rva) {
    try {
      const addr = base.add(rva);
      Interceptor.attach(addr, {
        onEnter(args) {
          const idx = args[1].toInt32() & 0xffff;
          console.log("\n### TEARDOWN komponentu idx=" + idx + "  hub=" + args[0]);
          if (teardownSeen++ < 5) {
            try {
              const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(a => a + "  (base+" + a.sub(base) + ")").join("\n     ");
              console.log("   KTO ZLECIL:\n     " + bt);
            } catch (e) { console.log("   bt err " + e); }
          }
        }
      });
      console.log("[+] teardown komponentu @ " + addr);
    } catch (e) {
      console.log("[!] nie podpialem teardownu (" + e.message + ")");
    }
  }
  hookTeardown(ptr("0xf4de00"));

  // ============ CZYTNIK CONFIGU POLACZENIA (connIdleTimeout itd.) =============
  // 0xf419b0 czyta z configu pingPeriod/defaultRequestTimeout/connIdleTimeout i
  // zapisuje wartosc/1000 do [conn+0x2f8] / [conn+0x1c4] / [conn+0x2fc] (ms).
  // Zerwanie (0xf3a580) wymaga stan[+0x30]==2 && (teraz - ost. aktywnosc) >
  // [conn+0x2fc]. Przy [conn+0x2fc]=0 wystarcza 1 ms ciszy. Przyczyna zera (2026-09-13,
  // dezasemblacja): wysylalismy "90" bez jednostki -> parser 0xf79d60 zwraca false,
  // getter 0xf39dc0 to ignoruje -> czytnik bierze 0. Fix: "90s" (blaze.py).
  // UWAGA: w run-14 ten hook NIE wypisal nic, choc poza konstruktorem to jedyny zapis
  // [conn+0x2fc]. Nizej hooki gettera, parsera i migawka conn rozstrzygaja to wprost.
  try {
    Interceptor.attach(base.add(0xf419b0), {
      onEnter() { this.conn = this.context.rcx; },
      onLeave() {
        try {
          const c = this.conn;
          console.log("[config] 0xf419b0: connIdleTimeout->[+0x2fc]=" +
                      c.add(0x2fc).readU32() + " defaultReqTimeout->[+0x1c4]=" +
                      c.add(0x1c4).readU32() + " stan[+0x30]=" + c.add(0x30).readU32());
        } catch (e) { console.log("[config] blad odczytu: " + e.message); }
      }
    });
    console.log("[+] czytnik configu polaczenia @ base+0xf419b0");
  } catch (e) { console.log("[!] nie podpialem czytnika configu: " + e.message); }

  // Getter configu polaczenia 0xf39dc0 = [vtable conn+0x50] (rcx=conn, rdx=char* klucz,
  // r8=int64* wynik w us). Lookup 0xf39cb0 szuka klucza w mapie [conn+0x3a0]; jesli jest,
  // wola parser i ZAWSZE zwraca 1 (wynik parsera ignoruje). Pokazuje, KTORE klucze klient
  // czyta, kiedy i jaka wartosc dostaje. Limit linii, bo getter moze byc goracy.
  let cfgGetLogs = 0;
  try {
    Interceptor.attach(base.add(0xf39dc0), {
      onEnter() {
        this.key = null;
        if (cfgGetLogs >= 60) return;
        try { this.key = this.context.rdx.readCString(64).split("\0")[0]; } catch (e) { this.key = "?"; }
        this.out = this.context.r8;
      },
      onLeave(retval) {
        if (this.key === null) return;
        cfgGetLogs++;
        let raw = "?";
        try { raw = this.out.readS64().toString(); } catch (e) {}
        console.log("[cfg-get] '" + this.key + "' znaleziony=" + (retval.toInt32() & 0xff) +
                    " wynik=" + raw + " us");
      }
    });
    console.log("[+] getter configu @ base+0xf39dc0");
  } catch (e) { console.log("[!] nie podpialem gettera configu: " + e.message); }

  // Lookup configu 0xf39cb0 = [vtable conn+0x40] (rcx=conn, rdx=char* klucz, r8=char** wynik)
  // -> al. Pod nim sa wszystkie typowane gettery (+0x48/+0x50/+0x58), wiec widac KAZDY
  // klucz, o ktory klient pyta - takze te, ktorych w CONF nie wysylamy (znaleziony=0).
  let cfgLookupLogs = 0;
  try {
    Interceptor.attach(base.add(0xf39cb0), {
      onEnter() {
        this.key = null;
        if (cfgLookupLogs >= 80) return;
        try { this.key = this.context.rdx.readCString(64).split("\0")[0]; } catch (e) { this.key = "?"; }
        this.out = this.context.r8;
      },
      onLeave(retval) {
        if (this.key === null) return;
        cfgLookupLogs++;
        const ok = retval.toInt32() & 0xff;
        let v = "";
        if (ok) { try { v = " wartosc='" + this.out.readPointer().readCString(64).split("\0")[0] + "'"; } catch (e) { v = " wartosc=?"; } }
        console.log("[cfg-lookup] '" + this.key + "' znaleziony=" + ok + v);
      }
    });
    console.log("[+] lookup configu @ base+0xf39cb0");
  } catch (e) { console.log("[!] nie podpialem lookupu configu: " + e.message); }

  // ============ STAN MASZYNY ONLINE GRY (0xa1bb00) ============
  // 0xa1bb00 = aktualizacja menedzera online warstwy gry, co klatke (ret 0xa1bb71 jest
  // w kazdym backtrace Blaze). [obj+0x20] = stan. Przy 9 i [[obj+0x30]+0x748]->vf+0xd0
  // == true gra przechodzi w 10, czyta bytevaultPort/Secure/Hostname z CONF i inicjuje
  // ByteVault (0xf71b40). Po postAuth gra nic nie wysyla i stoi na "Logowanie" - ten
  // obserwator mowi, na KTORYM stanie. Bez goracego hooka: obiekt lapiemy z pierwszego
  // wywolania, hook od razu odpinamy, a stan czytamy timerem co 1 s (loguje zmiany).
  let onlineObj = null;
  try {
    const onlineL = Interceptor.attach(base.add(0xa1bb00), {
      onEnter() {
        if (onlineObj !== null) return;
        onlineObj = this.context.rcx;
        console.log("[online] obiekt menedzera online gry = " + onlineObj);
        setTimeout(() => { try { onlineL.detach(); } catch (e) {} }, 0);
      }
    });
    let lastOnline = null;
    setInterval(() => {
      if (onlineObj === null) return;
      try {
        const s = "stan[+0x20]=" + onlineObj.add(0x20).readS32() +
                  " [+0x26]=" + onlineObj.add(0x26).readU8() +
                  " [+0x27]=" + onlineObj.add(0x27).readU8();
        if (s !== lastOnline) { lastOnline = s; console.log("[online] " + s); }
      } catch (e) {}
    }, 1000);
    console.log("[+] obserwator stanu online @ base+0xa1bb00 (hook jednorazowy + timer 1 s)");
  } catch (e) { console.log("[!] nie podpialem obserwatora online: " + e.message); }

  // ============ HANDLER ZDARZENIA HUBA 0xf41560 ("zalogowano" dla gry) ============
  // 0xf41560(rcx=hub, rdx=zdarzenie, r8d) - rejestrowany w 0xf45710 (lea @0xf459fb).
  // Szuka uzytkownika po [ev+0x10] (0xf390c0), wola czytnik configu 0xf419b0, a potem
  // TYLKO gdy [ev+0x26] != 0 i [ev+0x20] nie jest 4 ani 5 rozsyla do listenerow
  // [hub+0x1b0] slot +0x50 (thunk 0xf52828) = 0xa16a20 w grze = stan online 9.
  // W run-17 stan gry nie doszedl do 9 - ten log pokazuje, ktory warunek odpada.
  try {
    Interceptor.attach(base.add(0xf41560), {
      onEnter() {
        const ev = this.context.rdx;
        let s;
        try {
          let str = "";
          try {
            const p = ev.add(0x18).readPointer();
            if (!p.isNull()) str = p.readCString(48).split(/[\0�]/)[0];
          } catch (e) { str = "?"; }
          s = "id[+0x10]=" + ev.add(0x10).readU64() + " str[+0x18]='" + str +
              "' [+0x20]=" + ev.add(0x20).readU32() + " [+0x24]=" + ev.add(0x24).readU16() +
              " [+0x26]=" + ev.add(0x26).readU8() + " r8d=" + this.context.r8.toInt32();
        } catch (e) { s = "blad odczytu: " + e.message; }
        console.log("[hub-ev 0xf41560] " + s);
        try { console.log(hexdump(ev, { length: 0x40, header: false, ansi: false })); } catch (e) {}
        // Jednorazowy backtrace: adres powrotu w dyspozytorze notyfikacji 0xf29f90
        // (blok po "call r9") mowi, KTORA notyfikacja wywolala ten handler.
        if (!btDone["hub-ev"]) {
          btDone["hub-ev"] = true;
          try {
            console.log("   STOS:\n     " + Thread.backtrace(this.context, Backtracer.ACCURATE)
              .slice(0, 8).map(a => a + "  (base+" + a.sub(base) + ")").join("\n     "));
          } catch (e) {}
        }
      }
    });
    console.log("[+] handler zdarzenia huba @ base+0xf41560");
  } catch (e) { console.log("[!] nie podpialem 0xf41560: " + e.message); }

  // ============ SKAD STAN 6? (run-17/18: 2 -> 5 -> 6 zaraz po PostAuthResponse) ============
  // Kandydaci ze statyki: listener gry 0xa16df0 (->6), blad 0xa17780 (kod 0x19 -> 6),
  // start logowania 0xa0f160 (->5 albo ->6) i vf+0x10 obiektu online, ktora 0xa1bb00
  // wola w stanie 5, gdy NetConnStatus('conn') zwroci status zaczynajacy sie od '-'.
  // Wszystko to funkcje zdarzeniowe (rzadkie), wiec bez goracych hookow. Kazdy loguje
  // stan gry w chwili wywolania i raz stos - stos pokaze, co w SDK to wywolalo.
  function fourcc(v) {
    const n = v >>> 0;
    const s = String.fromCharCode((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
    return /^[\x20-\x7e]{4}$/.test(s) ? "'" + s + "'" : "0x" + n.toString(16);
  }
  function hookEvent(target, name, describe) {
    try {
      const addr = typeof target === "number" ? base.add(target) : target;
      Interceptor.attach(addr, {
        onEnter() {
          let st = "?";
          try { if (onlineObj !== null) st = onlineObj.add(0x20).readS32(); } catch (e) {}
          let extra = "";
          try { extra = describe ? describe(this.context) : ""; } catch (e) {}
          console.log("[ev] " + name + " (stan gry=" + st + ") " + extra);
          if (!btDone["ev " + name]) {
            btDone["ev " + name] = true;
            try {
              console.log("   STOS:\n     " + Thread.backtrace(this.context, Backtracer.ACCURATE)
                .slice(0, 10).map(a => a + "  (base+" + a.sub(base) + ")").join("\n     "));
            } catch (e) {}
          }
        }
      });
      console.log("[+] zdarzenie " + name + " @ " + addr);
    } catch (e) { console.log("[!] nie podpialem " + name + ": " + e.message); }
  }
  const regsOf = c => "rcx=" + c.rcx + " rdx=" + c.rdx + " r8=" + c.r8 + " r9=" + c.r9;
  // listener huba w grze - kolejne sloty vtable od 0x15cc930
  hookEvent(0xa0da60, "listener[0] 0xa0da60", regsOf);
  hookEvent(0xa0d9d0, "listener[1] 0xa0d9d0", regsOf);
  hookEvent(0xa16df0, "listener[2] 0xa16df0 (->6)", regsOf);
  hookEvent(0xa16f20, "listener[3] 0xa16f20 (->2)", regsOf);
  hookEvent(0xa16a20, "listener[4] 0xa16a20 (->9)", regsOf);
  hookEvent(0xa16f00, "listener[5] 0xa16f00 (1->2)", regsOf);
  hookEvent(0xa0dc70, "listener[6] 0xa0dc70", regsOf);
  hookEvent(0xa17780, "blad 0xa17780 (0x19 -> 6)", c => "kod(edx)=" + fourcc(c.rdx.toInt32()) + " " + regsOf(c));
  hookEvent(0xa0f160, "start logowania 0xa0f160 (->5/6)", regsOf);
  // vf+0x10 obiektu online (adres z jego vtable w runtime, gdy obiekt zostanie zlapany)
  let vf10Hooked = false;
  setInterval(() => {
    if (vf10Hooked || onlineObj === null) return;
    vf10Hooked = true;
    try {
      const vt = onlineObj.readPointer();
      const fn = vt.add(0x10).readPointer();
      console.log("[online] vtable=" + vt + " (base+" + vt.sub(base) + ") vf+0x10=" + fn +
                  " (base+" + fn.sub(base) + ")");
      hookEvent(fn, "online vf+0x10 (status conn '-...')", c => "status(edx)=" + fourcc(c.rdx.toInt32()));
    } catch (e) { console.log("[!] vf+0x10: " + e.message); }
  }, 500);

  // ============ HUB: zmiana stanu 0xf40570 i handler 0xf3feb0 (onAuthenticated) ============
  // run-19: obiekt online gry to BlazeStateEventHandler (vtable 0x15cc938: dtor, onConnected
  // 0xa16df0 -> 6, onDisconnected 0xa16f20, onAuthenticated 0xa16a20 -> 9, onDeAuthenticated,
  // onIncompatibleServerVersion). onConnected przyszlo, onAuthenticated NIE. Rozsylaja je
  // (slot +0x18 listenerow [hub+0x380]) tylko:
  //  - 0xf40570(rcx=hub, edx=nowy stan, r8d=user): [hub+0x24]=stary stan, ze stanu 5 tylko do 8,
  //    galaz onAuthenticated wymaga [hub+0x6e2] != 0,
  //  - 0xf3feb0 -> 0xf3fe10: handler zdarzenia (rejestracja w 0xf45710, funktor +0x298).
  let setStateLogs = 0;
  try {
    Interceptor.attach(base.add(0xf40570), {
      onEnter() {
        const c = this.context;
        let old = -1, flag = -1, game = "?";
        try { old = c.rcx.add(0x24).readU32(); flag = c.rcx.add(0x6e2).readU8(); } catch (e) {}
        const nw = c.rdx.toInt32();
        if (old === nw || setStateLogs >= 40) return;
        setStateLogs++;
        try { if (onlineObj !== null) game = onlineObj.add(0x20).readS32(); } catch (e) {}
        console.log("[hub] setState 0xf40570: " + old + " -> " + nw + " user(r8d)=" +
                    c.r8.toInt32() + " [hub+0x6e2]=" + flag + " (stan gry=" + game + ")");
        if (!btDone["hub setState"]) {
          btDone["hub setState"] = true;
          try {
            console.log("   STOS:\n     " + Thread.backtrace(c, Backtracer.ACCURATE).slice(0, 10)
              .map(a => a + "  (base+" + a.sub(base) + ")").join("\n     "));
          } catch (e) {}
        }
      }
    });
    console.log("[+] hub setState @ base+0xf40570");
  } catch (e) { console.log("[!] nie podpialem hub setState: " + e.message); }
  hookEvent(0xf3feb0, "hub 0xf3feb0 (-> onAuthenticated)", regsOf);

  // Parser TimeValue 0xf79d60 (rcx=int64* wynik, rdx=char* tekst) -> al. Segmenty
  // <liczba><d|h|m|s|ms>, wynik w us. Liczba bez jednostki = false i brak zapisu.
  let cfgParseLogs = 0;
  try {
    Interceptor.attach(base.add(0xf79d60), {
      onEnter() {
        this.s = null;
        if (cfgParseLogs >= 40) return;
        try { this.s = this.context.rdx.readCString(64).split("\0")[0]; } catch (e) { this.s = "?"; }
        this.out = this.context.rcx;
      },
      onLeave(retval) {
        if (this.s === null) return;
        cfgParseLogs++;
        const ok = retval.toInt32() & 0xff;
        let v = "(nic nie zapisano)";
        if (ok) { try { v = this.out.readS64().toString() + " us"; } catch (e) {} }
        console.log("[cfg-parse] '" + this.s + "' -> " +
                    (ok ? "OK " : "BLAD (brak jednostki?) ") + v);
      }
    });
    console.log("[+] parser czasu @ base+0xf79d60");
  } catch (e) { console.log("[!] nie podpialem parsera czasu: " + e.message); }

  // Migawka polaczenia: 0xf3a580 (slot 0 vtable conn 0x1416d41f0) leci co klatke dla
  // kazdego polaczenia. Logujemy tylko ZMIANY progow i stanu - widac, w ktorym momencie
  // (np. po naszym preAuth) idle zmienia sie z domyslnych 40000 ms.
  // Domyslnie WYLACZONE: zadanie spelnione (run-15: idle 40000 -> 90000 ms po preAuth),
  // a to hook CO KLATKE w watku glownym. Dwa zgony gry z abortem wewnatrz
  // frida-agent.dll (0xc0000409, 2026-09-13 01:58 i 12:59, bez ramek gry na stosie)
  // wypadly przy odpinaniu Fridy od dzialajacej gry - goracy hook to zbedne ryzyko.
  // Wlaczac tylko do diagnozy progow polaczenia.
  const CONN_SNAPSHOT = false;
  const connSnap = new Map();
  let connSnapLogs = 0;
  if (!CONN_SNAPSHOT) console.log("[*] migawka polaczenia WYLACZONA (CONN_SNAPSHOT=false)");
  if (CONN_SNAPSHOT) try {
    Interceptor.attach(base.add(0xf3a580), {
      onEnter() {
        if (connSnapLogs >= 60) return;
        const c = this.context.rcx;
        let s;
        try {
          s = "stan[+0x30]=" + c.add(0x30).readU32() +
              " idle[+0x2fc]=" + c.add(0x2fc).readU32() + "ms" +
              " ping[+0x2f8]=" + c.add(0x2f8).readU32() + "ms" +
              " req[+0x1c4]=" + c.add(0x1c4).readU32() + "ms";
        } catch (e) { return; }
        const k = c.toString();
        if (connSnap.get(k) === s) return;
        connSnap.set(k, s);
        connSnapLogs++;
        console.log("[conn " + k + "] " + s);
      }
    });
    console.log("[+] migawka polaczenia @ base+0xf3a580");
  } catch (e) { console.log("[!] nie podpialem migawki polaczenia: " + e.message); }

  // ============ CRASH GUARD: NULL callback w dyspozytorze notyfikacji =========
  // 0xf6c5f0(rcx=dispatcher, rdx=funkcja-callback, r8=kontekst): petla po
  // listenerach robi `call r14` gdzie r14=rdx. W teardownie polaczenia rdx bywa
  // NULL -> call 0 -> rip=0 -> access-violation (nasz crash w kazdym przebiegu).
  // Podmieniamy NULL na no-op: gra PRZEZYWA teardown, dzieki czemu zobaczymy, co
  // robi DALEJ po tym, jak sama zamknela polaczenie Blaze po postAuth - czy laczy
  // sie ponownie (rozlaczenie byloby normalnym krokiem Blaze), idzie do menu, czy
  // stoi. To rozstrzyga, czy crash to skutek uboczny normalnego rozlaczenia, czy
  // rozlaczenie jest realna blokada. Guard rusza TYLKO gdy rdx==NULL, wiec nie
  // rusza normalnych notyfikacji (0xf6c5f0 wolane jest tez z waznym callbackiem).
  const noopCb = new NativeCallback(function () {}, "void", ["pointer", "pointer"]);
  let guardHits = 0;
  try {
    Interceptor.attach(base.add(0xf6c5f0), {
      onEnter() {
        if (this.context.rdx.isNull()) {
          this.context.rdx = noopCb;
          if (guardHits++ < 8)
            console.log("[guard] 0xf6c5f0 rdx=NULL -> no-op (crash unikniety) #" + guardHits);
        }
      }
    });
    console.log("[+] crash guard @ base+0xf6c5f0");
  } catch (e) { console.log("[!] nie podpialem crash guard: " + e.message); }

  // ============ PRZEJSCIE STANU POLACZENIA ("conn") - powod rozlaczenia =======
  // Z crasha 14:07/14:31 (dezasemblacja): teardown (0xf4de00) jest SKUTKIEM
  // rozlaczenia, ktore idzie z PETLI AKTUALIZACJI CO KLATKE (0xefe99d -> 0xefa5f5
  // -> 0xf2505d), nie z obslugi przychodzacej wiadomosci. Konczy sie w funkcji
  // stanu polaczenia 0xf37f10, ktora:
  //   - przy flagach [rdi+0x339]=[rdi+0x33a]=[rdi+0x33c]=0 ustawia deadline
  //     [rdi+0x3b0] = [rdi+0x300] * 1000 (czyli [rdi+0x300] to timeout w SEKUNDACH)
  //   - loguje pod kategoria "conn", przekazujac esi = KOD STANU/POWODU.
  // Ten hook czyta esi (powod) i [rdi+0x300] (timeout, s) - jednoznacznie odroznia
  // idle-timeout (duza wartosc, np. 90 = connIdleTimeout) od timeoutu RPC
  // (30 = defaultRequestTimeout) od natychmiastowego zamkniecia. Fires rzadko
  // (tylko na zmianach stanu), wiec nie zasmieca logu jak poprzedni 0xf25000.
  let connSeen = 0;
  try {
    Interceptor.attach(base.add(0xf37f10), {
      onEnter(args) {
        const conn = args[0];
        const reason = this.context.rdx.toInt32();   // edx = 2. arg = powod/stan
        let tout = -1, f = "?", st = -1, thr = -1;
        try {
          tout = conn.add(0x300).readU32();
          f = conn.add(0x339).readU8() + "/" + conn.add(0x33a).readU8() +
              "/" + conn.add(0x33c).readU8();
          st = conn.add(0x30).readU32();              // [conn+0x30] = stan polaczenia
          thr = conn.add(0x2fc).readU32();            // [conn+0x2fc] = prog z 0xf3a580
        } catch (e) {}
        console.log("\n@@@ STAN POLACZENIA (0xf37f10) powod=" + reason +
                    " stan[+0x30]=" + st + " prog[+0x2fc]=" + thr +
                    " timeout=" + tout + "s  flagi[339/33a/33c]=" + f);
        if (connSeen++ < 4) {
          try {
            const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
              .slice(0, 8)
              .map(a => a + "  (base+" + a.sub(base) + ")").join("\n     ");
            console.log("   STOS:\n     " + bt);
          } catch (e) {}
        }
      }
    });
    console.log("[+] stan polaczenia (conn) @ base+0xf37f10");
  } catch (e) { console.log("[!] nie podpialem stanu polaczenia: " + e.message); }

  // --- podsluch polaczen sieciowych: pokaz KAZDY adres:port, do ktorego gra
  //     sie laczy (redirector, Blaze). To ujawni, dokad idzie po zdobyciu tokenu.
  function sockLog(sa, label) {
    try {
      const fam = sa.readU16();
      if (fam === 2) { // AF_INET
        const port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
        const ip = sa.add(4).readU8() + "." + sa.add(5).readU8() + "." +
                   sa.add(6).readU8() + "." + sa.add(7).readU8();
        console.log("[" + label + "] -> " + ip + ":" + port);
      }
    } catch (e) {}
  }
  // Frida 17: eksporty przez instancje modulu / getGlobalExportByName.
  function findExport(mod, name) {
    try { const m = Process.getModuleByName(mod); if (m && m.getExportByName) return m.getExportByName(name); } catch (e) {}
    try { if (Module.getGlobalExportByName) return Module.getGlobalExportByName(name); } catch (e) {}
    try { if (Module.getExportByName) return Module.getExportByName(mod, name); } catch (e) {}
    return null;
  }
  function hookConnect(name) {
    let ex = findExport("ws2_32.dll", name) || findExport("wsock32.dll", name);
    if (ex) {
      Interceptor.attach(ex, { onEnter(args) { sockLog(args[1], name); } });
      console.log("[+] net " + name + " @ " + ex);
    } else {
      console.log("[!] nie znalazlem eksportu " + name);
    }
  }
  hookConnect("connect");
  hookConnect("WSAConnect");

  // --- UDP: test QoS Blaze idzie po UDP, nie TCP. Jesli gra po preAuth sonduje
  //     ping-site'y, zobaczymy tu dokad i ile razy. CISZA tutaj = hipoteza QoS
  //     upada i blokada siedzi w danych sesji (UserSessionExtendedData).
  //     sendto(s, buf, len, flags, to, tolen) - adres celu w args[4].
  const udpSeen = {};                       // adres -> licznik (nie zalewamy logu)
  function hookSendto(name, addrArgIdx) {
    const ex = findExport("ws2_32.dll", name) || findExport("wsock32.dll", name);
    if (!ex) { console.log("[!] nie znalazlem eksportu " + name); return; }
    Interceptor.attach(ex, {
      onEnter(args) {
        try {
          const sa = args[addrArgIdx];
          if (sa.isNull()) return;
          if (sa.readU16() !== 2) return;   // tylko AF_INET
          const port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
          const ip = sa.add(4).readU8() + "." + sa.add(5).readU8() + "." +
                     sa.add(6).readU8() + "." + sa.add(7).readU8();
          const key = name + " " + ip + ":" + port;
          udpSeen[key] = (udpSeen[key] || 0) + 1;
          // pierwsze 3 pakiety na adres logujemy z trescia, potem co 50.
          if (udpSeen[key] <= 3 || udpSeen[key] % 50 === 0) {
            let head = "";
            try { head = bin2hex(args[1].readByteArray(Math.min(args[2].toInt32(), 32))); } catch (e) {}
            console.log("[UDP " + name + " #" + udpSeen[key] + "] -> " + ip + ":" + port +
                        "  " + args[2].toInt32() + " B  " + head);
          }
        } catch (e) {}
      }
    });
    console.log("[+] net " + name + " @ " + ex);
  }
  hookSendto("sendto", 4);
  hookSendto("WSASendTo", 6);              // (s, bufs, cnt, sent, flags, to, tolen, ...)

  // recvfrom: czy sonda QoS dostaje ODPOWIEDZ. Jesli gra wysyla, a nic nie wraca,
  // to nasz serwer musi odbijac pakiety QoS (responder UDP).
  const rfEx = findExport("ws2_32.dll", "recvfrom");
  if (rfEx) {
    Interceptor.attach(rfEx, {
      onEnter(a) { this.buf = a[1]; },
      onLeave(ret) {
        const n = ret.toInt32();
        if (n > 0) {
          let head = "";
          try { head = bin2hex(this.buf.readByteArray(Math.min(n, 32))); } catch (e) {}
          console.log("[UDP recvfrom] " + n + " B  " + head);
        }
      }
    });
    console.log("[+] net recvfrom @ " + rfEx);
  }

  // recv: czy gra ODCZYTUJE nasza odpowiedz? (zaszyfrowane, ale dlugosc/timing
  // powie, czy cokolwiek przyszlo po getServerInstance). Logujemy tylko zwroty >0.
  const recvEx = findExport("ws2_32.dll", "recv");
  if (recvEx) {
    Interceptor.attach(recvEx, {
      onEnter(a) { this.buf = a[1]; },
      onLeave(ret) {
        const n = ret.toInt32();
        if (n > 0) {
          let head = "";
          try { head = this.buf.readByteArray(Math.min(n, 24)); } catch (e) {}
          console.log("[recv] " + n + " B  " + (head ? bin2hex(head) : ""));
        }
      }
    });
    console.log("[+] net recv @ " + recvEx);
  }
  function bin2hex(ab) {
    const u = new Uint8Array(ab); let s = "";
    for (let i = 0; i < u.length; i++) s += ("0" + u[i].toString(16)).slice(-2);
    return s;
  }

  // --- DNS: kazda nazwa hosta, ktora gra probuje rozwiazac. Sam getaddrinfo nie
  //     wystarcza - DirtySDK/ProtoSSL moze isc przez gethostbyname albo wersje W.
  //     Linie maja prefiks "[dns <funkcja>]" (getaddrinfo woła wewnetrznie
  //     GetAddrInfoW, wiec ta sama nazwa moze wyjsc dwa razy).
  function hookDns(mod, name, wide) {
    const ex = findExport(mod, name);
    if (!ex) { console.log("[!] nie znalazlem eksportu " + mod + "!" + name); return; }
    try {
      Interceptor.attach(ex, {
        onEnter(args) {
          try {
            const h = wide ? args[0].readUtf16String() : args[0].readCString();
            if (h) console.log("[dns " + name + "] " + h);
          } catch (e) {}
        }
      });
      console.log("[+] dns " + name + " @ " + ex);
    } catch (e) { console.log("[!] nie podpialem " + name + ": " + e.message); }
  }
  hookDns("ws2_32.dll", "getaddrinfo", false);
  hookDns("ws2_32.dll", "GetAddrInfoW", true);
  hookDns("ws2_32.dll", "GetAddrInfoExW", true);
  hookDns("ws2_32.dll", "gethostbyname", false);
  hookDns("dnsapi.dll", "DnsQuery_A", false);
  hookDns("dnsapi.dll", "DnsQuery_W", true);
  hookDns("dnsapi.dll", "DnsQuery_UTF8", false);

  // ============ INICJALIZACJA BYTEVAULT (0xf71b40) ============
  // Wolane z 0xa1bcbd przy przejsciu stanu online gry 9 -> 10 (0xa1bb00):
  //   0xf71b40(rcx=[hub+0xc50], rdx=char* bytevaultHostname, r8w=bytevaultPort, r9b=secure)
  // Klucze bierze z CONF (bytevaultPort przez atoi, bytevaultSecure == "true",
  // bytevaultHostname jako string), a gdy ich brak - z domyslnych gry. Linia mowi,
  // czy gra w ogole dochodzi do ByteVault i pod jaki adres.
  try {
    Interceptor.attach(base.add(0xf71b40), {
      onEnter() {
        let h = "?";
        try { h = this.context.rdx.readCString(128).split("\0")[0]; } catch (e) {}
        console.log("[bytevault] init host='" + h + "' port=" +
                    (this.context.r8.toInt32() & 0xffff) +
                    " secure=" + (this.context.r9.toInt32() & 0xff));
      }
    });
    console.log("[+] init ByteVault @ base+0xf71b40");
  } catch (e) { console.log("[!] nie podpialem init ByteVault: " + e.message); }

  console.log("[*] gotowe - wejdz w grze w ONLINE.");
}
