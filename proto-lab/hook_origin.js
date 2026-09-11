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
  let crashLogged = false;
  const MOD_SPAN = 0x2000000;
  function inMod(a) {
    return a.compare(base) >= 0 && a.compare(base.add(MOD_SPAN)) < 0;
  }
  Process.setExceptionHandler(function (details) {
    if (crashLogged) return false;        // pierwszy wyjatek jest ten wazny
    crashLogged = true;
    const addr = details.address;
    console.log("\n########## WYJATEK ##########");
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
  hookLogger(ptr("0xec1880"));

  // Dodatkowo: kluczowe funkcje auth/online - sygnalizacja wejscia + wynik.
  let btDone = false;
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
        if (backtrace && !btDone) {
          btDone = true;
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
  hookFn(ptr("0xebd140"), "OriginRequestTicket");

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
  hookFn(ptr("0xf211e0"), "PostAuthResponse (decode naszej odp. postAuth?)");
  hookFn(ptr("0xf66220"), "UserSessionExtendedDataUpdate (decode notyfikacji)");
  hookFn(ptr("0xf65f90"), "NotifyUserAdded (decode UserAdded)");

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

  const gai = findExport("ws2_32.dll", "getaddrinfo");
  if (gai) {
    Interceptor.attach(gai, {
      onEnter(args) {
        try { const h = args[0].readCString(); if (h) console.log("[dns] " + h); } catch (e) {}
      }
    });
    console.log("[+] net getaddrinfo @ " + gai);
  } else {
    console.log("[!] nie znalazlem getaddrinfo");
  }

  console.log("[*] gotowe - wejdz w grze w ONLINE.");
}
