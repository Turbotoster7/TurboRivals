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

  function hookLogger(rva) {
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

  // Sonda przeplywu redirectora: getTypeDescription klas zadania i odpowiedzi.
  // Jesli "ServerInstanceInfo::getTypeDescr" sie odpala -> gra DEKODUJE nasza
  // odpowiedz (framing Fire2 OK). Jesli nie -> odrzuca juz na ramce/msgId.
  hookFn(ptr("0xf8a0f0"), "ServerInstanceRequest (encode zadania)", true);
  hookFn(ptr("0xf8a0e0"), "ServerInstanceInfo (decode?)");
  hookFn(ptr("0xf8a0c0"), "ServerInstance (decode?)");
  hookFn(ptr("0xf8a0d0"), "ServerInstanceError (decode?)");
  hookFn(ptr("0xf8a090"), "ServerAddressInfo (decode?)");

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
