// Frida - a look at the INTERNAL logs of the Origin SDK in NFS14.exe.
// Finding: functions 0xee2370 and 0xec1880 are LOGGERS (rcx=level, rdx=pointer to
// text). We hook them and print the log text -> we see the whole sequence of Origin
// SDK calls during the online attempt and the moment of the "offline" decision.
//
// Run: python proto-lab/frida_run.py

const MOD = "NFS14.exe";
let base = null;
try {
  if (typeof Process.getModuleByName === "function") base = Process.getModuleByName(MOD).base;
  else if (typeof Process.findModuleByName === "function") { const m = Process.findModuleByName(MOD); base = m && m.base; }
  else if (typeof Module.getBaseAddress === "function") base = Module.getBaseAddress(MOD);
} catch (e) { console.log("[!] error looking up the base: " + e); }

// Noise to filter out (called every frame) - we do not print these.
const SPAM = ["OriginUpdate entered", "OriginReadEnumeration", "OriginGetEnumerateStatus",
              "OriginRegisterEventCallback", "OriginUpdate"];

function isSpam(s) {
  for (const w of SPAM) if (s.indexOf(w) >= 0) return true;
  return false;
}

if (!base) {
  console.log("[!] module " + MOD + " not found - is the game running?");
} else {
  console.log("[*] " + MOD + " base = " + base);

  // ================= EXCEPTION HANDLER - FIRST =================
  // Set up BEFORE the hooks: if any hook fails to attach, the handler still
  // works. (It used to be at the end of the file, and a failed Interceptor.attach
  // aborted the whole script, so there was nobody left to catch the crash.)
  const MOD_SPAN = 0x2000000;
  function inMod(a) {
    return a.compare(base) >= 0 && a.compare(base.add(MOD_SPAN)) < 0;
  }
  // Exception reporting. MIND the trap that already fooled us once:
  // we used to log ONLY the first exception, and at startup the game throws
  // harmless first-chance exceptions from outside the module (SEH/C++, e.g. 0x7ffc...).
  // Such an exception ate the only slot and the real access violation was NOT shown -
  // in the A/B run of 2026-09-12 it looked as if variant A did not crash at all,
  // although it ended exactly like B. Now: every access violation is reported
  // (up to LIMIT_AV), and exceptions of other types only once and on one line,
  // so they do not drown out the log.
  let avLogged = 0, otherLogged = 0;
  const LIMIT_AV = 5;
  Process.setExceptionHandler(function (details) {
    const isAV = details.type === "access-violation";
    if (!isAV) {
      if (otherLogged++ === 0) {
        console.log("[first-chance exception, type=" + details.type + " @ " +
                    details.address + " - usually harmless, logged only once]");
      }
      return false;
    }
    if (avLogged++ >= LIMIT_AV) return false;
    const addr = details.address;
    console.log("\n########## EXCEPTION #" + avLogged + " ##########");
    console.log("  type:    " + details.type);
    console.log("  address: " + addr +
                (inMod(addr) ? "  (base+0x" + addr.sub(base).toString(16) + ")"
                             : "  (OUTSIDE the game module)"));
    if (details.memory) {
      console.log("  memory: operation=" + details.memory.operation +
                  " address=" + details.memory.address);
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
      console.log("  STACK:\n     " + bt);
    } catch (e) { console.log("  bt err " + e); }
    console.log("#############################\n");
    return false;                          // pass it on - the game will die anyway
  });
  console.log("[+] exception handler armed (will show the crash address)");

  function hookLogger(rva) {
    try {
      hookLoggerUnsafe(rva);
    } catch (e) {
      console.log("[!] could not hook the logger @ base+0x" + rva.toString(16) +
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
          // level 0xa0.... = Origin error -> we flag it
          const mark = lvl.indexOf("a0") === 0 ? "  <<< ERROR" : "";
          console.log("[log lvl=" + lvl + "] " + s + mark);
        }
      }
    });
    console.log("[+] logger @ " + addr);
  }

  hookLogger(ptr("0xee2370"));

  // 0xec1880 is NOT a logger - it is the "does Core (the EA App) respond" check:
  // no arguments, result in al. OriginRequestTicket (0xebd169) calls it right after
  // the log and on al==0 takes the error path. Hooked here earlier as a logger, it
  // read rdx, which after the previous call still held THE SAME text - that is why
  // every Origin log line came out TWICE in our logs.
  let coreChecks = 0, coreFails = 0;
  try {
    Interceptor.attach(base.add(0xec1880), {
      onLeave(ret) {
        const ok = (ret.toInt32() & 0xff) !== 0;
        if (coreChecks++ < 6 || (!ok && coreFails++ < 6)) {
          console.log("[core] EA App connected? " + (ok ? "YES" : "NO"));
        }
      }
    });
    console.log("[+] IsCoreConnected @ base+0xec1880");
  } catch (e) { console.log("[!] could not hook IsCoreConnected: " + e.message); }

  // Additionally: the key auth/online functions - signal entry + result.
  // Backtrace: ONCE PER HOOK, not once for the whole script. There used to be a
  // shared flag here, and the first hook with backtrace=true (ServerInstanceRequest,
  // which fires already at the redirector) took the only stack dump -
  // FullLoginResponse never printed its own, although it was exactly its backtrace
  // that was supposed to give us the RVA of the generic heat2 decoder (TDF_READER_RVA below).
  const btDone = {};
  function hookFn(rva, name, backtrace) {
    // Every hook in try/catch: Frida can refuse ("unable to intercept
    // function") when we attach before the game unpacks its code. Without it ONE
    // failed hook aborted the whole script and the remaining probes were never set up.
    try {
      hookFnUnsafe(rva, name, backtrace);
    } catch (e) {
      console.log("[!] could not hook " + name + " @ base+0x" + rva.toString(16) +
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
  // Origin token injection - DISABLED (dead end for now).
  // Signature established from the caller 0x9574c0:
  //   OriginRequestTicket(rcx=Core, rdx=callback @0x140955a90, r8=context)
  // so the function is ASYNCHRONOUS: the token is NOT written into a buffer, but
  // delivered by CALLING the callback (0x140955a90) with a token object once the
  // LSX reply arrives. Our attempt to write into the "buffer" hit the callback
  // pointer (code) -> error. A correct injection = build a token object and
  // call the callback with the right context - complex, postponed. For now we rely
  // on the real token from the EA App (login goes through when the token arrives in time).
  const INJECT_TOKEN = false;
  // We do NOT hook OriginRequestTicket (0xebd140) with attach when INJECT_TOKEN:
  // this function ends with a TAIL-JMP to 0xec3c80, which we REPLACE. A simultaneous
  // attach on 0xebd140 garbled the registers at the tail-jmp (crash 12.09, outTok
  // pointed into code). The LSX request/response is logged by logger 0xee2370 anyway.
  if (!INJECT_TOKEN)
    hookFn(ptr("0xebd140"), "OriginRequestTicket");

  // ============ Origin SDK error report ===================================
  // 0xebd800(rcx = code, rdx = description, r8 = file, r9 = line) builds
  // '%s(%d) Origin Error: 0x%08X'. It is the ONLY place where you can see how an
  // Origin request ended: the error paths of OriginRequestTicket
  // (0xebd1e0) and of the LSX ticket (0xec3d8c) jump exactly here. Without this hook
  // a failure was just silence in our log.
  try {
    Interceptor.attach(base.add(0xebd800), {
      onEnter(args) {
        let desc = "", file = "";
        try { desc = args[1].readCString() || ""; } catch (e) {}
        try { file = args[2].readCString() || ""; } catch (e) {}
        console.log("\n!!! ORIGIN ERROR 0x" + args[0].toUInt32().toString(16) +
                    "  " + desc + "   (" + file + ":" + args[3].toUInt32() + ")");
      }
    });
    console.log("[+] Origin error report @ base+0xebd800");
  } catch (e) { console.log("[!] could not hook the error report: " + e.message); }

  // ============ ORIGIN TOKEN INJECTION (bypassing the EA App) ==============
  // Why: when the EA App considers the game not activated, it does NOT answer the LSX
  // GetAuthToken. The game gets no ticket, never sends the Blaze login (1/152)
  // and shows the activation window - that is how the run of 2026-09-12 12:39 ended.
  // Our server does NOT VALIDATE the token (it accepts any AUTH), so it is enough
  // to give the game the same string the EA App issued back when it still worked.
  //
  // Where (from disassembling the dump, not from guessing): OriginRequestTicket 0xebd140
  // checks Core and jumps to
  //     0xec3c80(rcx=Core, rdx=user handle, r8=char** out, r9=size_t* outLen)
  // which allocates a 0x1a8 B context, stores r8/r9 and callback 0xec3dd0 in it
  // and WAITS in 0xec1770 with timeout -1 for the LSX reply. The whole callback is:
  //     mov [r8], [rax]        ; *out    = char* token
  //     mov [r9], [rax+0x10]   ; *outLen = length
  //     xor eax, eax           ; 0 = success
  // The token comes back as a POINTER to text, so we fake neither LSX, nor its
  // encryption, nor the event in the context - we hand over a pointer and zero.
  //
  // Why replace and not attach: the original waits with timeout -1, so with a
  // silent EA App onLeave would never fire, and the game would hang.
  //
  // Token: exactly the base64 the EA App issued on 2026-09-11 21:54. In the successful
  // login the game passed it to Blaze UNCHANGED (log-login.txt:66
  // AUTH='QVQx...'), so there is no encoding to reproduce here.
  // Expiry does not matter - OUR server accepts it.
  // DISABLED 2026-09-12 afternoon. The 13:59 run (launched through the EA App)
  // showed TWO things: (1) the EA App works again - the game passed the activation gate,
  // so the GetAuthToken token flows normally and the injection is unnecessary; (2) the
  // injection itself is BROKEN - the callback threw "access violation accessing
  // 0x140955a90" (a CODE address, not a buffer) on the outTok.writePointer line, returned
  // garbage (rax=0xeb00000000) and most likely IT caused the crash. Cause:
  // Interceptor.replace on 0xec3c80 collides with the attach on OriginRequestTicket
  // (0xebd140), which ends with a TAIL-JMP to 0xec3c80 - the argument registers
  // (r8/r9 = output buffers) come out garbled. To fix it for Track B we would have to
  // either remove the attach from 0xebd140, or hook the completion callback 0xec3dd0
  // instead of replacing. For now we rely on a working EA App (as in the successful login
  // of 11.09), to get to the postAuth blocker.
  const ORIGIN_TOKEN =
    "QVQxOjMuMDozLjA6MjQwOnd4VWwxOHRXOHNxQ1JTZFU5cU9UM1kyZTMwamxSSjZqdVczOjc0NzA0OnNlMGcw";
  let tokenBuf = null;          // the references MUST be global: a buffer and callback
  let ticketCb = null;          // freed by the GC = the game would read garbage
  let ticketHits = 0;
  if (INJECT_TOKEN) {
    try {
      tokenBuf = Memory.allocUtf8String(ORIGIN_TOKEN);
      ticketCb = new NativeCallback(function (core, user, outTok, outLen) {
        ticketHits++;
        // CRASH RESISTANCE (lesson from 12.09): on the first call the arguments
        // can be different (init), and outTok pointed into CODE -> the write crashed the
        // game. Every write in try/catch: when the pointer is not writable, we do NOT write
        // and return error a2000004 (just like the original 0xec3cc0 with no buffer) -
        // the game handles that instead of crashing. On the real call outTok/
        // outLen are writable and the token goes in.
        if (outTok.isNull() || outLen.isNull())
          return 0xa2000004 | 0;
        try {
          outTok.writePointer(tokenBuf);
          outLen.writeU64(ORIGIN_TOKEN.length);
        } catch (e) {
          if (ticketHits <= 3)
            console.log("[token] call #" + ticketHits + " has a non-writable " +
                        "buffer (" + outTok + ") - skipping, returning an error");
          return 0xa2000004 | 0;
        }
        if (ticketHits <= 3) {
          console.log("\n[token] SUBSTITUTING the Origin token (" + ORIGIN_TOKEN.length +
                      " B) instead of asking the EA App   [call #" + ticketHits + "]");
        }
        return 0;
      }, "int", ["pointer", "pointer", "pointer", "pointer"]);
      Interceptor.replace(base.add(0xec3c80), ticketCb);
      console.log("[+] TOKEN INJECTION active (0xec3c80 replaced)");
    } catch (e) {
      console.log("[!] could not replace 0xec3c80: " + e.message);
    }
  } else {
    console.log("[*] token injection DISABLED (INJECT_TOKEN=false)");
  }

  // ============ QoS coordinator reply parser (DirtySDK qosapi) ========
  // _QosApiParseResponse @0xfdb070(rcx = connection struct, rdx = QosApiRef).
  // The HTTP reply buffer lives at *(QosApiRef+0x128) + 0x112, and the return code
  // tells UNAMBIGUOUSLY whether the game accepted our XML:
  //    0  -> accepted, UDP probes should go out to <qosport>
  //   -1  -> XmlFind hit, but validation failed (0xfdb3f1): qosport == 0 or
  //          requestid == 0, or for qtyp==2 probesize == 0 / numprobes < 2
  //   -2  -> none of the <firewall>/<firetype>/<qos> elements was found
  //          (that was the case when we sent the TagField format "qos.numprobes=1 ...")
  function hookQosParse(rva) {
    try {
      const addr = base.add(rva);
      Interceptor.attach(addr, {
        onEnter(args) {
          this.ref = args[1];
          let txt = "(not read)";
          try {
            txt = this.ref.add(0x128).readPointer().add(0x112).readCString(512);
          } catch (e) { txt = "(error reading the buffer: " + e.message + ")"; }
          console.log("");
          console.log(">>> QosApiParseResponse, reply buffer:");
          console.log("    " + txt);
        },
        onLeave(ret) {
          const rc = ret.toInt32();
          const why = rc === 0 ? "XML ACCEPTED - UDP probes should go out"
                    : rc === -1 ? "validation rejected it (qosport/requestid == 0?)"
                    : rc === -2 ? "no <qos>/<firetype>/<firewall> element found"
                    : "unknown code";
          console.log("<<< QosApiParseResponse = " + rc + "  (" + why + ")");
          try {
            const st = this.ref.add(0x128).readPointer();
            console.log("    QoS state: qtyp=" + st.add(0x1118).readU32() +
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
      console.log("[!] could not hook QosApiParseResponse (" + e.message + ")");
    }
  }
  hookQosParse(ptr("0xfdb070"));

  // ================= STEP A: tracing the TDF (heat2) decoder =================
  // Goal: log EVERY tag the decoder reads from our reply. The last tag before an
  // error = the missing/bad field. There is no crash now, so it serves to
  // confirm WHICH fields the game really reads from postAuth/login.
  //
  // The decoder is called indirectly (vtable), so we get its address from the
  // BACKTRACE of the decode probe (below). Once we know it, we put the RVA here and
  // the script starts logging tags. Until then the decode probes' backtrace points to the right function.
  const TDF_READER_RVA = null;   // e.g. ptr("0xf8a200") - set it from the backtrace

  function decodeTag(raw) {
    // 24-bit tag -> 4 characters (6 bits/char, 0=space). Mirror of pe_probe.
    let s = "";
    for (const sh of [18, 12, 6, 0]) {
      const c = (raw >>> sh) & 0x3f;
      s += (c === 0) ? " " : String.fromCharCode(c + 0x20);
    }
    return s;
  }
  function tagFromU32(v) {
    // A wire tag is 3 bytes; in a register it can be raw (0x00TTTTTT) or <<8.
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
        // We do not know the signature - we log tag candidates from the argument registers.
        const cands = [];
        for (const [nm, reg] of [["rcx", this.context.rcx], ["rdx", this.context.rdx],
                                 ["r8", this.context.r8], ["r9", this.context.r9]]) {
          const lo = reg.toUInt32();
          const t = tagFromU32(lo);
          if (t.indexOf("?(") !== 0) cands.push(nm + "=" + t);
        }
        console.log("[TDF tag] " + (cands.length ? cands.join("  ") : "no readable tag"));
      }
    });
    console.log("[+] TDF reader trace @ " + addr);
  }
  if (TDF_READER_RVA !== null) traceTdfReader(TDF_READER_RVA);

  // Redirector flow probe: getTypeDescription of the request and reply classes.
  // If "ServerInstanceInfo::getTypeDescr" fires -> the game DECODES our
  // reply (Fire2 framing OK). If not -> it rejects it already at the frame/msgId.
  hookFn(ptr("0xf8a0f0"), "ServerInstanceRequest (request encode)", true);
  hookFn(ptr("0xf8a0e0"), "ServerInstanceInfo (decode?)");
  hookFn(ptr("0xf8a0c0"), "ServerInstance (decode?)");
  hookFn(ptr("0xf8a0d0"), "ServerInstanceError (decode?)");
  hookFn(ptr("0xf8a090"), "ServerAddressInfo (decode?)");
  // login / postAuth / notification after login.
  // backtrace=true on the FullLoginResponse decode: the stack reveals the GENERIC heat2
  // decoder (the function right above this one on the stack, in the NFS14 module). Put its
  // RVA into TDF_READER_RVA above to log every tag.
  hookFn(ptr("0xf0c0a0"), "FullLoginResponse (login reply decode) <- BACKTRACE to the decoder", true);
  hookFn(ptr("0xf211d0"), "PostAuthRequest (encode -> the game sends postAuth!)");
  // backtrace=true (run-20): the stack at the postAuth reply decode will show the Util reply
  // handler and the postAuth completion callback - onAuthenticated should come from there.
  hookFn(ptr("0xf211e0"), "PostAuthResponse (decode of our postAuth reply?)", true);
  // backtrace=true: in the 14:07 run getTypeDescr of FullLoginResponse (0xf0c0a0)
  // did NOT fire, but THIS notification and NotifyUserAdded DECODE TDF and definitely
  // fire. A backtrace from either one reveals the generic heat2 decoder
  // (the frame right above, in the module) -> TDF_READER_RVA.
  hookFn(ptr("0xf66220"), "UserSessionExtendedDataUpdate (notification decode)", true);
  hookFn(ptr("0xf65f90"), "NotifyUserAdded (decode UserAdded)", true);

  // ============ the joiner's decision to leave the game (15.09) =====================
  // log-30..32: a player who joined someone else's game sends, ~230 ms after the entitlement check,
  // startMatchmaking with AGAM.GIDL = [that game] and removePlayer - regardless of who the host is.
  // getTypeDescription of the request class fires when it is encoded, so a backtrace of EVERY
  // call (up to the limit) shows the NFS code that decided to leave. The first
  // StartMatchmakingRequest is the join - the next one is the interesting one. Entitlements = the
  // decode of the listUserEntitlements2 reply, i.e. the code that checks those entitlements.
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
          console.log("\n[decision] " + name + " #" + n + " (" +
                      new Date().toISOString().substr(11, 12) + ")\n     " + bt);
        }
      });
      console.log("[+] backtrace of every call (max " + limit + "): " + name +
                  " @ base+0x" + rva.toString(16));
    } catch (e) {
      console.log("[!] could not hook " + name + " @ base+0x" + rva.toString(16) + " (" + e.message + ")");
    }
  }
  hookBtEach(ptr("0xf66100"), "StartMatchmakingRequest (encode 4/13)", 8);
  hookBtEach(ptr("0xf66010"), "RemovePlayerRequest (encode 4/11)", 6);
  hookBtEach(ptr("0xf0c060"), "Entitlements (decode of the 1/29 reply)", 8);

  // ============ NFS matchmaking state machine (frida-33 + disassembly) =========
  // 0xa3b590 builds the criteria and calls the SDK's startMatchmaking with the result callback 0xa3c5f0
  // (this=rcx: [+0x98] MM session id, the callback stores [+0x9d]=1 done, [+0xa0]=edx result,
  // [+0xb0]=r9). 0xa3c1a0 checks "finished and OK" ([+0x9d] != 0 && [+0xa0] == 0).
  // 0xa11400 = entering the "retry matchmaking" state: counter [[this+0x110]+0x40], mode
  // [[this+0x130]+0x418], limit from the "matchmaking_retries" tweakable. 0xa6dfe0(rcx=machine,
  // rdx=state key) = state transition - we log the caller to find the condition.
  function hookSafe(rva, name, cb) {
    try { Interceptor.attach(base.add(rva), cb); console.log("[+] " + name + " @ base+0x" + rva.toString(16)); }
    catch (e) { console.log("[!] could not hook " + name + " (" + e.message + ")"); }
  }
  hookSafe(ptr("0xa3c5f0"), "MM result (NFS callback)", {
    onEnter(args) {
      const c = this.context;
      let jid = "?", mine = "?";
      try { jid = c.r8.readU32(); mine = c.rcx.add(0x98).readU32(); } catch (e) {}
      console.log("\n[mm-result] edx(result)=" + (c.rdx.toInt32()) + " r9=" + c.r9 + " jobId=" + jid +
                  " expected=" + mine + " this=" + c.rcx + " (" + new Date().toISOString().substr(11, 12) + ")");
    }
  });
  const mmSeen = {};
  // 0xa3c1a0 = MM state update: [+0x9d] done && [+0xa0] != 0 -> failure (key +0x428);
  // otherwise when [+0x9e] != 0: [+0xa4] <= 2 -> success (+0x410), > 2 -> failure (+0x428).
  // Called every frame - we only log a change of the 9d/9e/a0/a4 quadruple.
  hookSafe(ptr("0xa3c1a0"), "MM state update (0xa3c1a0)", {
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
        console.log("[mm-state] " + o + " " + k + " caller base+" + this.returnAddress.sub(base) +
                    " (" + new Date().toISOString().substr(11, 12) + ")");
      }
    }
  });
  hookSafe(ptr("0xa11400"), "MM retry (0xa11400)", {
    onEnter(args) {
      const t = this.context.rcx;
      let n = "?", mode = "?";
      try { n = t.add(0x110).readPointer().add(0x40).readU32(); mode = t.add(0x130).readPointer().add(0x418).readU32(); } catch (e) {}
      console.log("\n[mm-retry] counter=" + n + " mode=" + mode + " this=" + t + " (" +
                  new Date().toISOString().substr(11, 12) + ")");
    }
  });
  // 0xa3c570 = the object's second callback: when r8 == [this+0xb0] (the game from the MM result) it
  // zeroes [+0x98], stores [+0x9e]=1 and [+0xa4]=edx (status). 0xa3c1a0 treats the join as successful only
  // with status <= 2 - here you can see which status the game gets and who provides it (backtrace).
  let st2 = 0;
  hookSafe(ptr("0xa3c570"), "MM game status (0xa3c570)", {
    onEnter(args) {
      const c = this.context;
      let game = "?";
      try { game = c.rcx.add(0xb0).readPointer(); } catch (e) {}
      console.log("\n[mm-status] edx(status)=" + c.rdx.toInt32() + " r8(game)=" + c.r8 + " expected=" + game +
                  " r9=" + c.r9 + " this=" + c.rcx + " (" + new Date().toISOString().substr(11, 12) + ")");
      if (++st2 <= 4) {
        try {
          console.log("     " + Thread.backtrace(c, Backtracer.ACCURATE)
            .map(a => inMod(a) ? "base+" + a.sub(base) : String(a)).join("\n     "));
        } catch (e) { console.log("     bt err " + e); }
      }
    }
  });
  // 0xa1b770 = the "game lost" handler (frida-34): when rdx == [this+0x388] (the tracked game) it leaves
  // the state (vfunc+8 -> transition +0x660 -> "retry MM"), unregisters from the game and zeroes the pointer.
  // On the joiner it fires after the world has loaded - the stack will show what in the SDK removed the game.
  let lostBt = 0;
  hookSafe(ptr("0xa1b770"), "game lost (0xa1b770)", {
    onEnter(args) {
      const c = this.context;
      let tracked = "?";
      try { tracked = c.rcx.add(0x388).readPointer(); } catch (e) {}
      console.log("\n[game-lost] rdx(game)=" + c.rdx + " tracked=" + tracked + " r8=" + c.r8 + " r9=" + c.r9 +
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
  hookSafe(ptr("0xa6dfe0"), "state transition (0xa6dfe0)", {
    onEnter(args) {
      if (++trCount > 400) return;
      const c = this.context;
      const rel = c.rdx.sub(c.rcx).toInt32();
      console.log("[state] machine=" + c.rcx + " key=+0x" + rel.toString(16) +
                  " caller base+" + this.returnAddress.sub(base) + " (" + new Date().toISOString().substr(11, 12) + ")");
      // frida-34: transition +0x660 (00:44:51.581, through the delegate 0xa1b770) ended a successful join and
      // led to "retry MM" - the full stack shows who ordered it. Up to 3 dumps.
      if ((rel === 0x660 || rel === 0x188) && (trBt = (trBt || 0) + 1) <= 3) {
        try {
          console.log("     STACK +0x" + rel.toString(16) + ":\n     " + Thread.backtrace(c, Backtracer.ACCURATE)
            .map(a => inMod(a) ? "base+" + a.sub(base) : String(a)).join("\n     "));
        } catch (e) { console.log("     bt err " + e); }
      }
    }
  });

  // ============ component teardown ==========================
  // base+0xf4de00(rcx = hub, edx = component index): reads the component table
  // at [hub+0x310], indexes it by edx, calls two methods through the vtable and ZEROES
  // the slot (mov qword ptr [r15+rax], 0 @0xf4decd). The index is small - @0xf4def0
  // there is cmp edi,0x10 and its use as a bit number in a mask.
  //
  // Why: in the 2026-09-11 crash (rip=0, operation=execute at address 0) the deepest
  // return frame is base+0xf4df22, i.e. the inside of EXACTLY this function - the game
  // was tearing down a component and jumped through a pointer nobody had set. This
  // hook answers two questions at once: WHICH component is being torn down and WHO
  // ordered it. If the teardown shows up BEFORE the crash and was ordered from handling
  // our postAuth reply - the disconnect is the cause, and the crash the effect.
  let teardownSeen = 0;
  function hookTeardown(rva) {
    try {
      const addr = base.add(rva);
      Interceptor.attach(addr, {
        onEnter(args) {
          const idx = args[1].toInt32() & 0xffff;
          console.log("\n### TEARDOWN of component idx=" + idx + "  hub=" + args[0]);
          if (teardownSeen++ < 5) {
            try {
              const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(a => a + "  (base+" + a.sub(base) + ")").join("\n     ");
              console.log("   WHO ORDERED IT:\n     " + bt);
            } catch (e) { console.log("   bt err " + e); }
          }
        }
      });
      console.log("[+] component teardown @ " + addr);
    } catch (e) {
      console.log("[!] could not hook the teardown (" + e.message + ")");
    }
  }
  hookTeardown(ptr("0xf4de00"));

  // ============ CONNECTION CONFIG READER (connIdleTimeout etc.) =============
  // 0xf419b0 reads pingPeriod/defaultRequestTimeout/connIdleTimeout from the config and
  // stores value/1000 into [conn+0x2f8] / [conn+0x1c4] / [conn+0x2fc] (ms).
  // The drop (0xf3a580) requires state[+0x30]==2 && (now - last activity) >
  // [conn+0x2fc]. With [conn+0x2fc]=0, 1 ms of silence is enough. Cause of the zero (2026-09-13,
  // disassembly): we sent "90" without a unit -> parser 0xf79d60 returns false,
  // getter 0xf39dc0 ignores that -> the reader takes 0. Fix: "90s" (blaze.py).
  // NOTE: in run-14 this hook printed NOTHING, although apart from the constructor it is the only
  // write to [conn+0x2fc]. The getter, parser and conn snapshot hooks below settle this directly.
  try {
    Interceptor.attach(base.add(0xf419b0), {
      onEnter() { this.conn = this.context.rcx; },
      onLeave() {
        try {
          const c = this.conn;
          console.log("[config] 0xf419b0: connIdleTimeout->[+0x2fc]=" +
                      c.add(0x2fc).readU32() + " defaultReqTimeout->[+0x1c4]=" +
                      c.add(0x1c4).readU32() + " state[+0x30]=" + c.add(0x30).readU32());
        } catch (e) { console.log("[config] read error: " + e.message); }
      }
    });
    console.log("[+] connection config reader @ base+0xf419b0");
  } catch (e) { console.log("[!] could not hook the config reader: " + e.message); }

  // Connection config getter 0xf39dc0 = [vtable conn+0x50] (rcx=conn, rdx=char* key,
  // r8=int64* result in us). Lookup 0xf39cb0 looks the key up in the map [conn+0x3a0]; if present,
  // it calls the parser and ALWAYS returns 1 (it ignores the parser's result). Shows WHICH keys the
  // client reads, when, and what value it gets. Line limit, because the getter can be hot.
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
        console.log("[cfg-get] '" + this.key + "' found=" + (retval.toInt32() & 0xff) +
                    " result=" + raw + " us");
      }
    });
    console.log("[+] config getter @ base+0xf39dc0");
  } catch (e) { console.log("[!] could not hook the config getter: " + e.message); }

  // Config lookup 0xf39cb0 = [vtable conn+0x40] (rcx=conn, rdx=char* key, r8=char** result)
  // -> al. All the typed getters (+0x48/+0x50/+0x58) sit on top of it, so you see EVERY
  // key the client asks for - including those we do not send in CONF (found=0).
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
        if (ok) { try { v = " value='" + this.out.readPointer().readCString(64).split("\0")[0] + "'"; } catch (e) { v = " value=?"; } }
        console.log("[cfg-lookup] '" + this.key + "' found=" + ok + v);
      }
    });
    console.log("[+] config lookup @ base+0xf39cb0");
  } catch (e) { console.log("[!] could not hook the config lookup: " + e.message); }

  // ============ STATE OF THE GAME'S ONLINE MACHINE (0xa1bb00) ============
  // 0xa1bb00 = update of the game layer's online manager, every frame (ret 0xa1bb71 is
  // in every Blaze backtrace). [obj+0x20] = state. At 9 and [[obj+0x30]+0x748]->vf+0xd0
  // == true the game moves to 10, reads bytevaultPort/Secure/Hostname from CONF and initializes
  // ByteVault (0xf71b40). After postAuth the game sends nothing and sits on "Logging in" - this
  // observer tells in WHICH state. No hot hook: we catch the object from the first
  // call, detach the hook right away, and read the state with a timer every 1 s (logs changes).
  let onlineObj = null;
  try {
    const onlineL = Interceptor.attach(base.add(0xa1bb00), {
      onEnter() {
        if (onlineObj !== null) return;
        onlineObj = this.context.rcx;
        console.log("[online] the game's online manager object = " + onlineObj);
        setTimeout(() => { try { onlineL.detach(); } catch (e) {} }, 0);
      }
    });
    let lastOnline = null;
    setInterval(() => {
      if (onlineObj === null) return;
      try {
        const s = "state[+0x20]=" + onlineObj.add(0x20).readS32() +
                  " [+0x26]=" + onlineObj.add(0x26).readU8() +
                  " [+0x27]=" + onlineObj.add(0x27).readU8();
        if (s !== lastOnline) { lastOnline = s; console.log("[online] " + s); }
      } catch (e) {}
    }, 1000);
    console.log("[+] online state observer @ base+0xa1bb00 (one-shot hook + 1 s timer)");
  } catch (e) { console.log("[!] could not hook the online observer: " + e.message); }

  // ============ HUB EVENT HANDLER 0xf41560 ("logged in" for the game) ============
  // 0xf41560(rcx=hub, rdx=event, r8d) - registered in 0xf45710 (lea @0xf459fb).
  // It looks the user up by [ev+0x10] (0xf390c0), calls the config reader 0xf419b0, and then
  // ONLY when [ev+0x26] != 0 and [ev+0x20] is neither 4 nor 5 broadcasts to the listeners
  // [hub+0x1b0] slot +0x50 (thunk 0xf52828) = 0xa16a20 in the game = online state 9.
  // In run-17 the game state never reached 9 - this log shows which condition fails.
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
        } catch (e) { s = "read error: " + e.message; }
        console.log("[hub-ev 0xf41560] " + s);
        try { console.log(hexdump(ev, { length: 0x40, header: false, ansi: false })); } catch (e) {}
        // One-off backtrace: the return address in the notification dispatcher 0xf29f90
        // (the block after "call r9") tells WHICH notification called this handler.
        if (!btDone["hub-ev"]) {
          btDone["hub-ev"] = true;
          try {
            console.log("   STACK:\n     " + Thread.backtrace(this.context, Backtracer.ACCURATE)
              .slice(0, 8).map(a => a + "  (base+" + a.sub(base) + ")").join("\n     "));
          } catch (e) {}
        }
      }
    });
    console.log("[+] hub event handler @ base+0xf41560");
  } catch (e) { console.log("[!] could not hook 0xf41560: " + e.message); }

  // ============ WHERE DOES STATE 6 COME FROM? (run-17/18: 2 -> 5 -> 6 right after PostAuthResponse) ============
  // Candidates from static analysis: the game listener 0xa16df0 (->6), error 0xa17780 (code 0x19 -> 6),
  // login start 0xa0f160 (->5 or ->6) and vf+0x10 of the online object, which 0xa1bb00
  // calls in state 5 when NetConnStatus('conn') returns a status starting with '-'.
  // These are all event functions (rare), so no hot hooks. Each one logs the game
  // state at the moment of the call and the stack once - the stack shows what in the SDK called it.
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
          console.log("[ev] " + name + " (game state=" + st + ") " + extra);
          if (!btDone["ev " + name]) {
            btDone["ev " + name] = true;
            try {
              console.log("   STACK:\n     " + Thread.backtrace(this.context, Backtracer.ACCURATE)
                .slice(0, 10).map(a => a + "  (base+" + a.sub(base) + ")").join("\n     "));
            } catch (e) {}
          }
        }
      });
      console.log("[+] event " + name + " @ " + addr);
    } catch (e) { console.log("[!] could not hook " + name + ": " + e.message); }
  }
  const regsOf = c => "rcx=" + c.rcx + " rdx=" + c.rdx + " r8=" + c.r8 + " r9=" + c.r9;
  // the hub listener in the game - successive vtable slots from 0x15cc930
  hookEvent(0xa0da60, "listener[0] 0xa0da60", regsOf);
  hookEvent(0xa0d9d0, "listener[1] 0xa0d9d0", regsOf);
  hookEvent(0xa16df0, "listener[2] 0xa16df0 (->6)", regsOf);
  hookEvent(0xa16f20, "listener[3] 0xa16f20 (->2)", regsOf);
  hookEvent(0xa16a20, "listener[4] 0xa16a20 (->9)", regsOf);
  hookEvent(0xa16f00, "listener[5] 0xa16f00 (1->2)", regsOf);
  hookEvent(0xa0dc70, "listener[6] 0xa0dc70", regsOf);
  hookEvent(0xa17780, "error 0xa17780 (0x19 -> 6)", c => "code(edx)=" + fourcc(c.rdx.toInt32()) + " " + regsOf(c));
  hookEvent(0xa0f160, "login start 0xa0f160 (->5/6)", regsOf);
  // vf+0x10 of the online object (address from its vtable at runtime, once the object is caught)
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

  // ============ HUB: state change 0xf40570 and handler 0xf3feb0 (onAuthenticated) ============
  // run-19: the game's online object is a BlazeStateEventHandler (vtable 0x15cc938: dtor, onConnected
  // 0xa16df0 -> 6, onDisconnected 0xa16f20, onAuthenticated 0xa16a20 -> 9, onDeAuthenticated,
  // onIncompatibleServerVersion). onConnected arrived, onAuthenticated did NOT. They are broadcast
  // (slot +0x18 of the listeners [hub+0x380]) only by:
  //  - 0xf40570(rcx=hub, edx=new state, r8d=user): [hub+0x24]=old state, from state 5 only to 8,
  //    the onAuthenticated branch requires [hub+0x6e2] != 0,
  //  - 0xf3feb0 -> 0xf3fe10: event handler (registered in 0xf45710, functor +0x298).
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
                    c.r8.toInt32() + " [hub+0x6e2]=" + flag + " (game state=" + game + ")");
        if (!btDone["hub setState"]) {
          btDone["hub setState"] = true;
          try {
            console.log("   STACK:\n     " + Thread.backtrace(c, Backtracer.ACCURATE).slice(0, 10)
              .map(a => a + "  (base+" + a.sub(base) + ")").join("\n     "));
          } catch (e) {}
        }
      }
    });
    console.log("[+] hub setState @ base+0xf40570");
  } catch (e) { console.log("[!] could not hook hub setState: " + e.message); }
  hookEvent(0xf3feb0, "hub 0xf3feb0 (-> onAuthenticated)", regsOf);

  // TimeValue parser 0xf79d60 (rcx=int64* result, rdx=char* text) -> al. Segments
  // <number><d|h|m|s|ms>, result in us. A number without a unit = false and nothing stored.
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
        let v = "(nothing stored)";
        if (ok) { try { v = this.out.readS64().toString() + " us"; } catch (e) {} }
        console.log("[cfg-parse] '" + this.s + "' -> " +
                    (ok ? "OK " : "ERROR (missing unit?) ") + v);
      }
    });
    console.log("[+] time parser @ base+0xf79d60");
  } catch (e) { console.log("[!] could not hook the time parser: " + e.message); }

  // Connection snapshot: 0xf3a580 (slot 0 of the conn vtable 0x1416d41f0) runs every frame for
  // every connection. We only log CHANGES of the thresholds and the state - you can see at which
  // moment (e.g. after our preAuth) idle changes from the default 40000 ms.
  // DISABLED by default: the job is done (run-15: idle 40000 -> 90000 ms after preAuth),
  // and this is an EVERY-FRAME hook on the main thread. Two game deaths with an abort inside
  // frida-agent.dll (0xc0000409, 2026-09-13 01:58 and 12:59, no game frames on the stack)
  // happened while detaching Frida from the running game - a hot hook is an unnecessary risk.
  // Enable only to diagnose the connection thresholds.
  const CONN_SNAPSHOT = false;
  const connSnap = new Map();
  let connSnapLogs = 0;
  if (!CONN_SNAPSHOT) console.log("[*] connection snapshot DISABLED (CONN_SNAPSHOT=false)");
  if (CONN_SNAPSHOT) try {
    Interceptor.attach(base.add(0xf3a580), {
      onEnter() {
        if (connSnapLogs >= 60) return;
        const c = this.context.rcx;
        let s;
        try {
          s = "state[+0x30]=" + c.add(0x30).readU32() +
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
    console.log("[+] connection snapshot @ base+0xf3a580");
  } catch (e) { console.log("[!] could not hook the connection snapshot: " + e.message); }

  // ============ CRASH GUARD: NULL callback in the notification dispatcher =========
  // 0xf6c5f0(rcx=dispatcher, rdx=callback function, r8=context): the loop over the
  // listeners does `call r14` where r14=rdx. During connection teardown rdx can be
  // NULL -> call 0 -> rip=0 -> access violation (our crash in every run).
  // We replace NULL with a no-op: the game SURVIVES the teardown, so we get to see what
  // it does NEXT after closing the Blaze connection itself after postAuth - whether it
  // reconnects (the disconnect would be a normal Blaze step), goes to the menu, or
  // stalls. That decides whether the crash is a side effect of a normal disconnect, or
  // the disconnect is the real blocker. The guard only kicks in when rdx==NULL, so it does
  // not touch normal notifications (0xf6c5f0 is also called with a valid callback).
  const noopCb = new NativeCallback(function () {}, "void", ["pointer", "pointer"]);
  let guardHits = 0;
  try {
    Interceptor.attach(base.add(0xf6c5f0), {
      onEnter() {
        if (this.context.rdx.isNull()) {
          this.context.rdx = noopCb;
          if (guardHits++ < 8)
            console.log("[guard] 0xf6c5f0 rdx=NULL -> no-op (crash avoided) #" + guardHits);
        }
      }
    });
    console.log("[+] crash guard @ base+0xf6c5f0");
  } catch (e) { console.log("[!] could not hook the crash guard: " + e.message); }

  // ============ CONNECTION ("conn") STATE TRANSITION - the reason for the disconnect =======
  // From the 14:07/14:31 crash (disassembly): the teardown (0xf4de00) is the EFFECT
  // of a disconnect that comes from the PER-FRAME UPDATE LOOP (0xefe99d -> 0xefa5f5
  // -> 0xf2505d), not from handling an incoming message. It ends in the connection
  // state function 0xf37f10, which:
  //   - with flags [rdi+0x339]=[rdi+0x33a]=[rdi+0x33c]=0 sets the deadline
  //     [rdi+0x3b0] = [rdi+0x300] * 1000 (so [rdi+0x300] is a timeout in SECONDS)
  //   - logs under the "conn" category, passing esi = the STATE/REASON CODE.
  // This hook reads esi (the reason) and [rdi+0x300] (timeout, s) - it clearly tells apart
  // an idle timeout (a large value, e.g. 90 = connIdleTimeout) from an RPC timeout
  // (30 = defaultRequestTimeout) and from an immediate close. Fires rarely
  // (only on state changes), so it does not clutter the log like the earlier 0xf25000.
  let connSeen = 0;
  try {
    Interceptor.attach(base.add(0xf37f10), {
      onEnter(args) {
        const conn = args[0];
        const reason = this.context.rdx.toInt32();   // edx = 2nd arg = reason/state
        let tout = -1, f = "?", st = -1, thr = -1;
        try {
          tout = conn.add(0x300).readU32();
          f = conn.add(0x339).readU8() + "/" + conn.add(0x33a).readU8() +
              "/" + conn.add(0x33c).readU8();
          st = conn.add(0x30).readU32();              // [conn+0x30] = connection state
          thr = conn.add(0x2fc).readU32();            // [conn+0x2fc] = threshold from 0xf3a580
        } catch (e) {}
        console.log("\n@@@ CONNECTION STATE (0xf37f10) reason=" + reason +
                    " state[+0x30]=" + st + " threshold[+0x2fc]=" + thr +
                    " timeout=" + tout + "s  flags[339/33a/33c]=" + f);
        if (connSeen++ < 4) {
          try {
            const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
              .slice(0, 8)
              .map(a => a + "  (base+" + a.sub(base) + ")").join("\n     ");
            console.log("   STACK:\n     " + bt);
          } catch (e) {}
        }
      }
    });
    console.log("[+] connection state (conn) @ base+0xf37f10");
  } catch (e) { console.log("[!] could not hook the connection state: " + e.message); }

  // --- network connection tap: show EVERY address:port the game connects
  //     to (redirector, Blaze). This reveals where it goes after getting the token.
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
  // Frida 17: exports through the module instance / getGlobalExportByName.
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
      console.log("[!] export " + name + " not found");
    }
  }
  hookConnect("connect");
  hookConnect("WSAConnect");

  // >>> P2P-BEGIN (block tested separately: scratchpad/test_p2p_hook.py)
  // --- UDP: the Blaze QoS test goes over UDP, not TCP. If the game probes ping sites after
  //     preAuth, we will see here where and how many times. SILENCE here = the QoS hypothesis
  //     falls and the blocker sits in the session data (UserSessionExtendedData).
  //     sendto(s, buf, len, flags, to, tolen) - the target address in args[4].
  //
  //     Test 61: the game SENDS through sendto, but RECEIVES through WSARecvFrom - and the hook was
  //     only on recvfrom, which the game does not use. We never saw a single received P2P packet,
  //     so it was impossible to tell whether game traffic flows at all after returning to a migrated game.
  const udpTs = () => new Date().toISOString().substr(11, 12);
  const udpSeen = {};                       // address -> counter (we do not flood the log)
  function sockaddrIn(sa) {                 // -> [ip, port] or null
    if (sa.isNull() || sa.readU16() !== 2) return null;   // AF_INET only
    const port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
    const ip = sa.add(4).readU8() + "." + sa.add(5).readU8() + "." +
               sa.add(6).readU8() + "." + sa.add(7).readU8();
    return [ip, port];
  }

  // The game's P2P traffic: 3659 = game tunnel, 6000 = most likely VoIP. Per-peer counters and a summary
  // every 2 s - it shows WHEN traffic in either direction stops. "silence" is printed once, when a peer goes quiet.
  const P2P_PORTS = { 3659: true, 6000: true };
  const p2p = {};                           // "ip:port" -> {sent, sentB, recv, recvB, quiet}
  function p2pCount(ip, port, dir, bytes) {
    if (!P2P_PORTS[port]) return;
    const k = ip + ":" + port;
    const e = p2p[k] || (p2p[k] = { sent: 0, sentB: 0, recv: 0, recvB: 0, quiet: false });
    if (dir === "out") { e.sent++; e.sentB += bytes; } else { e.recv++; e.recvB += bytes; }
  }
  setInterval(() => {
    for (const k in p2p) {
      const e = p2p[k];
      if (e.sent || e.recv) {
        console.log("[p2p] (" + udpTs() + ") " + k + " sent=" + e.sent + " (" + e.sentB +
                    " B) received=" + e.recv + " (" + e.recvB + " B)");
        e.quiet = false;
      } else if (!e.quiet) {
        console.log("[p2p] (" + udpTs() + ") " + k + " silence in both directions");
        e.quiet = true;
      }
      e.sent = e.sentB = e.recv = e.recvB = 0;
    }
  }, 2000);

  function logUdp(key, arrow, ip, port, n, head) {
    udpSeen[key] = (udpSeen[key] || 0) + 1;
    // the first 3 packets per address are logged with their content, then every 50th.
    if (udpSeen[key] <= 3 || udpSeen[key] % 50 === 0)
      console.log("[UDP " + key.split(" ")[0] + " #" + udpSeen[key] + "] " + arrow + " " + ip + ":" +
                  port + "  " + n + " B  " + head + " (" + udpTs() + ")");
  }

  function hookSendto(name, addrArgIdx, wsaBufs) {
    const ex = findExport("ws2_32.dll", name) || findExport("wsock32.dll", name);
    if (!ex) { console.log("[!] export " + name + " not found"); return; }
    Interceptor.attach(ex, {
      onEnter(args) {
        try {
          const addr = sockaddrIn(args[addrArgIdx]);
          if (!addr) return;
          // sendto: (s, buf, len, ...); WSASendTo: (s, WSABUF[], count, ...) - WSABUF {ULONG len; char* buf}
          const buf = wsaBufs ? args[1].add(8).readPointer() : args[1];
          let n = 0;
          if (wsaBufs) { for (let i = 0; i < args[2].toInt32(); i++) n += args[1].add(16 * i).readU32(); }
          else n = args[2].toInt32();
          p2pCount(addr[0], addr[1], "out", n);
          let head = "";
          try { head = bin2hex(buf.readByteArray(Math.min(n, 32))); } catch (e) {}
          logUdp(name + " " + addr[0] + ":" + addr[1], "->", addr[0], addr[1], n, head);
        } catch (e) {}
      }
    });
    console.log("[+] net " + name + " @ " + ex);
  }
  hookSendto("sendto", 4, false);
  hookSendto("WSASendTo", 5, true);        // (s, bufs, cnt, sent, flags, to, tolen, ...)

  // Receiving. recvfrom(s, buf, len, flags, from, fromlen) returns the byte count; WSARecvFrom(s, WSABUF[],
  // count, lpRecvd, lpFlags, from, fromlen, lpOverlapped, ...) returns 0 and stores the byte count at
  // lpRecvd. Overlapped operations (WSA_IO_PENDING) are skipped - there is no length or sender yet.
  function hookRecvfrom(name, wsa) {
    const ex = findExport("ws2_32.dll", name);
    if (!ex) { console.log("[!] export " + name + " not found"); return; }
    Interceptor.attach(ex, {
      onEnter(a) {
        this.buf = a[1];                    // recvfrom: the buffer; WSARecvFrom: the WSABUF array
        this.nread = wsa ? a[3] : null;
        this.from = wsa ? a[5] : a[4];
      },
      onLeave(ret) {
        try {
          let n;
          if (wsa) {
            if (ret.toInt32() !== 0 || this.nread.isNull()) return;
            n = this.nread.readU32();
          } else {
            n = ret.toInt32();
          }
          if (n <= 0 || this.from.isNull()) return;
          const addr = sockaddrIn(this.from);
          if (!addr) return;
          p2pCount(addr[0], addr[1], "in", n);
          let head = "";
          try {
            const data = wsa ? this.buf.add(8).readPointer() : this.buf;
            head = bin2hex(data.readByteArray(Math.min(n, 32)));
          } catch (e) {}
          logUdp(name + " " + addr[0] + ":" + addr[1], "<-", addr[0], addr[1], n, head);
        } catch (e) {}
      }
    });
    console.log("[+] net " + name + " @ " + ex);
  }
  hookRecvfrom("recvfrom", false);
  hookRecvfrom("WSARecvFrom", true);
  // <<< P2P-END

  // recv: does the game READ our reply? (encrypted, but the length/timing
  // tells whether anything arrived after getServerInstance). We only log returns >0.
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

  // --- DNS: every host name the game tries to resolve. getaddrinfo alone is not
  //     enough - DirtySDK/ProtoSSL may go through gethostbyname or the W versions.
  //     Lines are prefixed "[dns <function>]" (getaddrinfo internally calls
  //     GetAddrInfoW, so the same name can come out twice).
  function hookDns(mod, name, wide) {
    const ex = findExport(mod, name);
    if (!ex) { console.log("[!] export " + mod + "!" + name + " not found"); return; }
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
    } catch (e) { console.log("[!] could not hook " + name + ": " + e.message); }
  }
  hookDns("ws2_32.dll", "getaddrinfo", false);
  hookDns("ws2_32.dll", "GetAddrInfoW", true);
  hookDns("ws2_32.dll", "GetAddrInfoExW", true);
  hookDns("ws2_32.dll", "gethostbyname", false);
  hookDns("dnsapi.dll", "DnsQuery_A", false);
  hookDns("dnsapi.dll", "DnsQuery_W", true);
  hookDns("dnsapi.dll", "DnsQuery_UTF8", false);

  // ============ BYTEVAULT INITIALIZATION (0xf71b40) ============
  // Called from 0xa1bcbd on the game's online state transition 9 -> 10 (0xa1bb00):
  //   0xf71b40(rcx=[hub+0xc50], rdx=char* bytevaultHostname, r8w=bytevaultPort, r9b=secure)
  // It takes the keys from CONF (bytevaultPort via atoi, bytevaultSecure == "true",
  // bytevaultHostname as a string), and when they are missing - from the game's defaults. The line
  // tells whether the game gets to ByteVault at all and at which address.
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
  } catch (e) { console.log("[!] could not hook the ByteVault init: " + e.message); }

  console.log("[*] ready - go ONLINE in the game.");
}
