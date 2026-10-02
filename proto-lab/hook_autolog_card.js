// Frida - Autolog's rival card: whose row a click finds empty, and no crash when it does.
//
// The 02.10 crash (NFS14.exe+0x9731bb, docs/decisions.md 1.0.12.7): clicking a rival in Autolog's
// list builds a card from the rival's "beat you" entries (RECM). For each entry:
//   0x9d5660  the loop; r14 = the entry, rsi = the speed wall object by id [r14+0x100]
//   0x9d593c  call 0x973dd0(rsi, &out, &key) - key = {u64 [r14+0x148] TABL, char[17]
//             [r14+0x170] TANA}: the rival's row looked up BY NAME in a char* tree at rsi+0x58
//             (root [+0x18] & ~1, node: right +0, left +8, key char* +0x18, row +0x20). The row's
//             stats are resolved on access from a key at row+0x10 (0x96d3c0 -> 0x14a390) and come
//             out NULL when nothing is registered under it.
//   0x96b960  float getter (rcx = those stats, rdx = the wall's stat name "speed" ...) - reads
//             [rcx+0x10] unchecked: the crash.
// This script logs every entry whose row has no stats, with all names on that wall, and hands the
// getter an empty container instead of NULL, so the game reads 0.0 and goes on.
//
// For the test with a second player in the session (open in decisions.md): on the host,
//     python proto-lab/frida_run.py proto-lab/hook_autolog_card.js --wait 600 --duration 7200
// then the guest drives through one of the cameras on his card and the host clicks him.
// End it by closing the game or with --duration: killing frida_run.py while the hooks are in
// takes the game down with it (frida-agent.dll_unloaded, 02.10 13:25).

const base = Process.getModuleByName("NFS14.exe").base;
const at = (rva) => base.add(rva);
const t0 = Date.now();
const ts = () => ((Date.now() - t0) / 1000).toFixed(1).padStart(7) + "s";

function name17(p) {
  // printable ASCII up to the first other byte - the names are not always NUL-terminated
  try {
    let s = "";
    for (const c of new Uint8Array(p.readByteArray(17))) {
      if (c < 32 || c > 126) break;
      s += String.fromCharCode(c);
    }
    return s;
  } catch (e) { return "<bad>"; }
}

function wallRows(tree) {
  const out = [], stack = [], anchor = tree.add(8);
  let n;
  try { n = tree.add(0x18).readPointer().and(ptr("0xfffffffffffffffe")); } catch (e) { return ["<unreadable>"]; }
  for (let guard = 0; (!n.isNull() && !n.equals(anchor)) || stack.length; guard++) {
    if (guard > 500) { out.push("..."); break; }
    while (!n.isNull() && !n.equals(anchor)) { stack.push(n); n = n.add(8).readPointer(); }
    n = stack.pop();
    let state = "?";
    try {
      const row = n.add(0x20).readPointer();
      state = row.isNull() ? "no row" : (row.add(0x38).readPointer().isNull() ? "no stats yet" : "stats");
    } catch (e) {}
    out.push(name17(n.add(0x18).readPointer()) + "=" + state);
    n = n.readPointer();
  }
  return out;
}

let card = 0, entry = 0, current = null;
Interceptor.attach(at(0x9d5660), {
  onEnter() { card++; entry = 0; },
  onLeave() { console.log(`${ts()} card #${card}: ${entry} entr${entry === 1 ? "y" : "ies"}`); }
});
Interceptor.attach(at(0x9d593c), {
  onEnter() {
    const c = this.context;
    entry++;
    try {
      current = { wall: c.r14.add(0x100).readU32(), id: c.r14.add(0x148).readU64().toString(),
                  name: name17(c.r14.add(0x170).readPointer()), type: c.rsi.add(0xe8).readU32(),
                  tree: c.rsi.add(0x58) };
    } catch (e) { current = null; }
  }
});
Interceptor.attach(at(0x973dd0), {
  onEnter() { this.out = this.context.rdx; this.card = this.returnAddress.equals(at(0x9d5941)); },
  onLeave() {
    if (!this.card || !current) return;
    try {
      if (!this.out.readPointer().isNull()) return;
    } catch (e) { return; }
    console.log(`${ts()} !!! card #${card} entry #${entry}: ${current.name} (${current.id}) on wall `
      + `${current.wall} (SpeedWallType ${current.type}) has NO STATS - the 02.10 crash. `
      + `Rows on that wall: ${wallRows(current.tree).join(", ")}`);
  }
});
const empty = Memory.alloc(0x40);          // begin == end == 0: the getter finds nothing, 0.0
Interceptor.attach(at(0x96b960), {
  onEnter() {
    if (!this.context.rcx.isNull()) return;
    this.context.rcx = empty;
    console.log(`${ts()}     crash prevented: "${name17(this.context.rdx)}" read from no stats`);
  }
});
// A crash this guard does not cover (02.10 evening: games quit at the end of an event, right after
// the Autolog reply): where it happened, as NFS14.exe+RVA with the stack. Not handled - the game
// goes down as it would anyway, the log keeps the address. First-chance exceptions of other types
// are frequent and harmless, so only access violations, at most 5.
const inMod = (a) => { try { return a.compare(base) >= 0 && a.compare(base.add(0x20bd000)) < 0; } catch (e) { return false; } };
const where = (a) => a + (inMod(a) ? `  (NFS14.exe+0x${a.sub(base).toString(16)})` : "");
let avLogged = 0;
Process.setExceptionHandler((details) => {
  if (details.type !== "access-violation" || avLogged++ >= 5) return false;
  console.log(`\n${ts()} ########## ACCESS VIOLATION #${avLogged} ##########`);
  console.log(`  at ${where(details.address)}`);
  if (details.memory) console.log(`  ${details.memory.operation} of ${details.memory.address}`);
  try {
    const c = details.context;
    console.log(`  rax=${c.rax} rbx=${c.rbx} rcx=${c.rcx} rdx=${c.rdx}`);
    console.log(`  rsi=${c.rsi} rdi=${c.rdi} r8=${c.r8} r9=${c.r9} r14=${c.r14}`);
    const bt = Thread.backtrace(c, Backtracer.ACCURATE).map(where).join("\n     ");
    console.log(`  STACK:\n     ${bt}`);
  } catch (e) { console.log(`  (no stack: ${e})`); }
  if (current) console.log(`  last card entry: #${entry} ${current.name} (${current.id}) on wall ${current.wall}`);
  return false;
});
console.log("[*] Autolog card hooks in place - click rivals in Autolog");
