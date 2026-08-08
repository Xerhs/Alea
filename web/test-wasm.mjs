// Headless correctness harness for seed-web (SPEC_WEB_OFFLINE §10 byte-parity).
// Runs the release .wasm in Node's browser-grade V8 WebAssembly engine with
// the SAME zero-import instantiation the offline page uses, and checks the
// three Phase-1 features against known-answer vectors.
//
// Usage: node test-wasm.mjs [path-to-wasm]
import fs from "node:fs";

const wasmPath =
  process.argv[2] ||
  `${process.env.HOME}/.cache/seedmaker-wasm/wasm32-unknown-unknown/release/seed_web.wasm`;

const bytes = fs.readFileSync(wasmPath);
const { instance } = await WebAssembly.instantiate(bytes, {}); // no imports
const ex = instance.exports;
const mem = () => new Uint8Array(ex.memory.buffer);

const dec = new TextDecoder();
const enc = new TextEncoder();

function readOutput(len) {
  if (len < 0) throw new Error(`wasm returned error code ${len}`);
  const ptr = ex.io_output_ptr();
  return dec.decode(mem().slice(ptr, ptr + len));
}

function parse(text) {
  const o = {};
  for (const line of text.split("\n")) {
    if (!line) continue;
    const t = line.indexOf("\t");
    o[line.slice(0, t)] = line.slice(t + 1);
  }
  return o;
}

function writeInput(str, offset = 0) {
  const ptr = ex.io_input_ptr();
  const b = enc.encode(str);
  mem().set(b, ptr + offset);
  return b.length;
}

let failures = 0;
function check(name, got, want) {
  const ok = got === want;
  if (!ok) failures++;
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}`);
  if (!ok) console.log(`        got:  ${got}\n        want: ${want}`);
}

// --------------------------------------------------------------------------
// Feature 1 — rehearsal (all-zero 16-byte entropy public vector).
// Expected: "abandon abandon ... about" and the four published addresses +
// fingerprint for that seed (empty passphrase). BIP84 anchor is the value the
// spec §2 smoke test pins.
// --------------------------------------------------------------------------
console.log("Feature 1 — rehearsal (all-zero public vector):");
{
  const out = parse(readOutput(ex.rehearsal()));
  check("status", out.status, "ok");
  check(
    "mnemonic",
    out.mnemonic,
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  );
  check("bip84 (spec §2 anchor)", out.bip84, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
  check("bip44", out.bip44, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA");
  check("bip49", out.bip49, "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf");
  check("bip86", out.bip86, "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr");
  check("fingerprint", out.fingerprint, "73c5da0a");
  REHEARSAL = out;
}
var REHEARSAL;

// --------------------------------------------------------------------------
// Feature 2 — verification display. Feed the SAME mnemonic back (empty
// passphrase) and require byte-identical public values to the rehearsal.
// Then a passphrase case against a known-answer, and a bad-checksum refusal.
// --------------------------------------------------------------------------
console.log("Feature 2 — verification display:");
{
  const m =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  const mlen = writeInput(m, 0);
  const out = parse(readOutput(ex.verify(mlen, 0)));
  check("status", out.status, "ok");
  check("no mnemonic echoed (secret)", out.mnemonic, undefined);
  check("bip84 == rehearsal", out.bip84, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
  check("fingerprint == rehearsal", out.fingerprint, "73c5da0a");

  // Passphrase "TREZOR" over the same mnemonic — BIP39 test vector seed
  // 0xc55257c360c07c72... ; derive & check the master fingerprint is stable
  // and DIFFERENT from the empty-passphrase one (passphrase changes the seed).
  const mlen2 = writeInput(m, 0);
  const plen2 = writeInput("TREZOR", mlen2);
  const out2 = parse(readOutput(ex.verify(mlen2, plen2)));
  check("passphrase status", out2.status, "ok");
  check(
    "passphrase changes fingerprint",
    String(out2.fingerprint !== "73c5da0a"),
    "true"
  );

  // Bad checksum: swap last word "about" -> "abandon" (invalid checksum).
  const bad =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
  const blen = writeInput(bad, 0);
  const outb = parse(readOutput(ex.verify(blen, 0)));
  check("bad checksum refused", outb.status, "error");
  check("bad checksum error msg", outb.error, "bad-checksum");

  // Unknown word.
  const uw = "zzzz abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  const ulen = writeInput(uw, 0);
  const outu = parse(readOutput(ex.verify(ulen, 0)));
  check("unknown word refused", outu.error, "unknown-word");
}

// --------------------------------------------------------------------------
// Feature 2b — "More derivation options" bounded grid (verify_grid).
// Standard ids: 0 BIP44, 1 BIP49, 2 BIP84, 3 BIP86. Cross-checked against the
// bip-0084.mediawiki published test vectors for the same abandon…about
// mnemonic (empty passphrase):
//   m/84'/0'/0'/0/0 (anchor)        = bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
//   m/84'/0'/0'/0/1 (non-zero index)= bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g
//   m/84'/0'/0'/1/0 (non-zero change)=bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el
// --------------------------------------------------------------------------
console.log("Feature 2b — more derivation options (verify_grid):");
{
  const m =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  const BIP84 = 2;

  // Parse the grid output into ordered addr rows (repeated `addr` records).
  function grid(mn, std, account, change, start, n, pass) {
    const mlen = writeInput(mn, 0);
    const plen = pass ? writeInput(pass, mlen) : 0;
    const len = ex.verify_grid(mlen, plen, std, account, change, start, n);
    const o = { addrs: [] };
    if (len < 0) { o.status = "error"; o.error = "code-" + len; return o; }
    const ptr = ex.io_output_ptr();
    const text = dec.decode(mem().slice(ptr, ptr + len));
    o._text = text;
    for (const line of text.split("\n")) {
      if (!line) continue;
      const t = line.indexOf("\t");
      const k = line.slice(0, t), v = line.slice(t + 1);
      if (k === "addr") {
        const s = v.indexOf(" ");
        o.addrs.push({ index: v.slice(0, s), address: v.slice(s + 1) });
      } else o[k] = v;
    }
    return o;
  }

  // BIP84, account 0, external chain, start index 0, N=5.
  const g = grid(m, BIP84, 0, 0, 0, 5);
  check("grid status", g.status, "ok");
  check("grid mode", g.mode, "grid");
  check("grid standard", g.standard, "bip84");
  check("grid fingerprint == anchor", g.fingerprint, "73c5da0a");
  check("grid returns N=5 rows", String(g.addrs.length), "5");
  check("grid row0 index", g.addrs[0].index, "0");
  check("grid index0 == BIP84 anchor", g.addrs[0].address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
  check("grid index1 (non-zero) == published", g.addrs[1].address, "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");
  check("grid row4 index", g.addrs[4].index, "4");
  // §24.3: no secret material must ever appear in the output.
  check("grid never echoes mnemonic", String(/abandon/.test(g._text)), "false");
  check("grid never leaks secrets", String(/xprv|xpub|privkey|\bwif\b|\bseed\b|chain.?code/i.test(g._text)), "false");

  // Non-zero CHANGE chain (internal), index 0 — published first change addr.
  const gc = grid(m, BIP84, 0, 1, 0, 1);
  check("grid change=1 status", gc.status, "ok");
  check("grid change=1 index0 == published change addr", gc.addrs[0].address, "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el");

  // Non-zero START index: start=1,N=1 must equal the index-1 published vector.
  const gs = grid(m, BIP84, 0, 0, 1, 1);
  check("grid start=1 index", gs.addrs[0].index, "1");
  check("grid start=1 address == published", gs.addrs[0].address, "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");

  // Passphrase changes the seed => addresses differ from the empty-pass grid.
  const gp = grid(m, BIP84, 0, 0, 0, 1, "TREZOR");
  check("grid passphrase status", gp.status, "ok");
  check("grid passphrase changes address", String(gp.addrs[0].address !== g.addrs[0].address), "true");

  // Bounds refusals (typed error lines).
  check("grid n=0 refused", grid(m, BIP84, 0, 0, 0, 0).error, "count-out-of-range");
  check("grid n=10 accepted (cap boundary)", grid(m, BIP84, 0, 0, 0, 10).status, "ok");
  check("grid n=11 refused (cap now 10)", grid(m, BIP84, 0, 0, 0, 11).error, "count-out-of-range");
  check("grid account=101 refused", grid(m, BIP84, 101, 0, 0, 5).error, "account-out-of-range");
  check("grid change=2 refused", grid(m, BIP84, 0, 2, 0, 5).error, "change-must-be-0-or-1");
  check("grid standard=9 refused", grid(m, 9, 0, 0, 0, 5).error, "unknown-standard");
  check("grid index overflow refused", grid(m, BIP84, 0, 0, 99998, 5).error, "index-out-of-range");
  check("grid bad-checksum refused", grid(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
    BIP84, 0, 0, 0, 5
  ).error, "bad-checksum");
}

// --------------------------------------------------------------------------
// Feature 3 — seed-compat Method C (iancoleman/bip39 raw entropy).
// Encoding ids (Encoding::ALL order): 0 binary,1 base6,2 dice,3 base10,4 hex,
// 5 cards. Hex "00000000000000000000000000000000" (32 zero nibbles = 128 bits
// of zero entropy) must reproduce the all-zero abandon..about mnemonic — the
// same byte-parity anchor, reached through the foreign-entropy front end.
// --------------------------------------------------------------------------
console.log("Feature 3 — entropy-encoding compat (Method C):");
{
  const HEX = 4;
  const inp = "00000000000000000000000000000000"; // 32 hex nibbles = 128 bits
  const ilen = writeInput(inp, 0);
  const out = parse(readOutput(ex.compat(HEX, ilen)));
  check("status", out.status, "ok");
  check("encoding", out.encoding, "hex");
  check("retained_bits", out.retained_bits, "128");
  check("entropy", out.entropy, "00000000000000000000000000000000");
  check(
    "mnemonic (foreign reproduction)",
    out.mnemonic,
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  );
  check("bip84 matches", out.bip84, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");

  // Dice encoding: face '6' -> base-6 digit 0 ("00"). 128 bits needs enough
  // symbols; all-'1' faces (base6 digit 1 -> "01"). Just assert a well-formed
  // 128-bit derive succeeds for a long all-'1' dice string.
  const DICE = 2;
  const dstr = "1".repeat(64); // 64 symbols x 2 bits (digit 1 -> "01") = 128 bits
  const dlen = writeInput(dstr, 0);
  const outd = parse(readOutput(ex.compat(DICE, dlen)));
  check("dice status ok", outd.status, "ok");
  check("dice retained_bits", outd.retained_bits, "128");

  // Refusal: too-short hex (not a 32-bit multiple worth of retained entropy).
  const shortlen = writeInput("00", 0);
  const outs = parse(readOutput(ex.compat(HEX, shortlen)));
  check("short input refused", outs.status, "error");
}

// --------------------------------------------------------------------------
// Scrub-on-early-return — the secret INPUT buffer must be ZEROED before every
// early return that could leave caller-written secret bytes in linear memory
// (re-audit LOW-1 / LOW-2). For each path: write a non-zero sentinel into
// INPUT, trigger the early return, then read INPUT back via exported memory
// and assert the relevant region is all zero.
//   - verify() passphrase-not-printable-ascii  -> scrubs INPUT[..m_len+p_len]
//   - verify() bad-input-length                -> scrubs the FULL INPUT_CAP
//   - verify_grid() bad-input-length           -> scrubs the FULL INPUT_CAP
// --------------------------------------------------------------------------
console.log("Scrub-on-early-return (INPUT zeroed on secret early-return paths):");
{
  const CAP = ex.io_input_cap();
  const fillInput = (len, val = 0xaa) => {
    const p = ex.io_input_ptr();
    const m = mem();
    for (let i = 0; i < len; i++) m[p + i] = val;
  };
  const inputAllZero = (len) => {
    const p = ex.io_input_ptr();
    const m = mem();
    for (let i = 0; i < len; i++) if (m[p + i] !== 0) return false;
    return true;
  };

  // (1) verify(): non-printable-ASCII passphrase. Valid mnemonic bytes (non-zero)
  // + a 0x01 passphrase byte (non-zero) -> reject path must scrub [..m_len+p_len].
  {
    const m =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const mlen = writeInput(m, 0);
    mem()[ex.io_input_ptr() + mlen] = 0x01; // non-printable passphrase byte
    const plen = 1;
    const out = parse(readOutput(ex.verify(mlen, plen)));
    check("verify non-ascii-pass refused", out.error, "passphrase-not-printable-ascii");
    check("verify non-ascii-pass scrubs INPUT[..m+p]", String(inputAllZero(mlen + plen)), "true");
  }

  // (2) verify(): bad input length (m_len > INPUT_CAP). Untrusted length ->
  // scrub the FULL INPUT_CAP. Sentinel-fill the whole buffer, then assert zero.
  {
    fillInput(CAP, 0xaa);
    const out = parse(readOutput(ex.verify(CAP + 1, 0)));
    check("verify bad-length refused", out.error, "bad-input-length");
    check("verify bad-length scrubs FULL INPUT_CAP", String(inputAllZero(CAP)), "true");
  }

  // (3) verify_grid(): bad input length (m_len > INPUT_CAP). Same full scrub.
  {
    fillInput(CAP, 0xaa);
    const BIP84 = 2;
    const out = parse(readOutput(ex.verify_grid(CAP + 1, 0, BIP84, 0, 0, 0, 5)));
    check("verify_grid bad-length refused", out.error, "bad-input-length");
    check("verify_grid bad-length scrubs FULL INPUT_CAP", String(inputAllZero(CAP)), "true");
  }
}

// --------------------------------------------------------------------------
// In-page self-hash — hash the wasm bytes themselves and compare to sha256sum.
// --------------------------------------------------------------------------
console.log("Self-hash (wasm_sha256 over the .wasm bytes):");
{
  const ptr = ex.io_input_ptr();
  mem().set(bytes, ptr);
  const h = readOutput(ex.wasm_sha256(bytes.length));
  const crypto = await import("node:crypto");
  const want = crypto.createHash("sha256").update(bytes).digest("hex");
  check("wasm self-hash == sha256sum", h, want);
}

console.log(
  failures === 0
    ? "\nALL CHECKS PASSED"
    : `\n${failures} CHECK(S) FAILED`
);
process.exit(failures === 0 ? 0 : 1);
