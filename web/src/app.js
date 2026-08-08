/* Alea Offline Web Edition — Phase 1 glue (SPEC_WEB_OFFLINE §13.2).
   Hand-rolled JS<->WASM marshalling over the zero-import seed-web ABI.
   No background-request APIs, no navigation (the page never assigns to the
   document location nor opens windows), no dynamic code evaluation, no
   worker/cache/canvas, no external resource. Single inline-script block
   (CSP sha256-pinned). All listeners attached via addEventListener (no inline
   handlers, which the hash-based CSP would block anyway). */
"use strict";
(function () {
  // The embedded WASM, base64. Replaced by the deterministic inliner (build.py).
  const WASM_B64 = "__WASM_B64__";

  const $ = (id) => document.getElementById(id);
  const encTE = new TextEncoder();
  const decTD = new TextDecoder();

  // ---- base64 -> Uint8Array (atob is a pure string API; not a network op) ----
  function b64ToBytes(b64) {
    const bin = atob(b64);
    const n = bin.length;
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  let ex = null; // wasm exports
  let wasmBytes = null;

  function mem() { return new Uint8Array(ex.memory.buffer); }

  function writeInput(str, offset) {
    const bytes = encTE.encode(str);
    mem().set(bytes, ex.io_input_ptr() + offset);
    return bytes.length;
  }

  function readOutput(len) {
    if (len < 0) return { status: "error", error: "wasm-error-code-" + len };
    const ptr = ex.io_output_ptr();
    const text = decTD.decode(mem().slice(ptr, ptr + len));
    const o = {};
    for (const line of text.split("\n")) {
      if (!line) continue;
      const t = line.indexOf("\t");
      if (t < 0) continue;
      o[line.slice(0, t)] = line.slice(t + 1);
    }
    return o;
  }

  // ---- Result rendering -----------------------------------------------------
  function row(k, v) {
    return '<div class="row"><div class="k">' + esc(k) + '</div><div class="v">' + esc(v) + "</div></div>";
  }
  function esc(s) {
    return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  }
  function addrRows(o) {
    return (
      row("Fingerprint", o.fingerprint || "?") +
      row("BIP44 (1…)", o.bip44 || "?") +
      row("BIP49 (3…)", o.bip49 || "?") +
      row("BIP84 (bc1q…)", o.bip84 || "?") +
      row("BIP86 (bc1p…)", o.bip86 || "?")
    );
  }
  function showResult(el, html) {
    el.innerHTML = html;
    el.classList.add("show");
  }
  function errHtml(o) {
    let extra = "";
    for (const k of ["retained_bits", "total_bits", "iancoleman_words", "accepted", "ignored"]) {
      if (o[k] !== undefined) extra += row(k, o[k]);
    }
    return '<div class="err">Refused: ' + esc(o.error || "unknown") + "</div>" + extra;
  }

  // ---- Feature 1: rehearsal -------------------------------------------------
  function runRehearsal() {
    const o = readOutput(ex.rehearsal());
    const el = $("reh-out");
    if (o.status !== "ok") return showResult(el, errHtml(o));
    showResult(
      el,
      '<span class="watermark">PUBLIC TEST — NEVER USE WITH FUNDS</span>' +
        row("Mnemonic", o.mnemonic) +
        addrRows(o)
    );
  }

  // ---- Feature 2: verification ---------------------------------------------
  function runVerify() {
    const m = $("ver-mnemonic").value.trim().replace(/\s+/g, " ");
    const p = $("ver-pass").value;
    const el = $("ver-out");
    if (!m) return showResult(el, '<div class="err">Enter a mnemonic.</div>');
    const mlen = writeInput(m, 0);
    const plen = writeInput(p, mlen);
    const o = readOutput(ex.verify(mlen, plen));
    // Best-effort: overwrite the input scratch we just used (JS side can't
    // truly scrub, but we clear what we can — the wasm already scrubbed its buffer).
    scrubInputView(mlen + plen);
    if (o.status !== "ok") return showResult(el, errHtml(o));
    showResult(
      el,
      '<span class="watermark">PUBLIC VALUES ONLY — no private key / xprv / seed is ever shown</span>' +
        addrRows(o) +
        '<p>These are the account-0 / index-0 first receive addresses (mainnet) and the BIP32 master fingerprint for the mnemonic you entered' +
        (p ? " with the passphrase you entered" : "") +
        ".</p>"
    );
  }

  // ---- Feature 2b: more derivation options (bounded first-N grid) ----------
  // The grid output reuses the line format but emits repeated `addr` records
  // (one per address), which the key/value object parser would collapse — so
  // parse it into an ordered list here instead. Each `addr` value is
  // "<index> <address>" (single space; neither field contains a space).
  function readGrid(len) {
    if (len < 0) return { status: "error", error: "wasm-error-code-" + len };
    const ptr = ex.io_output_ptr();
    const text = decTD.decode(mem().slice(ptr, ptr + len));
    const o = { addrs: [] };
    for (const line of text.split("\n")) {
      if (!line) continue;
      const t = line.indexOf("\t");
      if (t < 0) continue;
      const k = line.slice(0, t);
      const v = line.slice(t + 1);
      if (k === "addr") {
        const s = v.indexOf(" ");
        o.addrs.push({ index: v.slice(0, s), address: v.slice(s + 1) });
      } else {
        o[k] = v;
      }
    }
    return o;
  }

  function runGrid() {
    const m = $("ver-mnemonic").value.trim().replace(/\s+/g, " ");
    const p = $("ver-pass").value;
    const el = $("grid-out");
    if (!m) return showResult(el, '<div class="err">Enter a mnemonic in the field above first.</div>');
    const std = parseInt($("grid-std").value, 10);
    const account = parseInt($("grid-account").value, 10);
    const change = parseInt($("grid-change").value, 10);
    const start = parseInt($("grid-start").value, 10);
    const count = parseInt($("grid-count").value, 10);
    if (![std, account, change, start, count].every(Number.isFinite)) {
      return showResult(el, '<div class="err">Fill in all derivation parameters.</div>');
    }
    const mlen = writeInput(m, 0);
    const plen = writeInput(p, mlen);
    const o = readGrid(ex.verify_grid(mlen, plen, std, account >>> 0, change >>> 0, start >>> 0, count >>> 0));
    scrubInputView(mlen + plen);
    if (o.status !== "ok") return showResult(el, errHtml(o));
    const stdLabels = { bip44: "BIP44 (1…)", bip49: "BIP49 (3…)", bip84: "BIP84 (bc1q…)", bip86: "BIP86 (bc1p…)" };
    let rows = "";
    for (const a of o.addrs) {
      rows += '<tr><td class="gi">' + esc(a.index) + '</td><td class="ga">' + esc(a.address) + "</td></tr>";
    }
    const chainLabel = o.change === "1" ? "internal (change)" : "external (receive)";
    showResult(
      el,
      '<span class="watermark">PUBLIC VALUES ONLY — no private key / xprv / seed is ever shown</span>' +
        row("Standard", stdLabels[o.standard] || o.standard) +
        row("Account′", o.account) +
        row("Change", chainLabel) +
        row("Fingerprint", o.fingerprint || "?") +
        '<table class="gridtbl"><thead><tr><th>Index</th><th>Address</th></tr></thead><tbody>' +
        rows +
        "</tbody></table>" +
        "<p>These are additional derivation paths of the SAME seed (the mnemonic" +
        (p ? " and passphrase" : "") +
        " above) — different paths, not different seeds.</p>"
    );
  }

  // ---- Feature 3: entropy-encoding compat ----------------------------------
  function runCompat() {
    const encId = parseInt($("cmp-enc").value, 10);
    const input = $("cmp-input").value;
    const el = $("cmp-out");
    if (!input.trim()) return showResult(el, '<div class="err">Enter foreign entropy symbols.</div>');
    const ilen = writeInput(input, 0);
    const o = readOutput(ex.compat(encId, ilen));
    scrubInputView(ilen);
    if (o.status !== "ok") return showResult(el, errHtml(o));
    showResult(
      el,
      '<span class="watermark foreign">REPRODUCTION OF FOREIGN MATERIAL — NEVER AN ALEA SEED — NEVER USE WITH FUNDS</span>' +
        row("Encoding", o.encoding) +
        row("Retained bits", o.retained_bits) +
        row("Symbols used", o.accepted) +
        row("Chars ignored", o.ignored) +
        row("Entropy (hex)", o.entropy) +
        row("Mnemonic", o.mnemonic) +
        addrRows(o) +
        "<p>This reproduces another tool's (iancoleman/bip39) raw-entropy result so you can cross-check it. It is foreign/throwaway material, not an Alea-generated seed.</p>"
    );
  }

  function scrubInputView(n) {
    // Overwrite the shared input region we wrote into (defence in depth).
    const z = new Uint8Array(n);
    mem().set(z, ex.io_input_ptr());
  }

  // ---- Integrity: in-page WASM self-hash ------------------------------------
  function computeSelfHash() {
    mem().set(wasmBytes, ex.io_input_ptr());
    const len = ex.wasm_sha256(wasmBytes.length);
    if (len < 0) return;
    const ptr = ex.io_output_ptr();
    const hex = decTD.decode(mem().slice(ptr, ptr + len));
    $("selfhash").textContent = hex;
    $("selfhash-len").textContent = wasmBytes.length + " bytes";
  }

  // ---- Honesty machinery: online/origin detector ---------------------------
  function checkOrigin() {
    const proto = location.protocol; // read-only; never assigned
    const isFile = proto === "file:";
    const online = navigator.onLine === true;
    const banner = $("origin");
    let msg = "";
    if (proto === "http:" || proto === "https:") {
      msg =
        "You are running this from a WEB SERVER (" +
        esc(proto) +
        "). Download the .html file, verify its hash, DISCONNECT the network, and open it from a local file:// path instead.";
    } else if (online) {
      msg =
        "Your browser reports it is ONLINE (advisory only — navigator.onLine can be wrong). For any sensitive use, disconnect Wi-Fi / pull the cable before continuing.";
    }
    if (msg) {
      banner.innerHTML = "&#9888; " + msg;
      banner.classList.add("show");
    } else {
      banner.classList.remove("show");
    }
    void isFile;
  }

  // ---- Tabs -----------------------------------------------------------------
  function initTabs() {
    const tabs = Array.from(document.querySelectorAll(".tab"));
    const panels = Array.from(document.querySelectorAll(".panel"));
    tabs.forEach((tab) => {
      tab.addEventListener("click", () => {
        tabs.forEach((t) => t.setAttribute("aria-selected", "false"));
        panels.forEach((p) => p.classList.remove("active"));
        tab.setAttribute("aria-selected", "true");
        $(tab.dataset.target).classList.add("active");
      });
    });
  }

  // ---- First-run honesty disclosure ----------------------------------------
  function initDisclosure() {
    const ov = $("disclosure");
    $("disclosure-ok").addEventListener("click", () => {
      ov.setAttribute("hidden", "");
    });
  }

  // ---- Boot -----------------------------------------------------------------
  async function boot() {
    wasmBytes = b64ToBytes(WASM_B64);
    try {
      const { instance } = await WebAssembly.instantiate(wasmBytes, {}); // zero imports
      ex = instance.exports;
    } catch (e) {
      $("boot-error").textContent = "WASM failed to instantiate: " + (e && e.message);
      $("boot-error").classList.add("show");
      return;
    }
    initTabs();
    initDisclosure();
    checkOrigin();
    window.addEventListener("online", checkOrigin);
    window.addEventListener("offline", checkOrigin);
    $("reh-run").addEventListener("click", runRehearsal);
    $("ver-run").addEventListener("click", runVerify);
    $("grid-run").addEventListener("click", runGrid);
    $("cmp-run").addEventListener("click", runCompat);
    $("selfhash-run").addEventListener("click", computeSelfHash);
    // Show/hide passphrase (NOT type=password — SPEC_WEB_OFFLINE §11.1). The
    // field starts masked via the `.masked` CSS class; toggling the class is
    // CSP-clean (no inline style attribute, no CSSOM style needed).
    $("ver-pass-toggle").addEventListener("click", () => {
      const masked = $("ver-pass").classList.toggle("masked");
      $("ver-pass-toggle").textContent = masked ? "Show" : "Hide";
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
