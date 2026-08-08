#!/usr/bin/env python3
"""Deterministic inliner for the Alea Offline Web Edition (SPEC_WEB_OFFLINE §5.2).

Given the (optimized) .wasm plus the src/ shell + JS + CSS, emit a single
self-contained alea-web-offline.html (SPEC_WEB_OFFLINE §5.1 names the
deliverable normatively):

  * WASM base64-inlined into the single <script> as a `data:`-free string
    literal, instantiated in-page with zero imports.
  * All JS and CSS inlined (one <script>, one <style>).
  * The strict Phase-1 CSP injected into the <meta http-equiv>, with the
    SHA-256 of the exact inline <script> and <style> contents pinned into
    script-src / style-src.

Determinism: standard base64 (fixed alphabet, no wrapping), LF line endings,
fixed field order, no timestamp / hostname / build path embedded. Given a
byte-identical .wasm and unchanged src/, this reproduces a byte-identical
.html (the reproducible-build gate, §5.2/§10). wasm reproducibility pins
(rustc flags) are applied in build.sh; wasm-opt is applied there if present.
"""
import base64
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "src"


def sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    wasm_path = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        Path.home() / ".cache/seedmaker-wasm/wasm32-unknown-unknown/release/seed_web.wasm"
    )
    out_path = Path(sys.argv[2]) if len(sys.argv) > 2 else (HERE / "alea-web-offline.html")

    wasm = wasm_path.read_bytes()
    wasm_b64 = base64.b64encode(wasm).decode("ascii")  # no newlines, fixed alphabet

    # JS: substitute the wasm base64 into the placeholder, forming the exact
    # bytes that will live between <script> and </script>.
    js = (SRC / "app.js").read_text(encoding="utf-8")
    if "__WASM_B64__" not in js:
        print("ERROR: app.js has no __WASM_B64__ placeholder", file=sys.stderr)
        return 1
    script_content = js.replace("__WASM_B64__", wasm_b64)

    css = (SRC / "app.css").read_text(encoding="utf-8")
    style_content = css

    # CSP hashes are computed over the exact inline-content bytes (UTF-8), the
    # same bytes the browser hashes.
    script_hash = sha256_b64(script_content.encode("utf-8"))
    style_hash = sha256_b64(style_content.encode("utf-8"))

    csp = (
        "default-src 'none'; "
        f"script-src 'wasm-unsafe-eval' 'sha256-{script_hash}'; "
        f"style-src 'sha256-{style_hash}'; "
        "img-src 'none'; "
        "font-src 'none'; "
        "connect-src 'none'; "
        "base-uri 'none'; "
        "form-action 'none';"
    )

    shell = (SRC / "shell.html").read_text(encoding="utf-8")
    html = (
        shell.replace("{{CSP}}", csp)
        .replace("{{STYLE}}", style_content)
        .replace("{{SCRIPT}}", script_content)
    )
    # Normalize to LF, no trailing CR (determinism).
    html = html.replace("\r\n", "\n").replace("\r", "\n")

    html_bytes = html.encode("utf-8")
    out_path.write_bytes(html_bytes)

    print("=== Alea Offline Web Edition — inliner manifest ===")
    print(f"wasm            : {wasm_path}")
    print(f"wasm size       : {len(wasm)} bytes")
    print(f"wasm sha256     : {sha256_hex(wasm)}")
    print(f"script sha256   : sha256-{script_hash}")
    print(f"style  sha256   : sha256-{style_hash}")
    print(f"output          : {out_path}")
    print(f"output size     : {len(html_bytes)} bytes")
    print(f"output sha256   : {sha256_hex(html_bytes)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
