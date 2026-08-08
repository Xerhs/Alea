# QEMU/OVMF boot-test harness (WP-31, SPEC §29.3)

Scripts that boot an Alea UEFI edition (`seed-uefi-test` or
`seed-uefi-production`) under `qemu-system-x86_64` + OVMF, headless, and
assert against the output. Owned entirely by WP-31; see
`IMPLEMENTATION_MAP.md` §5/§6 for how this fits the rest of the project.

**Every script here is safe to run in an environment with no QEMU/OVMF
installed at all.** They check for `qemu-system-x86_64` and an OVMF
firmware pair *first*, before doing anything else, and print:

```
SKIPPED: qemu/ovmf not installed — run: sudo apt-get install -y qemu-system-x86 ovmf
```

then `exit 0`. No script here ever hangs or fails a CI job because the
tooling happens to be absent — that check is `require_prereqs_or_skip` in
`lib/common.sh`, and every entry-point script calls it as its first
action.

`lib/common.test.sh` is the one exception worth calling out: it unit-tests
`lib/common.sh`'s pure shell helpers (currently `build_esp`) directly,
never invokes `qemu-system-x86_64`, and always runs — `tests/qemu/lib/common.test.sh`
is a fast, QEMU-free sanity check.

## Prerequisites (once you want the real boot to run)

```sh
sudo apt-get install -y qemu-system-x86 ovmf
```

This installs `qemu-system-x86_64` and an OVMF firmware pair, normally at
`/usr/share/OVMF/OVMF_CODE.fd` / `/usr/share/OVMF/OVMF_VARS.fd`
(`lib/common.sh` also probes a few other distro layouts). If your distro
puts them somewhere else, point at them explicitly:

```sh
export OVMF_CODE=/path/to/OVMF_CODE.fd
export OVMF_VARS=/path/to/OVMF_VARS.fd
```

You'll also want the UEFI targets buildable:

```sh
source "$HOME/.cargo/env"
export CARGO_TARGET_DIR="$HOME/.cache/sf-target/wp-31"
cargo build -p seed-uefi-test --target x86_64-unknown-uefi
cargo build -p seed-uefi-production --target x86_64-unknown-uefi
```

(`run.sh`/`boot-smoke.sh`/`serial-drive.sh`/`screenshot.sh` all build the
binary themselves if it's missing, but building it once up front makes
repeated runs faster.)

## Scripts

| Script | Purpose |
| --- | --- |
| `drive-ceremony.py` | **The current driver.** Boots the real release image (or a single `.efi`), injects keys as an emulated PS/2 keyboard over QMP `send-key`, and captures a framebuffer `screendump` per named stage. This is the one to use. |
| `ppm2png.py` | Converts QEMU's binary-PPM `screendump` output to PNG. Pure standard library — no ImageMagick/PIL needed. |
| `decode-qr.py` | Decodes the Stage 7 export screen's QR out of a rendered PPM (zxing-cpp / OpenCV / `zbarimg`, whichever is installed). |
| `render-screens/` | Host binary that calls the SHIPPED `seed_flow::screens::export::render` against an in-memory framebuffer and dumps its real pixels — how the export QR gets checked at all (see "What QEMU cannot reach", below). |
| `run.sh` | Interactive boot: serial console attached to your terminal, for manual exploration. |
| `boot-smoke.sh` | Headless: boot, capture serial transcript, assert the pre-secret banner text appears. **Superseded** — see the serial note below. |
| `serial-drive.sh` | Headless: inject scripted keystrokes over serial, assert on the growing transcript. **Superseded** — see the serial note below. |
| `screenshot.sh` | Headless fixed-delay framebuffer capture with `golden/` hash comparison. Superseded by `drive-ceremony.py`, which captures at scripted points instead of at guessed delays. |

### Why `serial-drive.sh`/`boot-smoke.sh` no longer assert anything

Both grep the **serial transcript**. Since the 2026-08-06 GOP amendment
(commit 9625405) both UEFI editions render the entire ceremony through the
GOP linear framebuffer and write nothing to the firmware text console, so
that transcript is empty and every `EXPECT` has nothing to match. They are
left in place (they still boot cleanly and still short-circuit with
`SKIPPED:` where QEMU/OVMF are absent) but no new assertion should be added
to them; use `drive-ceremony.py` + screenshots instead.

### What QEMU cannot reach, and why that is correct

SPEC §11.2: *"If obvious virtualization is detected, production generation
MUST be disabled."* QEMU + OVMF trips several `seed_platform_x86::virt`
indicators at once (the CPUID hypervisor-present bit, the OVMF/QEMU firmware
strings, the emulated PCI display device), so the Stage 2 mandatory gates
fail closed with **"CANNOT CONTINUE — Virtualization indicators were detected
on this platform"** and the ceremony stops there.

Everything up to that point *is* reachable and is covered by
`scripts/production-launcher-and-gates.keys`: the six-item landing launcher,
Learn, Self-check, About, Stage 1 PREPARE's `[1][2][3]`+`[Enter]` checklist,
and the refusal itself. `scripts/verify-chainload.keys` covers `[2] Verify`
chain-loading `\EFI\ALEA\VERIFY.EFI` off the dual-file image.

Stages 2-7 (device, setup, entropy, generate, mnemonic, hidden re-entry,
passphrase, verify, export, finish) are **not** reachable in emulation, and
this harness deliberately does not try to make them reachable — defeating the
§11.2 gate to get a screenshot would be defeating a shipped safety property.
Their coverage comes from two other places instead:

* `seed-flow`'s own host tests drive the identical driver + screen renderers
  end-to-end over the frozen vectors (`cargo test -p seed-flow`);
* `render-screens/` paints the shipped export screen's real pixels for the
  QR-scannability check.

`scripts/production-happy-path.keys` records the full ceremony keystream
anyway — as the reference sequence for the SPEC §29.4 real-hardware pass.

All of them accept `test` or `production` as the edition argument
(`test` is the default where the script takes one at all); `production`
never displays a watermark or public test vectors (SPEC §4.1), so
`serial-drive.sh`'s bundled example script only targets `test` (the ack
and required-warning screens' text is identical in both editions since
both reuse `seed-flow`, but a production-edition equivalent should get
its own script rather than assuming so).

**Auto-boot / `startup.nsh`**: `lib/common.sh`'s `build_esp` drops a
one-line `startup.nsh` (`FS0:\EFI\BOOT\BOOTX64.EFI`) at the ESP root
alongside `\EFI\BOOT\BOOTX64.EFI`. This matters because a
never-before-booted OVMF's fresh NVRAM registers "EFI Internal Shell" as
Boot0001 *ahead of* the ESP's removable-media fallback, so without a
`startup.nsh` the firmware drops to an interactive `Shell>` prompt
instead of ever running the app — every script above would then time out
waiting for text that is never printed (or, for `screenshot.sh`,
silently baseline a screenshot of the Shell prompt). The UEFI Shell's own
convention is to auto-run a `startup.nsh` found at the root of a mapped
filesystem instead of dropping to the prompt, so this line chainloads
straight into `BOOTX64.EFI` regardless of which boot option NVRAM picked
first. See `lib/common.test.sh` for a host-only regression test that
this file is actually written.

### `run.sh`

```sh
tests/qemu/run.sh test                    # boot seed-uefi-test, no timeout
tests/qemu/run.sh production --timeout 30 # boot seed-uefi-production, kill after 30s
```

Serial is multiplexed onto your terminal (`-serial mon:stdio`): `Ctrl-A
C` toggles to the QEMU monitor, `Ctrl-A X` quits.

### `boot-smoke.sh`

```sh
tests/qemu/boot-smoke.sh test --timeout 15
```

Boots headlessly with serial redirected straight to a log file (no
monitor multiplexing), waits for the timeout (the pre-secret flow blocks
on a keypress that never arrives from `</dev/null`, so hitting the
timeout is the *expected*, successful path here — only the transcript
content is checked), then greps the transcript for the SPEC §22.1
opening-warning title and (test edition only) the `PUBLIC TEST PHRASE`
banner. Exits 1 and dumps the transcript if anything expected is
missing.

### `serial-drive.sh`

```sh
tests/qemu/serial-drive.sh tests/qemu/scripts/pre-secret-happy-path.keys test
```

Runs a small script language against the live serial transcript:

```
WAIT <seconds>          sleep before the next directive
SEND <literal text>     write literal bytes (no trailing newline)
KEY ENTER|ESC|BACKSPACE send the corresponding single control byte
EXPECT <substring>      poll the transcript for this substring (default
                        10s timeout, --expect-timeout to change it)
```

`scripts/pre-secret-happy-path.keys` (the old worked example) has been
**deleted**: it scripted the three separate acknowledgement screens the
2026-08-07 redesign merged into Stage 1 PREPARE's one `[1]`/`[2]`/`[3]`
checklist, and its `EXPECT` assertions had nothing to match post-GOP anyway.
The keystreams under `scripts/` are now driven by `drive-ceremony.py`.

**Why serial injection works at all**: the pre-secret flow
(`crates/seed-flow/src/keys.rs`) reads through the firmware's
`SIMPLE_TEXT_INPUT_PROTOCOL` (`ConIn`). Stock OVMF wires its serial port
into the same `TerminalDxe` console splitter as the graphical keyboard
console, so plain ASCII bytes on the serial chardev (`\r` for Enter,
`\x1b` for Escape, `\x08` for Backspace) arrive at `ConIn` as if typed
locally — the same mechanism every "drive the UEFI Shell over a serial
cable" guide relies on. **This has not been verified against a real
QEMU/OVMF install from this environment** (QEMU is not installed here);
the first real run is the actual verification. If a given OVMF build
turns out not to route serial into `ConIn` by default, that is a
firmware-configuration question, not a bug in this script.

#### Extending these scripts

The bundled example stops right after the third acknowledgement screen,
deliberately. What comes next (SPEC §11 mandatory-gate diagnostics,
including the SPEC §11.5 keyboard self-test's own keystroke sequence,
then the SPEC §8.4 required warning, then word-count/entropy-mode
selection, then — on into the secret phase — WP-26's physical-entry and
GOP mnemonic-display screens) is owned by WP-25/26
(`crates/seed-uefi-test/src/{flow_pre,flow_secret}/`), not this WP.
Extending `serial-drive.sh` scripts past that point is welcome, but
should be based on watching the real transcript from an actual QEMU run
first (`tests/qemu/run.sh test` interactively, or `boot-smoke.sh` with a
longer `--timeout` and reading its dumped transcript on failure) rather
than guessing at another WP's exact screen text/keybindings.

### `screenshot.sh`

```sh
tests/qemu/screenshot.sh test --delays "3 6 10" --out /tmp/sf-screens
```

Boots with a real (but `-display none`) GOP-capable video device
(`-vga std`) and a QEMU monitor reachable over a plain TCP socket
(`telnet:127.0.0.1:<port>,server,nowait`, driven with bash's own
`/dev/tcp` — no `nc`/`socat` dependency). At each delay in `--delays`
(seconds since boot), issues a monitor `screendump` and hash-compares the
result against `golden/<edition>/screen-<delay>s.sha256`. If no baseline
exists yet, writes one from this run and prints a `NOTE:` — **review the
`.ppm` by hand** before trusting a freshly-written baseline; this script
cannot know on its own whether a first capture is actually the expected
screen.

**Known limitation — fixed-delay capture, not event-driven.** There is
no signal from the guest back to this harness saying "the mnemonic
display is now on screen"; GOP framebuffer writes are invisible to
QEMU's monitor/serial introspection. Captures happen at fixed delays
after boot. This is inherently timing-fragile. The better long-term
design is: drive the pre-secret text menus with `serial-drive.sh` up to
the exact point of handoff into the secret phase (a point this harness
*can* detect, via `EXPECT`), then start `screenshot.sh`'s captures
relative to that known point instead of an absolute boot-time delay —
that composition is not wired up yet (`shared_file_needs` below).


## `artifacts/`

Reviewable PNG screenshots from a recorded run, one directory per run
(`artifacts/<date>-<task>/<run>/`). Committed deliberately — they are small
(~20-30 KB each) and are the evidence a reviewer actually looks at. The raw
`.ppm` framebuffer dumps they were converted from are ~12 MB each and are
`.gitignore`d everywhere in this tree; regenerate them by re-running
`drive-ceremony.py`.

## Quick start (current tooling)

```sh
# 1. build the release artifacts and the dual-file image
cargo build -p seed-uefi-production --target x86_64-unknown-uefi --release
cargo build -p alea-verify          --target x86_64-unknown-uefi --release
cargo run -p image-builder --bin image-builder -- \
    <...>/seed-uefi-production.efi out.img <...>/alea-verify.efi

# 2. drive it
python3 tests/qemu/drive-ceremony.py --image out.img \
    --script tests/qemu/scripts/production-launcher-and-gates.keys \
    --out tests/qemu/out/run1

# 3. look at the result
python3 tests/qemu/ppm2png.py --all tests/qemu/out/run1
```

## `golden/`

Per-edition baseline hashes for `screenshot.sh`, one `.sha256` file per
named capture (`golden/<edition>/screen-<delay>s.sha256`). Populated by
running `screenshot.sh` once QEMU/OVMF are actually available and
manually confirming each `.ppm` looks right, then committing the
resulting `.sha256` files (never commit the `.ppm` images themselves —
they're bulky and reproducible from a from a real run; keep them local
under `out/` if you want them for reference).

## `out/`

Scratch output for `screenshot.sh` runs (timestamped subdirectories).
Not committed; safe to delete.

## Manual run walkthrough

1. `sudo apt-get install -y qemu-system-x86 ovmf`
2. `source "$HOME/.cargo/env"; export CARGO_TARGET_DIR="$HOME/.cache/sf-target/wp-31"`
3. `cargo build -p seed-uefi-test --target x86_64-unknown-uefi`
4. `tests/qemu/run.sh test` — confirm you see the `Alea -- UEFI
   TEST EDITION` / `PUBLIC TEST PHRASE -- NEVER USE WITH FUNDS` banner and
   the SPEC §22.1 opening warning over serial.
5. `tests/qemu/boot-smoke.sh test --timeout 15` — same check, scripted;
   should print `PASS: ...` and exit 0.
6. `tests/qemu/serial-drive.sh tests/qemu/scripts/pre-secret-happy-path.keys test`
   — walks Stage 1 PREPARE's `[1]`/`[2]`/`[3]` checklist and `[Enter]`;
   should print `PASS: ...`. (The script still scripts the pre-redesign
   three acknowledgement screens — see the note above.)
7. `tests/qemu/screenshot.sh test --delays "3 6 10"` — first run writes
   baselines under `golden/test/`; open the `.ppm` files (e.g. `feh`,
   `eog`, ImageMagick `display`, or convert to PNG with
   `convert screen-3s.ppm screen-3s.png`) and confirm they show what you
   expect before trusting the baseline for future comparisons.

## What this harness intentionally does NOT do

Per SPEC §29.3: **"QEMU is never sufficient to approve production
platform security."** Nothing here substitutes for the SPEC §29.4
hardware matrix. In particular this harness cannot exercise: real EFI RNG
absence/presence variety, real RDSEED-capable/incapable CPUs, real
`PixelBltOnly` GOP implementations, or real Secure Boot configurations —
QEMU/OVMF only emulates a narrow slice of that space (see SPEC §29.3's
own list of what QEMU testing *can* usefully cover: bootability, menu
flow, GOP rendering incl. `PixelBltOnly` refusal if OVMF's virtual GPU
can be coaxed into it, keyboard input, simulated/missing EFI RNG,
watchdog behavior, shutdown requests, fault injection, test-build
watermarking).

## `shared_file_needs` (for the orchestrator, not actioned by this WP)

This WP owns only `tests/qemu/`; the following would need another WP's
sign-off to implement, and are documented here instead of being touched:

1. **A build-time "serial-mirror" affordance for the secret-phase GOP
   screens.** Right now the only way to check WP-26's mnemonic-display
   and related GOP-rendered screens is `screenshot.sh`'s fixed-delay
   framebuffer capture (see that script's own doc comment on the
   limitation). A `cfg`/feature-gated path in
   `crates/seed-flow/src/flow_secret/` (or its real-firmware
   wiring in `crates/seed-uefi-test/src/flow_secret/`) that *also* writes
   a plain-text line to the firmware text console (or a second UEFI
   `SIMPLE_TEXT_OUTPUT_PROTOCOL`-independent debug channel) whenever it
   transitions to a new named screen — e.g. `"[qemu-test] screen:
   mnemonic-display"` — gated so it compiles out entirely in the
   production edition and even in the test edition's normal release
   build, would let `serial-drive.sh` `EXPECT` on exact screen-transition
   points instead of guessing fixed delays. This requires editing files
   owned by WP-25/26 (`crates/seed-uefi-test/src/flow_secret/`,
   `crates/seed-flow/src/flow_secret/`), which are outside this
   WP's ownership, so it is not implemented here.
2. **Event-driven composition of `serial-drive.sh` and `screenshot.sh`.**
   Once (1) exists, the natural next step is a combined script that
   drives the pre-secret menus over serial up to the exact
   secret-phase-entry `EXPECT`, then immediately screendumps — replacing
   the fixed-delay heuristic. This is pure `tests/qemu/` work (within
   this WP's ownership) but is gated on (1) landing first, so it is left
   as a follow-up rather than built against guessed timings now.
3. **WP-29's image builder / readback verifier** (`tools/image-builder/`,
   `tools/media-readback-verifier/`) did not exist yet at the time this
   harness was written (`tools/` had no such directories). `build_esp` in
   `lib/common.sh` is a minimal, deterministic-enough stand-in (QEMU's
   `fat:` vvfat driver serving `\EFI\BOOT\BOOTX64.EFI` straight off a
   directory) sufficient for booting under QEMU, but is not the same
   thing as WP-29's real deterministic-image/readback-verification
   pipeline (SPEC §10, §32). Once WP-29 lands, this harness should
   probably build its ESP through that tool instead, for closer parity
   with what a real release image looks like.
