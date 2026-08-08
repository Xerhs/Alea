#!/usr/bin/env python3
"""Alea independent Python reference implementation CLI (WP-11,
SPEC §4.4).

Usage:
    python3 ref.py generate-candidates [OUT_DIR]
        Generate the candidate test-vector corpus and write it to
        OUT_DIR (default: tests/vectors/candidates/ relative to the
        repo root), per tests/vectors/SCHEMA.md.

    python3 ref.py check FILE [FILE ...]
        Re-run the full protocol over every case in each vector file and
        report any mismatch against the stored fields. Exit code 0 if
        every case round-trips, 1 otherwise.

    python3 ref.py compat generate [OUT_DIR]
        Generate the seed-compat candidate test-vector corpus (SPEC_COMPAT
        v0.6.1 §10.1, WP-C2) and write it to OUT_DIR (default:
        tests/vectors/compat/candidates/ relative to the repo root). These
        are CANDIDATES only -- WP-C3 owns freezing them to
        tests/vectors/compat/frozen/ after Rust/Python reconciliation and
        vendor-tool confirmation (IMPLEMENTATION_MAP_COMPAT.md §1.3).

    python3 ref.py compat check FILE [FILE ...]
        Re-run seed-compat's Method-A derivation over every case in each
        compat vector file and report any mismatch. Exit code 0 if every
        case round-trips, 1 otherwise.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from seedref import compat  # noqa: E402
from seedref import vectors  # noqa: E402


def _default_candidates_dir() -> Path:
    # reference/python/ref.py -> repo root is two levels up.
    repo_root = Path(__file__).resolve().parents[2]
    return repo_root / "tests" / "vectors" / "candidates"


def _default_compat_candidates_dir() -> Path:
    # reference/python/ref.py -> repo root is two levels up.
    repo_root = Path(__file__).resolve().parents[2]
    return repo_root / "tests" / "vectors" / "compat" / "candidates"


def cmd_generate_candidates(args: list) -> int:
    out_dir = Path(args[0]) if args else _default_candidates_dir()
    paths = vectors.write_candidates(str(out_dir))
    print(f"wrote {len(paths)} candidate vector file(s) to {out_dir}")
    for p in paths:
        print(f"  {p}")
    return 0


def cmd_check(args: list) -> int:
    if not args:
        print("usage: ref.py check FILE [FILE ...]", file=sys.stderr)
        return 2
    ok = True
    for path in args:
        problems = vectors.check_file(path)
        if problems:
            ok = False
            print(f"FAIL {path}")
            for p in problems:
                print(f"  {p}")
        else:
            print(f"OK   {path}")
    return 0 if ok else 1


def cmd_compat_generate(args: list) -> int:
    out_dir = Path(args[0]) if args else _default_compat_candidates_dir()
    paths = compat.write_candidates(str(out_dir))
    print(f"wrote {len(paths)} seed-compat candidate vector file(s) to {out_dir}")
    for p in paths:
        print(f"  {p}")
    return 0


def cmd_compat_check(args: list) -> int:
    if not args:
        print("usage: ref.py compat check FILE [FILE ...]", file=sys.stderr)
        return 2
    ok = True
    for path in args:
        problems = compat.check_file(path)
        if problems:
            ok = False
            print(f"FAIL {path}")
            for p in problems:
                print(f"  {p}")
        else:
            print(f"OK   {path}")
    return 0 if ok else 1


def cmd_compat(args: list) -> int:
    if not args:
        print("usage: ref.py compat {generate|check} ...", file=sys.stderr)
        return 2
    sub, rest = args[0], args[1:]
    if sub == "generate":
        return cmd_compat_generate(rest)
    if sub == "check":
        return cmd_compat_check(rest)
    print(f"unknown compat subcommand: {sub}", file=sys.stderr)
    print("usage: ref.py compat {generate|check} ...", file=sys.stderr)
    return 2


def main(argv: list) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "generate-candidates":
        return cmd_generate_candidates(rest)
    if cmd == "check":
        return cmd_check(rest)
    if cmd == "compat":
        return cmd_compat(rest)
    print(f"unknown command: {cmd}", file=sys.stderr)
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
