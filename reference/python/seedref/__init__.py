"""Alea independent Python reference implementation (WP-11).

SPEC §4.4: a small independent reference implementation, written from
SPEC.md and the public BIP documents alone (no Rust code was read while
writing this package -- that is the point of an independent reference).

It operates only on public test vectors, implements the transcript,
dice/coin, BIP39, BIP32 and address protocols, and is never a production
seed generator (SPEC §4.4).
"""
