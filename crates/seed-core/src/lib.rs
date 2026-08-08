//! `seed-core` — shared cryptographic core (SPEC §13).
//!
//! `#![no_std]`, no `alloc`, fixed-size buffers only. This crate holds the
//! frozen interface contracts and the leaf primitives + pipeline façade
//! that sit in the production dependency graph.
//!
//! Module ownership (`IMPLEMENTATION_MAP.md` §5/§6) — WP-00 (this file)
//! only declares the module tree; every module body below this line is
//! owned by its named work package and is edited only by that agent.
#![no_std]

/// Frozen interface contracts — types and traits only (WP-00).
pub mod contracts;

/// SHA-256 / SHA-512 / HMAC-SHA512 / PBKDF2 primitives (WP-01).
pub mod hash;

/// `hash160 = RIPEMD160(SHA256(x))` (WP-02).
pub mod hash160;

/// Base58Check fixed-buffer encoder (WP-03).
pub mod base58;

/// Bech32 / Bech32m fixed-buffer encoder (WP-04).
pub mod bech32;

/// BIP39 English wordlist, entropy/mnemonic conversion, prefix resolution,
/// seed derivation (WP-05).
pub mod bip39;

/// Fixed secret arena (WP-09).
pub mod arena;

/// BIP39 passphrase secret type (SPEC_PASSPHRASE §3, §5).
pub mod passphrase;

/// Core pipeline façade the UIs call (WP-15).
pub mod pipeline;
