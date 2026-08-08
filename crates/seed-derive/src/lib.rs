//! `seed-derive` — BIP32/secp256k1/address code (SPEC §9, §13, §24).
//!
//! Subject to the same `#![no_std]`, no-`alloc` and scrub rules as
//! `seed-core` (SPEC §9).
#![no_std]

/// Thin constant-time secp256k1 wrapper over `k256` (WP-06).
pub mod curve;

/// BIP32 master-key derivation, CKD, fingerprint (WP-13).
pub mod bip32;

/// P2PKH / P2SH-P2WPKH / P2WPKH / P2TR address construction (WP-14).
pub mod address;

/// BIP-380 output-script descriptors for the opt-in wallet-export screen.
pub mod descriptor;
