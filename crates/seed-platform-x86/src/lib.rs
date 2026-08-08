//! `seed-platform-x86` — x86-64 UEFI platform checks (SPEC §11, §15–16,
//! §18).
#![no_std]

/// UEFI entry/runtime scaffolding shared by both UEFI binaries (WP-17).
pub mod boot;

/// Watchdog disablement + per-transition re-assertion (WP-18, SPEC §11.1).
pub mod watchdog;

/// Virtualization detection (WP-19, SPEC §11.2).
pub mod virt;

/// Console-topology inspection (WP-20, SPEC §11.3).
pub mod console;

/// Keyboard layout self-test and hidden-entry primitive (WP-22, SPEC
/// §11.5, §12.3).
pub mod input;

/// Machine entropy: EFI RNG, RDSEED64, RDRAND (WP-24, SPEC §15–16, §18).
pub mod rng;

/// Injectable monotonic-clock abstraction + wall-clock `Deadline` for
/// bounding machine-entropy acquisition time (SPEC §15–16; real-hardware
/// slow-RDSEED hang fix).
pub mod time;
