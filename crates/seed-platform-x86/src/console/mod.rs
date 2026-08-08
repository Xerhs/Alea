//! Owned by WP-20 (SPEC §11.3). Console-topology inspection.
//!
//! SPEC §11.3 requires the application to inspect the active ConIn/ConOut/
//! ErrOut device paths *before generation* and refuse production
//! generation when:
//!
//! - a serial console path is active;
//! - a network console path is active;
//! - multiple active output paths cannot be explained;
//! - a known remote-management path is active;
//! - the path is vendor-specific and cannot be classified;
//! - the input path may accept remote input;
//! - device-path inspection fails.
//!
//! This module walks the binary UEFI device-path node stream for each
//! console and classifies every node. Classification is a **whitelist**:
//! local GOP/PCI/ACPI infrastructure and local USB/PS2/local-bus messaging
//! nodes are accepted; anything not explicitly recognised — including
//! parse failures, truncated nodes, and vendor-defined nodes — refuses,
//! per the fail-closed pitfall called out in `IMPLEMENTATION_MAP.md`
//! WP-20 ("Device-path inspection fails" -> disable).
//!
//! Node parsing itself is delegated to the pinned `uefi` crate's
//! [`uefi::proto::device_path`] types ([`DevicePath`], [`DevicePathNode`]),
//! which validate node-length bounds and total-path length against the
//! supplied byte slice (`TryFrom<&[u8]>`) without `alloc`. This module
//! adds the console-specific classification and structured report on top.
//!
//! Host tests (`cargo test -p seed-platform-x86`) exercise the classifier
//! against synthetic device-path byte sequences built by hand to match the
//! UEFI Device Path Protocol binary format (SPEC §11.3 DoD).

#![allow(clippy::module_name_repetitions)]

#[cfg(test)]
extern crate std;

use uefi::proto::device_path::{ByteConversionError, DevicePath, DevicePathNode, DeviceSubType, DeviceType};

/// Upper bound on the number of nodes a single console device path may
/// contain before this module gives up and fails closed. No `alloc`
/// (SPEC §13): the node summary list is a fixed-size array, not a `Vec`.
/// Real console paths (a handful of ACPI/PCI/USB hops) are far shorter
/// than this; a path this long is itself a reason for suspicion.
pub const MAX_NODES: usize = 24;

/// Upper bound on the number of device handles considered active for a
/// single console role (`ConIn`/`ConOut`/`ErrOut`) in one sweep. No
/// `alloc` (SPEC §13): handle buffers are fixed-size arrays, not `Vec`s.
///
/// Console-protocol enumeration (see [`uefi_backend::sweep_by_guid`] and
/// its `SimpleTextOutput`/`SimpleTextInput`/`GraphicsOutput` siblings)
/// sees strictly more handles than the EDK2 console-device tag sweep
/// alone did: every real display head plus every real input device plus
/// the firmware's own splitter/aggregate handle(s) all carry these
/// protocols. 16 absorbs a docked multi-head desktop (a handful of
/// display heads) with a USB keyboard and the splitter without coming
/// close to real-hardware handle counts; a firmware that reports more
/// than this is itself unexplainable and fails closed (SPEC §11.3:
/// "multiple active output paths cannot be explained").
pub const MAX_CONSOLE_HANDLES: usize = 16;

/// Which of the three consoles a [`PathReport`] describes (SPEC §11.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleRole {
    /// The active input console (`ConIn`).
    ConIn,
    /// The active output console (`ConOut`).
    ConOut,
    /// The active error-output console (`ErrOut`).
    ErrOut,
    /// An additional active output-capable handle beyond `ConOut`/`ErrOut`
    /// (SPEC §11.3: "multiple active output paths cannot be explained").
    ExtraOut,
}

/// Why a console device path was refused (SPEC §11.3). Each variant
/// corresponds to one of the enumerated MUST-refuse conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefuseReason {
    /// A serial (UART) messaging node is present.
    SerialConsole,
    /// A networking messaging node (MAC/IPv4/IPv6/VLAN/URI/DNS/Wi-Fi/
    /// Bluetooth/InfiniBand/REST/NVMe-oF) is present.
    NetworkConsole,
    /// A known remote-management node (BMC) is present.
    RemoteManagement,
    /// A node's type/subtype is not on the accept whitelist: vendor-
    /// defined hardware/messaging/media nodes, BIOS Boot Specification
    /// nodes, mid-path instance separators, and any other subtype this
    /// module does not recognise all land here. Fail closed rather than
    /// guess.
    VendorUnclassifiable,
    /// The byte stream did not parse as a well-formed UEFI device path
    /// (truncated node, length mismatch, missing end-entire node, or no
    /// path/handle available at all). SPEC §11.3: "device-path inspection
    /// fails" -> refuse.
    ParseFailure,
    /// More than one active output-capable console handle was reported
    /// and they do not reduce to the same device path, so the multiple
    /// paths cannot be explained (SPEC §11.3).
    MultipleOutputPaths,
    /// The input console's device path indicates it may accept remote
    /// input (i.e. its own classification came back Serial or Network).
    /// Reported specifically for [`ConsoleRole::ConIn`] so the diagnostic
    /// screen can use the exact SPEC §11.3 wording ("the input path may
    /// accept remote input").
    RemoteCapableInput,
}

impl RefuseReason {
    /// Fixed, human-readable summary suitable for the pre-secret
    /// diagnostics screen (SPEC §11.3: "MUST show a human-readable
    /// summary without exposing secret data"). Device-path bytes
    /// themselves are never formatted into text by this module — only
    /// this static classification string is shown.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::SerialConsole => "a serial console path is active",
            Self::NetworkConsole => "a network console path is active",
            Self::RemoteManagement => "a known remote-management path is active",
            Self::VendorUnclassifiable => "a console path is vendor-specific and cannot be classified",
            Self::ParseFailure => "device-path inspection failed",
            Self::MultipleOutputPaths => "multiple active output paths cannot be explained",
            Self::RemoteCapableInput => "the input path may accept remote input",
        }
    }
}

/// Accepted node categories (SPEC §11.3: "local GOP/USB/PS2 acceptable").
/// Purely descriptive — carried in [`NodeSummary`] for the structured
/// report; classification decisions are made from [`RefuseReason`] (the
/// `Err` side), not from this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// Hardware Device Path: PCI, PCCard, memory-mapped, or generic
    /// controller node. Local platform topology (e.g. the PCI hop leading
    /// to a GOP-capable display adapter).
    HardwareLocal,
    /// ACPI Device Path (`_HID`-based enumeration, including Expanded
    /// ACPI and `_ADR`/NVDIMM). Covers legacy PS/2 keyboard/mouse
    /// controllers and other ACPI-enumerated local platform devices.
    Acpi,
    /// Messaging Device Path node identifying a local bus attachment:
    /// USB, USB Class, USB WWID, 1394, SATA, device logical unit, NVMe
    /// namespace, SD/eMMC/UFS.
    MessagingLocalBus,
    /// Media Device Path node (file path, hard-drive partition, CD-ROM).
    /// Rare on a console path but benign when present.
    Media,
    /// The terminating End-Entire node.
    EndEntire,
}

/// One node's classification, kept for the structured report. `device_type`
/// and `sub_type` are the raw UEFI values (never secret, non-sensitive
/// platform topology data) so the diagnostics path can log/display them
/// without re-deriving them from firmware.
#[derive(Debug, Clone, Copy)]
pub struct NodeSummary {
    /// Raw UEFI device-path major type byte.
    pub device_type: u8,
    /// Raw UEFI device-path sub-type byte.
    pub sub_type: u8,
    /// This module's classification of the node.
    pub kind: Result<NodeKind, RefuseReason>,
}

/// Structured report for one console's device path (SPEC §11.3).
#[derive(Debug, Clone, Copy)]
pub struct PathReport {
    /// Which console this report describes.
    pub role: ConsoleRole,
    /// Per-node classification, in path order. Only the first
    /// [`Self::node_count`] entries are meaningful.
    pub nodes: [Option<NodeSummary>; MAX_NODES],
    /// Number of populated entries in [`Self::nodes`].
    pub node_count: usize,
    /// Overall verdict: `Ok(())` if every node classified as accepted,
    /// otherwise the first refuse reason encountered while walking the
    /// path (not necessarily the *worst* one — the first is sufficient to
    /// refuse, and reporting more would not add safety margin).
    pub verdict: Result<(), RefuseReason>,
}

impl PathReport {
    /// Build a report that refuses outright with `reason`, recording no
    /// nodes. Used for missing paths / parse failures / open failures —
    /// every case SPEC §11.3 spells out as "device-path inspection
    /// fails". `pub` so callers outside this module (the real-firmware
    /// wiring's system-table-handle fallback, and its unused-slot
    /// padding) can build one without duplicating this constant.
    #[must_use]
    pub const fn refuse(role: ConsoleRole, reason: RefuseReason) -> Self {
        Self {
            role,
            nodes: [None; MAX_NODES],
            node_count: 0,
            verdict: Err(reason),
        }
    }

    /// `true` if this console's path was fully classified as accepted.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        self.verdict.is_ok()
    }
}

/// Classify a single already-parsed device-path node (SPEC §11.3).
///
/// Whitelist match: every arm that returns `Ok` is an explicitly
/// recognised, locally-attached node type. The wildcard arms in each
/// device-type's sub-match, and the final catch-all, both return
/// [`RefuseReason::VendorUnclassifiable`] — an unrecognised subtype fails
/// closed rather than being assumed benign.
fn classify_node(node: &DevicePathNode) -> Result<NodeKind, RefuseReason> {
    let device_type = node.device_type();
    let sub_type = node.sub_type();

    if device_type == DeviceType::HARDWARE {
        return match sub_type {
            DeviceSubType::HARDWARE_PCI
            | DeviceSubType::HARDWARE_PCCARD
            | DeviceSubType::HARDWARE_MEMORY_MAPPED
            | DeviceSubType::HARDWARE_CONTROLLER => Ok(NodeKind::HardwareLocal),
            DeviceSubType::HARDWARE_BMC => Err(RefuseReason::RemoteManagement),
            _ => Err(RefuseReason::VendorUnclassifiable),
        };
    }

    if device_type == DeviceType::ACPI {
        return match sub_type {
            DeviceSubType::ACPI
            | DeviceSubType::ACPI_EXPANDED
            | DeviceSubType::ACPI_ADR
            | DeviceSubType::ACPI_NVDIMM => Ok(NodeKind::Acpi),
            _ => Err(RefuseReason::VendorUnclassifiable),
        };
    }

    if device_type == DeviceType::MESSAGING {
        return match sub_type {
            DeviceSubType::MESSAGING_USB
            | DeviceSubType::MESSAGING_USB_CLASS
            | DeviceSubType::MESSAGING_USB_WWID
            | DeviceSubType::MESSAGING_1394
            | DeviceSubType::MESSAGING_SATA
            | DeviceSubType::MESSAGING_DEVICE_LOGICAL_UNIT
            | DeviceSubType::MESSAGING_NVME_NAMESPACE
            | DeviceSubType::MESSAGING_SD
            | DeviceSubType::MESSAGING_EMMC
            | DeviceSubType::MESSAGING_UFS => Ok(NodeKind::MessagingLocalBus),
            DeviceSubType::MESSAGING_UART => Err(RefuseReason::SerialConsole),
            DeviceSubType::MESSAGING_MAC_ADDRESS
            | DeviceSubType::MESSAGING_IPV4
            | DeviceSubType::MESSAGING_IPV6
            | DeviceSubType::MESSAGING_VLAN
            | DeviceSubType::MESSAGING_URI
            | DeviceSubType::MESSAGING_DNS
            | DeviceSubType::MESSAGING_WIFI
            | DeviceSubType::MESSAGING_BLUETOOTH
            | DeviceSubType::MESSAGING_BLUETOOTH_LE
            | DeviceSubType::MESSAGING_INFINIBAND
            | DeviceSubType::MESSAGING_REST_SERVICE
            | DeviceSubType::MESSAGING_NVME_OF_NAMESPACE => Err(RefuseReason::NetworkConsole),
            _ => Err(RefuseReason::VendorUnclassifiable),
        };
    }

    if device_type == DeviceType::MEDIA {
        return match sub_type {
            DeviceSubType::MEDIA_FILE_PATH | DeviceSubType::MEDIA_HARD_DRIVE | DeviceSubType::MEDIA_CD_ROM => {
                Ok(NodeKind::Media)
            }
            _ => Err(RefuseReason::VendorUnclassifiable),
        };
    }

    // BIOS Boot Specification nodes, END_INSTANCE nodes reached mid-walk
    // (a second device-path instance — unexpected on a console handle),
    // and any device type outside the UEFI-defined 0x01..=0x05 range all
    // fall through here: unclassifiable, fail closed.
    Err(RefuseReason::VendorUnclassifiable)
}

/// Walk and classify an already-parsed [`DevicePath`] for `role` (SPEC
/// §11.3).
///
/// [`DevicePath::node_iter`] stops before the terminating end-entire node
/// and never yields it, so [`PathReport::node_count`] does not include an
/// `EndEntire` entry; the report's `verdict` is `Ok(())` only if every
/// yielded node classified as accepted.
///
/// A path with more than [`MAX_NODES`] nodes refuses with
/// [`RefuseReason::VendorUnclassifiable`] rather than growing the report
/// unboundedly (no `alloc`, SPEC §13).
#[must_use]
pub fn classify(role: ConsoleRole, path: &DevicePath) -> PathReport {
    let mut report = PathReport {
        role,
        nodes: [None; MAX_NODES],
        node_count: 0,
        verdict: Ok(()),
    };

    for node in path.node_iter() {
        if report.node_count >= MAX_NODES {
            report.verdict = Err(RefuseReason::VendorUnclassifiable);
            return report;
        }
        let kind = classify_node(node);
        report.nodes[report.node_count] = Some(NodeSummary {
            device_type: node.device_type().0,
            sub_type: node.sub_type().0,
            kind,
        });
        report.node_count += 1;
        if let Err(reason) = kind {
            if report.verdict.is_ok() {
                report.verdict = Err(reason);
            }
        }
    }

    // SPEC §11.3: the input path may accept remote input. Re-label a
    // ConIn refusal that came from a serial/network node with the more
    // specific wording so the diagnostics screen can quote it directly.
    if role == ConsoleRole::ConIn {
        if let Err(RefuseReason::SerialConsole | RefuseReason::NetworkConsole) = report.verdict {
            report.verdict = Err(RefuseReason::RemoteCapableInput);
        }
    }

    report
}

/// Parse `bytes` as a UEFI device path and classify it for `role` (SPEC
/// §11.3).
///
/// This is the entry point host tests use directly against synthetic
/// device-path byte sequences (IMPLEMENTATION_MAP WP-20 DoD). A parse
/// failure (truncated node, length mismatch, missing/invalid end-entire
/// node) refuses with [`RefuseReason::ParseFailure`] — "device-path
/// inspection fails" per SPEC §11.3 — rather than panicking or accepting
/// a partial path.
#[must_use]
pub fn parse_and_classify(role: ConsoleRole, bytes: &[u8]) -> PathReport {
    match <&DevicePath>::try_from(bytes) {
        Ok(path) => classify(role, path),
        Err(ByteConversionError::InvalidLength) => PathReport::refuse(role, RefuseReason::ParseFailure),
    }
}

/// Already-classified [`PathReport`]s for one console-topology sweep,
/// grouped by role (SPEC §11.3), ready for [`aggregate_topology`].
///
/// Each slice holds one report per path-bearing handle discovered for
/// that role by [`resolve_role`] (see that function's own doc comment
/// for the ordered-stages resolution this implements): `con_in`/
/// `con_out` are populated with [`ConsoleRole::ConIn`]/
/// [`ConsoleRole::ConOut`] on the first (primary) handle, any further
/// handles classified as [`ConsoleRole::ExtraOut`] for `con_out`.
/// `err_out` is empty when no `ErrOut` handle resolved at all — SPEC
/// §11.3: "its absence alone is not fatal" — never a refuse condition by
/// itself.
pub struct TopologySets<'a> {
    /// Every active `ConIn`-role report (SPEC §11.3: every input handle
    /// must be classified with role [`ConsoleRole::ConIn`] so a
    /// serial/network verdict is re-labelled
    /// [`RefuseReason::RemoteCapableInput`] for *every* input handle, not
    /// only the first).
    pub con_in: &'a [PathReport],
    /// Every active `ConOut`-role report; `con_out[0]` is the primary
    /// output handle, `con_out[1..]` are additional active output-capable
    /// handles (SPEC §11.3: "multiple active output paths cannot be
    /// explained").
    pub con_out: &'a [PathReport],
    /// Every active `ErrOut`-role report. Empty means "no active `ErrOut`
    /// handle was found" (not fatal on its own).
    pub err_out: &'a [PathReport],
    /// `true` when the sweep that produced these reports found more
    /// active handles than its fixed buffer could hold. A truncated
    /// sweep cannot be fully explained, so it fails closed exactly like
    /// an unexplained extra output path.
    pub truncated: bool,
}

/// Aggregate already-classified per-handle [`PathReport`]s into one
/// overall accept/refuse verdict (SPEC §11.3).
///
/// Evaluation order (fixed, preserves the previous `ConIn` -> `ConOut` ->
/// `ErrOut` precedence and adds the "multiple active output paths" check
/// this module previously skipped):
///
/// 1. A truncated sweep (more active handles than the fixed buffer could
///    hold) refuses with [`RefuseReason::MultipleOutputPaths`] — it
///    cannot be explained, so it fails closed.
/// 2. No active `ConIn` or no active `ConOut` report at all refuses with
///    [`RefuseReason::ParseFailure`] ("device-path inspection fails").
/// 3. The first `Err` among the `ConIn` reports, in order, is returned —
///    every input handle is checked, not only the first.
/// 4. The primary `ConOut` report's (`con_out[0]`) verdict, if `Err`, is
///    returned.
/// 5. Each further `ConOut` report (`con_out[1..]`) is checked: a
///    serial/network/remote-management verdict is returned as itself
///    (SPEC §11.3 names those conditions specifically regardless of
///    which output handle they appear on); any other `Err` (vendor-
///    unclassifiable, parse failure, or an inner truncation/remote-input
///    marker) collapses to [`RefuseReason::MultipleOutputPaths`] — an
///    unexplained second output path; an `Ok` extra output is a second
///    *fully classified, fully local* path (e.g. a second monitor) and
///    is explained, not refused.
/// 6. The first `Err` among the `ErrOut` reports, if any are present, is
///    returned. An empty `ErrOut` slice is not fatal.
/// 7. Otherwise `Ok(())`: generation may proceed.
#[must_use]
pub fn aggregate_topology(sets: &TopologySets<'_>) -> Result<(), RefuseReason> {
    if sets.truncated {
        return Err(RefuseReason::MultipleOutputPaths);
    }
    if sets.con_in.is_empty() || sets.con_out.is_empty() {
        return Err(RefuseReason::ParseFailure);
    }

    for report in sets.con_in {
        if let Err(reason) = report.verdict {
            return Err(reason);
        }
    }

    if let Err(reason) = sets.con_out[0].verdict {
        return Err(reason);
    }

    for report in &sets.con_out[1..] {
        if let Err(reason) = report.verdict {
            return Err(match reason {
                RefuseReason::SerialConsole
                | RefuseReason::NetworkConsole
                | RefuseReason::RemoteManagement => reason,
                RefuseReason::VendorUnclassifiable
                | RefuseReason::ParseFailure
                | RefuseReason::MultipleOutputPaths
                | RefuseReason::RemoteCapableInput => RefuseReason::MultipleOutputPaths,
            });
        }
        // Ok: a second fully-whitelisted local output path (e.g. a
        // second monitor) is explained, not refused.
    }

    for report in sets.err_out {
        if let Err(reason) = report.verdict {
            return Err(reason);
        }
    }

    Ok(())
}

/// One handle's `DevicePath` open disposition, the shared primitive every
/// sweep stage (tag or protocol) reduces to (SPEC §11.3).
///
/// Built by the UEFI-only [`uefi_backend`] from a real
/// `open_protocol::<DevicePath>(GetProtocol)` call; built by host tests
/// directly from fixture bytes via `<&DevicePath>::try_from`. Carrying
/// only a borrowed `&DevicePath` (never an owned handle or a live
/// `ScopedProtocol`) keeps this type, and therefore [`SweepAccumulator`],
/// entirely `cfg`-free and host-testable.
#[derive(Debug, Clone, Copy)]
pub enum HandleProbe<'a> {
    /// The handle carries a `DevicePath` — classify it.
    Path(&'a DevicePath),
    /// Opening `DevicePath` on this handle returned `Status::UNSUPPORTED`:
    /// the handle carries no device path at all. This is exactly the
    /// signature the real-hardware diagnostic proved the firmware's
    /// ConSplitter/virtual aggregate handle carries — the handle is
    /// **skipped**: neither counted as an active console member nor
    /// refused. A fully virtual vendor console with no device path
    /// forwarding output elsewhere is undetectable by any device-path
    /// inspection and is exactly SPEC §11.3's honesty rule ("these checks
    /// catch misconfiguration, not deception").
    NoDevicePath,
    /// Opening `DevicePath` on this handle failed with any error other
    /// than `Status::UNSUPPORTED`. Unlike `NoDevicePath` this is *not* the
    /// known splitter signature — it is an unexplained failure to inspect
    /// the handle at all, so it is counted and refused
    /// ([`RefuseReason::ParseFailure`]) rather than silently skipped.
    OpenError,
}

/// Outcome of one sweep stage (one tag GUID or one console protocol GUID)
/// for one console role (SPEC §11.3).
#[derive(Debug, Clone, Copy)]
pub enum SweepOutcome {
    /// The sweep's own handle search returned `Status::NOT_FOUND`: no
    /// handle on this firmware carries this tag/protocol at all. Falls
    /// through to the next stage.
    Absent,
    /// The sweep's handle search succeeded (possibly with zero handles).
    /// `reports[..len]` holds one classified report per **path-bearing**
    /// handle found (splitters already skipped by [`SweepAccumulator`]);
    /// `len == 0` is the OEM laptop's tag-sweep-hits-only-the-splitter case and
    /// also falls through to the next stage.
    Found {
        /// Per-handle classified reports, in discovery order.
        reports: [Option<PathReport>; MAX_CONSOLE_HANDLES],
        /// Number of populated entries in `reports`.
        len: usize,
    },
    /// More handles exist than the fixed buffer could hold, or the
    /// handle search returned some other firmware error. Cannot be fully
    /// explained; if this is the stage that would otherwise resolve the
    /// role, resolution fails closed (see [`resolve_role`]).
    Truncated,
}

/// Pure, `cfg`-free accumulator that turns a sequence of per-handle
/// [`HandleProbe`]s into a [`SweepOutcome`] (SPEC §11.3).
///
/// Splitter/aggregate handles ([`HandleProbe::NoDevicePath`]) are skipped
/// — neither counted nor refused. Role assignment happens strictly on the
/// **counted** (path-bearing) handles, in the order they are pushed: the
/// first counted handle gets `primary_role`, every subsequent one gets
/// `extra_role`. Because splitters are skipped first, a splitter that
/// happens to enumerate before the real device (firmware handle ordering
/// is not specified by the UEFI spec) cannot steal the primary role slot.
///
/// Holding only owned [`PathReport`]s (never a borrowed `DevicePath` or a
/// live `ScopedProtocol`) lets the UEFI caller open, probe, and drop each
/// handle's protocol one at a time inside its enumeration loop — no
/// lifetime knot from trying to keep every handle's protocol open at
/// once.
pub struct SweepAccumulator {
    reports: [Option<PathReport>; MAX_CONSOLE_HANDLES],
    len: usize,
    primary_role: ConsoleRole,
    extra_role: ConsoleRole,
}

impl SweepAccumulator {
    /// Start a new accumulator for one sweep stage. `primary_role` is
    /// assigned to the first path-bearing handle pushed; `extra_role` to
    /// every one after that.
    #[must_use]
    pub const fn new(primary_role: ConsoleRole, extra_role: ConsoleRole) -> Self {
        Self { reports: [None; MAX_CONSOLE_HANDLES], len: 0, primary_role, extra_role }
    }

    /// Record one handle's probe result (SPEC §11.3).
    ///
    /// [`HandleProbe::NoDevicePath`] is skipped: not counted, not
    /// refused. [`HandleProbe::Path`] is classified with the unchanged
    /// whitelist [`classify`]. [`HandleProbe::OpenError`] is counted as a
    /// [`RefuseReason::ParseFailure`] refusal — "device-path inspection
    /// fails" (SPEC §11.3) — distinct from the known-benign splitter
    /// signature.
    ///
    /// The caller is expected to push at most [`MAX_CONSOLE_HANDLES`]
    /// probes (the UEFI backend's own handle buffer is sized to that
    /// bound, so `locate_handle` itself never hands it more); a push past
    /// that bound is silently dropped rather than corrupting state or
    /// panicking, but this is unreachable in practice given that caller
    /// discipline.
    pub fn push(&mut self, probe: HandleProbe<'_>) {
        if self.len >= MAX_CONSOLE_HANDLES {
            return;
        }
        let report = match probe {
            HandleProbe::NoDevicePath => return,
            HandleProbe::Path(path) => {
                let role = if self.len == 0 { self.primary_role } else { self.extra_role };
                classify(role, path)
            }
            HandleProbe::OpenError => {
                let role = if self.len == 0 { self.primary_role } else { self.extra_role };
                PathReport::refuse(role, RefuseReason::ParseFailure)
            }
        };
        self.reports[self.len] = Some(report);
        self.len += 1;
    }

    /// Finish accumulation. `truncated` should be `true` only when the
    /// underlying handle search itself reported more handles than fit —
    /// never derived from anything counted here (see [`Self::push`]'s own
    /// doc comment on why this accumulator cannot overflow in practice).
    #[must_use]
    pub fn finish(self, truncated: bool) -> SweepOutcome {
        if truncated {
            return SweepOutcome::Truncated;
        }
        SweepOutcome::Found { reports: self.reports, len: self.len }
    }
}

/// Densified, per-role result of [`resolve_role`] (SPEC §11.3): the
/// reports from whichever stage resolved the role (or an empty/truncated
/// result if none did), ready to slice straight into
/// [`TopologySets`].
pub struct RoleResolution {
    /// Per-handle classified reports, in discovery order.
    /// `reports[..len]` is the meaningful prefix; unused trailing slots
    /// are filled with an arbitrary refuse report that is never read.
    pub reports: [PathReport; MAX_CONSOLE_HANDLES],
    /// Number of populated entries in `reports`.
    pub len: usize,
    /// `true` if the stage that would have resolved this role instead
    /// reported [`SweepOutcome::Truncated`].
    pub truncated: bool,
}

/// Resolve one console role from its ordered list of sweep stages (SPEC
/// §11.3): the EDK2 tag sweep first (fast-path/preferred source), then
/// console-protocol enumeration (portable fallback), evaluated strictly
/// in order.
///
/// A stage **resolves** the role iff it produced at least one
/// path-bearing report ([`SweepOutcome::Found`] with `len >= 1`) —
/// whether that report is a clean accept or a refusal. [`SweepOutcome::
/// Absent`] (`NOT_FOUND`) and [`SweepOutcome::Found`] with `len == 0`
/// (every handle at this stage was a path-less splitter — the OEM laptop's
/// `ConOut` tag case) both fall through to the next stage. Once a stage
/// resolves, no later stage is consulted at all — including one that
/// would report [`SweepOutcome::Truncated`]; later stages are
/// *alternative* sources for the same role, not additional members, so a
/// large handle population on an unconsulted later stage (e.g. many GOP
/// heads on firmware whose `SimpleTextOutput` sweep already resolved
/// cleanly) must not spuriously refuse the machine.
///
/// [`SweepOutcome::Truncated`] at the stage actually being consulted (no
/// earlier stage resolved) stops resolution for this role with
/// `truncated: true` — [`aggregate_topology`] turns that into
/// [`RefuseReason::MultipleOutputPaths`], fail-closed.
///
/// If every stage is `Absent` or empty-`Found`, the role resolves to an
/// empty report set (`len: 0`, `truncated: false`) — [`aggregate_topology
/// `]'s existing empty-`ConIn`/`ConOut` check refuses
/// [`RefuseReason::ParseFailure`] (an all-splitter machine fails closed);
/// an empty `ErrOut` is exempt from that check and stays non-fatal (SPEC
/// §11.3: "its absence alone is not fatal").
#[must_use]
pub fn resolve_role(stages: &[SweepOutcome]) -> RoleResolution {
    // Placeholder for unused trailing slots below `len` -- never read by
    // any caller (they all slice `reports[..len]`); `ConsoleRole::ConIn`
    // is an arbitrary choice, matching the same established padding
    // pattern this module's callers have always used.
    const PAD: PathReport = PathReport::refuse(ConsoleRole::ConIn, RefuseReason::ParseFailure);

    for stage in stages {
        match stage {
            SweepOutcome::Absent => {}
            SweepOutcome::Found { len: 0, .. } => {}
            SweepOutcome::Found { reports, len } => {
                let dense = core::array::from_fn(|i| reports[i].unwrap_or(PAD));
                return RoleResolution { reports: dense, len: *len, truncated: false };
            }
            SweepOutcome::Truncated => {
                return RoleResolution { reports: [PAD; MAX_CONSOLE_HANDLES], len: 0, truncated: true };
            }
        }
    }

    RoleResolution { reports: [PAD; MAX_CONSOLE_HANDLES], len: 0, truncated: false }
}

/// Real-firmware backend: obtains device paths from UEFI handles and
/// classifies them. Only compiled for the `x86_64-unknown-uefi` target,
/// never pulled into host `cargo test` runs.
///
/// # Resolving the *active* console handles without a runtime UEFI
/// variable read (SPEC §28)
///
/// SPEC §11.3's "active `ConIn`/`ConOut`/`ErrOut` device paths" are, on
/// EDK2-derived firmware, exactly the paths recorded in the `ConIn`/
/// `ConOut`/`ErrOut` UEFI variables — but SPEC §28 prohibits any runtime
/// UEFI variable read in production-reachable source, so this module
/// never performs one. EDK2's `ConPlatformDxe` driver
/// (`MdeModulePkg/Universal/Console/ConPlatformDxe`) already reads those
/// variables itself during boot and mirrors the *active-membership*
/// result onto three per-device tag protocol GUIDs, installed on every
/// device handle that is currently an active member of that console:
/// `EFI_CONSOLE_IN_DEVICE_GUID`, `EFI_CONSOLE_OUT_DEVICE_GUID`,
/// `EFI_STANDARD_ERROR_DEVICE_GUID` (`MdeModulePkg/Include/Guid/
/// {ConsoleInDevice,ConsoleOutDevice,StandardErrorDevice}.h`). Consulting
/// this tag first ([`uefi_backend::sweep_by_guid`]) is not a widening of what this gate
/// accepts — it is exactly SPEC §11.3's object of inspection, and a
/// device that is tagged *and* classifies as serial/network/remote still
/// refuses.
///
/// Real hardware surveyed for this change (an OEM laptop firmware
/// that does *not* follow the standard EDK2 tagging contract) proved the
/// tag sweep alone is not portable: its `ConOut` tag landed only on the
/// console *splitter*'s own virtual aggregate handle (no `DevicePath` at
/// all — `Status::UNSUPPORTED` on open), and its `ConIn`/`ErrOut` tags
/// were not installed on any handle whatsoever. Every UEFI firmware,
/// however, is required by the UEFI spec to install
/// `EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL`/`EFI_SIMPLE_TEXT_INPUT_PROTOCOL`/
/// `EFI_GRAPHICS_OUTPUT_PROTOCOL` directly on the real console devices;
/// the ConSplitter aggregate handles are exactly the ones *without* a
/// device path. [`resolve_role`] therefore falls through, per role, from
/// the tag sweep to enumerating those console protocols
/// ([`uefi_backend::sweep_simple_text_output`]/[`uefi_backend::sweep_simple_text_input`]/
/// [`uefi_backend::sweep_graphics_output`]) whenever the tag sweep does not itself
/// resolve a path-bearing handle — on the OEM laptop this finds the real iGPU
/// (`SimpleTextOutput`/`GraphicsOutput`, sharing one PCI/ACPI path) and
/// the real PS/2 keyboard (`SimpleTextInput`), skipping the path-less
/// splitter handles on each protocol, exactly reproducing the tag-sweep
/// behavior EDK2/OVMF firmware already gave for free.
///
/// # Over-refusal is the deliberate, safe default on enumeration
///
/// Unlike the tag sweep's active-membership semantics, a console-protocol
/// enumeration finds every console-*capable* handle, active or not —
/// whether a given handle is genuinely part of the active console cannot
/// be determined without a runtime UEFI variable read (banned, SPEC
/// §28). This module therefore treats every path-bearing handle found by
/// protocol enumeration as *potentially* active: any serial (UART) /
/// network (MAC/IPv4/IPv6/Wi-Fi/Bluetooth/...) / BMC / vendor-
/// unclassifiable path-bearing handle refuses the whole gate even when a
/// clean local device coexists (the unchanged [`aggregate_topology`]
/// logic already does this). Concretely: **a machine with serial-console
/// redirection (COM/SOL) enabled in firmware setup, on firmware that does
/// not implement EDK2 tagging, is correctly refused** with
/// [`RefuseReason::SerialConsole`]/[`RefuseReason::RemoteCapableInput`]
/// even while that redirection is idle; the remediation is disabling
/// redirection in firmware setup. This asymmetry versus the tag path
/// (where an idle, non-member redirection device does *not* refuse) is
/// deliberate — guessing "inactive" without a variable read would be a
/// fail-*open* guess, which this project's fail-closed floor does not
/// allow. Multi-head displays are not penalized: several fully-
/// whitelisted local `SimpleTextOutput`/`GraphicsOutput` handles are
/// "explained" second output paths (SPEC §11.3), not an unexplained
/// [`RefuseReason::MultipleOutputPaths`].
///
/// [`ProdConsoleGate`]: ../../../seed_flow/struct.ProdConsoleGate.html
#[cfg(target_os = "uefi")]
pub mod uefi_backend {
    use super::{ConsoleRole, HandleProbe, SweepAccumulator, SweepOutcome, MAX_CONSOLE_HANDLES};
    use core::mem::MaybeUninit;
    use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams, SearchType};
    use uefi::proto::console::gop::GraphicsOutput;
    use uefi::proto::console::text::{Input, Output};
    use uefi::proto::device_path::DevicePath;
    use uefi::{guid, Guid, Handle, Status};

    /// EDK2 `EFI_CONSOLE_IN_DEVICE_GUID`
    /// (`MdeModulePkg/Include/Guid/ConsoleInDevice.h`; not a UEFI-spec
    /// protocol, an EDK2-internal tag). Tagged by `ConPlatformDxe` onto
    /// every device handle currently an active member of `ConIn`.
    pub const CONSOLE_IN_DEVICE_GUID: Guid = guid!("d3b36f2b-d551-11d4-9a46-0090273fc14d");
    /// EDK2 `EFI_CONSOLE_OUT_DEVICE_GUID`
    /// (`MdeModulePkg/Include/Guid/ConsoleOutDevice.h`). Tagged onto every
    /// device handle currently an active member of `ConOut`.
    pub const CONSOLE_OUT_DEVICE_GUID: Guid = guid!("d3b36f2c-d551-11d4-9a46-0090273fc14d");
    /// EDK2 `EFI_STANDARD_ERROR_DEVICE_GUID`
    /// (`MdeModulePkg/Include/Guid/StandardErrorDevice.h`). Tagged onto
    /// every device handle currently an active member of `ErrOut`.
    pub const STANDARD_ERROR_DEVICE_GUID: Guid = guid!("d3b36f2d-d551-11d4-9a46-0090273fc14d");

    /// Shared sweep primitive (SPEC §11.3): locate every handle matching
    /// `search`, open each one's `DevicePath` read-only, and reduce the
    /// results through a [`SweepAccumulator`] into one [`SweepOutcome`].
    /// Every stage below — the three tag sweeps and the three
    /// console-protocol sweeps — is a thin, differently-parameterized
    /// call to this one function.
    ///
    /// Opens `DevicePath` with [`OpenProtocolAttributes::GetProtocol`] —
    /// a pure, non-exclusive read — rather than
    /// `boot::open_protocol_exclusive`/[`OpenProtocolAttributes::
    /// Exclusive`]: per the UEFI spec, an exclusive open attempts
    /// `DisconnectController` on every existing `ByDriver` opener of the
    /// protocol. On a real console handle that opener is
    /// `ConPlatformDxe`/`ConSplitterDxe` itself, live and driving the
    /// active console this gate is currently running through; an
    /// exclusive open would attempt to tear that down mid-check.
    /// `GetProtocol` has no such side effect on other agents.
    fn sweep(search: SearchType<'_>, primary_role: ConsoleRole, extra_role: ConsoleRole) -> SweepOutcome {
        let mut buf = [MaybeUninit::<Handle>::uninit(); MAX_CONSOLE_HANDLES];
        match boot::locate_handle(search, &mut buf) {
            Ok(handles) => {
                let mut acc = SweepAccumulator::new(primary_role, extra_role);
                for &handle in handles {
                    let params = OpenProtocolParams { handle, agent: boot::image_handle(), controller: None };
                    // SAFETY: this opens the `DevicePath` protocol
                    // read-only (`GetProtocol`) for the duration of one
                    // probe; the returned `ScopedProtocol` borrow does
                    // not outlive this loop iteration (it is consumed
                    // immediately by `acc.push`, which copies out an
                    // owned `PathReport`), and this pre-secret phase runs
                    // single-threaded with no reentrant handling of this
                    // code path, so nothing else can race the read or
                    // rely on this call not existing.
                    match unsafe { boot::open_protocol::<DevicePath>(params, OpenProtocolAttributes::GetProtocol) } {
                        Ok(scoped) => acc.push(HandleProbe::Path(&scoped)),
                        Err(e) if e.status() == Status::UNSUPPORTED => acc.push(HandleProbe::NoDevicePath),
                        Err(_) => acc.push(HandleProbe::OpenError),
                    }
                }
                acc.finish(false)
            }
            Err(e) if e.status() == Status::NOT_FOUND => SweepOutcome::Absent,
            // BUFFER_TOO_SMALL (more handles than MAX_CONSOLE_HANDLES) or
            // any other firmware error: cannot be fully explained, fail
            // closed.
            Err(_) => SweepOutcome::Truncated,
        }
    }

    /// Tag-sweep stage: locate every handle carrying the EDK2 console-
    /// device tag `guid` (SPEC §11.3 fast-path — see this module's own
    /// doc comment on why tag-resolved roles use active-membership
    /// semantics).
    #[must_use]
    pub fn sweep_by_guid(guid: &Guid, primary_role: ConsoleRole, extra_role: ConsoleRole) -> SweepOutcome {
        sweep(SearchType::ByProtocol(guid), primary_role, extra_role)
    }

    /// Protocol-enumeration stage: every handle carrying
    /// `EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL_GUID` = `387477c2-69c7-11d2-
    /// 8e39-00a0c969723b` (UEFI Spec §12.4; `edk2 MdePkg/Include/
    /// Protocol/SimpleTextOut.h`; byte-verified against vendored
    /// `uefi-raw-0.15.1/src/protocol/console.rs`
    /// `SimpleTextOutputProtocol::GUID`). Resolved via
    /// `SearchType::from_proto::<uefi::proto::console::text::Output>()` —
    /// no hand-typed GUID literal in this call site; the value above is
    /// the exact constant that expands to, written out for review
    /// byte-checking. Every UEFI-spec-conformant firmware installs this
    /// on the real text-console-capable output device(s) (SPEC §11.3
    /// portable fallback).
    #[must_use]
    pub fn sweep_simple_text_output(primary_role: ConsoleRole, extra_role: ConsoleRole) -> SweepOutcome {
        sweep(SearchType::from_proto::<Output>(), primary_role, extra_role)
    }

    /// Protocol-enumeration stage: every handle carrying
    /// `EFI_SIMPLE_TEXT_INPUT_PROTOCOL_GUID` = `387477c1-69c7-11d2-
    /// 8e39-00a0c969723b` (UEFI Spec §12.3; `edk2 MdePkg/Include/
    /// Protocol/SimpleTextIn.h`; byte-verified against vendored
    /// `uefi-raw-0.15.1/src/protocol/console.rs`
    /// `SimpleTextInputProtocol::GUID`). Resolved via
    /// `SearchType::from_proto::<uefi::proto::console::text::Input>()` —
    /// no hand-typed GUID literal in this call site.
    #[must_use]
    pub fn sweep_simple_text_input(primary_role: ConsoleRole, extra_role: ConsoleRole) -> SweepOutcome {
        sweep(SearchType::from_proto::<Input>(), primary_role, extra_role)
    }

    /// Protocol-enumeration stage: every handle carrying
    /// `EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID` = `9042a9de-23dc-4a38-96fb-
    /// 7aded080516a` (UEFI Spec §12.9; `edk2 MdeModulePkg/Include/
    /// Protocol/GraphicsOutput.h`; byte-verified against vendored
    /// `uefi-raw-0.15.1/src/protocol/console.rs`
    /// `GraphicsOutputProtocol::GUID`). Resolved via
    /// `SearchType::from_proto::<uefi::proto::console::gop::
    /// GraphicsOutput>()` — no hand-typed GUID literal in this call site.
    ///
    /// Last-resort output source only: [`resolve_role`] consults this
    /// stage only when [`sweep_simple_text_output`] resolved zero
    /// path-bearing handles, and the two are never merged — on both
    /// EDK2/OVMF and the surveyed OEM laptop, `GraphicsOutput` and
    /// `SimpleTextOutput` are installed on the *same* real display
    /// handle/path, so merging would double-count one device as two.
    #[must_use]
    pub fn sweep_graphics_output(primary_role: ConsoleRole, extra_role: ConsoleRole) -> SweepOutcome {
        sweep(SearchType::from_proto::<GraphicsOutput>(), primary_role, extra_role)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one raw device-path node: `[type, sub_type, len_lo, len_hi,
    /// ...payload]`.
    fn node(device_type: u8, sub_type: u8, payload: &[u8]) -> std::vec::Vec<u8> {
        let len = (4 + payload.len()) as u16;
        let mut out = std::vec![device_type, sub_type];
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// The mandatory End-Entire terminator node.
    fn end_entire() -> std::vec::Vec<u8> {
        std::vec![0x7F, 0xFF, 0x04, 0x00]
    }

    fn path_bytes(nodes: &[std::vec::Vec<u8>]) -> std::vec::Vec<u8> {
        let mut out = std::vec::Vec::new();
        for n in nodes {
            out.extend_from_slice(n);
        }
        out.extend_from_slice(&end_entire());
        out
    }

    // ---- accepted local topologies ----

    #[test]
    fn local_gop_pci_path_is_accepted() {
        // PciRoot(0x0)/Pci(0x2,0x0) -- a typical local GOP display adapter path.
        let bytes = path_bytes(&[
            node(0x02, 0x01, &[0u8; 12]), // ACPI PCI root bridge (HID+UID payload, contents irrelevant)
            node(0x01, 0x01, &[0x02, 0x00]), // Hardware/PCI: device 2, function 0
        ]);
        let report = parse_and_classify(ConsoleRole::ConOut, &bytes);
        assert!(report.is_accepted(), "verdict = {:?}", report.verdict);
        assert_eq!(report.node_count, 2);
    }

    #[test]
    fn local_usb_keyboard_path_is_accepted() {
        // PciRoot(0)/Pci(0x14,0x0)/USB(port,interface)
        let bytes = path_bytes(&[
            node(0x02, 0x01, &[0u8; 12]),
            node(0x01, 0x01, &[0x14, 0x00]),
            node(0x03, DeviceSubType::MESSAGING_USB.0, &[0x01, 0x00]),
        ]);
        let report = parse_and_classify(ConsoleRole::ConIn, &bytes);
        assert!(report.is_accepted(), "verdict = {:?}", report.verdict);
    }

    #[test]
    fn ps2_acpi_keyboard_path_is_accepted() {
        // Acpi(PNP0303,0) modelled as a plain ACPI node (payload contents
        // are not interpreted by this module -- classification is by
        // device_type/sub_type only, see module docs).
        let bytes = path_bytes(&[node(0x02, DeviceSubType::ACPI.0, &[0x03, 0x03, 0xD0, 0x41, 0x00, 0x00, 0x00, 0x00])]);
        let report = parse_and_classify(ConsoleRole::ConIn, &bytes);
        assert!(report.is_accepted(), "verdict = {:?}", report.verdict);
    }

    // ---- refuse: serial ----

    #[test]
    fn serial_uart_console_is_refused() {
        let bytes = path_bytes(&[
            node(0x02, 0x01, &[0u8; 12]),
            node(0x01, 0x01, &[0x01, 0x00]),
            node(0x03, DeviceSubType::MESSAGING_UART.0, &[0u8; 7]),
        ]);
        let report = parse_and_classify(ConsoleRole::ConOut, &bytes);
        assert_eq!(report.verdict, Err(RefuseReason::SerialConsole));
    }

    #[test]
    fn serial_con_in_is_reported_as_remote_capable_input() {
        let bytes = path_bytes(&[node(0x03, DeviceSubType::MESSAGING_UART.0, &[0u8; 7])]);
        let report = parse_and_classify(ConsoleRole::ConIn, &bytes);
        assert_eq!(report.verdict, Err(RefuseReason::RemoteCapableInput));
    }

    // ---- refuse: network ----

    #[test]
    fn network_mac_address_console_is_refused() {
        let bytes = path_bytes(&[node(0x03, DeviceSubType::MESSAGING_MAC_ADDRESS.0, &[0u8; 33])]);
        let report = parse_and_classify(ConsoleRole::ConOut, &bytes);
        assert_eq!(report.verdict, Err(RefuseReason::NetworkConsole));
    }

    #[test]
    fn network_ipv4_console_is_refused() {
        let bytes = path_bytes(&[node(0x03, DeviceSubType::MESSAGING_IPV4.0, &[0u8; 19])]);
        let report = parse_and_classify(ConsoleRole::ConOut, &bytes);
        assert_eq!(report.verdict, Err(RefuseReason::NetworkConsole));
    }

    #[test]
    fn wifi_console_is_refused_as_network() {
        let bytes = path_bytes(&[node(0x03, DeviceSubType::MESSAGING_WIFI.0, &[0u8; 34])]);
        let report = parse_and_classify(ConsoleRole::ConIn, &bytes);
        assert_eq!(report.verdict, Err(RefuseReason::RemoteCapableInput));
    }

    // ---- refuse: remote management ----

    #[test]
    fn bmc_console_is_refused_as_remote_management() {
        let bytes = path_bytes(&[node(0x01, DeviceSubType::HARDWARE_BMC.0, &[0u8; 5])]);
        let report = parse_and_classify(ConsoleRole::ConOut, &bytes);
        assert_eq!(report.verdict, Err(RefuseReason::RemoteManagement));
    }

    // ---- refuse: vendor-unclassifiable ----

    #[test]
    fn vendor_hardware_node_is_refused_unclassifiable() {
        let bytes = path_bytes(&[node(0x01, DeviceSubType::HARDWARE_VENDOR.0, &[0u8; 16])]);
        let report = parse_and_classify(ConsoleRole::ConOut, &bytes);
        assert_eq!(report.verdict, Err(RefuseReason::VendorUnclassifiable));
    }

    #[test]
    fn vendor_messaging_node_is_refused_unclassifiable() {
        let bytes = path_bytes(&[node(0x03, DeviceSubType::MESSAGING_VENDOR.0, &[0u8; 16])]);
        let report = parse_and_classify(ConsoleRole::ConOut, &bytes);
        assert_eq!(report.verdict, Err(RefuseReason::VendorUnclassifiable));
    }

    #[test]
    fn unknown_device_type_is_refused_unclassifiable() {
        // Device type 0x06 is outside the UEFI-defined 0x01..=0x05 range.
        let bytes = path_bytes(&[node(0x06, 0x01, &[0u8; 4])]);
        let report = parse_and_classify(ConsoleRole::ConOut, &bytes);
        assert_eq!(report.verdict, Err(RefuseReason::VendorUnclassifiable));
    }

    #[test]
    fn bios_boot_spec_node_is_refused_unclassifiable() {
        let bytes = path_bytes(&[node(0x05, 0x01, &[0u8; 8])]);
        let report = parse_and_classify(ConsoleRole::ConOut, &bytes);
        assert_eq!(report.verdict, Err(RefuseReason::VendorUnclassifiable));
    }

    #[test]
    fn mid_path_end_instance_node_is_refused_unclassifiable() {
        // Two device-path instances separated by END_INSTANCE, both
        // followed by the mandatory END_ENTIRE.
        let mut bytes = node(0x01, 0x01, &[0x02, 0x00]);
        bytes.extend_from_slice(&[0x7F, 0x01, 0x04, 0x00]); // END_INSTANCE
        bytes.extend_from_slice(&node(0x01, 0x01, &[0x03, 0x00]));
        bytes.extend_from_slice(&end_entire());
        let report = parse_and_classify(ConsoleRole::ConOut, &bytes);
        assert_eq!(report.verdict, Err(RefuseReason::VendorUnclassifiable));
    }

    // ---- refuse: parse failure ----

    #[test]
    fn empty_bytes_is_parse_failure() {
        let report = parse_and_classify(ConsoleRole::ConOut, &[]);
        assert_eq!(report.verdict, Err(RefuseReason::ParseFailure));
        assert_eq!(report.node_count, 0);
    }

    #[test]
    fn truncated_header_is_parse_failure() {
        // Only 3 bytes: a full node header needs 4.
        let report = parse_and_classify(ConsoleRole::ConOut, &[0x01, 0x01, 0x04]);
        assert_eq!(report.verdict, Err(RefuseReason::ParseFailure));
    }

    #[test]
    fn declared_length_past_end_of_slice_is_parse_failure() {
        // Header claims 8 bytes total but only 4 are supplied.
        let bytes = [0x01u8, 0x01, 0x08, 0x00];
        let report = parse_and_classify(ConsoleRole::ConOut, &bytes);
        assert_eq!(report.verdict, Err(RefuseReason::ParseFailure));
    }

    #[test]
    fn missing_end_entire_node_is_parse_failure() {
        // Well-formed single node, but no terminating END_ENTIRE.
        let bytes = node(0x01, 0x01, &[0x02, 0x00]);
        let report = parse_and_classify(ConsoleRole::ConOut, &bytes);
        assert_eq!(report.verdict, Err(RefuseReason::ParseFailure));
    }

    #[test]
    fn zero_length_node_is_parse_failure() {
        // Declared length 0 (less than the 4-byte header) must not be
        // accepted -- it would otherwise loop forever / read out of
        // bounds if it ever reached the caller's own walker. The `uefi`
        // crate's `TryFrom` rejects it; confirm that surfaces as our
        // ParseFailure, not a panic or a hang.
        let bytes = [0x01u8, 0x01, 0x00, 0x00];
        let report = parse_and_classify(ConsoleRole::ConOut, &bytes);
        assert_eq!(report.verdict, Err(RefuseReason::ParseFailure));
    }

    #[test]
    fn too_many_nodes_is_refused() {
        let mut nodes = std::vec::Vec::new();
        for _ in 0..(MAX_NODES + 1) {
            nodes.push(node(0x01, 0x01, &[0x00, 0x00]));
        }
        let bytes = path_bytes(&nodes);
        let report = parse_and_classify(ConsoleRole::ConOut, &bytes);
        assert_eq!(report.verdict, Err(RefuseReason::VendorUnclassifiable));
    }

    // ---- topology aggregation ----

    /// Shorthand: parse+classify `bytes` for `role`, used to build
    /// [`TopologySets`] slices in these tests exactly the way
    /// `firmware_wiring::ProdConsoleGate` builds them from real
    /// [`super::classify`] calls on handles resolved via
    /// [`super::uefi_backend::sweep_by_guid`] and its enumeration
    /// siblings.
    fn accepted(role: ConsoleRole, bytes: &[u8]) -> PathReport {
        parse_and_classify(role, bytes)
    }

    #[test]
    fn topology_accepts_when_all_three_consoles_are_local() {
        let usb_in = path_bytes(&[node(0x03, DeviceSubType::MESSAGING_USB.0, &[0x01, 0x00])]);
        let gop_out = path_bytes(&[node(0x01, 0x01, &[0x02, 0x00])]);
        let con_in = [accepted(ConsoleRole::ConIn, &usb_in)];
        let con_out = [accepted(ConsoleRole::ConOut, &gop_out)];
        let err_out = [accepted(ConsoleRole::ErrOut, &gop_out)];
        let verdict = aggregate_topology(&TopologySets {
            con_in: &con_in,
            con_out: &con_out,
            err_out: &err_out,
            truncated: false,
        });
        assert!(verdict.is_ok(), "verdict = {:?}", verdict);
    }

    #[test]
    fn topology_refuses_when_err_out_is_serial() {
        let usb_in = path_bytes(&[node(0x03, DeviceSubType::MESSAGING_USB.0, &[0x01, 0x00])]);
        let gop_out = path_bytes(&[node(0x01, 0x01, &[0x02, 0x00])]);
        let serial_err = path_bytes(&[node(0x03, DeviceSubType::MESSAGING_UART.0, &[0u8; 7])]);
        let con_in = [accepted(ConsoleRole::ConIn, &usb_in)];
        let con_out = [accepted(ConsoleRole::ConOut, &gop_out)];
        let err_out = [accepted(ConsoleRole::ErrOut, &serial_err)];
        let verdict = aggregate_topology(&TopologySets {
            con_in: &con_in,
            con_out: &con_out,
            err_out: &err_out,
            truncated: false,
        });
        assert_eq!(verdict, Err(RefuseReason::SerialConsole));
    }

    #[test]
    fn topology_empty_con_in_is_refused_parse_failure() {
        let gop_out = path_bytes(&[node(0x01, 0x01, &[0x02, 0x00])]);
        let con_out = [accepted(ConsoleRole::ConOut, &gop_out)];
        let verdict = aggregate_topology(&TopologySets {
            con_in: &[],
            con_out: &con_out,
            err_out: &[],
            truncated: false,
        });
        assert_eq!(verdict, Err(RefuseReason::ParseFailure));
    }

    #[test]
    fn topology_empty_con_out_is_refused_parse_failure() {
        let usb_in = path_bytes(&[node(0x03, DeviceSubType::MESSAGING_USB.0, &[0x01, 0x00])]);
        let con_in = [accepted(ConsoleRole::ConIn, &usb_in)];
        let verdict = aggregate_topology(&TopologySets {
            con_in: &con_in,
            con_out: &[],
            err_out: &[],
            truncated: false,
        });
        assert_eq!(verdict, Err(RefuseReason::ParseFailure));
    }

    #[test]
    fn topology_missing_err_out_alone_is_not_fatal() {
        let usb_in = path_bytes(&[node(0x03, DeviceSubType::MESSAGING_USB.0, &[0x01, 0x00])]);
        let gop_out = path_bytes(&[node(0x01, 0x01, &[0x02, 0x00])]);
        let con_in = [accepted(ConsoleRole::ConIn, &usb_in)];
        let con_out = [accepted(ConsoleRole::ConOut, &gop_out)];
        let verdict = aggregate_topology(&TopologySets {
            con_in: &con_in,
            con_out: &con_out,
            err_out: &[],
            truncated: false,
        });
        assert!(verdict.is_ok(), "verdict = {:?}", verdict);
    }

    #[test]
    fn topology_refuses_on_unexplained_extra_output_path() {
        // A vendor-defined second output handle cannot be explained.
        let usb_in = path_bytes(&[node(0x03, DeviceSubType::MESSAGING_USB.0, &[0x01, 0x00])]);
        let gop_out = path_bytes(&[node(0x01, 0x01, &[0x02, 0x00])]);
        let vendor_out = path_bytes(&[node(0x01, DeviceSubType::HARDWARE_VENDOR.0, &[0u8; 16])]);
        let con_in = [accepted(ConsoleRole::ConIn, &usb_in)];
        let con_out =
            [accepted(ConsoleRole::ConOut, &gop_out), accepted(ConsoleRole::ExtraOut, &vendor_out)];
        let verdict = aggregate_topology(&TopologySets {
            con_in: &con_in,
            con_out: &con_out,
            err_out: &[],
            truncated: false,
        });
        assert_eq!(verdict, Err(RefuseReason::MultipleOutputPaths));
    }

    #[test]
    fn topology_accepts_second_clean_local_output_path_as_explained() {
        // A second fully-local, fully-classified output (e.g. a second
        // monitor) is explained, not refused.
        let usb_in = path_bytes(&[node(0x03, DeviceSubType::MESSAGING_USB.0, &[0x01, 0x00])]);
        let gop_out = path_bytes(&[node(0x01, 0x01, &[0x02, 0x00])]);
        let other_gop = path_bytes(&[node(0x01, 0x01, &[0x03, 0x00])]);
        let con_in = [accepted(ConsoleRole::ConIn, &usb_in)];
        let con_out =
            [accepted(ConsoleRole::ConOut, &gop_out), accepted(ConsoleRole::ExtraOut, &other_gop)];
        let verdict = aggregate_topology(&TopologySets {
            con_in: &con_in,
            con_out: &con_out,
            err_out: &[],
            truncated: false,
        });
        assert!(verdict.is_ok(), "verdict = {:?}", verdict);
    }

    #[test]
    fn topology_accepts_second_clean_input_path() {
        let usb_in1 = path_bytes(&[node(0x03, DeviceSubType::MESSAGING_USB.0, &[0x01, 0x00])]);
        let usb_in2 = path_bytes(&[node(0x03, DeviceSubType::MESSAGING_USB.0, &[0x02, 0x00])]);
        let gop_out = path_bytes(&[node(0x01, 0x01, &[0x02, 0x00])]);
        let con_in = [accepted(ConsoleRole::ConIn, &usb_in1), accepted(ConsoleRole::ConIn, &usb_in2)];
        let con_out = [accepted(ConsoleRole::ConOut, &gop_out)];
        let verdict = aggregate_topology(&TopologySets {
            con_in: &con_in,
            con_out: &con_out,
            err_out: &[],
            truncated: false,
        });
        assert!(verdict.is_ok(), "verdict = {:?}", verdict);
    }

    #[test]
    fn topology_second_output_serial_refuses_as_serial() {
        let usb_in = path_bytes(&[node(0x03, DeviceSubType::MESSAGING_USB.0, &[0x01, 0x00])]);
        let gop_out = path_bytes(&[node(0x01, 0x01, &[0x02, 0x00])]);
        let uart_out = path_bytes(&[node(0x03, DeviceSubType::MESSAGING_UART.0, &[0u8; 7])]);
        let con_in = [accepted(ConsoleRole::ConIn, &usb_in)];
        let con_out =
            [accepted(ConsoleRole::ConOut, &gop_out), accepted(ConsoleRole::ExtraOut, &uart_out)];
        let verdict = aggregate_topology(&TopologySets {
            con_in: &con_in,
            con_out: &con_out,
            err_out: &[],
            truncated: false,
        });
        assert_eq!(verdict, Err(RefuseReason::SerialConsole));
    }

    #[test]
    fn topology_second_output_network_refuses_as_network() {
        let usb_in = path_bytes(&[node(0x03, DeviceSubType::MESSAGING_USB.0, &[0x01, 0x00])]);
        let gop_out = path_bytes(&[node(0x01, 0x01, &[0x02, 0x00])]);
        let net_out = path_bytes(&[node(0x03, DeviceSubType::MESSAGING_MAC_ADDRESS.0, &[0u8; 33])]);
        let con_in = [accepted(ConsoleRole::ConIn, &usb_in)];
        let con_out =
            [accepted(ConsoleRole::ConOut, &gop_out), accepted(ConsoleRole::ExtraOut, &net_out)];
        let verdict = aggregate_topology(&TopologySets {
            con_in: &con_in,
            con_out: &con_out,
            err_out: &[],
            truncated: false,
        });
        assert_eq!(verdict, Err(RefuseReason::NetworkConsole));
    }

    #[test]
    fn topology_second_output_bmc_refuses_as_remote_management() {
        let usb_in = path_bytes(&[node(0x03, DeviceSubType::MESSAGING_USB.0, &[0x01, 0x00])]);
        let gop_out = path_bytes(&[node(0x01, 0x01, &[0x02, 0x00])]);
        let bmc_out = path_bytes(&[node(0x01, DeviceSubType::HARDWARE_BMC.0, &[0u8; 5])]);
        let con_in = [accepted(ConsoleRole::ConIn, &usb_in)];
        let con_out =
            [accepted(ConsoleRole::ConOut, &gop_out), accepted(ConsoleRole::ExtraOut, &bmc_out)];
        let verdict = aggregate_topology(&TopologySets {
            con_in: &con_in,
            con_out: &con_out,
            err_out: &[],
            truncated: false,
        });
        assert_eq!(verdict, Err(RefuseReason::RemoteManagement));
    }

    #[test]
    fn topology_truncated_sweep_refuses_multiple_output_paths() {
        let usb_in = path_bytes(&[node(0x03, DeviceSubType::MESSAGING_USB.0, &[0x01, 0x00])]);
        let gop_out = path_bytes(&[node(0x01, 0x01, &[0x02, 0x00])]);
        let con_in = [accepted(ConsoleRole::ConIn, &usb_in)];
        let con_out = [accepted(ConsoleRole::ConOut, &gop_out)];
        let verdict = aggregate_topology(&TopologySets {
            con_in: &con_in,
            con_out: &con_out,
            err_out: &[],
            truncated: true,
        });
        assert_eq!(verdict, Err(RefuseReason::MultipleOutputPaths));
    }

    #[test]
    fn topology_second_input_serial_refuses_as_remote_capable_input() {
        // SPEC §11.3: EVERY active input handle must be checked, not only
        // the first -- a second input handle classified with role ConIn
        // that turns out to be serial/network must be relabeled
        // RemoteCapableInput exactly like the first would be.
        let usb_in = path_bytes(&[node(0x03, DeviceSubType::MESSAGING_USB.0, &[0x01, 0x00])]);
        let uart_in = path_bytes(&[node(0x03, DeviceSubType::MESSAGING_UART.0, &[0u8; 7])]);
        let gop_out = path_bytes(&[node(0x01, 0x01, &[0x02, 0x00])]);
        let con_in = [accepted(ConsoleRole::ConIn, &usb_in), accepted(ConsoleRole::ConIn, &uart_in)];
        let con_out = [accepted(ConsoleRole::ConOut, &gop_out)];
        let verdict = aggregate_topology(&TopologySets {
            con_in: &con_in,
            con_out: &con_out,
            err_out: &[],
            truncated: false,
        });
        assert_eq!(verdict, Err(RefuseReason::RemoteCapableInput));
    }

    // ---- real-hardware fixtures (OEM laptop, read from firmware
    // ConOut/ConIn/ErrOut UEFI variables 2026-08-06; attribute prefix
    // stripped, raw device-path bytes only) ----

    /// `ACPI(PNP0A03 PCI-root) / PCI(dev 0x02, Intel iGPU) /
    /// ACPI_ADR(0x80013400 display) / End`.
    const DELL_CONOUT_HEX: &str = "02010c00d041030a0000000001010600000202030800003401807fff0400";
    /// `ACPI(PNP0A03 PCI-root) / PCI(dev 0x1F, LPC) / ACPI(PNP0303 PS/2
    /// keyboard) / End`.
    const DELL_CONIN_HEX: &str = "02010c00d041030a0000000001010600001f02010c00d0410303000000007fff0400";

    fn decode_hex(s: &str) -> std::vec::Vec<u8> {
        assert_eq!(s.len() % 2, 0, "odd-length hex fixture");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex fixture"))
            .collect()
    }

    #[test]
    fn dell_conout_display_path_is_accepted() {
        let bytes = decode_hex(DELL_CONOUT_HEX);
        let report = parse_and_classify(ConsoleRole::ConOut, &bytes);
        assert!(report.is_accepted(), "verdict = {:?}", report.verdict);
        assert_eq!(report.node_count, 3);
        let kinds: std::vec::Vec<NodeKind> =
            report.nodes[..report.node_count].iter().map(|n| n.unwrap().kind.unwrap()).collect();
        assert_eq!(kinds, std::vec![NodeKind::Acpi, NodeKind::HardwareLocal, NodeKind::Acpi]);
    }

    #[test]
    fn dell_conin_ps2_path_is_accepted() {
        let bytes = decode_hex(DELL_CONIN_HEX);
        let report = parse_and_classify(ConsoleRole::ConIn, &bytes);
        assert!(report.is_accepted(), "verdict = {:?}", report.verdict);
        assert_eq!(report.node_count, 3);
        let kinds: std::vec::Vec<NodeKind> =
            report.nodes[..report.node_count].iter().map(|n| n.unwrap().kind.unwrap()).collect();
        assert_eq!(kinds, std::vec![NodeKind::Acpi, NodeKind::HardwareLocal, NodeKind::Acpi]);
    }

    #[test]
    fn dell_full_topology_is_accepted() {
        // Proves the actual over-refusal bug is fixed: classifying the
        // real OEM laptop's ConIn/ConOut/ErrOut device paths (not the system-
        // table splitter handle) passes the full aggregated gate.
        let conout = decode_hex(DELL_CONOUT_HEX);
        let conin = decode_hex(DELL_CONIN_HEX);
        let con_in = [accepted(ConsoleRole::ConIn, &conin)];
        let con_out = [accepted(ConsoleRole::ConOut, &conout)];
        let err_out = [accepted(ConsoleRole::ErrOut, &conout)];
        let verdict = aggregate_topology(&TopologySets {
            con_in: &con_in,
            con_out: &con_out,
            err_out: &err_out,
            truncated: false,
        });
        assert!(verdict.is_ok(), "verdict = {:?}", verdict);
    }

    // ---- portable resolver: HandleProbe / SweepAccumulator /
    // SweepOutcome / resolve_role (SPEC §11.3) ----
    //
    // These tests exercise the pure, `cfg`-free resolver layer directly
    // (no UEFI backend involved), using the same real-hardware fixtures as
    // above plus synthetic serial/network/BMC/vendor paths. They prove
    // the portable resolver fixes the diagnosed OEM laptop over-refusal (the
    // ConOut tag lands only on the path-less splitter; the real devices
    // are found via console-protocol enumeration) while every existing
    // refusal condition stays byte-identical.

    fn devpath(bytes: &[u8]) -> &DevicePath {
        <&DevicePath>::try_from(bytes).expect("valid fixture path")
    }

    /// Build a [`SweepOutcome::Found`] from an ordered list of probes,
    /// mirroring exactly what `uefi_backend::sweep`'s enumeration loop
    /// pushes for one stage's discovered handles.
    fn found(probes: &[HandleProbe<'_>], primary: ConsoleRole, extra: ConsoleRole) -> SweepOutcome {
        let mut acc = SweepAccumulator::new(primary, extra);
        for &probe in probes {
            acc.push(probe);
        }
        acc.finish(false)
    }

    fn usb_in_bytes() -> std::vec::Vec<u8> {
        path_bytes(&[node(0x03, DeviceSubType::MESSAGING_USB.0, &[0x01, 0x00])])
    }

    fn clean_pci_out_bytes() -> std::vec::Vec<u8> {
        path_bytes(&[node(0x01, 0x01, &[0x02, 0x00])])
    }

    fn second_clean_pci_out_bytes() -> std::vec::Vec<u8> {
        path_bytes(&[node(0x01, 0x01, &[0x03, 0x00])])
    }

    fn uart_bytes() -> std::vec::Vec<u8> {
        path_bytes(&[node(0x03, DeviceSubType::MESSAGING_UART.0, &[0u8; 7])])
    }

    fn mac_bytes() -> std::vec::Vec<u8> {
        path_bytes(&[node(0x03, DeviceSubType::MESSAGING_MAC_ADDRESS.0, &[0u8; 33])])
    }

    fn bmc_bytes() -> std::vec::Vec<u8> {
        path_bytes(&[node(0x01, DeviceSubType::HARDWARE_BMC.0, &[0u8; 5])])
    }

    fn vendor_bytes() -> std::vec::Vec<u8> {
        path_bytes(&[node(0x01, DeviceSubType::HARDWARE_VENDOR.0, &[0u8; 16])])
    }

    /// (A1) The real OEM laptop topology: ConOut tag hits only the splitter
    /// (no `DevicePath`) and falls through to `SimpleTextOutput`
    /// enumeration, which finds the real iGPU; ConIn tag is entirely
    /// absent and falls through to `SimpleTextInput` enumeration, which
    /// finds the real PS/2 keyboard; StdErr tag is absent (non-fatal).
    /// The aggregated gate PASSES.
    #[test]
    fn dell_full_enumeration_topology_passes() {
        let conout_bytes = decode_hex(DELL_CONOUT_HEX);
        let conin_bytes = decode_hex(DELL_CONIN_HEX);

        // OUTPUT stages: [tag, SimpleTextOutput, GraphicsOutput].
        let out_tag = found(&[HandleProbe::NoDevicePath], ConsoleRole::ConOut, ConsoleRole::ExtraOut);
        let out_text = found(
            &[HandleProbe::Path(devpath(&conout_bytes)), HandleProbe::NoDevicePath],
            ConsoleRole::ConOut,
            ConsoleRole::ExtraOut,
        );
        let out = resolve_role(&[out_tag, out_text, SweepOutcome::Absent]);
        assert_eq!(out.len, 1);
        assert!(out.reports[0].is_accepted(), "verdict = {:?}", out.reports[0].verdict);

        // INPUT stages: [tag, SimpleTextInput].
        let in_text = found(
            &[HandleProbe::Path(devpath(&conin_bytes)), HandleProbe::NoDevicePath],
            ConsoleRole::ConIn,
            ConsoleRole::ConIn,
        );
        let in_ = resolve_role(&[SweepOutcome::Absent, in_text]);
        assert_eq!(in_.len, 1);
        assert!(in_.reports[0].is_accepted(), "verdict = {:?}", in_.reports[0].verdict);

        // ERROUT stage: [tag] only, absent -- not fatal.
        let err = resolve_role(&[SweepOutcome::Absent]);
        assert_eq!(err.len, 0);

        let verdict = aggregate_topology(&TopologySets {
            con_in: &in_.reports[..in_.len],
            con_out: &out.reports[..out.len],
            err_out: &err.reports[..err.len],
            truncated: out.truncated || in_.truncated || err.truncated,
        });
        assert!(verdict.is_ok(), "verdict = {:?}", verdict);
    }

    /// (A2) The ConOut tag stage, on its own, resolves to zero
    /// path-bearing reports (only the splitter was tagged) and therefore
    /// falls through; the `SimpleTextOutput` stage supplies the real
    /// classification.
    #[test]
    fn dell_conout_tag_on_splitter_falls_through() {
        let conout_bytes = decode_hex(DELL_CONOUT_HEX);
        let tag = found(&[HandleProbe::NoDevicePath], ConsoleRole::ConOut, ConsoleRole::ExtraOut);
        assert!(matches!(tag, SweepOutcome::Found { len: 0, .. }), "splitter-only tag stage must be empty, not Absent");
        let text = found(&[HandleProbe::Path(devpath(&conout_bytes))], ConsoleRole::ConOut, ConsoleRole::ExtraOut);
        let resolved = resolve_role(&[tag, text]);
        assert_eq!(resolved.len, 1);
        assert!(resolved.reports[0].is_accepted(), "verdict = {:?}", resolved.reports[0].verdict);
        assert_eq!(resolved.reports[0].role, ConsoleRole::ConOut);
    }

    /// (B1) A serial output handle refuses the whole gate even with a
    /// clean local handle also present (primary slot).
    #[test]
    fn enumeration_output_serial_handle_refuses_whole_gate() {
        let bad = uart_bytes();
        let clean = clean_pci_out_bytes();
        let stage = found(
            &[HandleProbe::Path(devpath(&bad)), HandleProbe::Path(devpath(&clean))],
            ConsoleRole::ConOut,
            ConsoleRole::ExtraOut,
        );
        let resolved = resolve_role(&[stage]);
        let con_in = [accepted(ConsoleRole::ConIn, &usb_in_bytes())];
        let verdict = aggregate_topology(&TopologySets {
            con_in: &con_in,
            con_out: &resolved.reports[..resolved.len],
            err_out: &[],
            truncated: false,
        });
        assert_eq!(verdict, Err(RefuseReason::SerialConsole));
    }

    /// (B1 ordering-pinned) The same serial handle, landing in the
    /// *extra* slot instead of primary, still refuses as `SerialConsole`
    /// specifically (SPEC §11.3 names serial/network/remote-management
    /// regardless of which output handle carries it) -- unlike a vendor-
    /// unclassifiable extra handle, which collapses to
    /// `MultipleOutputPaths` (see below).
    #[test]
    fn enumeration_output_serial_handle_in_extra_slot_still_labeled_serial() {
        let clean = clean_pci_out_bytes();
        let bad = uart_bytes();
        let stage = found(
            &[HandleProbe::Path(devpath(&clean)), HandleProbe::Path(devpath(&bad))],
            ConsoleRole::ConOut,
            ConsoleRole::ExtraOut,
        );
        let resolved = resolve_role(&[stage]);
        let con_in = [accepted(ConsoleRole::ConIn, &usb_in_bytes())];
        let verdict = aggregate_topology(&TopologySets {
            con_in: &con_in,
            con_out: &resolved.reports[..resolved.len],
            err_out: &[],
            truncated: false,
        });
        assert_eq!(verdict, Err(RefuseReason::SerialConsole));
    }

    /// (B2) A network output handle refuses the whole gate.
    #[test]
    fn enumeration_output_network_handle_refuses_whole_gate() {
        let bad = mac_bytes();
        let clean = clean_pci_out_bytes();
        let stage = found(
            &[HandleProbe::Path(devpath(&bad)), HandleProbe::Path(devpath(&clean))],
            ConsoleRole::ConOut,
            ConsoleRole::ExtraOut,
        );
        let resolved = resolve_role(&[stage]);
        let con_in = [accepted(ConsoleRole::ConIn, &usb_in_bytes())];
        let verdict = aggregate_topology(&TopologySets {
            con_in: &con_in,
            con_out: &resolved.reports[..resolved.len],
            err_out: &[],
            truncated: false,
        });
        assert_eq!(verdict, Err(RefuseReason::NetworkConsole));
    }

    /// (B3) A BMC output handle refuses the whole gate.
    #[test]
    fn enumeration_output_bmc_handle_refuses_whole_gate() {
        let bad = bmc_bytes();
        let clean = clean_pci_out_bytes();
        let stage = found(
            &[HandleProbe::Path(devpath(&bad)), HandleProbe::Path(devpath(&clean))],
            ConsoleRole::ConOut,
            ConsoleRole::ExtraOut,
        );
        let resolved = resolve_role(&[stage]);
        let con_in = [accepted(ConsoleRole::ConIn, &usb_in_bytes())];
        let verdict = aggregate_topology(&TopologySets {
            con_in: &con_in,
            con_out: &resolved.reports[..resolved.len],
            err_out: &[],
            truncated: false,
        });
        assert_eq!(verdict, Err(RefuseReason::RemoteManagement));
    }

    /// (B4) A vendor-unclassifiable output handle in the primary slot
    /// refuses the whole gate as `VendorUnclassifiable`.
    #[test]
    fn enumeration_output_vendor_handle_in_primary_slot_refuses_vendor_unclassifiable() {
        let bad = vendor_bytes();
        let clean = clean_pci_out_bytes();
        let stage = found(
            &[HandleProbe::Path(devpath(&bad)), HandleProbe::Path(devpath(&clean))],
            ConsoleRole::ConOut,
            ConsoleRole::ExtraOut,
        );
        let resolved = resolve_role(&[stage]);
        let con_in = [accepted(ConsoleRole::ConIn, &usb_in_bytes())];
        let verdict = aggregate_topology(&TopologySets {
            con_in: &con_in,
            con_out: &resolved.reports[..resolved.len],
            err_out: &[],
            truncated: false,
        });
        assert_eq!(verdict, Err(RefuseReason::VendorUnclassifiable));
    }

    /// (B4 ordering-pinned) The same vendor-unclassifiable handle, in the
    /// *extra* slot, refuses as the unexplained-second-path label
    /// instead (still a refusal either way -- only the label differs by
    /// slot, never accept-vs-refuse; see `aggregate_topology` step 5).
    #[test]
    fn enumeration_output_vendor_handle_in_extra_slot_refuses_multiple_output_paths() {
        let clean = clean_pci_out_bytes();
        let bad = vendor_bytes();
        let stage = found(
            &[HandleProbe::Path(devpath(&clean)), HandleProbe::Path(devpath(&bad))],
            ConsoleRole::ConOut,
            ConsoleRole::ExtraOut,
        );
        let resolved = resolve_role(&[stage]);
        let con_in = [accepted(ConsoleRole::ConIn, &usb_in_bytes())];
        let verdict = aggregate_topology(&TopologySets {
            con_in: &con_in,
            con_out: &resolved.reports[..resolved.len],
            err_out: &[],
            truncated: false,
        });
        assert_eq!(verdict, Err(RefuseReason::MultipleOutputPaths));
    }

    /// (B, input) A serial input handle refuses as `RemoteCapableInput`
    /// even with a clean local input handle also present.
    #[test]
    fn enumeration_input_serial_handle_refuses_as_remote_capable_input() {
        let bad = uart_bytes();
        let clean = usb_in_bytes();
        let stage = found(
            &[HandleProbe::Path(devpath(&bad)), HandleProbe::Path(devpath(&clean))],
            ConsoleRole::ConIn,
            ConsoleRole::ConIn,
        );
        let resolved = resolve_role(&[stage]);
        let con_out = [accepted(ConsoleRole::ConOut, &clean_pci_out_bytes())];
        let verdict = aggregate_topology(&TopologySets {
            con_in: &resolved.reports[..resolved.len],
            con_out: &con_out,
            err_out: &[],
            truncated: false,
        });
        assert_eq!(verdict, Err(RefuseReason::RemoteCapableInput));
    }

    /// (C) Two clean local `SimpleTextOutput`/`GOP` handles (a docked
    /// multi-head display) plus a path-less splitter: the splitter is
    /// skipped (not counted), and two fully-whitelisted local outputs are
    /// "explained" (SPEC §11.3), not `MultipleOutputPaths`.
    #[test]
    fn multi_head_two_clean_local_outputs_pass() {
        let head1 = clean_pci_out_bytes();
        let head2 = second_clean_pci_out_bytes();
        let stage = found(
            &[HandleProbe::Path(devpath(&head1)), HandleProbe::Path(devpath(&head2)), HandleProbe::NoDevicePath],
            ConsoleRole::ConOut,
            ConsoleRole::ExtraOut,
        );
        let resolved = resolve_role(&[stage]);
        assert_eq!(resolved.len, 2, "the path-less splitter must be skipped, not counted");
        let con_in = [accepted(ConsoleRole::ConIn, &usb_in_bytes())];
        let verdict = aggregate_topology(&TopologySets {
            con_in: &con_in,
            con_out: &resolved.reports[..resolved.len],
            err_out: &[],
            truncated: false,
        });
        assert!(verdict.is_ok(), "verdict = {:?}", verdict);
    }

    /// (D) Every stage for both `ConIn` and `ConOut` resolves to either
    /// `Absent` or a splitter-only `Found{len: 0}`: nothing is
    /// resolvable at all, and the gate fails closed with `ParseFailure`.
    #[test]
    fn all_splitters_refuse_parse_failure() {
        let out_stages = [
            found(&[HandleProbe::NoDevicePath], ConsoleRole::ConOut, ConsoleRole::ExtraOut),
            found(&[HandleProbe::NoDevicePath, HandleProbe::NoDevicePath], ConsoleRole::ConOut, ConsoleRole::ExtraOut),
            SweepOutcome::Absent,
        ];
        let in_stages = [SweepOutcome::Absent, found(&[HandleProbe::NoDevicePath], ConsoleRole::ConIn, ConsoleRole::ConIn)];
        let out = resolve_role(&out_stages);
        let in_ = resolve_role(&in_stages);
        assert_eq!(out.len, 0);
        assert_eq!(in_.len, 0);
        let verdict = aggregate_topology(&TopologySets {
            con_in: &in_.reports[..in_.len],
            con_out: &out.reports[..out.len],
            err_out: &[],
            truncated: false,
        });
        assert_eq!(verdict, Err(RefuseReason::ParseFailure));
    }

    /// (E1) The stage actually being consulted (no earlier stage
    /// resolved) reports `Truncated`: resolution stops with
    /// `truncated: true`, which `aggregate_topology` turns into
    /// `MultipleOutputPaths` -- fail closed on an unexplainable handle
    /// count.
    #[test]
    fn truncated_stage_refuses() {
        let resolved = resolve_role(&[SweepOutcome::Absent, SweepOutcome::Truncated]);
        assert!(resolved.truncated);
        assert_eq!(resolved.len, 0);
        let con_in = [accepted(ConsoleRole::ConIn, &usb_in_bytes())];
        let con_out = [accepted(ConsoleRole::ConOut, &clean_pci_out_bytes())];
        let verdict = aggregate_topology(&TopologySets {
            con_in: &con_in,
            con_out: &con_out,
            err_out: &[],
            truncated: resolved.truncated,
        });
        assert_eq!(verdict, Err(RefuseReason::MultipleOutputPaths));
    }

    /// (E2) A stage resolves cleanly *before* a later stage would report
    /// `Truncated`: the later stage is an alternative source, never
    /// consulted, and must not spuriously refuse the machine.
    #[test]
    fn later_stage_truncation_ignored_after_resolution() {
        let clean = clean_pci_out_bytes();
        let stage2 = found(&[HandleProbe::Path(devpath(&clean))], ConsoleRole::ConOut, ConsoleRole::ExtraOut);
        let resolved = resolve_role(&[SweepOutcome::Absent, stage2, SweepOutcome::Truncated]);
        assert!(!resolved.truncated, "a later, never-consulted stage's Truncated must not propagate");
        assert_eq!(resolved.len, 1);
        assert!(resolved.reports[0].is_accepted());
    }

    /// (F) Active-membership semantics (SPEC §11.3 "active" device
    /// paths): the tag stage resolving with a clean local handle means
    /// the enumeration stage -- which in this fixture contains a serial
    /// handle that is merely *present*, not tagged as an active console
    /// member -- is never consulted at all. This is not a widening: it
    /// is the exact semantics the shipped tag sweep already had, and a
    /// genuinely *active* serial member (tagged) still refuses (see the
    /// `enumeration_*_refuses_*` tests above, which model the
    /// conservative-closure default used once enumeration IS consulted).
    #[test]
    fn tag_resolution_is_authoritative() {
        let clean = clean_pci_out_bytes();
        let uart = uart_bytes();
        let tag_stage = found(&[HandleProbe::Path(devpath(&clean))], ConsoleRole::ConOut, ConsoleRole::ExtraOut);
        let enum_stage = found(&[HandleProbe::Path(devpath(&uart))], ConsoleRole::ConOut, ConsoleRole::ExtraOut);
        let resolved = resolve_role(&[tag_stage, enum_stage]);
        assert_eq!(resolved.len, 1);
        assert!(
            resolved.reports[0].is_accepted(),
            "tag stage resolved cleanly; the serial-carrying enumeration stage must never be consulted"
        );
    }

    /// (G) `HandleProbe::OpenError` is counted and refused
    /// (`ParseFailure`) -- distinct from `HandleProbe::NoDevicePath`,
    /// which is silently skipped. Collapsing both to the same disposition
    /// would silently fail open on a genuine, unexplained
    /// device-path-open failure.
    #[test]
    fn open_error_probe_refuses_distinct_from_skip() {
        let mut acc = SweepAccumulator::new(ConsoleRole::ConOut, ConsoleRole::ExtraOut);
        acc.push(HandleProbe::OpenError);
        match acc.finish(false) {
            SweepOutcome::Found { reports, len } => {
                assert_eq!(len, 1, "OpenError must be counted, unlike NoDevicePath");
                assert_eq!(reports[0].unwrap().verdict, Err(RefuseReason::ParseFailure));
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    /// (H) Role assignment happens strictly on counted (path-bearing)
    /// handles, after splitter-skip: a path-less handle enumerated first
    /// must not consume the primary-role slot.
    #[test]
    fn accumulator_assigns_primary_then_extra_role_after_skip() {
        let a = clean_pci_out_bytes();
        let b = second_clean_pci_out_bytes();
        let mut acc = SweepAccumulator::new(ConsoleRole::ConOut, ConsoleRole::ExtraOut);
        acc.push(HandleProbe::NoDevicePath);
        acc.push(HandleProbe::Path(devpath(&a)));
        acc.push(HandleProbe::Path(devpath(&b)));
        match acc.finish(false) {
            SweepOutcome::Found { reports, len } => {
                assert_eq!(len, 2);
                assert_eq!(reports[0].unwrap().role, ConsoleRole::ConOut);
                assert_eq!(reports[1].unwrap().role, ConsoleRole::ExtraOut);
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    /// (I) A tagged, path-bearing ErrOut serial handle is still fully
    /// gated -- ErrOut's "absence is not fatal" exemption (SPEC §11.3)
    /// only ever applies to an *empty* resolution, never to a resolved
    /// refusal.
    #[test]
    fn errout_tagged_serial_refuses() {
        let uart = uart_bytes();
        let stage = found(&[HandleProbe::Path(devpath(&uart))], ConsoleRole::ErrOut, ConsoleRole::ErrOut);
        let err = resolve_role(&[stage]);
        let con_in = [accepted(ConsoleRole::ConIn, &usb_in_bytes())];
        let con_out = [accepted(ConsoleRole::ConOut, &clean_pci_out_bytes())];
        let verdict = aggregate_topology(&TopologySets {
            con_in: &con_in,
            con_out: &con_out,
            err_out: &err.reports[..err.len],
            truncated: false,
        });
        assert_eq!(verdict, Err(RefuseReason::SerialConsole));
    }

    /// (I) An `Absent` ErrOut resolution (no stage found anything) is not
    /// fatal on its own (SPEC §11.3).
    #[test]
    fn errout_absent_not_fatal() {
        let err = resolve_role(&[SweepOutcome::Absent]);
        assert_eq!(err.len, 0);
        let con_in = [accepted(ConsoleRole::ConIn, &usb_in_bytes())];
        let con_out = [accepted(ConsoleRole::ConOut, &clean_pci_out_bytes())];
        let verdict = aggregate_topology(&TopologySets {
            con_in: &con_in,
            con_out: &con_out,
            err_out: &err.reports[..err.len],
            truncated: false,
        });
        assert!(verdict.is_ok(), "verdict = {:?}", verdict);
    }

    #[test]
    fn describe_reason_strings_are_non_empty() {
        let reasons = [
            RefuseReason::SerialConsole,
            RefuseReason::NetworkConsole,
            RefuseReason::RemoteManagement,
            RefuseReason::VendorUnclassifiable,
            RefuseReason::ParseFailure,
            RefuseReason::MultipleOutputPaths,
            RefuseReason::RemoteCapableInput,
        ];
        for r in reasons {
            assert!(!r.describe().is_empty());
        }
    }
}
