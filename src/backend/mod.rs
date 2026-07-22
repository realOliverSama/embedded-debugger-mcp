//! Debug backend abstraction (dual-engine).
//!
//! A single `DebugBackend` trait unifies the two execution engines so the MCP
//! tool layer speaks one API and never learns two. The concrete engine (probe-rs
//! native, or OpenOCD via GDB Remote Serial Protocol) is an implementation
//! detail chosen at `connect` time.

use async_trait::async_trait;

use crate::error::Result;

mod openocd_backend;
mod probe_rs_backend;
pub mod rsp;

pub use openocd_backend::OpenOcdBackend;
pub use probe_rs_backend::ProbeRsBackend;

/// Which engine backs a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    ProbeRs,
    OpenOcd,
}

impl std::fmt::Display for BackendKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendKind::ProbeRs => write!(f, "probe-rs"),
            BackendKind::OpenOcd => write!(f, "openocd"),
        }
    }
}

/// Core registers a backend can resolve by role (architecture-neutral subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreRegId {
    Pc,
    Sp,
    Lr,
}

/// Coarse core execution state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreState {
    Halted,
    Running,
    Unknown,
}

impl std::fmt::Display for CoreState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoreState::Halted => write!(f, "Halted"),
            CoreState::Running => write!(f, "Running"),
            CoreState::Unknown => write!(f, "Unknown"),
        }
    }
}

/// A snapshot of the most commonly needed core state, gathered in one shot to
/// save the model a round of individual reads.
#[derive(Debug, Clone)]
pub struct CoreSnapshot {
    pub pc: u32,
    pub sp: u32,
    pub state: CoreState,
    pub halt_reason: Option<String>,
}

/// Executability of one target memory region, as reported by the backend's
/// target description. Consumed by breakpoint-address validation before any
/// hardware breakpoint slot is touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutableRegion {
    pub name: Option<String>,
    pub range: std::ops::Range<u64>,
    pub executable: bool,
}

/// Everything the breakpoint-address validator needs from a backend.
///
/// `regions: None` means the backend cannot determine the target memory map;
/// callers must then apply a safe rejection policy rather than guessing.
#[derive(Debug, Clone)]
pub struct BreakpointAddressContext {
    /// True when the connected core is an ARM Cortex-M, whose fixed 4 GiB
    /// memory map defines architecturally execute-never (XN) regions.
    pub is_cortex_m: bool,
    pub regions: Option<Vec<ExecutableRegion>>,
}

/// Cortex-M launch state for an SRAM-loaded image, programmed while the core
/// is halted. `pc` keeps the Thumb bit exactly as stored in the vector table;
/// `xpsr` carries the T bit so the execution state is well defined regardless
/// of how the debug port interprets PC bit 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SramLaunchState {
    pub vtor: u32,
    pub msp: u32,
    pub pc: u32,
    pub xpsr: u32,
}

/// Read-only snapshot of the Cortex-M special registers that decide interrupt
/// masking and execution mode, decoded from the DCRSR "EXTRA" register
/// (id 0b10100: CONTROL[31:24] FAULTMASK[23:16] BASEPRI[15:8] PRIMASK[7:0]).
/// Reading requires a halted core; no target code is executed and no
/// register or memory is modified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpecialRegisters {
    pub primask: u8,
    pub basepri: u8,
    pub faultmask: u8,
    pub control: u8,
    pub msp: u32,
    pub psp: u32,
    pub xpsr: u32,
    /// DHCSR.S_SDE (bit 20): secure debug enabled. Related evidence for the
    /// core security state, which probe-rs does not expose directly.
    pub dhcsr_sde: Option<bool>,
}

/// Decode the packed DCRSR EXTRA register into (PRIMASK, BASEPRI, FAULTMASK, CONTROL).
pub fn unpack_extra_register(extra: u32) -> (u8, u8, u8, u8) {
    (
        (extra & 0xFF) as u8,
        ((extra >> 8) & 0xFF) as u8,
        ((extra >> 16) & 0xFF) as u8,
        ((extra >> 24) & 0xFF) as u8,
    )
}

/// Pack (PRIMASK, BASEPRI, FAULTMASK, CONTROL) back into the DCRSR EXTRA layout.
/// Inverse of `unpack_extra_register`.
pub fn pack_extra_register(primask: u8, basepri: u8, faultmask: u8, control: u8) -> u32 {
    primask as u32 | (basepri as u32) << 8 | (faultmask as u32) << 16 | (control as u32) << 24
}

/// Evidence for one interrupt-mask normalization (read-modify-write of the
/// DCRSR EXTRA register that only clears PRIMASK/BASEPRI/FAULTMASK).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaskNormalization {
    /// (PRIMASK, BASEPRI, FAULTMASK) before normalization.
    pub masks_before: (u8, u8, u8),
    /// (PRIMASK, BASEPRI, FAULTMASK) read back after normalization.
    pub masks_after: (u8, u8, u8),
    pub control_before: u8,
    pub control_after: u8,
    /// CONTROL survived the read-modify-write bit-for-bit.
    pub control_preserved: bool,
    /// All three masks are zero in the readback.
    pub normalized: bool,
}

/// The unified debug engine interface. probe-rs and OpenOCD both implement it.
#[async_trait]
pub trait DebugBackend: Send {
    fn kind(&self) -> BackendKind;

    async fn read_bytes(&mut self, address: u64, len: usize) -> Result<Vec<u8>>;
    async fn write_bytes(&mut self, address: u64, data: &[u8]) -> Result<()>;

    async fn halt(&mut self) -> Result<()>;
    async fn run(&mut self) -> Result<()>;
    async fn step(&mut self) -> Result<()>;
    async fn reset(&mut self, halt_after: bool) -> Result<()>;

    async fn core_reg(&mut self, reg: CoreRegId) -> Result<u32>;
    async fn status(&mut self) -> Result<CoreState>;

    async fn set_hw_breakpoint(&mut self, address: u64) -> Result<()>;
    async fn clear_hw_breakpoint(&mut self, address: u64) -> Result<()>;

    /// Describe what this backend knows for breakpoint-address validation.
    /// Must be side-effect free: no hardware access, no state change.
    async fn breakpoint_address_context(&self) -> Result<BreakpointAddressContext>;

    /// Program the Cortex-M launch state (VTOR/MSP/xPSR/PC) for a previously
    /// loaded SRAM image. The core must already be halted; implementations
    /// must not resume execution.
    async fn prepare_sram_launch(&mut self, launch: SramLaunchState) -> Result<()>;

    /// Read the interrupt-mask/mode special registers (PRIMASK/BASEPRI/
    /// FAULTMASK/CONTROL plus MSP/PSP/xPSR). Read-only; requires a halted
    /// core on implementations that go through DCRSR.
    async fn read_special_registers(&mut self) -> Result<SpecialRegisters>;

    /// Clear PRIMASK/BASEPRI/FAULTMASK via a read-modify-write of the DCRSR
    /// EXTRA register, preserving CONTROL bit-for-bit, with readback proof.
    /// Requires a halted core and DHCSR.C_MASKINTS == 0; must fail closed on
    /// any read/write/verify error. Internal capability for the deterministic
    /// SRAM launch path — NOT exposed as a public MCP tool.
    async fn clear_interrupt_masks(&mut self) -> Result<MaskNormalization>;

    /// Read a single little-endian 32-bit word. Default via `read_bytes`.
    async fn read_word(&mut self, address: u64) -> Result<u32> {
        let b = self.read_bytes(address, 4).await?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// One-shot core snapshot (state + PC + SP), tolerant of missing registers.
    async fn snapshot(&mut self) -> Result<CoreSnapshot> {
        let state = self.status().await.unwrap_or(CoreState::Unknown);
        let pc = self.core_reg(CoreRegId::Pc).await.unwrap_or(0);
        let sp = self.core_reg(CoreRegId::Sp).await.unwrap_or(0);
        Ok(CoreSnapshot {
            pc,
            sp,
            state,
            halt_reason: None,
        })
    }
}

#[cfg(test)]
mod special_register_tests {
    use super::unpack_extra_register;

    #[test]
    fn unpack_extra_decodes_all_four_masks() {
        // CONTROL=0x02, FAULTMASK=0x00, BASEPRI=0x40, PRIMASK=0x01
        let (primask, basepri, faultmask, control) = unpack_extra_register(0x0200_4001);
        assert_eq!(primask, 0x01);
        assert_eq!(basepri, 0x40);
        assert_eq!(faultmask, 0x00);
        assert_eq!(control, 0x02);
    }

    #[test]
    fn unpack_extra_all_zero_and_all_ones() {
        assert_eq!(unpack_extra_register(0), (0, 0, 0, 0));
        assert_eq!(unpack_extra_register(0xFFFF_FFFF), (0xFF, 0xFF, 0xFF, 0xFF));
    }
}

#[cfg(test)]
mod extra_pack_tests {
    use super::{pack_extra_register, unpack_extra_register};

    #[test]
    fn pack_unpack_round_trip() {
        for &(p, b, f, c) in &[(0u8, 0u8, 0u8, 0u8), (1, 0, 0, 0x0C), (0xFF, 0x40, 1, 2)] {
            assert_eq!(
                unpack_extra_register(pack_extra_register(p, b, f, c)),
                (p, b, f, c)
            );
        }
    }

    #[test]
    fn normalize_clears_only_masks_keeps_control() {
        let extra = pack_extra_register(1, 0x20, 1, 0x0C);
        let (_, _, _, control) = unpack_extra_register(extra);
        let normalized = pack_extra_register(0, 0, 0, control);
        assert_eq!(normalized, 0x0C00_0000);
        assert_eq!(unpack_extra_register(normalized), (0, 0, 0, 0x0C));
    }
}
