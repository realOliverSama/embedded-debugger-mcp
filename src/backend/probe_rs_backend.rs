//! probe-rs native engine (default backend).

use std::sync::Arc;

use async_trait::async_trait;
use probe_rs::{config::MemoryRegion, CoreStatus, MemoryInterface, RegisterValue, Session};
use tokio::sync::Mutex;

use super::{
    BackendKind, BreakpointAddressContext, CoreRegId, CoreState, DebugBackend, ExecutableRegion,
    MaskNormalization, SpecialRegisters, SramLaunchState,
};
use crate::error::{DebugError, Result};

/// Wraps a shared probe-rs `Session`. The same `Arc` is also held by the
/// session record so probe-rs-specific tools (flash, RTT) can keep using it.
pub struct ProbeRsBackend {
    session: Arc<Mutex<Session>>,
}

impl ProbeRsBackend {
    pub fn new(session: Arc<Mutex<Session>>) -> Self {
        Self { session }
    }
}

#[async_trait]
impl DebugBackend for ProbeRsBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::ProbeRs
    }

    async fn read_bytes(&mut self, address: u64, len: usize) -> Result<Vec<u8>> {
        let mut session = self.session.lock().await;
        let mut core = session.core(0)?;
        let mut buf = vec![0u8; len];
        core.read(address, &mut buf)
            .map_err(|e| DebugError::MemoryAccessFailed(e.to_string()))?;
        Ok(buf)
    }

    async fn write_bytes(&mut self, address: u64, data: &[u8]) -> Result<()> {
        let mut session = self.session.lock().await;
        let mut core = session.core(0)?;
        core.write(address, data)
            .map_err(|e| DebugError::MemoryAccessFailed(e.to_string()))?;
        Ok(())
    }

    async fn halt(&mut self) -> Result<()> {
        let mut session = self.session.lock().await;
        let mut core = session.core(0)?;
        core.halt(std::time::Duration::from_millis(1000))
            .map_err(|e| DebugError::InternalError(format!("halt failed: {}", e)))?;
        Ok(())
    }

    async fn run(&mut self) -> Result<()> {
        let mut session = self.session.lock().await;
        let mut core = session.core(0)?;
        core.run()
            .map_err(|e| DebugError::InternalError(format!("run failed: {}", e)))?;
        Ok(())
    }

    async fn step(&mut self) -> Result<()> {
        let mut session = self.session.lock().await;
        let mut core = session.core(0)?;
        core.step()
            .map_err(|e| DebugError::InternalError(format!("step failed: {}", e)))?;
        Ok(())
    }

    async fn reset(&mut self, halt_after: bool) -> Result<()> {
        let mut session = self.session.lock().await;
        let mut core = session.core(0)?;
        if halt_after {
            core.reset_and_halt(std::time::Duration::from_millis(1000))
                .map_err(|e| DebugError::InternalError(format!("reset_and_halt failed: {}", e)))?;
        } else {
            core.reset()
                .map_err(|e| DebugError::InternalError(format!("reset failed: {}", e)))?;
        }
        Ok(())
    }

    async fn core_reg(&mut self, reg: CoreRegId) -> Result<u32> {
        let mut session = self.session.lock().await;
        let mut core = session.core(0)?;
        let id = match reg {
            CoreRegId::Pc => core.program_counter(),
            CoreRegId::Sp => core.stack_pointer(),
            CoreRegId::Lr => core.return_address(),
        };
        let value: RegisterValue = core
            .read_core_reg(id)
            .map_err(|e| DebugError::InternalError(format!("read core reg failed: {}", e)))?;
        Ok(value.try_into().unwrap_or(0u32))
    }

    async fn status(&mut self) -> Result<CoreState> {
        let mut session = self.session.lock().await;
        let mut core = session.core(0)?;
        let status = core
            .status()
            .map_err(|e| DebugError::InternalError(format!("status failed: {}", e)))?;
        Ok(match status {
            CoreStatus::Halted(_) => CoreState::Halted,
            CoreStatus::Running => CoreState::Running,
            _ => CoreState::Unknown,
        })
    }

    async fn set_hw_breakpoint(&mut self, address: u64) -> Result<()> {
        let mut session = self.session.lock().await;
        let mut core = session.core(0)?;
        core.set_hw_breakpoint(address)
            .map_err(|e| DebugError::InternalError(format!("set breakpoint failed: {}", e)))?;
        Ok(())
    }

    async fn clear_hw_breakpoint(&mut self, address: u64) -> Result<()> {
        let mut session = self.session.lock().await;
        let mut core = session.core(0)?;
        core.clear_hw_breakpoint(address)
            .map_err(|e| DebugError::InternalError(format!("clear breakpoint failed: {}", e)))?;
        Ok(())
    }

    async fn prepare_sram_launch(&mut self, launch: SramLaunchState) -> Result<()> {
        /// SCB->VTOR on ARMv6-M/v7-M/v8-M.
        const SCB_VTOR: u64 = 0xE000_ED08;

        let mut session = self.session.lock().await;
        let mut core = session.core(0)?;

        // Safety: launch state may only be programmed on a halted core.
        let status = core
            .status()
            .map_err(|e| DebugError::InternalError(format!("status failed: {e}")))?;
        if !matches!(status, CoreStatus::Halted(_)) {
            return Err(DebugError::InternalError(
                "prepare_sram_launch requires a halted core; refusing to program launch state while running".to_string(),
            ));
        }

        core.write_word_32(SCB_VTOR, launch.vtor)
            .map_err(|e| DebugError::MemoryAccessFailed(format!("write VTOR failed: {e}")))?;

        let registers = core.registers();
        let msp_id = registers
            .msp()
            .ok_or_else(|| DebugError::InternalError("MSP register not available".to_string()))?
            .id();
        let psr_id = registers
            .psr()
            .ok_or_else(|| DebugError::InternalError("xPSR register not available".to_string()))?
            .id();
        let pc_id = registers
            .pc()
            .ok_or_else(|| DebugError::InternalError("PC register not available".to_string()))?
            .id();

        core.write_core_reg(msp_id, launch.msp)
            .map_err(|e| DebugError::InternalError(format!("write MSP failed: {e}")))?;
        core.write_core_reg(psr_id, launch.xpsr)
            .map_err(|e| DebugError::InternalError(format!("write xPSR failed: {e}")))?;
        core.write_core_reg(pc_id, launch.pc)
            .map_err(|e| DebugError::InternalError(format!("write PC failed: {e}")))?;
        Ok(())
    }

    async fn read_special_registers(&mut self) -> Result<SpecialRegisters> {
        /// DHCSR: Debug Halting Control and Status Register.
        const DHCSR: u64 = 0xE000_EDF0;
        const DHCSR_S_SDE: u32 = 1 << 20;

        let mut session = self.session.lock().await;
        let mut core = session.core(0)?;

        // DCRSR register access requires a halted core.
        let status = core
            .status()
            .map_err(|e| DebugError::InternalError(format!("status failed: {e}")))?;
        if !matches!(status, CoreStatus::Halted(_)) {
            return Err(DebugError::InternalError(
                "read_special_registers requires a halted core (special registers are read via DCRSR). Halt the target first.".to_string(),
            ));
        }

        let registers = core.registers();
        let extra_id = registers
            .other_by_name("EXTRA")
            .ok_or_else(|| {
                DebugError::InternalError(
                    "EXTRA register (PRIMASK/BASEPRI/FAULTMASK/CONTROL) not exposed by this core"
                        .to_string(),
                )
            })?
            .id();
        let msp_id = registers
            .msp()
            .ok_or_else(|| DebugError::InternalError("MSP register not available".to_string()))?
            .id();
        let psp_id = registers
            .psp()
            .ok_or_else(|| DebugError::InternalError("PSP register not available".to_string()))?
            .id();
        let psr_id = registers
            .psr()
            .ok_or_else(|| DebugError::InternalError("xPSR register not available".to_string()))?
            .id();

        let extra: u32 = core
            .read_core_reg(extra_id)
            .map_err(|e| DebugError::InternalError(format!("read EXTRA failed: {e}")))?;
        let msp: u32 = core
            .read_core_reg(msp_id)
            .map_err(|e| DebugError::InternalError(format!("read MSP failed: {e}")))?;
        let psp: u32 = core
            .read_core_reg(psp_id)
            .map_err(|e| DebugError::InternalError(format!("read PSP failed: {e}")))?;
        let xpsr: u32 = core
            .read_core_reg(psr_id)
            .map_err(|e| DebugError::InternalError(format!("read xPSR failed: {e}")))?;
        let dhcsr = core
            .read_word_32(DHCSR)
            .map_err(|e| DebugError::InternalError(format!("read DHCSR failed: {e}")))?;

        let (primask, basepri, faultmask, control) = super::unpack_extra_register(extra);
        Ok(SpecialRegisters {
            primask,
            basepri,
            faultmask,
            control,
            msp,
            psp,
            xpsr,
            dhcsr_sde: Some(dhcsr & DHCSR_S_SDE != 0),
        })
    }

    async fn clear_interrupt_masks(&mut self) -> Result<MaskNormalization> {
        /// DHCSR: Debug Halting Control and Status Register.
        const DHCSR: u64 = 0xE000_EDF0;
        const DHCSR_C_MASKINTS: u32 = 1 << 3;

        let mut session = self.session.lock().await;
        let mut core = session.core(0)?;

        // (2) Core must be halted right before normalization.
        let status = core
            .status()
            .map_err(|e| DebugError::InternalError(format!("status failed: {e}")))?;
        if !matches!(status, CoreStatus::Halted(_)) {
            return Err(DebugError::InternalError(
                "clear_interrupt_masks requires a halted core; refusing while running".to_string(),
            ));
        }

        // (2) DHCSR.C_MASKINTS must be 0, otherwise interrupt state is being
        // force-masked by the debugger itself and normalizing is meaningless.
        let dhcsr = core
            .read_word_32(DHCSR)
            .map_err(|e| DebugError::InternalError(format!("read DHCSR failed: {e}")))?;
        if dhcsr & DHCSR_C_MASKINTS != 0 {
            return Err(DebugError::InternalError(format!(
                "DHCSR.C_MASKINTS is set (DHCSR=0x{dhcsr:08X}); refusing mask normalization"
            )));
        }

        // (3) Read the packed EXTRA register through the core register API.
        let registers = core.registers();
        let extra_id = registers
            .other_by_name("EXTRA")
            .ok_or_else(|| {
                DebugError::InternalError("EXTRA register not exposed by this core".to_string())
            })?
            .id();
        let before: u32 = core
            .read_core_reg(extra_id)
            .map_err(|e| DebugError::InternalError(format!("read EXTRA failed: {e}")))?;
        let (primask, basepri, faultmask, control) = super::unpack_extra_register(before);
        let masks_before = (primask, basepri, faultmask);

        // (4) Idempotent when already clean: skip the write entirely.
        if masks_before == (0, 0, 0) {
            return Ok(MaskNormalization {
                masks_before,
                masks_after: masks_before,
                control_before: control,
                control_after: control,
                control_preserved: true,
                normalized: true,
            });
        }

        // (5) Read-modify-write: zero the three mask bytes, keep CONTROL.
        let packed = super::pack_extra_register(0, 0, 0, control);
        core.write_core_reg(extra_id, packed)
            .map_err(|e| DebugError::InternalError(format!("write EXTRA failed: {e}")))?;

        // (6) Readback proof.
        let after: u32 = core
            .read_core_reg(extra_id)
            .map_err(|e| DebugError::InternalError(format!("readback EXTRA failed: {e}")))?;
        let (p2, b2, f2, control_after) = super::unpack_extra_register(after);
        let masks_after = (p2, b2, f2);
        if masks_after != (0, 0, 0) {
            return Err(DebugError::InternalError(format!(
                "mask readback mismatch: PRIMASK={p2} BASEPRI={b2} FAULTMASK={f2} (expected all 0)"
            )));
        }
        if control_after != control {
            return Err(DebugError::InternalError(format!(
                "CONTROL changed during mask normalization: before=0x{control:02X} after=0x{control_after:02X}"
            )));
        }

        Ok(MaskNormalization {
            masks_before,
            masks_after,
            control_before: control,
            control_after,
            control_preserved: true,
            normalized: true,
        })
    }

    async fn breakpoint_address_context(&self) -> Result<BreakpointAddressContext> {
        let session = self.session.lock().await;
        let target = session.target();
        let is_cortex_m = target
            .cores
            .first()
            .map(|core| core.core_type.is_cortex_m())
            .unwrap_or(false);
        let regions = target
            .memory_map
            .iter()
            .map(executable_region_from_target)
            .collect();
        Ok(BreakpointAddressContext {
            is_cortex_m,
            regions: Some(regions),
        })
    }
}

/// Convert one probe-rs target-description region into its executability view.
fn executable_region_from_target(region: &MemoryRegion) -> ExecutableRegion {
    let (name, executable) = match region {
        MemoryRegion::Ram(ram) => (ram.name.clone(), ram.is_executable()),
        MemoryRegion::Nvm(nvm) => (nvm.name.clone(), nvm.is_executable()),
        MemoryRegion::Generic(generic) => (generic.name.clone(), generic.is_executable()),
    };
    ExecutableRegion {
        name,
        range: region.address_range(),
        executable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use probe_rs::config::{MemoryAccess, NvmRegion, RamRegion};

    #[test]
    fn ram_region_without_execute_permission_is_reported_non_executable() {
        let region = MemoryRegion::Ram(RamRegion {
            name: Some("SRAM_NOEXEC".to_string()),
            range: 0x2000_0000..0x2001_0000,
            cores: vec!["main".to_string()],
            access: Some(MemoryAccess {
                read: true,
                write: true,
                execute: false,
                boot: false,
            }),
        });
        let info = executable_region_from_target(&region);
        assert_eq!(info.range, 0x2000_0000..0x2001_0000);
        assert!(!info.executable);
    }

    #[test]
    fn nvm_region_defaults_to_executable() {
        let region = MemoryRegion::Nvm(NvmRegion {
            name: Some("Flash".to_string()),
            range: 0x0800_0000..0x0810_0000,
            cores: vec!["main".to_string()],
            is_alias: false,
            access: None,
        });
        let info = executable_region_from_target(&region);
        assert!(info.executable);
        assert_eq!(info.name.as_deref(), Some("Flash"));
    }
}
