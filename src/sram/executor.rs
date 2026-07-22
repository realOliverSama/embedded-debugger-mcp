//! Target-side execution of a validated `SramLoadPlan`.
//!
//! Launch modes:
//! - `DeterministicReset` — cold start: system reset-and-halt BEFORE any SRAM
//!   write, verify caches are off after reset, write, verify, optionally
//!   program launch state and run. This is the only mode allowed with
//!   `start=true`, because a target that previously ran firmware may hold
//!   stale caches / NVIC / peripheral state (see the D-30 incident report:
//!   cache-enabled firmware + SRAM rewrite without maintenance produced an
//!   incoherent execution mix).
//! - `PreserveState` — load-only, no reset, no launch. Writing via the debug
//!   AHB and readback-verifying it is cache-independent and therefore sound
//!   even while caches are enabled, but NOTHING may be run from the loaded
//!   image afterwards without a deterministic reset first.
//!
//! Failure semantics: any failure aborts before `run`, reports the failing
//! stage with address and reason, and leaves the core halted. No fallback to
//! flash programming, ever.

use sha2::{Digest, Sha256};

use super::elf_plan::SramLoadPlan;
use crate::backend::{CoreState, DebugBackend, SramLaunchState};

/// xPSR with only the Thumb bit set — the architecturally required execution
/// state for Cortex-M after a debugger-programmed launch.
pub const LAUNCH_XPSR_THUMB: u32 = 0x0100_0000;

/// SCB->CCR (Configuration and Control Register) — holds the cache enable bits.
const SCB_CCR: u64 = 0xE000_ED14;
const CCR_DCACHE_EN: u32 = 1 << 16;
const CCR_ICACHE_EN: u32 = 1 << 17;

/// How the loaded image may be launched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchMode {
    /// System reset-and-halt before writing; the only mode that may start the
    /// core. Guarantees core/NVIC/peripheral/cache state is not inherited
    /// from previously running firmware.
    DeterministicReset,
    /// No reset; load-only. `start=true` in this mode is rejected.
    PreserveState,
}

impl LaunchMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            LaunchMode::DeterministicReset => "deterministic_reset",
            LaunchMode::PreserveState => "preserve_state",
        }
    }
}

/// Snapshot of the SCB cache-enable state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheState {
    pub ccr: u32,
    pub icache_enabled: bool,
    pub dcache_enabled: bool,
}

impl CacheState {
    fn from_ccr(ccr: u32) -> Self {
        Self {
            ccr,
            icache_enabled: ccr & CCR_ICACHE_EN != 0,
            dcache_enabled: ccr & CCR_DCACHE_EN != 0,
        }
    }
}

/// Per-segment execution evidence.
#[derive(Debug, Clone)]
pub struct SramSegmentReport {
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub executable: bool,
    pub chunks_written: usize,
    pub bytes_verified: u64,
}

/// Full execution evidence returned to the tool layer.
#[derive(Debug, Clone)]
pub struct SramLoadReport {
    pub segments: Vec<SramSegmentReport>,
    /// SHA-256 over the readback image, computed identically to the plan
    /// digest; equality with `plan.image_sha256` is the verification proof.
    pub readback_sha256: String,
    pub matches_plan_digest: bool,
    pub launch_mode: LaunchMode,
    pub reset_performed: bool,
    /// Human-readable reset mechanism, when performed.
    pub reset_kind: Option<String>,
    pub cache_state_before_reset: Option<CacheState>,
    pub cache_state_after_reset: Option<CacheState>,
    /// True when the core was halted by us for a preserve-state load.
    pub halted_for_load: bool,
    /// True when the deterministic launch state (VTOR/MSP/xPSR/PC) was
    /// programmed after a verified deterministic reset sequence.
    pub deterministic_start: bool,
    pub started: bool,
    /// Interrupt-mask normalization evidence (only present when the
    /// deterministic start path ran).
    pub mask_normalization: Option<crate::backend::MaskNormalization>,
}

fn stage_error(stage: &str, address: u64, detail: impl std::fmt::Display) -> String {
    format!("SRAM load failed at stage '{stage}', address 0x{address:08X}: {detail}")
}

async fn read_cache_state(
    backend: &mut dyn DebugBackend,
    stage: &str,
) -> Result<CacheState, String> {
    let bytes = backend
        .read_bytes(SCB_CCR, 4)
        .await
        .map_err(|e| stage_error(stage, SCB_CCR, format!("cannot read SCB->CCR: {e}")))?;
    if bytes.len() != 4 {
        return Err(stage_error(
            stage,
            SCB_CCR,
            format!("short read on SCB->CCR: {} bytes", bytes.len()),
        ));
    }
    Ok(CacheState::from_ccr(u32::from_le_bytes(
        bytes.try_into().unwrap(),
    )))
}

/// Execute `plan` against `backend`.
///
/// Call order guarantee for `DeterministicReset`:
///   reset-and-halt → confirm Halted → cache check → write → verify
///   → (start: program launch state) → (start: run)
///
/// When `start` is false the function never programs launch state and never
/// resumes the core, regardless of mode.
pub async fn execute_sram_load(
    backend: &mut dyn DebugBackend,
    elf_bytes: &[u8],
    plan: &SramLoadPlan,
    chunk_size: usize,
    launch_mode: LaunchMode,
    start: bool,
) -> Result<SramLoadReport, String> {
    if chunk_size == 0 {
        return Err("chunk_size must be greater than zero".to_string());
    }

    // preserve_state + start=true is refused before touching the target.
    if start && launch_mode == LaunchMode::PreserveState {
        return Err(
            "SRAM load rejected at stage 'launch-mode': launch_mode=preserve_state with start=true is not supported. \
             Starting a loaded image requires launch_mode=deterministic_reset so that core/NVIC/peripheral/cache \
             state is not inherited from previously running firmware."
                .to_string(),
        );
    }

    // Record the cache state inherited from whatever ran before.
    let cache_state_before_reset = Some(read_cache_state(backend, "cache-state-before").await?);

    let mut reset_performed = false;
    let mut reset_kind: Option<String> = None;
    let mut cache_state_after_reset: Option<CacheState> = None;
    let mut halted_for_load = false;

    match launch_mode {
        LaunchMode::DeterministicReset => {
            // (b) system reset-and-halt BEFORE any SRAM write. probe-rs
            // reset_and_halt uses AIRCR.SYSRESETREQ (system reset: core +
            // NVIC + peripherals), not a PC/SP-only fake reset.
            backend
                .reset(true)
                .await
                .map_err(|e| stage_error("reset-and-halt", plan.entry, e))?;
            reset_performed = true;
            reset_kind = Some(
                "system reset-and-halt (AIRCR.SYSRESETREQ, core+NVIC+peripherals)".to_string(),
            );

            // (c) the core MUST be halted after the reset; otherwise we write nothing.
            match backend.status().await {
                Ok(CoreState::Halted) => {}
                Ok(state) => {
                    return Err(stage_error(
                        "reset-confirm",
                        plan.entry,
                        format!("core is {state} after reset-and-halt, expected Halted; zero bytes written"),
                    ));
                }
                Err(e) => return Err(stage_error("reset-confirm", plan.entry, e)),
            }

            // (d+e+f) caches must be OFF after the reset. If silicon keeps
            // them on, refuse rather than risk stale execution.
            let after = read_cache_state(backend, "cache-state-after-reset").await?;
            if after.icache_enabled || after.dcache_enabled {
                return Err(stage_error(
                    "cache-check",
                    SCB_CCR,
                    format!(
                        "caches still enabled after reset (CCR=0x{:08X}, I={}, D={}); refusing to write. Zero bytes written.",
                        after.ccr, after.icache_enabled, after.dcache_enabled
                    ),
                ));
            }
            cache_state_after_reset = Some(after);
        }
        LaunchMode::PreserveState => {
            // Load-only path: halt if running so the write/verify is coherent
            // from the core's point of view. No reset, no launch afterwards.
            match backend.status().await {
                Ok(CoreState::Halted) => {}
                Ok(_) => {
                    backend
                        .halt()
                        .await
                        .map_err(|e| stage_error("halt", plan.entry, e))?;
                    halted_for_load = true;
                }
                Err(e) => return Err(stage_error("status", plan.entry, e)),
            }
        }
    }

    // ---- stage: write + zero fill + verify ----
    let mut reports = Vec::new();

    for seg in &plan.segments {
        let file_start = seg.file_offset as usize;
        let file_end = file_start + seg.filesz as usize;
        let file_bytes = &elf_bytes[file_start..file_end];
        let mut chunks_written = 0usize;
        for (i, chunk) in file_bytes.chunks(chunk_size).enumerate() {
            let addr = seg.paddr + (i * chunk_size) as u64;
            backend
                .write_bytes(addr, chunk)
                .await
                .map_err(|e| stage_error("write", addr, e))?;
            chunks_written += 1;
        }

        let zero_len = seg.memsz - seg.filesz;
        if zero_len > 0 {
            let zero_chunk = vec![0u8; zero_len.min(chunk_size as u64) as usize];
            let mut written = 0u64;
            while written < zero_len {
                let addr = seg.paddr + seg.filesz + written;
                let n = (zero_len - written).min(zero_chunk.len() as u64) as usize;
                backend
                    .write_bytes(addr, &zero_chunk[..n])
                    .await
                    .map_err(|e| stage_error("zero-fill", addr, e))?;
                chunks_written += 1;
                written += n as u64;
            }
        }

        let mut readback = Vec::with_capacity(seg.memsz as usize);
        let mut done = 0u64;
        while done < seg.memsz {
            let addr = seg.paddr + done;
            let n = (seg.memsz - done).min(chunk_size as u64) as usize;
            let data = backend
                .read_bytes(addr, n)
                .await
                .map_err(|e| stage_error("readback", addr, e))?;
            if data.len() != n {
                return Err(stage_error(
                    "readback",
                    addr,
                    format!("short read: expected {n} bytes, got {}", data.len()),
                ));
            }
            readback.extend_from_slice(&data);
            done += n as u64;
        }
        let mut expected = Vec::with_capacity(seg.memsz as usize);
        expected.extend_from_slice(file_bytes);
        expected.resize(seg.memsz as usize, 0);
        if readback != expected {
            let mismatch_at = readback
                .iter()
                .zip(expected.iter())
                .position(|(a, b)| a != b)
                .map(|i| seg.paddr + i as u64)
                .unwrap_or(seg.paddr);
            return Err(stage_error(
                "verify",
                mismatch_at,
                "readback does not match the ELF image; NOT starting the core",
            ));
        }

        reports.push(SramSegmentReport {
            paddr: seg.paddr,
            filesz: seg.filesz,
            memsz: seg.memsz,
            executable: seg.executable,
            chunks_written,
            bytes_verified: seg.memsz,
        });
    }

    // ---- digest over readback, computed identically to the plan digest ----
    let mut hasher = Sha256::new();
    for seg in &plan.segments {
        hasher.update(seg.paddr.to_le_bytes());
        let mut done = 0u64;
        while done < seg.memsz {
            let addr = seg.paddr + done;
            let n = (seg.memsz - done).min(chunk_size as u64) as usize;
            let data = backend
                .read_bytes(addr, n)
                .await
                .map_err(|e| stage_error("digest-readback", addr, e))?;
            hasher.update(&data);
            done += n as u64;
        }
    }
    let readback_sha256 = hex_digest(&hasher.finalize());
    let matches_plan_digest = readback_sha256 == plan.image_sha256;
    if !matches_plan_digest {
        return Err(format!(
            "SRAM load failed at stage 'digest': readback SHA-256 {readback_sha256} != plan SHA-256 {}; NOT starting the core",
            plan.image_sha256
        ));
    }

    // ---- stage: launch (deterministic start only, only when requested) ----
    let mut deterministic_start = false;
    let mut mask_normalization = None;
    if start {
        // start=true is only reachable in DeterministicReset mode.
        backend
            .prepare_sram_launch(SramLaunchState {
                vtor: plan.vector_table as u32,
                msp: plan.initial_msp,
                pc: plan.reset_handler,
                xpsr: LAUNCH_XPSR_THUMB,
            })
            .await
            .map_err(|e| stage_error("launch", plan.vector_table, e))?;
        deterministic_start = true;

        // Normalize inherited interrupt masks (PRIMASK/BASEPRI/FAULTMASK → 0,
        // CONTROL preserved) with readback proof, immediately before run.
        // Fail closed: any error here means run is never called.
        let normalization = backend
            .clear_interrupt_masks()
            .await
            .map_err(|e| stage_error("mask-normalize", plan.vector_table, e))?;
        mask_normalization = Some(normalization);

        backend
            .run()
            .await
            .map_err(|e| stage_error("run", plan.reset_handler as u64, e))?;
    }

    Ok(SramLoadReport {
        segments: reports,
        readback_sha256,
        matches_plan_digest,
        launch_mode,
        reset_performed,
        reset_kind,
        cache_state_before_reset,
        cache_state_after_reset,
        halted_for_load,
        deterministic_start,
        started: start,
        mask_normalization,
    })
}

fn hex_digest(digest: &[u8]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{
        BackendKind, BreakpointAddressContext, CoreRegId, CoreState, SramLaunchState,
    };
    use crate::error::Result as CrateResult;
    use crate::sram::elf_plan::{plan_sram_load, SramLoadSegment, VectorTableSource};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory mock backend with a full action log and controllable
    /// reset/status/cache behaviour.
    struct MockBackend {
        memory: Mutex<HashMap<u64, u8>>,
        state: Mutex<CoreState>,
        log: Mutex<Vec<String>>,
        reset_fails: bool,
        halted_after_reset: bool,
        ccr_after_reset: u32,
        launch_fails: bool,
        corrupt_reads_at: Mutex<Option<u64>>,
        extra: Mutex<u32>,
        dhcsr: Mutex<u32>,
        extra_write_fails: bool,
        extra_readback_corrupt: bool,
        running_at_normalize: bool,
    }

    impl MockBackend {
        fn new(state: CoreState) -> Self {
            let mut mem = HashMap::new();
            // Pre-reset cache state: both caches enabled (firmware ran before).
            mem.insert(SCB_CCR, 0x01);
            mem.insert(SCB_CCR + 1, 0x02);
            mem.insert(SCB_CCR + 2, 0x03);
            mem.insert(SCB_CCR + 3, 0x00); // CCR = 0x00030201, IC+DC on
            Self {
                memory: Mutex::new(mem),
                state: Mutex::new(state),
                log: Mutex::new(Vec::new()),
                reset_fails: false,
                halted_after_reset: true,
                ccr_after_reset: 0x0, // real silicon: caches off after system reset
                launch_fails: false,
                corrupt_reads_at: Mutex::new(None),
                // BootROM-inherited state observed on real hardware: PRIMASK=1.
                extra: Mutex::new(0x0000_0001),
                dhcsr: Mutex::new(0x0111_0001), // C_MASKINTS = 0
                extra_write_fails: false,
                extra_readback_corrupt: false,
                running_at_normalize: false,
            }
        }
        fn calls(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }
        fn count(&self, prefix: &str) -> usize {
            self.log
                .lock()
                .unwrap()
                .iter()
                .filter(|c| c.starts_with(prefix))
                .count()
        }
        fn write_count(&self) -> usize {
            self.count("write")
        }
    }

    #[async_trait]
    impl DebugBackend for MockBackend {
        fn kind(&self) -> BackendKind {
            BackendKind::ProbeRs
        }
        async fn read_bytes(&mut self, address: u64, len: usize) -> CrateResult<Vec<u8>> {
            self.log
                .lock()
                .unwrap()
                .push(format!("read@0x{address:08X}"));
            let mem = self.memory.lock().unwrap();
            let corrupt = *self.corrupt_reads_at.lock().unwrap();
            Ok((0..len)
                .map(|i| {
                    let a = address + i as u64;
                    let mut v = *mem.get(&a).unwrap_or(&0);
                    if corrupt == Some(a) {
                        v ^= 0xFF;
                    }
                    v
                })
                .collect())
        }
        async fn write_bytes(&mut self, address: u64, data: &[u8]) -> CrateResult<()> {
            self.log
                .lock()
                .unwrap()
                .push(format!("write@0x{address:08X}"));
            let mut mem = self.memory.lock().unwrap();
            for (i, b) in data.iter().enumerate() {
                mem.insert(address + i as u64, *b);
            }
            Ok(())
        }
        async fn halt(&mut self) -> CrateResult<()> {
            self.log.lock().unwrap().push("halt".to_string());
            *self.state.lock().unwrap() = CoreState::Halted;
            Ok(())
        }
        async fn run(&mut self) -> CrateResult<()> {
            self.log.lock().unwrap().push("run".to_string());
            *self.state.lock().unwrap() = CoreState::Running;
            Ok(())
        }
        async fn step(&mut self) -> CrateResult<()> {
            Ok(())
        }
        async fn reset(&mut self, halt_after: bool) -> CrateResult<()> {
            self.log
                .lock()
                .unwrap()
                .push(format!("reset(halt_after={halt_after})"));
            if self.reset_fails {
                return Err(crate::error::DebugError::InternalError(
                    "mock reset failure".to_string(),
                ));
            }
            // Simulate system reset: caches cleared to the configured value.
            let ccr = self.ccr_after_reset;
            {
                let mut mem = self.memory.lock().unwrap();
                for (i, b) in ccr.to_le_bytes().iter().enumerate() {
                    mem.insert(SCB_CCR + i as u64, *b);
                }
            }
            *self.state.lock().unwrap() = if self.halted_after_reset && halt_after {
                CoreState::Halted
            } else {
                CoreState::Running
            };
            Ok(())
        }
        async fn core_reg(&mut self, _reg: CoreRegId) -> CrateResult<u32> {
            Ok(0)
        }
        async fn status(&mut self) -> CrateResult<CoreState> {
            self.log.lock().unwrap().push("status".to_string());
            Ok(*self.state.lock().unwrap())
        }
        async fn set_hw_breakpoint(&mut self, _address: u64) -> CrateResult<()> {
            Ok(())
        }
        async fn clear_hw_breakpoint(&mut self, _address: u64) -> CrateResult<()> {
            Ok(())
        }
        async fn breakpoint_address_context(&self) -> CrateResult<BreakpointAddressContext> {
            Ok(BreakpointAddressContext {
                is_cortex_m: true,
                regions: None,
            })
        }
        async fn prepare_sram_launch(&mut self, launch: SramLaunchState) -> CrateResult<()> {
            self.log
                .lock()
                .unwrap()
                .push(format!("prepare_launch(vtor=0x{:08X})", launch.vtor));
            if self.launch_fails {
                return Err(crate::error::DebugError::InternalError(
                    "mock launch failure".to_string(),
                ));
            }
            Ok(())
        }
        async fn read_special_registers(
            &mut self,
        ) -> CrateResult<crate::backend::SpecialRegisters> {
            Ok(crate::backend::SpecialRegisters {
                primask: 0,
                basepri: 0,
                faultmask: 0,
                control: 0,
                msp: 0,
                psp: 0,
                xpsr: 0x0100_0000,
                dhcsr_sde: None,
            })
        }
        async fn clear_interrupt_masks(
            &mut self,
        ) -> CrateResult<crate::backend::MaskNormalization> {
            use crate::backend::{pack_extra_register, unpack_extra_register, MaskNormalization};
            self.log.lock().unwrap().push("mask_normalize".to_string());
            if self.running_at_normalize {
                *self.state.lock().unwrap() = CoreState::Running;
            }
            if !matches!(*self.state.lock().unwrap(), CoreState::Halted) {
                return Err(crate::error::DebugError::InternalError(
                    "mock: core not halted".to_string(),
                ));
            }
            let dhcsr = *self.dhcsr.lock().unwrap();
            if dhcsr & 0x8 != 0 {
                return Err(crate::error::DebugError::InternalError(
                    "mock: C_MASKINTS set".to_string(),
                ));
            }
            let before = *self.extra.lock().unwrap();
            let (p, b, f, control) = unpack_extra_register(before);
            if (p, b, f) == (0, 0, 0) {
                return Ok(MaskNormalization {
                    masks_before: (0, 0, 0),
                    masks_after: (0, 0, 0),
                    control_before: control,
                    control_after: control,
                    control_preserved: true,
                    normalized: true,
                });
            }
            if self.extra_write_fails {
                return Err(crate::error::DebugError::InternalError(
                    "mock: EXTRA write failed".to_string(),
                ));
            }
            *self.extra.lock().unwrap() = pack_extra_register(0, 0, 0, control);
            let mut after = *self.extra.lock().unwrap();
            if self.extra_readback_corrupt {
                after ^= 0x1; // readback shows PRIMASK still set
            }
            let (p2, b2, f2, control_after) = unpack_extra_register(after);
            if (p2, b2, f2) != (0, 0, 0) {
                return Err(crate::error::DebugError::InternalError(
                    "mock: readback mismatch".to_string(),
                ));
            }
            if control_after != control {
                return Err(crate::error::DebugError::InternalError(
                    "mock: CONTROL changed".to_string(),
                ));
            }
            Ok(MaskNormalization {
                masks_before: (p, b, f),
                masks_after: (0, 0, 0),
                control_before: control,
                control_after,
                control_preserved: true,
                normalized: true,
            })
        }
    }

    fn test_plan() -> (Vec<u8>, crate::sram::elf_plan::SramLoadPlan) {
        let mut image = vec![0xAAu8; 0x100];
        image[0x10..0x14].copy_from_slice(&0x3402_0000u32.to_le_bytes()); // MSP
        image[0x14..0x18].copy_from_slice(&0x3400_0021u32.to_le_bytes()); // Reset|Thumb
        let plan = SramLoadPlan {
            entry: 0x3400_0021,
            vector_table: 0x3400_0010,
            vector_table_source: VectorTableSource::ExplicitOverride,
            initial_msp: 0x3402_0000,
            reset_handler: 0x3400_0021,
            segments: vec![SramLoadSegment {
                paddr: 0x3400_0000,
                file_offset: 0,
                filesz: 0x100,
                memsz: 0x140,
                executable: true,
            }],
            image_sha256: String::new(),
            total_write_bytes: 0x140,
        };
        let mut hasher = Sha256::new();
        hasher.update(0x3400_0000u64.to_le_bytes());
        hasher.update(&image);
        hasher.update(vec![0u8; 0x40]);
        let plan = SramLoadPlan {
            image_sha256: hex_digest(&hasher.finalize()),
            ..plan
        };
        (image, plan)
    }

    #[tokio::test]
    async fn start_true_deterministic_reset_full_sequence() {
        let (image, plan) = test_plan();
        let mut backend = MockBackend::new(CoreState::Running);
        let report = execute_sram_load(
            &mut backend,
            &image,
            &plan,
            64,
            LaunchMode::DeterministicReset,
            true,
        )
        .await
        .expect("deterministic start must succeed");

        assert!(report.started);
        assert!(report.deterministic_start);
        assert!(report.reset_performed);
        assert!(report
            .reset_kind
            .as_deref()
            .unwrap()
            .contains("SYSRESETREQ"));
        assert!(report.cache_state_before_reset.unwrap().icache_enabled);
        assert!(report.cache_state_before_reset.unwrap().dcache_enabled);
        let after = report.cache_state_after_reset.unwrap();
        assert!(!after.icache_enabled && !after.dcache_enabled);
        assert!(report.matches_plan_digest);

        // Strict order: reset-and-halt → (cache reads) → write → verify(reads)
        // → launch registers → mask normalization → run
        let calls = backend.calls();
        let pos = |p: &str| {
            calls
                .iter()
                .position(|c| c.starts_with(p))
                .unwrap_or(usize::MAX)
        };
        let first_write = pos("write");
        let first_launch = pos("prepare_launch");
        let mask_pos = pos("mask_normalize");
        let run_pos = pos("run");
        assert!(
            pos("reset(halt_after=true)") < first_write,
            "reset must precede writes: {calls:?}"
        );
        assert!(
            pos("read@0xE000ED14") < first_write,
            "cache check must precede writes: {calls:?}"
        );
        assert!(
            first_write < first_launch,
            "writes must precede launch: {calls:?}"
        );
        assert!(
            first_launch < mask_pos,
            "launch must precede mask normalization: {calls:?}"
        );
        assert!(
            mask_pos < run_pos,
            "mask normalization must precede run: {calls:?}"
        );
        assert_eq!(calls.iter().filter(|c| *c == "run").count(), 1);

        // Mask normalization evidence: PRIMASK was 1 (BootROM-inherited), now 0.
        let masks = report.mask_normalization.expect("mask evidence");
        assert_eq!(masks.masks_before, (1, 0, 0));
        assert_eq!(masks.masks_after, (0, 0, 0));
        assert!(masks.control_preserved);
        assert!(masks.normalized);
    }

    #[tokio::test]
    async fn reset_failure_means_zero_writes() {
        let (image, plan) = test_plan();
        let mut backend = MockBackend::new(CoreState::Running);
        backend.reset_fails = true;
        let err = execute_sram_load(
            &mut backend,
            &image,
            &plan,
            64,
            LaunchMode::DeterministicReset,
            true,
        )
        .await
        .expect_err("reset failure must abort");
        assert!(err.contains("reset-and-halt"), "{err}");
        assert_eq!(backend.write_count(), 0, "zero writes after reset failure");
        assert_eq!(backend.count("run"), 0);
    }

    #[tokio::test]
    async fn not_halted_after_reset_means_zero_writes() {
        let (image, plan) = test_plan();
        let mut backend = MockBackend::new(CoreState::Running);
        backend.halted_after_reset = false; // reset "succeeds" but core runs
        let err = execute_sram_load(
            &mut backend,
            &image,
            &plan,
            64,
            LaunchMode::DeterministicReset,
            true,
        )
        .await
        .expect_err("running core after reset-and-halt must abort");
        assert!(err.contains("reset-confirm"), "{err}");
        assert_eq!(backend.write_count(), 0);
        assert_eq!(backend.count("run"), 0);
    }

    #[tokio::test]
    async fn caches_still_on_after_reset_safely_rejected() {
        let (image, plan) = test_plan();
        let mut backend = MockBackend::new(CoreState::Running);
        backend.ccr_after_reset = 0x0003_0000; // silicon kept caches on
        let err = execute_sram_load(
            &mut backend,
            &image,
            &plan,
            64,
            LaunchMode::DeterministicReset,
            true,
        )
        .await
        .expect_err("caches on after reset must abort");
        assert!(err.contains("cache-check"), "{err}");
        assert!(err.contains("refusing to write"), "{err}");
        assert_eq!(backend.write_count(), 0);
        assert_eq!(backend.count("run"), 0);
    }

    #[tokio::test]
    async fn readback_mismatch_blocks_run_in_deterministic_mode() {
        let (image, plan) = test_plan();
        let mut backend = MockBackend::new(CoreState::Running);
        *backend.corrupt_reads_at.lock().unwrap() = Some(0x3400_0080);
        let err = execute_sram_load(
            &mut backend,
            &image,
            &plan,
            64,
            LaunchMode::DeterministicReset,
            true,
        )
        .await
        .expect_err("corrupted readback must fail");
        assert!(err.contains("verify"), "{err}");
        assert_eq!(backend.count("run"), 0);
        assert_eq!(backend.count("prepare_launch"), 0);
    }

    #[tokio::test]
    async fn launch_failure_blocks_run() {
        let (image, plan) = test_plan();
        let mut backend = MockBackend::new(CoreState::Running);
        backend.launch_fails = true;
        let err = execute_sram_load(
            &mut backend,
            &image,
            &plan,
            64,
            LaunchMode::DeterministicReset,
            true,
        )
        .await
        .expect_err("launch failure must fail");
        assert!(err.contains("launch"), "{err}");
        assert_eq!(backend.count("run"), 0);
    }

    #[tokio::test]
    async fn running_core_at_normalize_blocks_run() {
        let (image, plan) = test_plan();
        let mut backend = MockBackend::new(CoreState::Running);
        backend.running_at_normalize = true;
        let err = execute_sram_load(
            &mut backend,
            &image,
            &plan,
            64,
            LaunchMode::DeterministicReset,
            true,
        )
        .await
        .expect_err("running core at normalization must abort");
        assert!(err.contains("mask-normalize"), "{err}");
        assert_eq!(backend.count("run"), 0);
    }

    #[tokio::test]
    async fn c_maskints_set_blocks_run() {
        let (image, plan) = test_plan();
        let mut backend = MockBackend::new(CoreState::Running);
        *backend.dhcsr.lock().unwrap() = 0x0111_0009; // C_MASKINTS set
        let err = execute_sram_load(
            &mut backend,
            &image,
            &plan,
            64,
            LaunchMode::DeterministicReset,
            true,
        )
        .await
        .expect_err("C_MASKINTS must abort");
        assert!(err.contains("mask-normalize"), "{err}");
        assert_eq!(backend.count("run"), 0);
    }

    #[tokio::test]
    async fn extra_write_failure_blocks_run() {
        let (image, plan) = test_plan();
        let mut backend = MockBackend::new(CoreState::Running);
        backend.extra_write_fails = true;
        let err = execute_sram_load(
            &mut backend,
            &image,
            &plan,
            64,
            LaunchMode::DeterministicReset,
            true,
        )
        .await
        .expect_err("write failure must abort");
        assert!(err.contains("mask-normalize"), "{err}");
        assert_eq!(backend.count("run"), 0);
    }

    #[tokio::test]
    async fn extra_readback_mismatch_blocks_run() {
        let (image, plan) = test_plan();
        let mut backend = MockBackend::new(CoreState::Running);
        backend.extra_readback_corrupt = true;
        let err = execute_sram_load(
            &mut backend,
            &image,
            &plan,
            64,
            LaunchMode::DeterministicReset,
            true,
        )
        .await
        .expect_err("readback mismatch must abort");
        assert!(err.contains("mask-normalize"), "{err}");
        assert_eq!(backend.count("run"), 0);
    }

    #[tokio::test]
    async fn masks_already_zero_is_idempotent() {
        let (image, plan) = test_plan();
        let mut backend = MockBackend::new(CoreState::Running);
        *backend.extra.lock().unwrap() = 0x0; // already clean
        let report = execute_sram_load(
            &mut backend,
            &image,
            &plan,
            64,
            LaunchMode::DeterministicReset,
            true,
        )
        .await
        .expect("idempotent normalization must succeed");
        let masks = report.mask_normalization.unwrap();
        assert_eq!(masks.masks_before, (0, 0, 0));
        assert_eq!(masks.masks_after, (0, 0, 0));
        assert!(masks.normalized);
        assert_eq!(backend.count("run"), 1);
    }

    #[tokio::test]
    async fn control_preserved_with_nonzero_control() {
        let (image, plan) = test_plan();
        let mut backend = MockBackend::new(CoreState::Running);
        *backend.extra.lock().unwrap() = 0x0C00_0001; // CONTROL=0x0C, PRIMASK=1
        let report = execute_sram_load(
            &mut backend,
            &image,
            &plan,
            64,
            LaunchMode::DeterministicReset,
            true,
        )
        .await
        .expect("normalization must succeed");
        let masks = report.mask_normalization.unwrap();
        assert_eq!(masks.masks_before, (1, 0, 0));
        assert_eq!(masks.masks_after, (0, 0, 0));
        assert_eq!(masks.control_before, 0x0C);
        assert_eq!(masks.control_after, 0x0C);
        assert!(masks.control_preserved);
        assert_eq!(*backend.extra.lock().unwrap(), 0x0C00_0000);
    }

    #[tokio::test]
    async fn preserve_state_with_start_true_rejected_before_any_target_call() {
        let (image, plan) = test_plan();
        let mut backend = MockBackend::new(CoreState::Running);
        let err = execute_sram_load(
            &mut backend,
            &image,
            &plan,
            64,
            LaunchMode::PreserveState,
            true,
        )
        .await
        .expect_err("preserve_state+start=true must be rejected");
        assert!(err.contains("launch-mode"), "{err}");
        assert!(err.contains("deterministic_reset"), "{err}");
        // Only the launch-mode check may run: not even a status/cache read.
        assert!(
            backend.calls().is_empty(),
            "no backend calls expected: {:?}",
            backend.calls()
        );
    }

    #[tokio::test]
    async fn start_false_deterministic_resets_but_never_runs() {
        let (image, plan) = test_plan();
        let mut backend = MockBackend::new(CoreState::Running);
        let report = execute_sram_load(
            &mut backend,
            &image,
            &plan,
            64,
            LaunchMode::DeterministicReset,
            false,
        )
        .await
        .expect("load-only deterministic must succeed");
        assert!(report.reset_performed);
        assert!(!report.started);
        assert!(!report.deterministic_start);
        assert_eq!(backend.count("run"), 0);
        assert_eq!(backend.count("prepare_launch"), 0);
        assert!(report.matches_plan_digest);
    }

    #[tokio::test]
    async fn start_false_preserve_state_loads_without_reset() {
        let (image, plan) = test_plan();
        let mut backend = MockBackend::new(CoreState::Running);
        let report = execute_sram_load(
            &mut backend,
            &image,
            &plan,
            64,
            LaunchMode::PreserveState,
            false,
        )
        .await
        .expect("preserve-state load-only must succeed");
        assert!(!report.reset_performed);
        assert!(report.reset_kind.is_none());
        assert!(report.cache_state_after_reset.is_none());
        assert!(report.cache_state_before_reset.unwrap().icache_enabled);
        assert!(report.halted_for_load); // was running, we halted it
        assert!(!report.started);
        assert_eq!(backend.count("run"), 0);
        assert_eq!(backend.count("reset"), 0);
        assert!(report.matches_plan_digest);
        // BSS zero-filled
        let mem = backend.memory.lock().unwrap();
        for a in 0x3400_0100..0x3400_0140u64 {
            assert_eq!(*mem.get(&a).unwrap_or(&0), 0, "BSS at 0x{a:X}");
        }
    }

    #[tokio::test]
    async fn zero_chunk_size_rejected() {
        let (image, plan) = test_plan();
        let mut backend = MockBackend::new(CoreState::Halted);
        assert!(execute_sram_load(
            &mut backend,
            &image,
            &plan,
            0,
            LaunchMode::DeterministicReset,
            false
        )
        .await
        .is_err());
    }

    #[test]
    fn planner_still_rejects_junk() {
        let wl = 0x3400_0000..0x3420_0000;
        assert!(plan_sram_load(b"junk", &wl, None).is_err());
    }
}
