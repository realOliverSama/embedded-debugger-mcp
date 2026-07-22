//! AI-facing crash-diagnosis tools.
//!
//! Design for flagship models: aggregate the scattered reads into ONE call and
//! return a compact, structured evidence bundle (raw register values + which
//! bits are set). We do NOT assert a root cause or embed a teaching decision
//! tree — the model reasons over the evidence. This saves context (one call
//! instead of ~6 `read_memory`) without over-teaching.

use rmcp::{handler::server::tool::Parameters, model::*, tool, tool_router, ErrorData as McpError};
use std::future::Future;
use tracing::{debug, error, info};

use super::session::EmbeddedDebuggerToolHandler;
use crate::backend::{CoreRegId, DebugBackend};
use crate::tools::types::*;
use probe_rs_debug::{exception_handler_for_core, DebugInfo, DebugRegisters};

// ARMv7-M System Control Block fault registers (identical on all Cortex-M).
// Source: ARMv7-M Architecture Reference Manual, System Control Block.
const CPUID: u64 = 0xE000_ED00;
const ICSR: u64 = 0xE000_ED04;
const SHCSR: u64 = 0xE000_ED24;
const CFSR: u64 = 0xE000_ED28;
const HFSR: u64 = 0xE000_ED2C;
const MMFAR: u64 = 0xE000_ED34;
const BFAR: u64 = 0xE000_ED38;

// Actionable CFSR bits (bit index -> name). Compact evidence, not a tutorial.
const CFSR_BITS: &[(u32, &str)] = &[
    // MemManage fault (MFSR, byte 0)
    (0, "IACCVIOL"),
    (1, "DACCVIOL"),
    (3, "MUNSTKERR"),
    (4, "MSTKERR"),
    (7, "MMARVALID"),
    // BusFault (BFSR, byte 1)
    (8, "IBUSERR"),
    (9, "PRECISERR"),
    (10, "IMPRECISERR"),
    (11, "UNSTKERR"),
    (12, "STKERR"),
    (15, "BFARVALID"),
    // UsageFault (UFSR, bytes 2-3)
    (16, "UNDEFINSTR"),
    (17, "INVSTATE"),
    (18, "INVPC"),
    (19, "NOCP"),
    (24, "UNALIGNED"),
    (25, "DIVBYZERO"),
];

const HFSR_BITS: &[(u32, &str)] = &[(1, "VECTTBL"), (30, "FORCED"), (31, "DEBUGEVT")];

fn set_flags(value: u32, table: &[(u32, &str)]) -> Vec<String> {
    table
        .iter()
        .filter(|(bit, _)| value & (1 << bit) != 0)
        .map(|(_, name)| name.to_string())
        .collect()
}

async fn read_word_opt(backend: &mut Box<dyn DebugBackend>, addr: u64) -> Option<u32> {
    backend.read_word(addr).await.ok()
}

fn hex_or_null(v: Option<u32>) -> serde_json::Value {
    match v {
        Some(x) => serde_json::Value::String(format!("0x{:08X}", x)),
        None => serde_json::Value::Null,
    }
}

/// Decoded Cortex-M EXC_RETURN (the LR value while halted in an exception
/// handler). Determines which stack holds the pushed frame and its size.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ExcReturn {
    in_exception: bool,
    uses_psp: bool,
    extended: bool,
}

fn decode_exc_return(lr: u32) -> ExcReturn {
    // EXC_RETURN values are 0xFFFFFFxx. Bit 2 (SPSEL): 1 => PSP. Bit 4: 0 =>
    // extended (FPU) frame.
    let in_exception = (lr & 0xFFFF_FF00) == 0xFFFF_FF00;
    ExcReturn {
        in_exception,
        uses_psp: in_exception && (lr & 0x4) != 0,
        extended: in_exception && (lr & 0x10) == 0,
    }
}

/// Cortex-M exception stack frame offsets (basic and extended share these for
/// the core registers; FP registers, if any, follow xPSR).
const STACKED_LR_OFFSET: u64 = 0x14;
const STACKED_PC_OFFSET: u64 = 0x18;

/// Build a frame JSON object from an address and its resolved source location.
fn frame_json(index: usize, addr: u32, role: &str, di: &DebugInfo) -> serde_json::Value {
    let sl = di.get_source_location(addr as u64);
    let (file, line) = match &sl {
        Some(s) => (Some(s.path.to_path().display().to_string()), s.line),
        None => (None, None),
    };
    serde_json::json!({
        "index": index,
        "role": role,
        "pc": format!("0x{:08X}", addr),
        "file": file,
        "line": line,
    })
}

#[tool_router(router = diagnostics_tool_router, vis = "pub")]
impl EmbeddedDebuggerToolHandler {
    #[tool(
        description = "Aggregate crash evidence in one call: read the Cortex-M SCB fault registers \
        (CFSR/HFSR/MMFAR/BFAR/SHCSR/CPUID/ICSR) plus PC/SP/LR and return a compact structured \
        bundle with the set fault bits. Returns raw evidence for you to reason over; it does not \
        assert a root cause. Halt the target first for meaningful values."
    )]
    async fn diagnose_fault(
        &self,
        Parameters(args): Parameters<DiagnoseFaultArgs>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Diagnosing fault for session: {}", args.session_id);
        let session_arc = self.get_session(&args.session_id).await?;

        let mut backend = session_arc.backend.lock().await;
        let backend_kind = backend.kind().to_string();

        let cfsr = read_word_opt(&mut backend, CFSR).await;
        let hfsr = read_word_opt(&mut backend, HFSR).await;
        let mmfar = read_word_opt(&mut backend, MMFAR).await;
        let bfar = read_word_opt(&mut backend, BFAR).await;
        let shcsr = read_word_opt(&mut backend, SHCSR).await;
        let cpuid = read_word_opt(&mut backend, CPUID).await;
        let icsr = read_word_opt(&mut backend, ICSR).await;

        let pc = backend.core_reg(CoreRegId::Pc).await.ok();
        let sp = backend.core_reg(CoreRegId::Sp).await.ok();
        let lr = backend.core_reg(CoreRegId::Lr).await.ok();
        drop(backend);

        let cfsr_flags = cfsr.map(|v| set_flags(v, CFSR_BITS)).unwrap_or_default();
        let hfsr_flags = hfsr.map(|v| set_flags(v, HFSR_BITS)).unwrap_or_default();

        // Fault addresses are only meaningful when the matching *ARVALID bit is set.
        let mmfar_valid = cfsr.map(|v| v & (1 << 7) != 0).unwrap_or(false);
        let bfar_valid = cfsr.map(|v| v & (1 << 15) != 0).unwrap_or(false);
        let mmfar_value = if mmfar_valid {
            hex_or_null(mmfar)
        } else {
            serde_json::Value::Null
        };
        let bfar_value = if bfar_valid {
            hex_or_null(bfar)
        } else {
            serde_json::Value::Null
        };

        let report = serde_json::json!({
            "session": args.session_id,
            "backend": backend_kind,
            "target": session_arc.target_chip,
            "core": {
                "pc": hex_or_null(pc),
                "sp": hex_or_null(sp),
                "lr": hex_or_null(lr),
            },
            "scb_raw": {
                "cfsr": hex_or_null(cfsr),
                "hfsr": hex_or_null(hfsr),
                "shcsr": hex_or_null(shcsr),
                "cpuid": hex_or_null(cpuid),
                "icsr": hex_or_null(icsr),
                "mmfar": hex_or_null(mmfar),
                "bfar": hex_or_null(bfar),
            },
            "cfsr_flags": cfsr_flags,
            "hfsr_flags": hfsr_flags,
            "fault_address": {
                "mmfar": mmfar_value,
                "bfar": bfar_value,
            },
            "note": "Raw Cortex-M fault evidence. No root cause asserted; reason from the set bits and fault address. Values are meaningful only when the core is halted in the fault context."
        });

        let text = serde_json::to_string_pretty(&report)
            .unwrap_or_else(|e| format!("{{\"error\":\"serialize failed: {}\"}}", e));

        info!("Diagnose completed for session: {}", args.session_id);
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    #[tool(
        description = "Read the Cortex-M special registers that control interrupt masking and \
        execution mode (PRIMASK, BASEPRI, FAULTMASK, CONTROL) plus MSP/PSP/xPSR, decoded from \
        the DCRSR EXTRA register. Read-only: no target code is executed and nothing is modified. \
        Requires a halted core. Also reports DHCSR.S_SDE (secure debug enabled); the core's \
        current security state is not exposed by probe-rs and is reported as unavailable."
    )]
    async fn read_special_registers(
        &self,
        Parameters(args): Parameters<ReadSpecialRegistersArgs>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Reading special registers for session: {}", args.session_id);
        let session_arc = self.get_session(&args.session_id).await?;

        let regs = {
            let mut backend = session_arc.backend.lock().await;
            backend.read_special_registers().await.map_err(|e| {
                error!(
                    "Failed to read special registers for session {}: {}",
                    args.session_id, e
                );
                McpError::internal_error(format!("Failed to read special registers: {}", e), None)
            })?
        };

        let report = serde_json::json!({
            "session": args.session_id,
            "primask": regs.primask,
            "primask_meaning": if regs.primask & 1 != 0 { "all maskable interrupts BLOCKED" } else { "interrupts allowed" },
            "basepri": regs.basepri,
            "faultmask": regs.faultmask,
            "control": regs.control,
            "msp": format!("0x{:08X}", regs.msp),
            "psp": format!("0x{:08X}", regs.psp),
            "xpsr": format!("0x{:08X}", regs.xpsr),
            "dhcsr_sde": regs.dhcsr_sde,
            "security_state": "unavailable (probe-rs does not expose the current security state; DHCSR.S_SDE reported separately)",
            "note": "Read-only DCRSR access on a halted core; no target code executed."
        });

        let text = serde_json::to_string_pretty(&report)
            .unwrap_or_else(|e| format!("{{\"error\":\"serialize failed: {}\"}}", e));

        info!("Special registers read for session: {}", args.session_id);
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    #[tool(
        description = "Unwind the stack after a crash and map each frame to a source line. On the \
        probe-rs backend this returns a full DWARF backtrace (function + file:line per frame). On \
        the OpenOCD backend it reads the Cortex-M exception stack frame and maps the faulting PC \
        and caller LR to source lines. Requires elf_path pointing at firmware built with debug \
        info (.debug_line). Halt the target in the fault context first."
    )]
    async fn unwind_exception(
        &self,
        Parameters(args): Parameters<UnwindExceptionArgs>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Unwinding stack for session: {}", args.session_id);
        let session_arc = self.get_session(&args.session_id).await?;
        let elf = args.elf_path.clone();

        // probe-rs backend: full DWARF backtrace via probe-rs's own unwinder.
        // Everything after acquiring the lock is synchronous so the !Send
        // DebugInfo never crosses an await point.
        if let Some(prs) = session_arc.probe_rs_session.clone() {
            let frames = {
                let mut session = prs.lock().await;
                let mut core = session.core(0).map_err(|e| {
                    McpError::internal_error(format!("Failed to get core: {}", e), None)
                })?;
                let di = DebugInfo::from_file(&elf).map_err(|e| {
                    McpError::internal_error(
                        format!("Failed to load debug info from '{}': {}", elf, e),
                        None,
                    )
                })?;
                let registers = DebugRegisters::from_core(&mut core);
                let handler = exception_handler_for_core(core.core_type());
                let instruction_set = core.instruction_set().ok();
                let stack = di
                    .unwind(&mut core, registers, handler.as_ref(), instruction_set)
                    .map_err(|e| {
                        McpError::internal_error(format!("Stack unwind failed: {}", e), None)
                    })?;
                stack
                    .iter()
                    .enumerate()
                    .map(|(i, f)| {
                        let pc: u32 = f.pc.try_into().unwrap_or(0);
                        let (file, line) = match &f.source_location {
                            Some(s) => (Some(s.path.to_path().display().to_string()), s.line),
                            None => (None, None),
                        };
                        serde_json::json!({
                            "index": i,
                            "pc": format!("0x{:08X}", pc),
                            "function": f.function_name.clone(),
                            "file": file,
                            "line": line,
                        })
                    })
                    .collect::<Vec<_>>()
            };

            let report = serde_json::json!({
                "session": args.session_id,
                "backend": "probe-rs",
                "elf": elf,
                "method": "probe-rs DWARF unwind (full backtrace, innermost first)",
                "frames": frames,
                "note": "Each frame is mapped to source via DWARF. Needs firmware built with debug info; halt in the fault context for a meaningful trace."
            });
            let text = serde_json::to_string_pretty(&report)
                .unwrap_or_else(|e| format!("{{\"error\":\"serialize failed: {}\"}}", e));
            info!(
                "Unwind (probe-rs) completed for session: {}",
                args.session_id
            );
            return Ok(CallToolResult::success(vec![Content::text(text)]));
        }

        // OpenOCD (no probe-rs Core): Level-1 exception-frame read + mapping.
        let (cur_pc, cur_sp, lr, backend_kind) = {
            let mut backend = session_arc.backend.lock().await;
            let kind = backend.kind().to_string();
            let pc = backend.core_reg(CoreRegId::Pc).await.ok();
            let sp = backend.core_reg(CoreRegId::Sp).await.ok();
            let lr = backend.core_reg(CoreRegId::Lr).await.ok();
            (pc, sp, lr, kind)
        };

        let exc = lr.map(decode_exc_return).unwrap_or_default();
        let mut stacked_pc = None;
        let mut stacked_lr = None;
        let note: &str;
        if exc.in_exception && !exc.uses_psp {
            if let Some(sp) = cur_sp {
                let mut backend = session_arc.backend.lock().await;
                stacked_pc = backend.read_word(sp as u64 + STACKED_PC_OFFSET).await.ok();
                stacked_lr = backend.read_word(sp as u64 + STACKED_LR_OFFSET).await.ok();
                note = "Cortex-M exception frame on MSP (bare-metal). Frame role 'faulting-pc' is the crashing instruction.";
            } else {
                note = "In an exception but SP is unavailable; showing current PC only.";
            }
        } else if exc.in_exception && exc.uses_psp {
            note = "Faulting frame is on PSP (RTOS/threaded); the OpenOCD backend cannot read PSP here. Use the probe-rs backend for a full backtrace.";
        } else {
            note = "Core is not in an exception context (LR is not EXC_RETURN); showing current PC only.";
        }

        // Synchronous DWARF mapping (DebugInfo is !Send; no await in this block).
        let frames = {
            let di = DebugInfo::from_file(&elf).map_err(|e| {
                McpError::internal_error(
                    format!("Failed to load debug info from '{}': {}", elf, e),
                    None,
                )
            })?;
            let mut v = Vec::new();
            let mut idx = 0;
            if let Some(p) = stacked_pc {
                v.push(frame_json(idx, p, "faulting-pc", &di));
                idx += 1;
            }
            if let Some(l) = stacked_lr {
                v.push(frame_json(idx, l, "caller-lr", &di));
                idx += 1;
            }
            if let Some(p) = cur_pc {
                v.push(frame_json(idx, p, "current-pc", &di));
            }
            v
        };

        let report = serde_json::json!({
            "session": args.session_id,
            "backend": backend_kind,
            "elf": elf,
            "method": "cortex-m exception frame (Level 1)",
            "in_exception": exc.in_exception,
            "frames": frames,
            "note": note,
        });
        let text = serde_json::to_string_pretty(&report)
            .unwrap_or_else(|e| format!("{{\"error\":\"serialize failed: {}\"}}", e));
        info!(
            "Unwind (level-1) completed for session: {}",
            args.session_id
        );
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_divbyzero_and_valid_bits() {
        // DIVBYZERO (bit 25) + MMARVALID (bit 7)
        let cfsr = (1 << 25) | (1 << 7);
        let flags = set_flags(cfsr, CFSR_BITS);
        assert!(flags.contains(&"DIVBYZERO".to_string()));
        assert!(flags.contains(&"MMARVALID".to_string()));
        assert!(!flags.contains(&"UNALIGNED".to_string()));
    }

    #[test]
    fn decodes_hfsr_forced() {
        let flags = set_flags(1 << 30, HFSR_BITS);
        assert_eq!(flags, vec!["FORCED".to_string()]);
    }

    #[test]
    fn exc_return_thread_msp_basic() {
        // 0xFFFFFFF9: return to Thread mode, MSP, basic frame.
        let e = decode_exc_return(0xFFFF_FFF9);
        assert!(e.in_exception);
        assert!(!e.uses_psp);
        assert!(!e.extended);
    }

    #[test]
    fn exc_return_thread_psp() {
        // 0xFFFFFFFD: return to Thread mode, PSP.
        let e = decode_exc_return(0xFFFF_FFFD);
        assert!(e.in_exception);
        assert!(e.uses_psp);
    }

    #[test]
    fn exc_return_extended_fpu_frame() {
        // 0xFFFFFFE1: handler mode, MSP, extended (FPU) frame (bit4 == 0).
        let e = decode_exc_return(0xFFFF_FFE1);
        assert!(e.in_exception);
        assert!(!e.uses_psp);
        assert!(e.extended);
    }

    #[test]
    fn normal_lr_is_not_exception() {
        // A normal return address is not EXC_RETURN.
        let e = decode_exc_return(0x0800_1234);
        assert!(!e.in_exception);
        assert_eq!(e, ExcReturn::default());
    }
}
