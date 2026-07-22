//! Dedicated `load_elf_to_sram` tool.
//!
//! Loads an ELF image into target SRAM strictly via its program headers,
//! verifies by readback + SHA-256, and only on explicit request programs the
//! Cortex-M launch state (VTOR/MSP/xPSR/PC) and resumes the core. This is the
//! ONLY sanctioned way to launch SRAM images; it deliberately exposes no
//! generic register-write capability.

use rmcp::{handler::server::tool::Parameters, model::*, tool, tool_router, ErrorData as McpError};
use std::future::Future;
use tracing::{error, info};

use super::formatting::parse_address;
use super::session::EmbeddedDebuggerToolHandler;
use crate::sram::elf_plan::{plan_sram_load, VectorTableSource};
use crate::sram::executor::{execute_sram_load, CacheState, LaunchMode};
use crate::tools::types::*;

const DEFAULT_CHUNK_SIZE: usize = 2048;

fn parse_launch_mode(raw: Option<&str>) -> Result<LaunchMode, McpError> {
    match raw.map(|s| s.trim()) {
        None | Some("") | Some("deterministic_reset") => Ok(LaunchMode::DeterministicReset),
        Some("preserve_state") => Ok(LaunchMode::PreserveState),
        Some(other) => Err(McpError::invalid_params(
            format!(
                "Invalid launch_mode '{}'. Supported: 'deterministic_reset' (default), 'preserve_state'.",
                other
            ),
            None,
        )),
    }
}

fn format_cache_state(state: &Option<CacheState>) -> String {
    match state {
        Some(s) => format!(
            "CCR=0x{:08X} (I-cache: {}, D-cache: {})",
            s.ccr,
            if s.icache_enabled { "ON" } else { "off" },
            if s.dcache_enabled { "ON" } else { "off" }
        ),
        None => "n/a (no reset performed)".to_string(),
    }
}

#[tool_router(router = sram_loader_tool_router, vis = "pub")]
impl EmbeddedDebuggerToolHandler {
    #[tool(
        description = "Load an ELF image into target SRAM via its program headers (never flash), verify by readback with SHA-256 evidence, and optionally set the Cortex-M launch state (VTOR/MSP/xPSR/PC from the vector table) and start execution. Every PT_LOAD must fit inside the caller-supplied SRAM whitelist. launch_mode: 'deterministic_reset' (default; system reset-and-halt before writing, caches must be off after reset, required for start=true) or 'preserve_state' (load-only, no reset; start=true is rejected). start defaults to false (load only)."
    )]
    async fn load_elf_to_sram(
        &self,
        Parameters(args): Parameters<LoadElfToSramArgs>,
    ) -> Result<CallToolResult, McpError> {
        // ---- parse and validate arguments (no hardware touched yet) ----
        let sram_start = parse_address(&args.sram_start).map_err(|e| {
            McpError::invalid_params(
                format!("Invalid sram_start '{}': {}", args.sram_start, e),
                None,
            )
        })?;
        let sram_end = parse_address(&args.sram_end).map_err(|e| {
            McpError::invalid_params(format!("Invalid sram_end '{}': {}", args.sram_end, e), None)
        })?;
        let vector_table_address = match &args.vector_table_address {
            Some(v) => Some(parse_address(v).map_err(|e| {
                McpError::invalid_params(
                    format!("Invalid vector_table_address '{}': {}", v, e),
                    None,
                )
            })?),
            None => None,
        };
        let start = args.start.unwrap_or(false);
        let launch_mode = parse_launch_mode(args.launch_mode.as_deref())?;
        let chunk_size = args
            .chunk_size
            .unwrap_or(DEFAULT_CHUNK_SIZE)
            .clamp(1, self.config.memory.max_write_size);

        // ---- resolve and read the ELF (same path policy as flash tools) ----
        let elf_path =
            self.resolve_allowed_file_path(&args.elf_path, self.config.security.max_file_size)?;
        let elf_bytes = std::fs::read(&elf_path).map_err(|e| {
            McpError::internal_error(
                format!("Failed to read ELF '{}': {}", elf_path.display(), e),
                None,
            )
        })?;

        // ---- pure planning: all safety checks run before any target write ----
        let whitelist = sram_start..sram_end;
        let plan = plan_sram_load(&elf_bytes, &whitelist, vector_table_address).map_err(|e| {
            error!("SRAM load rejected at planning stage: {}", e);
            McpError::invalid_params(format!("SRAM load rejected: {}", e), None)
        })?;

        let session_arc = self.get_session(&args.session_id).await?;

        // ---- execute against the target ----
        let report = {
            let mut backend = session_arc.backend.lock().await;
            execute_sram_load(
                &mut **backend,
                &elf_bytes,
                &plan,
                chunk_size,
                launch_mode,
                start,
            )
            .await
            .map_err(|e| {
                error!("SRAM load failed for session {}: {}", args.session_id, e);
                McpError::internal_error(e, None)
            })?
        };

        // ---- report ----
        let vt_source = match plan.vector_table_source {
            VectorTableSource::Symbol => "symbol g_pfnVectors",
            VectorTableSource::Section => "section .isr_vector",
            VectorTableSource::ExplicitOverride => "explicit vector_table_address",
        };
        let mask_lines = match &report.mask_normalization {
            Some(m) => format!(
                "Interrupt masks before: PRIMASK={} BASEPRI={} FAULTMASK={}\n\
                Interrupt masks after:  PRIMASK={} BASEPRI={} FAULTMASK={}\n\
                CONTROL before/after: 0x{:02X}/0x{:02X} (preserved: {})\n\
                Interrupt masks normalized: {}\n",
                m.masks_before.0,
                m.masks_before.1,
                m.masks_before.2,
                m.masks_after.0,
                m.masks_after.1,
                m.masks_after.2,
                m.control_before,
                m.control_after,
                m.control_preserved,
                m.normalized
            ),
            None => "Interrupt masks: n/a (no launch; mask context untouched)\n".to_string(),
        };
        let mut segment_lines = String::new();
        for seg in &report.segments {
            segment_lines.push_str(&format!(
                "  0x{:08X}..0x{:08X}  filesz={} memsz={} exec={} chunks={} verified={}B\n",
                seg.paddr,
                seg.paddr + seg.memsz,
                seg.filesz,
                seg.memsz,
                seg.executable,
                seg.chunks_written,
                seg.bytes_verified
            ));
        }
        let message = format!(
            "SRAM ELF load completed successfully.\n\n\
            Session ID: {}\n\
            ELF: {}\n\
            SRAM whitelist: 0x{:08X}..0x{:08X}\n\
            Segments loaded:\n{}\
            Total bytes written: {}\n\
            Chunk size: {}\n\
            Plan SHA-256:     {}\n\
            Readback SHA-256: {} ({})\n\
            Vector table: 0x{:08X} ({})\n\
            Initial MSP: 0x{:08X}\n\
            Reset_Handler: 0x{:08X}\n\
            ELF entry: 0x{:08X}\n\
            Launch mode: {}\n\
            Reset performed: {}\n\
            Reset kind: {}\n\
            Cache state before reset: {}\n\
            Cache state after reset: {}\n\
            Halted for load: {}\n\
            Deterministic start: {}\n\
            Started: {}\n\
            {}\n\
            {}",
            args.session_id,
            elf_path.display(),
            sram_start,
            sram_end,
            segment_lines,
            plan.total_write_bytes,
            chunk_size,
            plan.image_sha256,
            report.readback_sha256,
            if report.matches_plan_digest {
                "MATCH"
            } else {
                "MISMATCH"
            },
            plan.vector_table,
            vt_source,
            plan.initial_msp,
            plan.reset_handler,
            plan.entry,
            report.launch_mode.as_str(),
            report.reset_performed,
            report.reset_kind.as_deref().unwrap_or("none"),
            format_cache_state(&report.cache_state_before_reset),
            format_cache_state(&report.cache_state_after_reset),
            report.halted_for_load,
            report.deterministic_start,
            report.started,
            mask_lines,
            if start {
                "Launch state programmed: VTOR/MSP/xPSR/PC set from the vector table after a deterministic reset; core resumed."
            } else if report.reset_performed {
                "Load only (start=false): system reset-and-halt performed, image verified; launch state NOT programmed and run was not called. Core left halted."
            } else {
                "Load only (start=false, preserve_state): no reset performed; launch state NOT programmed and run was not called. Core left halted. Note: starting this image later requires a deterministic reset first."
            }
        );

        info!(
            "SRAM ELF loaded for session {}: {} bytes, started={}",
            args.session_id, plan.total_write_bytes, start
        );
        Ok(CallToolResult::success(vec![Content::text(message)]))
    }
}
