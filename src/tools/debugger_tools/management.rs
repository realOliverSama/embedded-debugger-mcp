use rmcp::{handler::server::tool::Parameters, model::*, tool, tool_router, ErrorData as McpError};
use std::future::Future;
use std::sync::Arc;
use tracing::{debug, error, info};

use super::session::{DebugSession, EmbeddedDebuggerToolHandler};
use crate::backend::{DebugBackend, OpenOcdBackend, ProbeRsBackend};
use crate::rtt::RttManager;
use crate::tools::types::*;
use probe_rs::{probe::list::Lister, Permissions};
use tokio::sync::OwnedSemaphorePermit;

#[tool_router(router = management_tool_router, vis = "pub")]
impl EmbeddedDebuggerToolHandler {
    // =============================================================================
    // Debugger Management Tools (4 tools)
    // =============================================================================

    #[tool(description = "List all available debug probes (J-Link, ST-Link, DAPLink, etc.)")]
    async fn list_probes(
        &self,
        Parameters(_args): Parameters<ListProbesArgs>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Listing available debug probes");

        // Real probe-rs integration
        let probes = Lister::new().list_all();
        let message = if probes.is_empty() {
            "No debug probes found.\n\nPlease ensure your probe is connected and drivers are installed.\nSupported probes: J-Link, ST-Link, DAPLink, Black Magic Probe".to_string()
        } else {
            let mut result = format!("Found {} debug probe(s):\n\n", probes.len());

            for (i, probe) in probes.iter().enumerate() {
                result.push_str(&format!("{}. {}\n", i + 1, probe.identifier));
                result.push_str(&format!(
                    "   VID:PID = {:04X}:{:04X}\n",
                    probe.vendor_id, probe.product_id
                ));

                if let Some(serial) = &probe.serial_number {
                    result.push_str(&format!("   Serial: {}\n", serial));
                }

                result.push_str(&format!("   Probe Type: {:?}\n", probe.probe_type()));
                result.push('\n');
            }

            result
        };

        info!("Listed {} debug probes", probes.len());
        Ok(CallToolResult::success(vec![Content::text(message)]))
    }

    #[tool(description = "Connect to a debug probe and target chip")]
    async fn connect(
        &self,
        Parameters(args): Parameters<ConnectArgs>,
    ) -> Result<CallToolResult, McpError> {
        debug!(
            "Connecting to probe '{}' and target '{}'",
            args.probe_selector, args.target_chip
        );

        let session_slot = self
            .session_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                McpError::internal_error(
                    format!(
                        "Session limit exceeded. Maximum {} sessions allowed.",
                        self.max_sessions
                    ),
                    None,
                )
            })?;

        // OpenOCD backend: talk to an already-running openocd over GDB RSP.
        if args.backend.eq_ignore_ascii_case("openocd") {
            return self.connect_openocd(&args, session_slot).await;
        }

        // Real probe-rs implementation
        let probes = Lister::new().list_all();

        if probes.is_empty() {
            return Err(McpError::internal_error(
                "No debug probes found. Please connect a supported probe (J-Link, ST-Link, DAPLink, etc.)".to_string(),
                None
            ));
        }

        let selected_probe = if args.probe_selector.to_lowercase() == "auto" {
            probes.first()
        } else {
            probes
                .iter()
                .find(|p| p.identifier.contains(&args.probe_selector))
        };

        match selected_probe {
            Some(probe_info) => {
                info!("Opening probe: {}", probe_info.identifier);
                match probe_info.open() {
                    Ok(mut probe) => {
                        let actual_speed = probe.set_speed(args.speed_khz).map_err(|e| {
                            McpError::internal_error(
                                format!(
                                    "Failed to set probe speed to {} kHz: {}",
                                    args.speed_khz, e
                                ),
                                None,
                            )
                        })?;

                        let permissions = if self.flash_erase_allowed() {
                            Permissions::new().allow_erase_all()
                        } else {
                            Permissions::new()
                        };

                        let connect_under_reset =
                            args.connect_under_reset || self.config.debugger.connect_under_reset;
                        let halt_after_connect =
                            args.resolved_halt_after_connect(self.config.debugger.halt_on_connect);

                        info!("Attaching to target: {}", args.target_chip);
                        let attach_result = if connect_under_reset {
                            probe.attach_under_reset(&args.target_chip, permissions)
                        } else {
                            probe.attach(&args.target_chip, permissions)
                        };

                        match attach_result {
                            Ok(mut session) => {
                                if halt_after_connect {
                                    let mut core = session.core(0).map_err(|e| {
                                        McpError::internal_error(
                                            format!(
                                                "Connected but failed to get core for halt: {}",
                                                e
                                            ),
                                            None,
                                        )
                                    })?;
                                    core.halt(std::time::Duration::from_millis(
                                        self.config.debugger.connection_timeout_ms,
                                    ))
                                    .map_err(|e| {
                                        McpError::internal_error(
                                            format!("Connected but failed to halt target: {}", e),
                                            None,
                                        )
                                    })?;
                                }

                                let session_id = format!("session_{}", uuid::Uuid::new_v4());

                                let shared_session = Arc::new(tokio::sync::Mutex::new(session));
                                let backend: Box<dyn DebugBackend> =
                                    Box::new(ProbeRsBackend::new(shared_session.clone()));

                                let debug_session = DebugSession {
                                    session_id: session_id.clone(),
                                    probe_identifier: probe_info.identifier.clone(),
                                    target_chip: args.target_chip.clone(),
                                    created_at: chrono::Utc::now(),
                                    backend: Arc::new(tokio::sync::Mutex::new(backend)),
                                    probe_rs_session: Some(shared_session),
                                    rtt_manager: Arc::new(tokio::sync::Mutex::new(
                                        RttManager::new(),
                                    )),
                                    _session_slot: session_slot,
                                };

                                // Store session
                                {
                                    let mut sessions = self.sessions.write().await;
                                    sessions.insert(session_id.clone(), Arc::new(debug_session));
                                }

                                let message = format!(
                                    "Debug session established.\n\n\
                                    Session ID: {}\n\
                                    Probe: {} (VID:PID = {:04X}:{:04X})\n\
                                    Target: {}\n\
                                    Speed: {} kHz\n\
                                    Connect under reset: {}\n\
                                    Halted after connect: {}\n\
                                    Connected at: {}\n\n\
                                    Target connection established and ready for debugging.\n\
                                    Use this session ID for all debug operations.",
                                    session_id,
                                    probe_info.identifier,
                                    probe_info.vendor_id,
                                    probe_info.product_id,
                                    args.target_chip,
                                    actual_speed,
                                    connect_under_reset,
                                    halt_after_connect,
                                    chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                                );

                                info!("Created debug session: {}", session_id);
                                Ok(CallToolResult::success(vec![Content::text(message)]))
                            }
                            Err(e) => {
                                error!("Failed to attach to target '{}': {}", args.target_chip, e);
                                let error_msg = format!(
                                    "Failed to attach to target '{}'\n\n\
                                    Error: {}\n\n\
                                    Suggestions:\n\
                                    - Check target chip name (try: STM32F407VGTx, nRF52840_xxAA)\n\
                                    - Ensure target is powered and connected\n\
                                    - Verify SWD/JTAG connections",
                                    args.target_chip, e
                                );
                                Err(McpError::internal_error(error_msg, None))
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to open probe '{}': {}", probe_info.identifier, e);
                        let error_msg = format!(
                            "Failed to open probe '{}'\n\nError: {}\n\n\
                            Suggestions:\n\
                            - Check probe drivers installation\n\
                            - Verify USB connection\n\
                            - Try disconnecting and reconnecting probe",
                            probe_info.identifier, e
                        );
                        Err(McpError::internal_error(error_msg, None))
                    }
                }
            }
            None => {
                let available_probes: Vec<String> = probes
                    .iter()
                    .map(|p| format!("- {}", p.identifier))
                    .collect();

                let error_msg = format!(
                    "Probe '{}' not found\n\n\
                    Available probes:\n{}\n\n\
                    Use 'auto' to connect to first available probe.",
                    args.probe_selector,
                    available_probes.join("\n")
                );
                Err(McpError::internal_error(error_msg, None))
            }
        }
    }

    #[tool(description = "Disconnect from a debug session")]
    async fn disconnect(
        &self,
        Parameters(args): Parameters<DisconnectArgs>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Disconnecting session: {}", args.session_id);

        // Remove session from storage
        let removed_session = {
            let mut sessions = self.sessions.write().await;
            sessions.remove(&args.session_id)
        };

        match removed_session {
            Some(session) => {
                let message = format!(
                    "Debug session disconnected successfully\n\n\
                    Session ID: {}\n\
                    Probe: {}\n\
                    Target: {}\n\
                    Duration: {:.1} minutes\n\n\
                    probe-rs Session resources have been cleaned up.",
                    args.session_id,
                    session.probe_identifier,
                    session.target_chip,
                    (chrono::Utc::now() - session.created_at).num_seconds() as f64 / 60.0
                );

                info!("Disconnected debug session: {}", args.session_id);
                Ok(CallToolResult::success(vec![Content::text(message)]))
            }
            None => {
                let error_msg = format!(
                    "Session '{}' not found\n\nUse 'connect' to establish a debug session first",
                    args.session_id
                );
                Err(McpError::internal_error(error_msg, None))
            }
        }
    }

    #[tool(description = "Get basic information about a debug session")]
    async fn probe_info(
        &self,
        Parameters(args): Parameters<ProbeInfoArgs>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Getting probe info for session: {}", args.session_id);

        // Get session from storage
        let session_arc = self.get_session(&args.session_id).await?;

        // Calculate session duration
        let duration_minutes =
            (chrono::Utc::now() - session_arc.created_at).num_seconds() as f64 / 60.0;

        let message = format!(
            "Debug Session Information\n\n\
            Probe Information:\n\
            - Identifier: {}\n\
            - Connected: true\n\n\
            Target Information:\n\
            - Chip: {}\n\n\
            Session Status:\n\
            - Session ID: {}\n\
            - Created: {}\n\
            - Duration: {:.1} minutes\n\n\
            Session is active and ready for operations.",
            session_arc.probe_identifier,
            session_arc.target_chip,
            args.session_id,
            session_arc.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
            duration_minutes
        );

        info!("Retrieved probe info for session: {}", args.session_id);
        Ok(CallToolResult::success(vec![Content::text(message)]))
    }
}

impl EmbeddedDebuggerToolHandler {
    /// Establish a session backed by an already-running OpenOCD over GDB RSP.
    async fn connect_openocd(
        &self,
        args: &ConnectArgs,
        session_slot: OwnedSemaphorePermit,
    ) -> Result<CallToolResult, McpError> {
        let address = args.openocd_address.clone();
        info!("Connecting via OpenOCD GDB RSP at {}", address);

        let mut backend = OpenOcdBackend::connect(&address).await.map_err(|e| {
            McpError::internal_error(
                format!(
                    "Failed to connect to OpenOCD at {}: {}. Ensure openocd is running and \
                     exposing its GDB port (e.g. openocd -f interface/stlink.cfg -f target/stm32f4x.cfg).",
                    address, e
                ),
                None,
            )
        })?;

        let halt_after_connect =
            args.resolved_halt_after_connect(self.config.debugger.halt_on_connect);

        if halt_after_connect {
            let _ = backend.halt().await;
        }

        let session_id = format!("session_{}", uuid::Uuid::new_v4());
        let boxed: Box<dyn DebugBackend> = Box::new(backend);
        let debug_session = DebugSession {
            session_id: session_id.clone(),
            probe_identifier: format!("openocd@{}", address),
            target_chip: args.target_chip.clone(),
            created_at: chrono::Utc::now(),
            backend: Arc::new(tokio::sync::Mutex::new(boxed)),
            probe_rs_session: None,
            rtt_manager: Arc::new(tokio::sync::Mutex::new(RttManager::new())),
            _session_slot: session_slot,
        };

        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id.clone(), Arc::new(debug_session));
        }

        let message = format!(
            "Debug session established (OpenOCD backend).\n\n\
            Session ID: {}\n\
            OpenOCD: {}\n\
            Target: {}\n\
            Halted after connect: {}\n\n\
            Available: read_memory, write_memory, halt, run, step, reset, breakpoints, \
            diagnose_fault. Flash and RTT require the probe-rs backend.",
            session_id, address, args.target_chip, halt_after_connect
        );

        info!("Created OpenOCD debug session: {}", session_id);
        Ok(CallToolResult::success(vec![Content::text(message)]))
    }
}
