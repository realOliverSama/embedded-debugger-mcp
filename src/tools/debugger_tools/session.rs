use rmcp::{handler::server::router::tool::ToolRouter, ErrorData as McpError};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, RwLock, Semaphore};

use crate::backend::DebugBackend;
use crate::config::Config;
use crate::rtt::RttManager;
use probe_rs::Session;

/// Debug session information.
///
/// `backend` is the unified execution engine (probe-rs or OpenOCD) that the
/// core/memory/control tools drive. `probe_rs_session` is only present for
/// probe-rs sessions and is retained so probe-rs-specific tools (flash, RTT)
/// can keep using the native `Session` directly.
pub struct DebugSession {
    pub session_id: String,
    pub probe_identifier: String,
    pub target_chip: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub backend: Arc<tokio::sync::Mutex<Box<dyn DebugBackend>>>,
    pub probe_rs_session: Option<Arc<tokio::sync::Mutex<Session>>>,
    pub rtt_manager: Arc<tokio::sync::Mutex<RttManager>>,
    pub(super) _session_slot: OwnedSemaphorePermit,
}

impl DebugSession {
    /// Return the probe-rs `Session` for probe-rs-only operations, or a clear
    /// error when the active session uses the OpenOCD backend.
    pub(super) fn probe_session(&self) -> Result<Arc<tokio::sync::Mutex<Session>>, McpError> {
        self.probe_rs_session.clone().ok_or_else(|| {
            McpError::internal_error(
                "This operation requires the probe-rs backend; the active session uses OpenOCD. \
                 Reconnect with backend=\"probe-rs\" for flash/RTT operations."
                    .to_string(),
                None,
            )
        })
    }
}

/// Embedded debugger tool handler with debug, RTT, and flash tools.
#[derive(Clone)]
pub struct EmbeddedDebuggerToolHandler {
    #[allow(dead_code)]
    pub(crate) tool_router: ToolRouter<EmbeddedDebuggerToolHandler>,
    pub(crate) sessions: Arc<RwLock<HashMap<String, Arc<DebugSession>>>>,
    pub(crate) config: Arc<Config>,
    pub(crate) max_sessions: usize,
    pub(crate) session_slots: Arc<Semaphore>,
}

impl EmbeddedDebuggerToolHandler {
    pub fn new(config: impl Into<Config>) -> Self {
        let config = config.into();
        let max_sessions = config.server.max_sessions;
        Self {
            tool_router: Self::management_tool_router()
                + Self::target_control_tool_router()
                + Self::memory_tool_router()
                + Self::diagnostics_tool_router()
                + Self::rtt_tool_router()
                + Self::flash_tool_router()
                + Self::sram_loader_tool_router(),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            config: Arc::new(config),
            max_sessions,
            session_slots: Arc::new(Semaphore::new(max_sessions)),
        }
    }

    pub(super) async fn get_session(
        &self,
        session_id: &str,
    ) -> Result<Arc<DebugSession>, McpError> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).cloned().ok_or_else(|| {
            McpError::internal_error(
                format!(
                    "Session '{}' not found. Use 'connect' to establish a debug session first.",
                    session_id
                ),
                None,
            )
        })
    }
}

impl Default for EmbeddedDebuggerToolHandler {
    fn default() -> Self {
        Self::new(5)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combined_router_registers_all_tools() {
        let handler = EmbeddedDebuggerToolHandler::default();
        let tools = handler.tool_router.list_all();
        let names = tools
            .iter()
            .map(|tool| tool.name.as_ref())
            .collect::<std::collections::HashSet<_>>();

        assert_eq!(tools.len(), 26);
        for expected in [
            "list_probes",
            "connect",
            "disconnect",
            "probe_info",
            "halt",
            "run",
            "reset",
            "step",
            "get_status",
            "read_memory",
            "write_memory",
            "set_breakpoint",
            "clear_breakpoint",
            "load_elf_to_sram",
            "read_special_registers",
            "diagnose_fault",
            "unwind_exception",
            "rtt_attach",
            "rtt_detach",
            "rtt_read",
            "rtt_write",
            "rtt_channels",
            "flash_erase",
            "flash_program",
            "flash_verify",
            "run_firmware",
        ] {
            assert!(names.contains(expected), "missing tool: {expected}");
        }
    }
}
