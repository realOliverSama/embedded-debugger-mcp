use rmcp::{handler::server::tool::Parameters, model::*, tool, tool_router, ErrorData as McpError};
use std::future::Future;
use tracing::{debug, error, info};

use super::formatting::{format_memory_data, parse_address, parse_data};
use super::session::EmbeddedDebuggerToolHandler;
use crate::tools::types::*;

#[tool_router(router = memory_tool_router, vis = "pub")]
impl EmbeddedDebuggerToolHandler {
    // =============================================================================
    // Memory Operation Tools (2 tools)
    // =============================================================================

    #[tool(description = "Read memory from the target")]
    async fn read_memory(
        &self,
        Parameters(args): Parameters<ReadMemoryArgs>,
    ) -> Result<CallToolResult, McpError> {
        debug!(
            "Reading memory for session: {} at address {}",
            args.session_id, args.address
        );

        let address = match parse_address(&args.address) {
            Ok(addr) => addr,
            Err(e) => {
                error!("Invalid address '{}': {}", args.address, e);
                return Err(McpError::internal_error(
                    format!("Invalid address '{}': {}", args.address, e),
                    None,
                ));
            }
        };

        let session_arc = self.get_session(&args.session_id).await?;
        self.ensure_memory_read_allowed(&session_arc, address, args.size)?;

        let data = {
            let mut backend = session_arc.backend.lock().await;
            backend.read_bytes(address, args.size).await.map_err(|e| {
                error!(
                    "Failed to read memory for session {}: {}",
                    args.session_id, e
                );
                McpError::internal_error(format!("Failed to read memory: {}", e), None)
            })?
        };

        let formatted_data = format_memory_data(&data, &args.format, address);
        let message = format!(
            "Memory read completed successfully.\n\n\
            Session ID: {}\n\
            Address: 0x{:08X}\n\
            Size: {} bytes\n\
            Format: {}\n\n\
            Data:\n{}",
            args.session_id, address, args.size, args.format, formatted_data
        );

        info!("Memory read completed for session: {}", args.session_id);
        Ok(CallToolResult::success(vec![Content::text(message)]))
    }

    #[tool(description = "Write memory to the target")]
    async fn write_memory(
        &self,
        Parameters(args): Parameters<WriteMemoryArgs>,
    ) -> Result<CallToolResult, McpError> {
        debug!(
            "Writing memory for session: {} at address {}",
            args.session_id, args.address
        );

        let address = match parse_address(&args.address) {
            Ok(addr) => addr,
            Err(e) => {
                error!("Invalid address '{}': {}", args.address, e);
                return Err(McpError::internal_error(
                    format!("Invalid address '{}': {}", args.address, e),
                    None,
                ));
            }
        };

        let data = match parse_data(&args.data, &args.format) {
            Ok(data) => data,
            Err(e) => {
                error!("Invalid data '{}': {}", args.data, e);
                return Err(McpError::internal_error(
                    format!("Invalid data '{}': {}", args.data, e),
                    None,
                ));
            }
        };

        let session_arc = self.get_session(&args.session_id).await?;
        self.ensure_memory_write_allowed(&session_arc, address, data.len())?;

        {
            let mut backend = session_arc.backend.lock().await;
            backend.write_bytes(address, &data).await.map_err(|e| {
                error!(
                    "Failed to write memory for session {}: {}",
                    args.session_id, e
                );
                McpError::internal_error(format!("Failed to write memory: {}", e), None)
            })?;
        }

        let message = format!(
            "Memory write completed successfully.\n\n\
            Session ID: {}\n\
            Address: 0x{:08X}\n\
            Data: {}\n\
            Format: {}\n\
            Bytes written: {}",
            args.session_id,
            address,
            args.data,
            args.format,
            data.len()
        );

        info!("Memory write completed for session: {}", args.session_id);
        Ok(CallToolResult::success(vec![Content::text(message)]))
    }

    // =============================================================================
    // Breakpoint Tools (2 tools)
    // =============================================================================

    #[tool(description = "Set a breakpoint at the specified address")]
    async fn set_breakpoint(
        &self,
        Parameters(args): Parameters<SetBreakpointArgs>,
    ) -> Result<CallToolResult, McpError> {
        debug!(
            "Setting breakpoint for session: {} at address {}",
            args.session_id, args.address
        );

        if args.breakpoint_type != "hardware" {
            return Err(McpError::internal_error(
                format!(
                    "Unsupported breakpoint_type '{}'. Only hardware breakpoints are implemented.",
                    args.breakpoint_type
                ),
                None,
            ));
        }

        let address = match parse_address(&args.address) {
            Ok(addr) => addr,
            Err(e) => {
                error!("Invalid address '{}': {}", args.address, e);
                return Err(McpError::internal_error(
                    format!("Invalid address '{}': {}", args.address, e),
                    None,
                ));
            }
        };

        let session_arc = self.get_session(&args.session_id).await?;

        {
            let mut backend = session_arc.backend.lock().await;

            // Validate BEFORE touching any hardware breakpoint slot: a rejected
            // address must not consume a comparator, change core state, or
            // leave session resources behind.
            let context = backend.breakpoint_address_context().await.map_err(|e| {
                error!(
                    "Failed to query breakpoint validation context for session {}: {}",
                    args.session_id, e
                );
                McpError::internal_error(
                    format!("Failed to validate breakpoint address: {}", e),
                    None,
                )
            })?;
            if let Err(reason) =
                super::breakpoint_policy::ensure_breakpoint_address_valid(address, &context)
            {
                error!(
                    "Rejected breakpoint for session {} at 0x{:08X}: {}",
                    args.session_id, address, reason
                );
                return Err(McpError::invalid_params(reason, None));
            }

            backend.set_hw_breakpoint(address).await.map_err(|e| {
                error!(
                    "Failed to set breakpoint for session {}: {}",
                    args.session_id, e
                );
                McpError::internal_error(format!("Failed to set breakpoint: {}", e), None)
            })?;
        }

        let message = format!(
            "Breakpoint set successfully.\n\n\
            Session ID: {}\n\
            Address: 0x{:08X}\n\
            Type: Hardware breakpoint\n\n\
            The target will halt when execution reaches this address.",
            args.session_id, address
        );

        info!(
            "Breakpoint set for session: {} at 0x{:08X}",
            args.session_id, address
        );
        Ok(CallToolResult::success(vec![Content::text(message)]))
    }

    #[tool(description = "Clear a breakpoint at the specified address")]
    async fn clear_breakpoint(
        &self,
        Parameters(args): Parameters<ClearBreakpointArgs>,
    ) -> Result<CallToolResult, McpError> {
        debug!(
            "Clearing breakpoint for session: {} at address {}",
            args.session_id, args.address
        );

        let address = match parse_address(&args.address) {
            Ok(addr) => addr,
            Err(e) => {
                error!("Invalid address '{}': {}", args.address, e);
                return Err(McpError::internal_error(
                    format!("Invalid address '{}': {}", args.address, e),
                    None,
                ));
            }
        };

        let session_arc = self.get_session(&args.session_id).await?;

        {
            let mut backend = session_arc.backend.lock().await;
            backend.clear_hw_breakpoint(address).await.map_err(|e| {
                error!(
                    "Failed to clear breakpoint for session {}: {}",
                    args.session_id, e
                );
                McpError::internal_error(format!("Failed to clear breakpoint: {}", e), None)
            })?;
        }

        let message = format!(
            "Breakpoint cleared successfully.\n\n\
            Session ID: {}\n\
            Address: 0x{:08X}\n\n\
            The breakpoint has been removed.",
            args.session_id, address
        );

        info!(
            "Breakpoint cleared for session: {} at 0x{:08X}",
            args.session_id, address
        );
        Ok(CallToolResult::success(vec![Content::text(message)]))
    }
}
