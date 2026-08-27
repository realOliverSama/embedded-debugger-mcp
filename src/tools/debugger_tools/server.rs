use rmcp::{
    handler::server::tool::ToolCallContext, model::*, service::RequestContext,
    ErrorData as McpError, RoleServer, ServerHandler,
};
use tracing::info;

use super::session::EmbeddedDebuggerToolHandler;

/// rmcp 0.3.2 generates tool input schemas with JSON Schema draft-07 settings,
/// placing nested subschemas under `definitions` and referencing them as
/// `#/definitions/Name`. Strict model providers (e.g. Moonshot/Kimi) only
/// accept the 2019-09+ spelling `$defs` / `#/$defs/Name` and reject the entire
/// request when a tool schema uses the draft-07 form. This rewrites the schema
/// on the wire; the two forms are semantically identical (a pure rename), and
/// server-side argument parsing deserializes the raw arguments with serde and
/// never consults the schema, so tool behavior is unaffected.
fn rewrite_defs_keyword(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(defs) = map.remove("definitions") {
                map.insert("$defs".to_string(), defs);
            }
            for v in map.values_mut() {
                rewrite_defs_keyword(v);
            }
        }
        serde_json::Value::Array(items) => {
            for v in items {
                rewrite_defs_keyword(v);
            }
        }
        serde_json::Value::String(s) => {
            if let Some(rest) = s.strip_prefix("#/definitions/") {
                *s = format!("#/$defs/{rest}");
            }
        }
        _ => {}
    }
}

// NOTE: implemented manually instead of via `#[tool_handler]` so that
// `list_tools` can rewrite `definitions` -> `$defs` (see above). `call_tool`
// below is exactly what the macro would generate.
impl ServerHandler for EmbeddedDebuggerToolHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation::from_build_env(),
            instructions: Some("Embedded debugging and flash programming MCP server for ARM Cortex-M, RISC-V, and other targets. A single tool set runs over two interchangeable backends chosen at connect: probe-rs (default, native, RTT/flash) or OpenOCD (backend=\"openocd\", via GDB RSP, for chips probe-rs does not cover). Exposes 24 tools: list_probes, connect, disconnect, probe_info, halt, run, reset, step, get_status, read_memory, write_memory, set_breakpoint, clear_breakpoint, diagnose_fault, unwind_exception, rtt_attach, rtt_detach, rtt_read, rtt_write, rtt_channels, flash_erase, flash_program, flash_verify, run_firmware.".to_string()),
        }
    }

    async fn initialize(
        &self,
        _request: InitializeRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        info!("Embedded Debugger MCP server initialized with 24 tools (dual backend: probe-rs + OpenOCD)");
        Ok(self.get_info())
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParam,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let tcc = ToolCallContext::new(self, request, context);
        self.tool_router.call(tcc).await
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let mut result = ListToolsResult::with_all_items(self.tool_router.list_all());
        for tool in &mut result.tools {
            let mut schema = serde_json::Value::Object(tool.input_schema.as_ref().clone());
            rewrite_defs_keyword(&mut schema);
            if let serde_json::Value::Object(map) = schema {
                tool.input_schema = std::sync::Arc::new(map);
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::rewrite_defs_keyword;

    #[test]
    fn rewrites_definitions_key_and_refs_recursively() {
        let mut schema = serde_json::json!({
            "type": "object",
            "properties": {
                "memory_ranges": {
                    "type": "array",
                    "items": { "$ref": "#/definitions/MemoryRange" }
                }
            },
            "definitions": {
                "MemoryRange": {
                    "type": "object",
                    "properties": {
                        "start": { "type": "string" },
                        "nested": { "$ref": "#/definitions/Inner" }
                    }
                },
                "Inner": { "type": "string" }
            }
        });
        rewrite_defs_keyword(&mut schema);
        assert_eq!(
            schema["properties"]["memory_ranges"]["items"]["$ref"],
            "#/$defs/MemoryRange"
        );
        assert!(schema.get("definitions").is_none());
        assert_eq!(
            schema["$defs"]["MemoryRange"]["properties"]["nested"]["$ref"],
            "#/$defs/Inner"
        );
    }

    #[test]
    fn leaves_other_values_untouched() {
        let mut schema = serde_json::json!({
            "type": "object",
            "properties": { "session_id": { "type": "string", "description": "Session ID" } },
            "required": ["session_id"]
        });
        let original = schema.clone();
        rewrite_defs_keyword(&mut schema);
        assert_eq!(schema, original);
    }

    #[test]
    fn all_registered_tool_schemas_use_defs_form() {
        let handler = super::EmbeddedDebuggerToolHandler::new(crate::config::Config::default());
        for tool in handler.tool_router.list_all() {
            let mut schema = serde_json::Value::Object(tool.input_schema.as_ref().clone());
            rewrite_defs_keyword(&mut schema);
            let text = schema.to_string();
            assert!(
                !text.contains("#/definitions/") && !text.contains("\"definitions\""),
                "tool {} still contains draft-07 definitions after rewrite",
                tool.name
            );
        }
    }
}
