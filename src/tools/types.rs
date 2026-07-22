//! Type definitions for embedded debugger MCP tools

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// =============================================================================
// Debugger Management Types
// =============================================================================

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListProbesArgs {
    // No parameters needed
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ConnectArgs {
    /// Probe selector (serial number, identifier, or "auto" for first available)
    pub probe_selector: String,
    /// Target chip name (e.g., "STM32F407VGTx", "nRF52840_xxAA")
    pub target_chip: String,
    /// Connection speed in kHz (default: 4000)
    #[serde(default = "default_speed_khz")]
    pub speed_khz: u32,
    /// Whether to connect under reset
    #[serde(default)]
    pub connect_under_reset: bool,
    /// Whether to halt after connecting.
    ///
    /// When omitted, the debugger configuration default is used.
    #[serde(default)]
    pub halt_after_connect: Option<bool>,
    /// Debug engine: "probe-rs" (default, native) or "openocd" (GDB RSP).
    #[serde(default = "default_backend")]
    pub backend: String,
    /// OpenOCD GDB remote address when backend="openocd" (default "127.0.0.1:3333").
    /// Requires a running `openocd` exposing its GDB port.
    #[serde(default = "default_openocd_address")]
    pub openocd_address: String,
}

impl ConnectArgs {
    pub(crate) fn resolved_halt_after_connect(&self, config_default: bool) -> bool {
        self.halt_after_connect.unwrap_or(config_default)
    }
}

fn default_speed_khz() -> u32 {
    4000
}
fn default_backend() -> String {
    "probe-rs".to_string()
}
fn default_openocd_address() -> String {
    "127.0.0.1:3333".to_string()
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DisconnectArgs {
    /// Session ID to disconnect
    pub session_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ProbeInfoArgs {
    /// Session ID to get info for
    pub session_id: String,
}

// =============================================================================
// Target Control Types
// =============================================================================

#[derive(Debug, Deserialize, JsonSchema)]
pub struct HaltArgs {
    /// Session ID
    pub session_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RunArgs {
    /// Session ID
    pub session_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ResetArgs {
    /// Session ID
    pub session_id: String,
    /// Reset type: "hardware" or "software"
    #[serde(default = "default_reset_type")]
    pub reset_type: String,
    /// Whether to halt after reset
    #[serde(default = "default_true")]
    pub halt_after_reset: bool,
}

fn default_reset_type() -> String {
    "hardware".to_string()
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StepArgs {
    /// Session ID
    pub session_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetStatusArgs {
    /// Session ID
    pub session_id: String,
}

// =============================================================================
// Diagnostics Types
// =============================================================================

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DiagnoseFaultArgs {
    /// Session ID
    pub session_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadSpecialRegistersArgs {
    /// Session ID
    pub session_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UnwindExceptionArgs {
    /// Session ID
    pub session_id: String,
    /// Path to the firmware ELF built with debug info (.debug_line), used to
    /// map addresses to source file:line.
    pub elf_path: String,
}

// =============================================================================
// Memory Operation Types
// =============================================================================

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadMemoryArgs {
    /// Session ID
    pub session_id: String,
    /// Memory address (hex string like "0x8000000" or decimal)
    pub address: String,
    /// Number of bytes to read
    pub size: usize,
    /// Output format: "hex", "binary", "ascii", "words32", "words16"
    #[serde(default = "default_format")]
    pub format: String,
}

fn default_format() -> String {
    "hex".to_string()
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WriteMemoryArgs {
    /// Session ID
    pub session_id: String,
    /// Memory address (hex string like "0x8000000" or decimal)
    pub address: String,
    /// Data to write
    pub data: String,
    /// Input format: "hex", "binary", "ascii", "words32", "words16"
    #[serde(default = "default_format")]
    pub format: String,
}

// =============================================================================
// Breakpoint Management Types
// =============================================================================

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetBreakpointArgs {
    /// Session ID
    pub session_id: String,
    /// Breakpoint address (hex string like "0x8000000" or decimal)
    pub address: String,
    /// Breakpoint type: "hardware" or "software"
    #[serde(default = "default_breakpoint_type")]
    pub breakpoint_type: String,
}

fn default_breakpoint_type() -> String {
    "hardware".to_string()
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ClearBreakpointArgs {
    /// Session ID
    pub session_id: String,
    /// Breakpoint address (hex string like "0x8000000" or decimal)
    pub address: String,
}

// =============================================================================
// Flash Programming Types
// =============================================================================

// =============================================================================
// New Flash Programming Types
// =============================================================================

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FlashEraseArgs {
    /// Session ID
    pub session_id: String,
    /// Erase type: "all" for full chip, "sectors" for specific sectors
    #[serde(default = "default_erase_all")]
    pub erase_type: String,
    /// Start address for sector erase (hex string like "0x8000000" or decimal)
    pub address: Option<String>,
    /// Size in bytes for sector erase
    pub size: Option<u32>,
}

fn default_erase_all() -> String {
    "all".to_string()
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FlashProgramArgs {
    /// Session ID
    pub session_id: String,
    /// Path to file to program (ELF, HEX, BIN)
    pub file_path: String,
    /// File format: "auto", "elf", "hex", "bin"
    #[serde(default = "default_auto_format")]
    pub format: String,
    /// Base address for BIN files (hex string or decimal)
    pub base_address: Option<String>,
    /// Whether to verify after programming
    #[serde(default = "default_true")]
    pub verify: bool,
}

fn default_auto_format() -> String {
    "auto".to_string()
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FlashVerifyArgs {
    /// Session ID
    pub session_id: String,
    /// File path to verify against (optional)
    pub file_path: Option<String>,
    /// Hex data to verify against (alternative to file_path)
    pub data: Option<String>,
    /// Address to start verification (hex string or decimal)
    pub address: String,
    /// Number of bytes to verify
    pub size: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RunFirmwareArgs {
    /// Session ID
    pub session_id: String,
    /// Path to firmware file
    pub file_path: String,
    /// File format: "auto", "elf", "hex", "bin"
    #[serde(default = "default_auto_format")]
    pub format: String,
    /// Whether to reset after flashing
    #[serde(default = "default_true")]
    pub reset_after_flash: bool,
    /// Whether to attach RTT after reset
    #[serde(default = "default_true")]
    pub attach_rtt: bool,
    /// RTT attach timeout in milliseconds
    #[serde(default = "default_rtt_timeout")]
    pub rtt_timeout_ms: u32,
}

fn default_rtt_timeout() -> u32 {
    3000
}

// =============================================================================
// RTT Communication Types
// =============================================================================

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RttAttachArgs {
    /// Session ID
    pub session_id: String,
    /// RTT control block address (optional, auto-detected if not provided)
    pub control_block_address: Option<String>,
    /// Memory ranges to search for RTT control block
    /// Each range is a tuple of (start_address, end_address)
    pub memory_ranges: Option<Vec<MemoryRange>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MemoryRange {
    pub start: String,
    pub end: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RttDetachArgs {
    /// Session ID
    pub session_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RttReadArgs {
    /// Session ID
    pub session_id: String,
    /// RTT channel number (usually 0 for default output)
    #[serde(default)]
    pub channel: u32,
    /// Maximum bytes to read
    #[serde(default = "default_max_bytes")]
    pub max_bytes: usize,
    /// Timeout in milliseconds
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_max_bytes() -> usize {
    1024
}
fn default_timeout_ms() -> u64 {
    1000
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RttWriteArgs {
    /// Session ID
    pub session_id: String,
    /// RTT channel number (usually 0 for default input)
    #[serde(default)]
    pub channel: u32,
    /// Data to write
    pub data: String,
    /// Data encoding: "utf8", "hex", "binary"
    #[serde(default = "default_encoding")]
    pub encoding: String,
}

fn default_encoding() -> String {
    "utf8".to_string()
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RttChannelsArgs {
    /// Session ID
    pub session_id: String,
}

// =============================================================================
// Response Types (for internal use)
// =============================================================================

#[derive(Debug, Serialize)]
pub struct ProbeInfo {
    pub identifier: String,
    pub vendor_id: u16,
    pub product_id: u16,
    pub serial_number: Option<String>,
    pub probe_type: String,
    pub speed_khz: u32,
    pub version: String,
}

#[derive(Debug, Serialize)]
pub struct TargetInfo {
    pub chip_name: String,
    pub architecture: String,
    pub core_type: String,
    pub memory_map: Vec<MemoryRegion>,
}

#[derive(Debug, Serialize)]
pub struct MemoryRegion {
    pub name: String,
    pub start: u64,
    pub size: u64,
    pub access: String,
}

#[derive(Debug, Serialize)]
pub struct CoreInfo {
    pub pc: u64,
    pub sp: u64,
    pub state: String,
    pub halt_reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SessionStatus {
    pub session_id: String,
    pub connected: bool,
    pub target_state: String,
    pub created_at: String,
    pub last_activity: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterValue {
    pub name: String,
    pub value: u64,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Breakpoint {
    pub id: u32,
    pub address: u64,
    pub breakpoint_type: String,
    pub enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct FlashResult {
    pub bytes_programmed: usize,
    pub programming_time_ms: u64,
    pub verification_result: bool,
}

#[derive(Debug, Serialize)]
pub struct RttChannelInfo {
    pub channel: u32,
    pub name: String,
    pub direction: String, // "up", "down"
    pub buffer_size: usize,
    pub flags: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LoadElfToSramArgs {
    /// Session ID
    pub session_id: String,
    /// Absolute path to the ELF file to load
    pub elf_path: String,
    /// Start of the allowed SRAM range (hex string like "0x34000000" or decimal), inclusive
    pub sram_start: String,
    /// End of the allowed SRAM range (hex string like "0x34200000" or decimal), exclusive
    pub sram_end: String,
    /// Explicit vector table address (hex or decimal). Required only when the ELF has neither a 'g_pfnVectors' symbol nor an '.isr_vector' section
    #[serde(default)]
    pub vector_table_address: Option<String>,
    /// Start execution after loading: program VTOR/MSP/xPSR/PC from the vector table and run. Default false (load only)
    #[serde(default)]
    pub start: Option<bool>,
    /// Launch mode: "deterministic_reset" (default) or "preserve_state". start=true requires deterministic_reset (preserve_state+start=true is rejected). start=false with deterministic_reset performs a system reset-and-halt before writing; use preserve_state to load without reset
    #[serde(default)]
    pub launch_mode: Option<String>,
    /// Write/verify chunk size in bytes. Default 2048; clamped to the configured memory.max_write_size
    #[serde(default)]
    pub chunk_size: Option<usize>,
}

#[cfg(test)]
mod connect_args_tests {
    use super::ConnectArgs;

    #[test]
    fn explicit_false_overrides_true_config_default() {
        let args: ConnectArgs = serde_json::from_str(
            r#"{
                "probe_selector": "auto",
                "target_chip": "STM32N647",
                "halt_after_connect": false
            }"#,
        )
        .expect("ConnectArgs should deserialize");

        assert_eq!(args.halt_after_connect, Some(false));
        assert!(!args.resolved_halt_after_connect(true));
    }

    #[test]
    fn explicit_true_overrides_false_config_default() {
        let args: ConnectArgs = serde_json::from_str(
            r#"{
                "probe_selector": "auto",
                "target_chip": "STM32N647",
                "halt_after_connect": true
            }"#,
        )
        .expect("ConnectArgs should deserialize");

        assert_eq!(args.halt_after_connect, Some(true));
        assert!(args.resolved_halt_after_connect(false));
    }

    #[test]
    fn omitted_value_uses_config_default() {
        let args: ConnectArgs = serde_json::from_str(
            r#"{
                "probe_selector": "auto",
                "target_chip": "STM32N647"
            }"#,
        )
        .expect("ConnectArgs should deserialize");

        assert_eq!(args.halt_after_connect, None);
        assert!(args.resolved_halt_after_connect(true));
        assert!(!args.resolved_halt_after_connect(false));
    }
}
