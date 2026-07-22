//! RMCP tool handler implementation for embedded debugging.
//!
//! The tool router is split by domain while keeping one exported handler type for RMCP.

mod breakpoint_policy;
mod diagnostics;
mod flash;
mod formatting;
mod guards;
mod management;
mod memory;
mod rtt;
mod server;
mod session;
mod sram_loader;
mod target_control;

pub use session::{DebugSession, EmbeddedDebuggerToolHandler};
