//! Embedded Debugger MCP Server
//!
//! A Model Context Protocol server for embedded debugging using probe-rs.
//! Provides AI assistants with debugging and flash programming tools for
//! embedded systems including ARM Cortex-M, RISC-V, J-Link, DAPLink, ST-Link, and other debug probes.

pub mod backend;
pub mod config;
pub mod debugger;
pub mod error;
pub mod flash;
pub mod rtt;
pub mod sram;
pub mod tools;
pub mod utils;

pub use config::Config;
pub use error::{DebugError, Result};
pub use tools::EmbeddedDebuggerToolHandler;
