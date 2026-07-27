//! Build script: keep pi's MCP metadata cache in sync with this binary.
//!
//! pi-mcp-adapter caches this server's tool list and input schemas in
//! `~/.pi/agent/mcp-cache.json`, keyed only by the server *config* hash
//! (command/args/env/cwd) with a 7-day TTL — it cannot notice that the
//! binary was rebuilt. A stale cache made pi keep serving outdated tool
//! schemas to the model provider (this once caused Moonshot to reject every
//! request with "references must start with #/$defs/").
//!
//! Wiping the cache on every build forces pi to re-fetch fresh tool metadata
//! from the newly built binary on its next start. The cache regenerates
//! automatically, so deleting it is always safe and cheap.
//!
//! With no `cargo:rerun-if-*` directives emitted, Cargo re-runs this script
//! whenever any package source changes, which is exactly what we want.

fn main() {
    if let Some(home) = std::env::var_os("HOME") {
        let cache = std::path::Path::new(&home).join(".pi/agent/mcp-cache.json");
        match std::fs::remove_file(&cache) {
            Ok(()) => println!(
                "cargo:warning=removed stale pi MCP metadata cache ({})",
                cache.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => println!(
                "cargo:warning=could not remove pi MCP metadata cache ({}): {e}",
                cache.display()
            ),
        }
    }
}
