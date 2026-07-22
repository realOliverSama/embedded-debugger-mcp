//! Flash programming manager - Real probe-rs integration

use crate::error::{DebugError, Result};
use std::path::Path;
use std::time::Instant;
use tracing::{debug, info, warn};

// Probe-rs imports
use probe_rs::{
    flashing::{self, FlashProgress},
    MemoryInterface, Session,
};

/// Erase operation types
#[derive(Debug, Clone)]
pub enum EraseType {
    /// Erase entire flash
    All,
    /// Erase specific sectors
    Sectors { address: u64, size: usize },
}

/// File format types
#[derive(Debug, Clone)]
pub enum FileFormat {
    Auto,
    Elf,
    Hex,
    Bin,
}

/// Erase operation result
#[derive(Debug)]
pub struct EraseResult {
    pub erase_time_ms: u64,
    pub sectors_erased: Option<usize>,
}

/// Programming operation result
#[derive(Debug)]
pub struct ProgramResult {
    pub bytes_programmed: usize,
    pub programming_time_ms: u64,
    pub verification_result: Option<bool>,
}

/// Verification result
#[derive(Debug)]
pub struct VerifyResult {
    pub success: bool,
    pub bytes_verified: usize,
    pub mismatches: Vec<VerifyMismatch>,
}

/// Verification mismatch
#[derive(Debug)]
pub struct VerifyMismatch {
    pub address: u64,
    pub expected: u8,
    pub actual: u8,
}

/// Flash manager for programming operations
pub struct FlashManager;

impl FlashManager {
    /// Create a new flash manager
    pub fn new() -> Self {
        Self
    }

    /// Erase flash memory
    pub async fn erase_flash(session: &mut Session, erase_type: EraseType) -> Result<EraseResult> {
        let start_time = Instant::now();

        match erase_type {
            EraseType::All => {
                debug!("Starting full flash erase");
                let mut progress = FlashProgress::empty();
                flashing::erase_all(session, &mut progress).map_err(|e| {
                    DebugError::FlashOperationFailed(format!("Full erase failed: {}", e))
                })?;

                info!("Full flash erase completed");
                Ok(EraseResult {
                    erase_time_ms: start_time.elapsed().as_millis() as u64,
                    sectors_erased: None,
                })
            }
            EraseType::Sectors { address, size } => {
                Err(DebugError::FlashOperationFailed(format!(
                    "Sector erase by address is not implemented safely for probe-rs 0.25 (requested address 0x{address:08X}, size {size} bytes). Use erase_type='all' or add a target-specific sector-index mapping before enabling this operation."
                )))
            }
        }
    }

    /// Program file to flash
    pub async fn program_file(
        session: &mut Session,
        file_path: &Path,
        format: FileFormat,
        base_address: Option<u64>,
        verify: bool,
    ) -> Result<ProgramResult> {
        let start_time = Instant::now();

        // Check file existence
        if !file_path.exists() {
            return Err(DebugError::FlashOperationFailed(format!(
                "File not found: {}",
                file_path.display()
            )));
        }

        debug!("Programming file: {}", file_path.display());

        // Determine format
        let probe_format = match format {
            FileFormat::Auto => {
                // Auto-detect based on extension
                match file_path.extension().and_then(|s| s.to_str()) {
                    Some("elf") => flashing::Format::Elf(Default::default()),
                    Some("hex") => flashing::Format::Hex,
                    Some("bin") => flashing::Format::Bin(probe_rs::flashing::BinOptions {
                        base_address,
                        skip: 0,
                    }),
                    _ => {
                        return Err(DebugError::FlashOperationFailed(
                            "Cannot auto-detect file format".to_string(),
                        ))
                    }
                }
            }
            FileFormat::Elf => flashing::Format::Elf(Default::default()),
            FileFormat::Hex => flashing::Format::Hex,
            FileFormat::Bin => flashing::Format::Bin(probe_rs::flashing::BinOptions {
                base_address,
                skip: 0,
            }),
        };

        // Setup download options - use default and override what we need
        let mut options = flashing::DownloadOptions::default();
        options.verify = verify;

        // Set base address for BIN files - this might need to be handled differently
        if matches!(probe_format, flashing::Format::Bin(_)) {
            if let Some(addr) = base_address {
                // Note: probe-rs API may need different approach for base address
                warn!("Base address specification for BIN files: 0x{:08X} - may require different API usage", addr);
            }
        }

        // Execute programming
        flashing::download_file_with_options(session, file_path, probe_format, options)
            .map_err(|e| DebugError::FlashOperationFailed(format!("Programming failed: {}", e)))?;

        let elapsed = start_time.elapsed().as_millis() as u64;

        info!("File programming completed in {}ms", elapsed);

        // Since we can't get exact bytes from probe-rs API, estimate from file size
        let file_size = std::fs::metadata(file_path)
            .map(|m| m.len() as usize)
            .unwrap_or(0);

        Ok(ProgramResult {
            bytes_programmed: file_size,
            programming_time_ms: elapsed,
            verification_result: verify.then_some(true),
        })
    }

    /// Program binary data to flash
    pub async fn program_data(
        _session: &mut Session,
        data: &[u8],
        base_address: u64,
    ) -> Result<ProgramResult> {
        debug!(
            "Rejected direct flash data programming: {} bytes to address 0x{:08X}",
            data.len(),
            base_address
        );
        Err(DebugError::FlashOperationFailed(
            "Direct flash programming by memory write is disabled. Program ELF/HEX/BIN files through probe-rs flash algorithms instead."
                .to_string(),
        ))
    }

    /// Verify flash contents
    pub async fn verify_flash(
        session: &mut Session,
        expected_data: &[u8],
        address: u64,
    ) -> Result<VerifyResult> {
        debug!(
            "Verifying {} bytes at address 0x{:08X}",
            expected_data.len(),
            address
        );

        let mut core = session
            .core(0)
            .map_err(|e| DebugError::FlashOperationFailed(format!("Failed to get core: {}", e)))?;

        // Read actual data from flash
        let mut actual_data = vec![0u8; expected_data.len()];
        core.read(address, &mut actual_data).map_err(|e| {
            DebugError::FlashOperationFailed(format!("Failed to read flash: {}", e))
        })?;

        // Compare data and find mismatches
        let mut mismatches = Vec::new();
        for (i, (expected, actual)) in expected_data.iter().zip(actual_data.iter()).enumerate() {
            if expected != actual {
                mismatches.push(VerifyMismatch {
                    address: address + i as u64,
                    expected: *expected,
                    actual: *actual,
                });
            }
        }

        let success = mismatches.is_empty();

        if success {
            info!(
                "Flash verification successful: {} bytes",
                expected_data.len()
            );
        } else {
            warn!("Flash verification failed: {} mismatches", mismatches.len());
        }

        Ok(VerifyResult {
            success,
            bytes_verified: expected_data.len(),
            mismatches,
        })
    }
}

impl Default for FlashManager {
    fn default() -> Self {
        Self::new()
    }
}
