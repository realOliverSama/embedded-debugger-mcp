//! Breakpoint address validation policy.
//!
//! Validation runs in the tool layer BEFORE `set_hw_breakpoint` touches any
//! hardware breakpoint slot, so a rejected address never changes core state,
//! never consumes a comparator, and never leaks session resources.
//!
//! Layered verdicts, in order:
//! 1. Thumb halfword alignment (odd addresses are rejected with guidance about
//!    the Thumb state bit);
//! 2. Target memory map from the backend (probe-rs target description): an
//!    address inside an executable region is accepted; an address covered only
//!    by non-executable regions is rejected;
//! 3. Addresses the target map does not describe (target maps can be
//!    incomplete — e.g. the probe-rs 0.30 STM32N647 map omits the executable
//!    SRAM alias at 0x3400_0000) fall back to the ARM Cortex-M fixed memory
//!    map, which architecturally marks Peripheral / External Device / PPB /
//!    Vendor_SYS ranges execute-never;
//! 4. When neither a memory map nor a known fixed-map architecture is
//!    available, the address is rejected with an explicit, safe error.

use std::ops::Range;

use crate::backend::BreakpointAddressContext;

/// ARM Cortex-M (ARMv6-M / ARMv7-M / ARMv8-M) fixed memory map ranges that are
/// architecturally execute-never (XN):
/// - 0x4000_0000..0x6000_0000: Peripheral
/// - 0xA000_0000..0xE000_0000: External Device
/// - 0xE000_0000..end: Private Peripheral Bus + Vendor_SYS
const CORTEX_M_XN_RANGES: &[Range<u64>] = &[
    0x4000_0000..0x6000_0000,
    0xA000_0000..0xE000_0000,
    0xE000_0000..0x1_0000_0000,
];

/// Validate `address` as a hardware breakpoint target for the given backend
/// context. Returns `Err` with a human-readable reason when the address must
/// not be programmed into a comparator.
pub(super) fn ensure_breakpoint_address_valid(
    address: u64,
    context: &BreakpointAddressContext,
) -> Result<(), String> {
    // 1. Thumb halfword alignment.
    if !address.is_multiple_of(2) {
        return Err(format!(
            "Breakpoint address 0x{address:08X} is not 2-byte aligned. Thumb code is halfword-aligned; an odd address usually means the Thumb state bit (bit 0) was included — pass the execution address with bit 0 cleared (0x{:08X}).",
            address & !1
        ));
    }

    let regions = match &context.regions {
        Some(regions) => regions,
        None => {
            return Err(
                "Cannot verify breakpoint address: the active backend does not expose the target memory map, so executability cannot be determined. Refusing to set the breakpoint (safe rejection policy)."
                    .to_string(),
            );
        }
    };

    // 2. Target memory map verdicts. An address covered by several overlapping
    //    regions (aliases) is accepted when ANY of them is executable, and
    //    rejected only when ALL containing regions are non-executable.
    let mut contained_by_non_executable = Vec::new();
    for region in regions {
        if region.range.contains(&address) {
            if region.executable {
                return Ok(());
            }
            contained_by_non_executable.push(format!(
                "'{}' (0x{:08X}..0x{:08X}, execute=false)",
                region.name.as_deref().unwrap_or("unnamed"),
                region.range.start,
                region.range.end
            ));
        }
    }
    if !contained_by_non_executable.is_empty() {
        return Err(format!(
            "Breakpoint address 0x{address:08X} lies in non-executable target memory: {}.",
            contained_by_non_executable.join(", ")
        ));
    }

    // 3. Unmapped address: fall back to the architectural memory map when the
    //    core has one. Cortex-M XN ranges are fixed by the ARM architecture,
    //    so this is a reliable executability judgement even where the target
    //    description is incomplete.
    if context.is_cortex_m {
        if let Some(xn) = CORTEX_M_XN_RANGES.iter().find(|r| r.contains(&address)) {
            return Err(format!(
                "Breakpoint address 0x{address:08X} is outside every region of the target memory map and falls inside the architecturally execute-never range 0x{:08X}..0x{:08X} of the ARM Cortex-M fixed memory map.",
                xn.start, xn.end
            ));
        }
        return Ok(());
    }

    // 4. Nothing reliable to validate against: reject explicitly and safely.
    Err(format!(
        "Breakpoint address 0x{address:08X} is outside every region of the target memory map and the core architecture provides no fixed memory map to validate against. Refusing to set the breakpoint (safe rejection policy)."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::ExecutableRegion;

    fn region(name: &str, start: u64, end: u64, executable: bool) -> ExecutableRegion {
        ExecutableRegion {
            name: Some(name.to_string()),
            range: start..end,
            executable,
        }
    }

    /// Mirrors the probe-rs 0.30 built-in STM32N647 target description.
    /// Note: the executable AXISRAM alias at 0x3400_0000 (where SRAM firmware
    /// actually runs on this chip) is deliberately absent, exactly as in the
    /// real target map.
    fn stm32n647_context() -> BreakpointAddressContext {
        BreakpointAddressContext {
            is_cortex_m: true,
            regions: Some(vec![
                region("ITCMRAM", 0x0000_0000, 0x0004_0000, true),
                region("DTCMRAM", 0x2000_0000, 0x2004_0000, true),
                region("AXISRAM1234", 0x2400_0000, 0x243E_0000, true),
                region("SRAM_GFXMM", 0x2500_0000, 0x2600_0000, true),
                region("SRAMAHB12", 0x2800_0000, 0x2800_8000, true),
                region("Flash", 0x3418_0400, 0x341C_0000, true),
            ]),
        }
    }

    #[test]
    fn valid_sram_code_address_is_accepted() {
        // The real T-11/T-13 address: valid code in the N647 SRAM alias that
        // the probe-rs target map does not list.
        assert!(ensure_breakpoint_address_valid(0x3400_6340, &stm32n647_context()).is_ok());
    }

    #[test]
    fn address_inside_executable_map_region_is_accepted() {
        let context = BreakpointAddressContext {
            is_cortex_m: true,
            regions: Some(vec![region("Flash", 0x0800_0000, 0x0810_0000, true)]),
        };
        assert!(ensure_breakpoint_address_valid(0x0800_0100, &context).is_ok());
    }

    #[test]
    fn out_of_map_top_address_is_rejected() {
        // Regression for T-13: 0xFFFFFFFE is 2-byte aligned but lives in the
        // Cortex-M Vendor_SYS XN range and must be rejected.
        let err = ensure_breakpoint_address_valid(0xFFFF_FFFE, &stm32n647_context())
            .expect_err("0xFFFFFFFE must be rejected");
        assert!(err.contains("execute-never"), "unexpected reason: {err}");
    }

    #[test]
    fn odd_address_is_rejected_with_thumb_bit_guidance() {
        let err = ensure_breakpoint_address_valid(0x3400_6341, &stm32n647_context())
            .expect_err("odd address must be rejected");
        assert!(err.contains("Thumb"), "unexpected reason: {err}");
    }

    #[test]
    fn peripheral_address_is_rejected() {
        // 0x4000_0000 is the Cortex-M Peripheral XN range and is not in the
        // N647 target map either.
        assert!(ensure_breakpoint_address_valid(0x4000_0000, &stm32n647_context()).is_err());
    }

    #[test]
    fn private_peripheral_bus_address_is_rejected() {
        assert!(ensure_breakpoint_address_valid(0xE000_ED00, &stm32n647_context()).is_err());
    }

    #[test]
    fn external_device_address_is_rejected() {
        assert!(ensure_breakpoint_address_valid(0xA000_0000, &stm32n647_context()).is_err());
    }

    #[test]
    fn explicitly_non_executable_region_is_rejected() {
        let context = BreakpointAddressContext {
            is_cortex_m: true,
            regions: Some(vec![region("SRAM_NOEXEC", 0x2000_0000, 0x2004_0000, false)]),
        };
        let err = ensure_breakpoint_address_valid(0x2000_0100, &context)
            .expect_err("execute=false region must be rejected");
        assert!(err.contains("non-executable"), "unexpected reason: {err}");
    }

    #[test]
    fn overlapping_alias_with_one_executable_region_is_accepted() {
        let context = BreakpointAddressContext {
            is_cortex_m: true,
            regions: Some(vec![
                region("SRAM_ALIAS_NOEXEC", 0x2000_0000, 0x2004_0000, false),
                region("SRAM_EXEC", 0x2000_0000, 0x2004_0000, true),
            ]),
        };
        assert!(ensure_breakpoint_address_valid(0x2000_0100, &context).is_ok());
    }

    #[test]
    fn unknown_memory_map_is_rejected_safely() {
        let context = BreakpointAddressContext {
            is_cortex_m: false,
            regions: None,
        };
        let err = ensure_breakpoint_address_valid(0x0800_0000, &context)
            .expect_err("unverifiable backend must reject");
        assert!(err.contains("safe rejection"), "unexpected reason: {err}");
    }

    #[test]
    fn unmapped_address_on_non_cortex_m_is_rejected() {
        let context = BreakpointAddressContext {
            is_cortex_m: false,
            regions: Some(vec![region("RAM", 0x2000_0000, 0x2004_0000, true)]),
        };
        assert!(ensure_breakpoint_address_valid(0x4000_0000, &context).is_err());
    }

    #[test]
    fn parse_address_rejects_garbage_and_overflow() {
        use super::super::formatting::parse_address;

        assert!(parse_address("0xZZZZ").is_err());
        assert!(parse_address("not-an-address").is_err());
        // 2^64 overflows u64 and must fail parsing, not wrap.
        assert!(parse_address("0x10000000000000000").is_err());
        assert!(parse_address("18446744073709551616").is_err());
        // Sanity: the boundary itself still parses.
        assert_eq!(parse_address("0xFFFFFFFFFFFFFFFF").unwrap(), u64::MAX);
    }
}
