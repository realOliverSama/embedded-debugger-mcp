//! Pure ELF load planning for the dedicated SRAM loader.
//!
//! This module never touches hardware. It parses an ELF32 image and produces
//! a validated `SramLoadPlan` describing exactly which bytes must go where,
//! how the image must be verified, and the Cortex-M launch state derived from
//! the vector table. All safety checks run here, before any target write:
//!
//! - ELF class/machine sanity (ELF32, little-endian, EM_ARM);
//! - every PT_LOAD: `p_filesz <= p_memsz`, overflow-free address math,
//!   file-bounds checks, whole segment inside the caller-supplied SRAM
//!   whitelist (and outside architecturally dangerous ranges);
//! - vector table discovery (symbol `g_pfnVectors`, else section
//!   `.isr_vector`, else an explicit override; ambiguity/absence is an
//!   error, never a guess);
//! - vector table sanity: initial MSP aligned and in RAM, reset vector with
//!   the Thumb bit set and pointing inside a loaded executable segment;
//! - ELF entry consistency with the loaded executable image;
//! - SHA-256 over the exact laid-out image (file bytes + zero fill).

use std::ops::Range;

use object::elf::{PF_X, PT_LOAD};
use object::read::elf::{ElfFile, FileHeader, ProgramHeader};
use object::read::{Object, ObjectSection, ObjectSymbol};
use object::Endianness;
use sha2::{Digest, Sha256};

/// Format a SHA-256 digest as lowercase hex (sha2 0.11 output has no LowerHex).
fn hex_digest(digest: &[u8]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Name of the vector table symbol used by STM32 startup code.
pub const VECTOR_TABLE_SYMBOL: &str = "g_pfnVectors";
/// Name of the vector table section used by STM32 linker scripts.
pub const VECTOR_TABLE_SECTION: &str = ".isr_vector";

/// ARM Cortex-M address ranges that must never be written by the SRAM
/// loader, regardless of the caller-supplied whitelist:
/// Peripheral, External Device, PPB + Vendor_SYS.
const FORBIDDEN_WRITE_RANGES: &[Range<u64>] = &[
    0x4000_0000..0x6000_0000,
    0xA000_0000..0xE000_0000,
    0xE000_0000..0x1_0000_0000,
];

/// One validated PT_LOAD segment to load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SramLoadSegment {
    pub paddr: u64,
    pub file_offset: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub executable: bool,
}

impl SramLoadSegment {
    pub fn end(&self) -> u64 {
        // Invariant: checked during planning.
        self.paddr + self.memsz
    }
}

/// How the vector table address was determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VectorTableSource {
    Symbol,
    Section,
    ExplicitOverride,
}

/// A fully validated load + launch plan.
#[derive(Debug, Clone)]
pub struct SramLoadPlan {
    pub entry: u64,
    pub vector_table: u64,
    pub vector_table_source: VectorTableSource,
    pub initial_msp: u32,
    /// Reset vector as stored in the vector table (Thumb bit set).
    pub reset_handler: u32,
    pub segments: Vec<SramLoadSegment>,
    /// SHA-256 over the exact laid-out image: for each segment in address
    /// order, the 8-byte LE paddr followed by filesz file bytes and
    /// (memsz-filesz) zero bytes.
    pub image_sha256: String,
    /// Total bytes to be written (file bytes + zero fill).
    pub total_write_bytes: u64,
}

fn ranges_overlap(a: &Range<u64>, b: &Range<u64>) -> bool {
    a.start < b.end && b.start < a.end
}

/// Build a validated load plan for `elf_bytes` targeting `whitelist`
/// (half-open `[start, end)`). `vector_table_override` forces the vector
/// table address when the caller knows better than the ELF metadata.
pub fn plan_sram_load(
    elf_bytes: &[u8],
    whitelist: &Range<u64>,
    vector_table_override: Option<u64>,
) -> Result<SramLoadPlan, String> {
    if whitelist.start >= whitelist.end {
        return Err(format!(
            "Invalid SRAM whitelist 0x{:08X}..0x{:08X}: empty or reversed range.",
            whitelist.start, whitelist.end
        ));
    }
    for forbidden in FORBIDDEN_WRITE_RANGES {
        if ranges_overlap(whitelist, forbidden) {
            return Err(format!(
                "SRAM whitelist 0x{:08X}..0x{:08X} intersects the forbidden range 0x{:08X}..0x{:08X} (Peripheral/External Device/PPB/Vendor_SYS). Refusing.",
                whitelist.start, whitelist.end, forbidden.start, forbidden.end
            ));
        }
    }

    let elf: ElfFile<object::elf::FileHeader32<Endianness>, &[u8]> =
        ElfFile::parse(elf_bytes).map_err(|e| format!("Failed to parse ELF: {e}"))?;

    if elf.elf_header().e_machine(elf.endian()) != object::elf::EM_ARM {
        return Err(format!(
            "ELF machine {} is not EM_ARM ({}). Refusing to load an image for a different architecture.",
            elf.elf_header().e_machine(elf.endian()),
            object::elf::EM_ARM
        ));
    }

    // ---- collect and validate PT_LOAD segments ----
    let mut segments: Vec<SramLoadSegment> = Vec::new();
    for ph in elf
        .elf_header()
        .program_headers(elf.endian(), elf_bytes)
        .map_err(|e| format!("Failed to read program headers: {e}"))?
    {
        if ph.p_type(elf.endian()) != PT_LOAD {
            continue;
        }
        let paddr: u64 = ph.p_paddr(elf.endian()).into();
        let vaddr: u64 = ph.p_vaddr(elf.endian()).into();
        let executable = ph.p_flags(elf.endian()) & PF_X != 0;
        if paddr != vaddr && executable {
            // Execution contract: code must be written at the address it runs
            // from. A non-executable data segment with VMA != LMA is the LRUN
            // linker layout (.data LMA follows .text; CRT copies LMA -> VMA at
            // startup), matching GDB/STM32CubeIDE `load` which writes at LMA.
            return Err(format!(
                "Executable PT_LOAD has paddr 0x{paddr:08X} != vaddr 0x{vaddr:08X}; refusing to run code that was not loaded at its execution address."
            ));
        }
        let filesz: u64 = ph.p_filesz(elf.endian()).into();
        let memsz: u64 = ph.p_memsz(elf.endian()).into();
        let offset: u64 = ph.p_offset(elf.endian()).into();
        if filesz > memsz {
            return Err(format!(
                "PT_LOAD at 0x{paddr:08X} has p_filesz ({filesz}) > p_memsz ({memsz}). Refusing."
            ));
        }
        if memsz == 0 {
            continue; // nothing to load; harmless
        }
        if filesz == 0 {
            // Pure NOLOAD segment (no file bytes): e.g. an external-RAM .bss
            // (.EXTRAM at 0x90000000) placed by the linker script but never
            // written by a debugger. GDB/STM32CubeIDE skip such segments
            // entirely and the owning application initializes the memory
            // itself (in-SRAM .bss is zeroed by the startup code). Planning
            // a zero-fill — and whitelist-checking the address — would be
            // stricter than GDB semantics and could target an uninitialized
            // external device, so plan no writes for it.
            continue;
        }
        let seg_end = paddr
            .checked_add(memsz)
            .ok_or_else(|| format!("PT_LOAD at 0x{paddr:08X} size 0x{memsz:X} overflows u64."))?;
        let file_end = offset
            .checked_add(filesz)
            .ok_or_else(|| format!("PT_LOAD file range at offset 0x{offset:X} overflows u64."))?;
        if file_end > elf_bytes.len() as u64 {
            return Err(format!(
                "PT_LOAD at 0x{paddr:08X} references file bytes 0x{offset:X}..0x{file_end:X} beyond the file size 0x{:X}. Truncated or corrupt ELF?",
                elf_bytes.len()
            ));
        }
        let seg_range = paddr..seg_end;
        if !whitelist.contains(&paddr) || seg_end > whitelist.end {
            return Err(format!(
                "PT_LOAD 0x{paddr:08X}..0x{seg_end:08X} is not fully inside the SRAM whitelist 0x{:08X}..0x{:08X}. Refusing.",
                whitelist.start, whitelist.end
            ));
        }
        for forbidden in FORBIDDEN_WRITE_RANGES {
            if ranges_overlap(&seg_range, forbidden) {
                return Err(format!(
                    "PT_LOAD 0x{paddr:08X}..0x{seg_end:08X} intersects forbidden range 0x{:08X}..0x{:08X}. Refusing.",
                    forbidden.start, forbidden.end
                ));
            }
        }
        segments.push(SramLoadSegment {
            paddr,
            file_offset: offset,
            filesz,
            memsz,
            executable: ph.p_flags(elf.endian()) & PF_X != 0,
        });
    }
    if segments.is_empty() {
        return Err("ELF contains no loadable PT_LOAD segments.".to_string());
    }
    segments.sort_by_key(|s| s.paddr);

    // ---- vector table discovery ----
    let (vector_table, vector_table_source) = if let Some(vt) = vector_table_override {
        (vt, VectorTableSource::ExplicitOverride)
    } else {
        let mut symbol_hits: Vec<u64> = Vec::new();
        for sym in elf.symbols() {
            if sym
                .name()
                .map(|n| n == VECTOR_TABLE_SYMBOL)
                .unwrap_or(false)
            {
                symbol_hits.push(sym.address());
            }
        }
        if symbol_hits.len() == 1 {
            (symbol_hits[0], VectorTableSource::Symbol)
        } else if symbol_hits.len() > 1 {
            return Err(format!(
                "Symbol '{VECTOR_TABLE_SYMBOL}' is defined {} times; cannot uniquely determine the vector table. Pass vector_table_address explicitly.",
                symbol_hits.len()
            ));
        } else {
            let mut section_hits: Vec<u64> = Vec::new();
            for section in elf.sections() {
                if section
                    .name()
                    .map(|n| n == VECTOR_TABLE_SECTION)
                    .unwrap_or(false)
                {
                    section_hits.push(section.address());
                }
            }
            match section_hits.len() {
                1 => (section_hits[0], VectorTableSource::Section),
                0 => {
                    return Err(format!(
                        "Cannot determine the vector table address: no '{VECTOR_TABLE_SYMBOL}' symbol and no '{VECTOR_TABLE_SECTION}' section. Pass vector_table_address explicitly."
                    ))
                }
                n => {
                    return Err(format!(
                        "Section '{VECTOR_TABLE_SECTION}' appears {n} times; cannot uniquely determine the vector table. Pass vector_table_address explicitly."
                    ))
                }
            }
        }
    };

    // Vector table must lie inside a loaded segment.
    let vt_segment = segments
        .iter()
        .find(|s| vector_table >= s.paddr && vector_table + 8 <= s.end())
        .ok_or_else(|| {
            format!(
                "Vector table 0x{vector_table:08X} (plus 8 header bytes) is not inside any loaded PT_LOAD segment. Refusing."
            )
        })?;

    // ---- read vector entries from the FILE bytes ----
    let vt_file_off = vt_segment
        .file_offset
        .checked_add(vector_table - vt_segment.paddr)
        .ok_or_else(|| "Vector table file offset overflow.".to_string())?;
    let vt_end = vt_file_off
        .checked_add(8)
        .ok_or_else(|| "Vector table file range overflow.".to_string())?;
    if vt_end > elf_bytes.len() as u64 {
        return Err("Vector table bytes are outside the ELF file. Corrupt image.".to_string());
    }
    let initial_msp = u32::from_le_bytes(
        elf_bytes[vt_file_off as usize..vt_file_off as usize + 4]
            .try_into()
            .unwrap(),
    );
    let reset_handler = u32::from_le_bytes(
        elf_bytes[vt_file_off as usize + 4..vt_end as usize]
            .try_into()
            .unwrap(),
    );

    // ---- validate vectors ----
    if initial_msp % 4 != 0 {
        return Err(format!(
            "Initial MSP 0x{initial_msp:08X} is not 4-byte aligned. Corrupt vector table?"
        ));
    }
    // A full-descending stack starts one-past the end of RAM, so the initial
    // MSP may equal the (exclusive) whitelist end.
    if (initial_msp as u64) < whitelist.start || (initial_msp as u64) > whitelist.end {
        return Err(format!(
            "Initial MSP 0x{initial_msp:08X} is outside the SRAM whitelist 0x{:08X}..0x{:08X}. Refusing.",
            whitelist.start, whitelist.end
        ));
    }
    if reset_handler & 1 == 0 {
        return Err(format!(
            "Reset_Handler 0x{reset_handler:08X} does not have the Thumb bit (bit 0) set. Cortex-M cannot execute ARM state code. Refusing."
        ));
    }
    let reset_addr = (reset_handler & !1) as u64;
    let reset_in_executable = segments
        .iter()
        .any(|s| s.executable && reset_addr >= s.paddr && reset_addr < s.end());
    if !reset_in_executable {
        return Err(format!(
            "Reset_Handler 0x{reset_addr:08X} (Thumb bit cleared) is not inside any loaded executable PT_LOAD segment. Refusing."
        ));
    }

    // ---- entry consistency ----
    let entry: u64 = elf.elf_header().e_entry(elf.endian()).into();
    let entry_addr = entry & !1;
    let entry_in_executable = segments
        .iter()
        .any(|s| s.executable && entry_addr >= s.paddr && entry_addr < s.end());
    if !entry_in_executable {
        return Err(format!(
            "ELF entry 0x{entry_addr:08X} is not inside any loaded executable PT_LOAD segment; entry/vector/loaded-image mismatch. Refusing."
        ));
    }

    // ---- image digest ----
    let mut hasher = Sha256::new();
    let mut total_write_bytes: u64 = 0;
    for seg in &segments {
        hasher.update(seg.paddr.to_le_bytes());
        let start = seg.file_offset as usize;
        let end = start + seg.filesz as usize;
        hasher.update(&elf_bytes[start..end]);
        if seg.memsz > seg.filesz {
            let zeros = vec![0u8; (seg.memsz - seg.filesz) as usize];
            hasher.update(&zeros);
        }
        total_write_bytes += seg.memsz;
    }

    Ok(SramLoadPlan {
        entry,
        vector_table,
        vector_table_source,
        initial_msp,
        reset_handler,
        segments,
        image_sha256: hex_digest(&hasher.finalize()),
        total_write_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const WL: Range<u64> = 0x3400_0000..0x3420_0000;

    // ---- minimal ELF32 LE ARM builder for tests ----
    struct SegmentSpec {
        paddr: u32,
        vaddr: Option<u32>,
        data: Vec<u8>,
        memsz: u32,
        flags: u32,
    }

    fn build_elf(
        entry: u32,
        segments: &[SegmentSpec],
        sections: &[(&str, u32)],
        symbols: &[(&str, u32)],
    ) -> Vec<u8> {
        const EHSIZE: usize = 52;
        const PHSIZE: usize = 32;
        const SHSIZE: usize = 40;

        let phnum = segments.len();
        let phoff = EHSIZE;
        // Lay segment data after program headers.
        let mut data_off = (phoff + phnum * PHSIZE) as u32;
        let mut phdrs: Vec<[u32; 8]> = Vec::new();
        let mut payload: Vec<u8> = Vec::new();
        for seg in segments {
            let aligned = (data_off + 0xFFF) & !0xFFF;
            while (phoff + phnum * PHSIZE + payload.len()) < aligned as usize {
                payload.push(0);
            }
            let file_off = (phoff + phnum * PHSIZE + payload.len()) as u32;
            payload.extend_from_slice(&seg.data);
            let vaddr = seg.vaddr.unwrap_or(seg.paddr);
            phdrs.push([
                1, // PT_LOAD
                file_off,
                vaddr,
                seg.paddr,
                seg.data.len() as u32,
                seg.memsz,
                seg.flags,
                0x1000,
            ]);
            data_off = file_off + seg.data.len() as u32;
        }

        // Section machinery: .isr_vector (optional), .symtab, .strtab, .shstrtab
        let mut shdrs: Vec<[u32; 10]> = vec![[0; 10]]; // NULL
        let mut shstr = b"\0".to_vec();
        let mut strtab = b"\0".to_vec();
        let mut symtab: Vec<u8> = vec![0u8; 16]; // NULL symbol

        // shstrtab indexes
        let mut section_name_offsets = Vec::new();
        for (name, _) in sections {
            section_name_offsets.push(shstr.len() as u32);
            shstr.extend_from_slice(name.as_bytes());
            shstr.push(0);
        }
        let symtab_name_off = shstr.len() as u32;
        shstr.extend_from_slice(b".symtab\0");
        let strtab_name_off = shstr.len() as u32;
        shstr.extend_from_slice(b".strtab\0");
        let shstrtab_name_off = shstr.len() as u32;
        shstr.extend_from_slice(b".shstrtab\0");

        // Section headers for named sections (PROGBITS, addr given, no file content needed by parser for our use)
        for (i, (_, addr)) in sections.iter().enumerate() {
            shdrs.push([
                section_name_offsets[i],
                1,   // SHT_PROGBITS
                0x6, // ALLOC|EXECINSTR-ish
                *addr,
                0,
                0x10,
                0,
                0,
                4,
                0,
            ]);
        }

        // symbols
        let mut symbol_name_offsets = Vec::new();
        for (name, _) in symbols {
            symbol_name_offsets.push(strtab.len() as u32);
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
        }
        for (i, (_, value)) in symbols.iter().enumerate() {
            let mut e = [0u8; 16];
            e[0..4].copy_from_slice(&symbol_name_offsets[i].to_le_bytes());
            e[4..8].copy_from_slice(&value.to_le_bytes());
            e[12] = 0x12; // GLOBAL FUNC
            e[14..16].copy_from_slice(&1u16.to_le_bytes()); // shndx 1
            symtab.extend_from_slice(&e);
        }

        let mut cursor = (phoff + phnum * PHSIZE + payload.len()) as u32;
        let align = |c: u32| (c + 3) & !3;

        // symtab section
        cursor = align(cursor);
        let symtab_off = cursor;
        cursor += symtab.len() as u32;
        let symtab_idx = shdrs.len();
        shdrs.push([
            symtab_name_off,
            2, // SHT_SYMTAB
            0,
            0,
            symtab_off,
            symtab.len() as u32,
            (symtab_idx + 1) as u32, // link -> strtab
            1,                       // info: one local symbol
            4,
            16,
        ]);
        // strtab section
        let strtab_off = cursor;
        cursor += strtab.len() as u32;
        shdrs.push([
            strtab_name_off,
            3,
            0,
            0,
            strtab_off,
            strtab.len() as u32,
            0,
            0,
            1,
            0,
        ]);
        // shstrtab section
        let shstrtab_off = cursor;
        cursor += shstr.len() as u32;
        let shstrtab_idx = shdrs.len();
        shdrs.push([
            shstrtab_name_off,
            3,
            0,
            0,
            shstrtab_off,
            shstr.len() as u32,
            0,
            0,
            1,
            0,
        ]);

        let shoff = align(cursor);

        // ---- assemble ----
        let mut out = Vec::new();
        out.extend_from_slice(b"\x7FELF\x01\x01\x01\0\0\0\0\0\0\0\0\0"); // ELF32 LE
        out.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        out.extend_from_slice(&40u16.to_le_bytes()); // EM_ARM
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&entry.to_le_bytes());
        out.extend_from_slice(&(phoff as u32).to_le_bytes());
        out.extend_from_slice(&shoff.to_le_bytes());
        out.extend_from_slice(&0x0500_0000u32.to_le_bytes()); // EABI v5
        out.extend_from_slice(&(EHSIZE as u16).to_le_bytes());
        out.extend_from_slice(&(PHSIZE as u16).to_le_bytes());
        out.extend_from_slice(&(phnum as u16).to_le_bytes());
        out.extend_from_slice(&(SHSIZE as u16).to_le_bytes());
        out.extend_from_slice(&(shdrs.len() as u16).to_le_bytes());
        out.extend_from_slice(&(shstrtab_idx as u16).to_le_bytes());
        for ph in &phdrs {
            for w in ph {
                out.extend_from_slice(&w.to_le_bytes());
            }
        }
        out.extend_from_slice(&payload);
        while out.len() < symtab_off as usize {
            out.push(0);
        }
        out.extend_from_slice(&symtab);
        while out.len() < strtab_off as usize {
            out.push(0);
        }
        out.extend_from_slice(&strtab);
        while out.len() < shstrtab_off as usize {
            out.push(0);
        }
        out.extend_from_slice(&shstr);
        while out.len() < shoff as usize {
            out.push(0);
        }
        for sh in &shdrs {
            for w in sh {
                out.extend_from_slice(&w.to_le_bytes());
            }
        }
        out
    }

    /// Standard layout mimicking this project: LOAD at 0x34000000 (ELF header
    /// bytes at the segment start), vector table NOT at the segment start but
    /// at 0x34000400, reset handler in executable range.
    fn good_elf() -> Vec<u8> {
        let mut seg_data = vec![0u8; 0x600];
        // vector table at offset 0x400
        seg_data[0x400..0x404].copy_from_slice(&0x3420_0000u32.to_le_bytes()); // MSP
        seg_data[0x404..0x408].copy_from_slice(&0x3400_04A1u32.to_le_bytes()); // Reset (Thumb)
        build_elf(
            0x3400_04A1,
            &[SegmentSpec {
                paddr: 0x3400_0000,
                vaddr: None,
                data: seg_data,
                memsz: 0x700, // 0x100 BSS zero-fill
                flags: 0x7,   // RWE
            }],
            &[(VECTOR_TABLE_SECTION, 0x3400_0400)],
            &[(VECTOR_TABLE_SYMBOL, 0x3400_0400)],
        )
    }

    #[test]
    fn valid_project_style_elf_is_accepted() {
        let elf = good_elf();
        let plan = plan_sram_load(&elf, &WL, None).expect("valid ELF must plan");
        assert_eq!(plan.vector_table, 0x3400_0400);
        assert_eq!(plan.vector_table_source, VectorTableSource::Symbol);
        assert_eq!(plan.initial_msp, 0x3420_0000);
        assert_eq!(plan.reset_handler, 0x3400_04A1);
        assert_eq!(plan.segments.len(), 1);
        assert_eq!(plan.segments[0].memsz - plan.segments[0].filesz, 0x100); // BSS
        assert_eq!(plan.image_sha256.len(), 64);
    }

    #[test]
    fn vector_table_differs_from_load_base() {
        // Guard against the "LOAD base == vector table" assumption.
        let elf = good_elf();
        let plan = plan_sram_load(&elf, &WL, None).unwrap();
        assert_ne!(plan.vector_table, plan.segments[0].paddr);
    }

    #[test]
    fn vector_table_from_section_when_no_symbol() {
        let mut seg_data = vec![0u8; 0x600];
        seg_data[0x400..0x404].copy_from_slice(&0x3420_0000u32.to_le_bytes());
        seg_data[0x404..0x408].copy_from_slice(&0x3400_04A1u32.to_le_bytes());
        let elf = build_elf(
            0x3400_04A1,
            &[SegmentSpec {
                paddr: 0x3400_0000,
                vaddr: None,
                data: seg_data,
                memsz: 0x600,
                flags: 0x7,
            }],
            &[(VECTOR_TABLE_SECTION, 0x3400_0400)],
            &[],
        );
        let plan = plan_sram_load(&elf, &WL, None).unwrap();
        assert_eq!(plan.vector_table_source, VectorTableSource::Section);
    }

    #[test]
    fn explicit_override_used_when_metadata_missing() {
        let mut seg_data = vec![0u8; 0x600];
        seg_data[0x400..0x404].copy_from_slice(&0x3420_0000u32.to_le_bytes());
        seg_data[0x404..0x408].copy_from_slice(&0x3400_04A1u32.to_le_bytes());
        let elf = build_elf(
            0x3400_04A1,
            &[SegmentSpec {
                paddr: 0x3400_0000,
                vaddr: None,
                data: seg_data,
                memsz: 0x600,
                flags: 0x7,
            }],
            &[],
            &[],
        );
        assert!(plan_sram_load(&elf, &WL, None).is_err());
        let plan = plan_sram_load(&elf, &WL, Some(0x3400_0400)).unwrap();
        assert_eq!(
            plan.vector_table_source,
            VectorTableSource::ExplicitOverride
        );
    }

    #[test]
    fn multiple_load_segments_accepted() {
        let mut seg0 = vec![0u8; 0x600];
        seg0[0x400..0x404].copy_from_slice(&0x3420_0000u32.to_le_bytes());
        seg0[0x404..0x408].copy_from_slice(&0x3400_04A1u32.to_le_bytes());
        let elf = build_elf(
            0x3400_04A1,
            &[
                SegmentSpec {
                    paddr: 0x3400_0000,
                    vaddr: None,
                    data: seg0,
                    memsz: 0x600,
                    flags: 0x5,
                },
                SegmentSpec {
                    paddr: 0x3401_0000,
                    vaddr: None,
                    data: vec![1, 2, 3, 4],
                    memsz: 0x20,
                    flags: 0x6,
                },
            ],
            &[(VECTOR_TABLE_SECTION, 0x3400_0400)],
            &[],
        );
        let plan = plan_sram_load(&elf, &WL, None).unwrap();
        assert_eq!(plan.segments.len(), 2);
    }

    #[test]
    fn noload_zero_filesz_segment_outside_whitelist_is_skipped() {
        // AlienTek Debug builds place a multi-MB .EXTRAM (NOLOAD) segment at
        // 0x90000000 (XSPI1 HyperRAM). It carries no file bytes and no
        // debugger ever writes it; the planner must skip it instead of
        // refusing the whole ELF for exceeding the SRAM whitelist.
        let mut seg_data = vec![0u8; 0x600];
        seg_data[0x400..0x404].copy_from_slice(&0x3420_0000u32.to_le_bytes());
        seg_data[0x404..0x408].copy_from_slice(&0x3400_04A1u32.to_le_bytes());
        let elf = build_elf(
            0x3400_04A1,
            &[
                SegmentSpec {
                    paddr: 0x3400_0000,
                    vaddr: None,
                    data: seg_data,
                    memsz: 0x700,
                    flags: 0x7,
                },
                SegmentSpec {
                    paddr: 0x9000_0000,
                    vaddr: None,
                    data: Vec::new(),
                    memsz: 0x1F_4000, // 2 MB NOLOAD external-RAM bss
                    flags: 0x6,       // RW, not executable
                },
            ],
            &[(VECTOR_TABLE_SECTION, 0x3400_0400)],
            &[(VECTOR_TABLE_SYMBOL, 0x3400_0400)],
        );
        let plan = plan_sram_load(&elf, &WL, None)
            .expect("NOLOAD-only segment outside the whitelist must be skipped");
        assert_eq!(plan.segments.len(), 1);
        assert_eq!(plan.segments[0].paddr, 0x3400_0000);
    }

    #[test]
    fn segment_outside_whitelist_rejected() {
        let elf = build_elf(
            0x3400_04A1,
            &[SegmentSpec {
                paddr: 0x2000_0000,
                vaddr: None,
                data: vec![0; 0x10],
                memsz: 0x10,
                flags: 0x7,
            }],
            &[],
            &[],
        );
        let err = plan_sram_load(&elf, &WL, None).unwrap_err();
        assert!(err.contains("whitelist"), "{err}");
    }

    #[test]
    fn data_segment_vma_ne_lma_planned_at_lma() {
        // Real LRUN linker layout (01_LED Debug ELF): exec segment holds the
        // vector table; .data has LMA right after .text (bank A) and VMA in
        // bank B. GDB/STM32CubeIDE load writes the data segment at its LMA;
        // the CRT startup then copies LMA -> VMA.
        let mut data = vec![0u8; 0xC];
        data.copy_from_slice(&[0xAA; 0xC]);
        let vec_data = {
            let mut d = vec![0u8; 0x800]; // exec segment covers Reset target 0x340004A0
            d[0x400..0x404].copy_from_slice(&0x3420_0000u32.to_le_bytes()); // MSP
            d[0x404..0x408].copy_from_slice(&0x3400_04A1u32.to_le_bytes()); // Reset
            d
        };
        let elf = build_elf(
            0x3400_04A1,
            &[
                SegmentSpec {
                    paddr: 0x3400_0000,
                    vaddr: None,
                    data: vec_data,
                    memsz: 0x800,
                    flags: 0x7, // exec: vector table + code
                },
                SegmentSpec {
                    paddr: 0x3400_040C,
                    vaddr: Some(0x3408_0000),
                    data,
                    memsz: 0x10,
                    flags: 0x6, // RW data, LMA != VMA
                },
            ],
            &[(".isr_vector", 0x3400_0400)],
            &[],
        );
        let plan = plan_sram_load(&elf, &WL, None).expect("LRUN layout must be accepted");
        assert_eq!(plan.segments.len(), 2);
        assert!(plan.segments[0].executable, "first segment must be exec");
        assert_eq!(
            plan.segments[1].paddr, 0x3400_040C,
            "data segment must be written at its LMA"
        );
        assert!(!plan.segments[1].executable);
    }

    #[test]
    fn executable_segment_vma_ne_lma_rejected() {
        let elf = build_elf(
            0x3400_04A1,
            &[SegmentSpec {
                paddr: 0x3400_0000,
                vaddr: Some(0x3408_0000),
                data: vec![0; 0x20],
                memsz: 0x20,
                flags: 0x7, // executable
            }],
            &[],
            &[],
        );
        let err = plan_sram_load(&elf, &WL, None).unwrap_err();
        assert!(err.contains("Executable PT_LOAD"), "{err}");
    }

    #[test]
    fn flash_peripheral_ppb_addresses_rejected() {
        for paddr in [0x0800_0000u32, 0x4000_0000, 0xE000_E000, 0x7010_0000] {
            let elf = build_elf(
                0x3400_04A1,
                &[SegmentSpec {
                    paddr,
                    vaddr: None,
                    data: vec![0; 0x10],
                    memsz: 0x10,
                    flags: 0x7,
                }],
                &[],
                &[],
            );
            assert!(
                plan_sram_load(&elf, &WL, None).is_err(),
                "paddr 0x{paddr:08X} must be rejected"
            );
        }
    }

    #[test]
    fn filesz_greater_than_memsz_rejected() {
        let mut ph = SegmentSpec {
            paddr: 0x3400_0000,
            vaddr: None,
            data: vec![0; 0x20],
            memsz: 0x10,
            flags: 0x7,
        };
        ph.memsz = 0x10;
        let elf = build_elf(0x3400_04A1, &[ph], &[], &[]);
        let err = plan_sram_load(&elf, &WL, None).unwrap_err();
        assert!(err.contains("p_filesz"), "{err}");
    }

    #[test]
    fn overflow_in_segment_end_rejected() {
        // paddr near u64 max would overflow paddr+memsz; as u32 fields the
        // classic overflow case is vaddr/paddr+u64. Use paddr=0xFFFF_F000 with
        // huge memsz via builder limits: instead craft a segment whose
        // file_offset+filesz exceeds the file.
        let mut elf = good_elf();
        // Corrupt the first program header p_filesz to a huge value.
        let phoff = 52usize;
        let filesz_field = phoff + 16;
        elf[filesz_field..filesz_field + 4].copy_from_slice(&0x7FFF_FFF0u32.to_le_bytes());
        assert!(plan_sram_load(&elf, &WL, None).is_err());
    }

    #[test]
    fn truncated_and_garbage_elf_rejected() {
        assert!(plan_sram_load(b"\x7FELF", &WL, None).is_err());
        assert!(plan_sram_load(b"not an elf at all", &WL, None).is_err());
        assert!(plan_sram_load(&[], &WL, None).is_err());
    }

    #[test]
    fn non_arm_machine_rejected() {
        let mut elf = good_elf();
        elf[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        let err = plan_sram_load(&elf, &WL, None).unwrap_err();
        assert!(err.contains("EM_ARM"), "{err}");
    }

    #[test]
    fn misaligned_msp_rejected() {
        let mut seg_data = vec![0u8; 0x600];
        seg_data[0x400..0x404].copy_from_slice(&0x3420_0002u32.to_le_bytes());
        seg_data[0x404..0x408].copy_from_slice(&0x3400_04A1u32.to_le_bytes());
        let elf = build_elf(
            0x3400_04A1,
            &[SegmentSpec {
                paddr: 0x3400_0000,
                vaddr: None,
                data: seg_data,
                memsz: 0x600,
                flags: 0x7,
            }],
            &[(VECTOR_TABLE_SECTION, 0x3400_0400)],
            &[],
        );
        let err = plan_sram_load(&elf, &WL, None).unwrap_err();
        assert!(err.contains("MSP"), "{err}");
    }

    #[test]
    fn msp_outside_ram_rejected() {
        let mut seg_data = vec![0u8; 0x600];
        seg_data[0x400..0x404].copy_from_slice(&0x2000_0000u32.to_le_bytes());
        seg_data[0x404..0x408].copy_from_slice(&0x3400_04A1u32.to_le_bytes());
        let elf = build_elf(
            0x3400_04A1,
            &[SegmentSpec {
                paddr: 0x3400_0000,
                vaddr: None,
                data: seg_data,
                memsz: 0x600,
                flags: 0x7,
            }],
            &[(VECTOR_TABLE_SECTION, 0x3400_0400)],
            &[],
        );
        assert!(plan_sram_load(&elf, &WL, None).is_err());
    }

    #[test]
    fn non_thumb_reset_handler_rejected() {
        let mut seg_data = vec![0u8; 0x600];
        seg_data[0x400..0x404].copy_from_slice(&0x3420_0000u32.to_le_bytes());
        seg_data[0x404..0x408].copy_from_slice(&0x3400_04A0u32.to_le_bytes()); // bit0 = 0
        let elf = build_elf(
            0x3400_04A0,
            &[SegmentSpec {
                paddr: 0x3400_0000,
                vaddr: None,
                data: seg_data,
                memsz: 0x600,
                flags: 0x7,
            }],
            &[(VECTOR_TABLE_SECTION, 0x3400_0400)],
            &[],
        );
        let err = plan_sram_load(&elf, &WL, None).unwrap_err();
        assert!(err.contains("Thumb"), "{err}");
    }

    #[test]
    fn reset_handler_outside_loaded_executable_rejected() {
        let mut seg_data = vec![0u8; 0x600];
        seg_data[0x400..0x404].copy_from_slice(&0x3420_0000u32.to_le_bytes());
        seg_data[0x404..0x408].copy_from_slice(&0x3401_0001u32.to_le_bytes()); // not loaded
        let elf = build_elf(
            0x3400_04A1,
            &[SegmentSpec {
                paddr: 0x3400_0000,
                vaddr: None,
                data: seg_data,
                memsz: 0x600,
                flags: 0x7,
            }],
            &[(VECTOR_TABLE_SECTION, 0x3400_0400)],
            &[],
        );
        let err = plan_sram_load(&elf, &WL, None).unwrap_err();
        assert!(err.contains("Reset_Handler"), "{err}");
    }

    #[test]
    fn entry_outside_executable_rejected() {
        let elf = build_elf(
            0x2000_0001,
            &[SegmentSpec {
                paddr: 0x3400_0000,
                vaddr: None,
                data: vec![0; 0x600],
                memsz: 0x600,
                flags: 0x7,
            }],
            &[],
            &[],
        );
        assert!(plan_sram_load(&elf, &WL, Some(0x3400_0400)).is_err());
    }

    #[test]
    fn whitelist_intersecting_forbidden_ranges_rejected() {
        assert!(plan_sram_load(&good_elf(), &(0x4000_0000..0x5000_0000), None).is_err());
        assert!(plan_sram_load(&good_elf(), &(0xE000_0000..0xF000_0000), None).is_err());
    }

    #[test]
    fn real_fixture_elfs_parse_when_available() {
        // Integration with the four real L2 fixture ELFs. Skipped unless the
        // fixture directory is provided via env var.
        let Ok(dir) = std::env::var("SRAM_ELF_FIXTURE_DIR") else {
            eprintln!("SRAM_ELF_FIXTURE_DIR not set; skipping real-ELF fixture test");
            return;
        };
        for name in [
            "build-fixture-baseline",
            "build-fault-hardfault",
            "build-fault-led-period",
            "build-fault-startup-stall",
        ] {
            let path = std::path::Path::new(&dir)
                .join(name)
                .join("08_Basic_Timer_Appli.elf");
            let bytes =
                std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let plan = plan_sram_load(&bytes, &WL, None)
                .unwrap_or_else(|e| panic!("plan {}: {e}", path.display()));
            assert_eq!(plan.vector_table, 0x3400_0400, "{name}");
            assert_eq!(plan.initial_msp % 4, 0, "{name}");
            // Full-descending stack: initial MSP may equal the top of RAM.
            assert!(
                (plan.initial_msp as u64) >= WL.start && (plan.initial_msp as u64) <= WL.end,
                "{name}: MSP 0x{:08X} outside whitelist",
                plan.initial_msp
            );
            assert_eq!(plan.reset_handler & 1, 1, "{name}");
            let reset = (plan.reset_handler & !1) as u64;
            assert!(
                plan.segments
                    .iter()
                    .any(|s| s.executable && reset >= s.paddr && reset < s.end()),
                "{name}"
            );
            eprintln!(
                "{name}: vt=0x{:08X} msp=0x{:08X} reset=0x{:08X} entry=0x{:08X} sha256={}",
                plan.vector_table,
                plan.initial_msp,
                plan.reset_handler,
                plan.entry,
                plan.image_sha256
            );
        }
    }
}
