use std::{borrow::Cow, cmp::Ordering, path::PathBuf, str::FromStr, time::Instant};

use anyhow::{bail, Context};
use clap::Parser;
use coff::{CoffFile, CoffSection};
use coff::relocations::RelocationType;
use flags::{DllCharacteristics, FileCharacteristics, SectionCharacteristics};
use itertools::Itertools;
use parse::Parse;
use pe::{DosHeader, PeFile};

mod coff;
mod flags;
mod parse;
mod pe;
mod util;

#[derive(Parser)]
struct Cli {
    input_files: Vec<PathBuf>,
}

fn process_section_relocations<'a>(
    section: &mut CoffSection<'a>,
    global_symbols: &GlobalSymbolTable<'a>,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    section_rva: u64,
    all_sections: &[CoffSection<'a>],
) -> anyhow::Result<()> {
    // Skip if no relocations
    if section.relocations.is_empty() {
        return Ok(());
    }

    // Section must have data to relocate
    let data = section.data.as_mut()
        .context("Section has relocations but no data")?;
    
    // Process each relocation
    for reloc in &section.relocations {
        // Get the symbol being referenced
        let symbol = global_symbols.get_by_index(section.id.object_idx, reloc.symbol_table_index as usize)
            .context("Invalid symbol reference in relocation")?;
        
        // Get target section number (1-based)
        let target_section = symbol.entry.section_number;
        if target_section <= 0 {
            bail!("Cannot relocate to undefined symbol {}", symbol.name);
        }

        // Look up target section's VA from its header
        let target_section = all_sections.iter()
            .find(|s| s.header.section_number == target_section)
            .context("Target section not found")?;
            
        let target_address = image_base + target_section.header.virtual_address as u64 + symbol.entry.value as u64;

        // Apply relocation at offset
        match reloc.type_ {
            RelocationType::Absolute => {
                // No-op relocation
            }
            RelocationType::Dir32 => {
                // Write 32-bit VA 
                let offset = reloc.virtual_address as usize;
                let value = target_address as u32;
                data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            }
            RelocationType::Dir32NB => {
                // Write 32-bit RVA (relative to image base)
                let offset = reloc.virtual_address as usize;
                let value = (target_address - image_base) as u32;
                data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            }
            RelocationType::Rel32 => {
                // Write 32-bit relative offset from next instruction
                let offset = reloc.virtual_address as usize;
                let source_va = image_base + section_rva + (offset as u64 + 4);
                let value = ((target_address as i64) - (source_va as i64)) as u32;
                data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            }
            _ => bail!("Unsupported relocation type {:?}", reloc.type_),
        }
    }

    // Clear relocations after processing
    section.relocations.clear();
    
    Ok(())
}

fn process_all_relocations<'a>(
    sections: &mut [CoffSection<'a>],
    global_symbols: &GlobalSymbolTable<'a>,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
) -> anyhow::Result<()> {
    // Calculate and store virtual addresses in section headers
    let mut current_va = 0u64;
    
    for section in sections.iter_mut() {
        // Align VA to section alignment
        current_va = (current_va + section_alignment as u64 - 1) & !(section_alignment as u64 - 1);
        
        // Store VA in section header
        section.header.virtual_address = current_va as u32;
        
        // Set virtual size equal to raw data size for now
        if let Some(data) = &section.data {
            section.header.virtual_size = data.len() as u32;
            current_va += data.len() as u64;
        }
    }

    // Process relocations using VAs from headers
    for section in sections.iter_mut() {
        process_section_relocations(
            section,
            global_symbols,
            image_base,
            section_alignment, 
            file_alignment,
            section.header.virtual_address as u64,
            sections
        )?;
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let file_data = cli
        .input_files
        .into_iter()
        .map(|file_path| std::fs::read(file_path))
        .collect::<Result<Vec<_>, _>>()?;

    let mut object_files = file_data
        .iter()
        .map(|file_data| CoffFile::parse(&mut file_data.as_slice()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!(e))?;

    for (object_file_idx, object_file) in object_files.iter_mut().enumerate() {
        for section in &mut object_file.sections {
            section.id.object_idx = object_file_idx;
        }
    }

    println!("{object_files:#?}");

    // Collect all symbols into global symbol table
    let mut global_symbols = collect_global_symbols(&object_files)?;

    let sections = object_files
        .iter()
        .flat_map(|o| o.sections.clone())
        .collect_vec();

    let merged_sections = order_and_merge_sections(sections)?;
    let (code_size, init_data_size, uninit_data_size) = count_section_totals(&merged_sections);

    let package_version = clap::crate_version!();
    let (package_major_version, package_minor_version, _) =
        package_version.splitn(3, '.').collect_tuple().unwrap();
    let package_major_version = u8::from_str(package_major_version).unwrap();
    let package_minor_version = u8::from_str(package_minor_version).unwrap();

    // Process relocations before creating PE file
    process_all_relocations(
        &mut merged_sections,
        &global_symbols,
        0x400000, // Image base
        0x1000,   // Section alignment
        0x200     // File alignment
    )?;

    let pe_file = PeFile {
        dos_header: DosHeader { e_lfanew: 0 },
        coff_header: coff::CoffFileHeader {
            machine: coff::Machine::I386,
            // TODO
            time_date_stamp: 0,
            characteristics: FileCharacteristics::EXECUTABLE_IMAGE,

            // ignored, calculated when writing PE file
            number_of_sections: 0,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_header: 0,
        },
        optional_header: pe::OptionalHeader {
            magic: pe::OptionalHeader::MAGIC_PE32,
            major_linker_version: package_major_version,
            minor_linker_version: package_minor_version,
            size_of_code: code_size,
            size_of_initialized_data: init_data_size,
            size_of_uninitialized_data: uninit_data_size,

            // TODO
            address_of_entry_point: 0,
            base_of_code: 0,

            image_base: 0x400000,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            major_operating_system_version: 6,
            minor_operating_system_version: 0,
            major_image_version: 0,
            minor_image_version: 0,
            major_subsystem_version: 6,
            minor_subsystem_version: 0,
            win32_version_value: 0,
            // ignored, calculated when writing PE file
            size_of_image: 0,
            size_of_headers: 0,
            // checksum is not validated, so don't bother computing one
            checksum: 0,
            subsystem: flags::Subsystem::WindowsGui,
            dll_characteristics: DllCharacteristics::empty(),

            // TODO
            size_of_stack_reserve: 0,
            size_of_stack_commit: 0,
            size_of_heap_reserve: 0,
            size_of_heap_commit: 0,
            loader_flags: 0,

            // ignored, calculated when writing PE file
            number_of_rva_and_sizes: 0,
            data_directories: vec![],
        },
        sections: merged_sections,
        string_table: None,
        symbol_table: None,
    };

    Ok(())
}

/// Counts the total amount of (code, initialized data, uninitialized data)
fn count_section_totals(merged_sections: &[coff::CoffSection<'_>]) -> (u32, u32, u32) {
    let mut code_size = 0;
    let mut init_data_size = 0;
    let mut uninit_data_size = 0;

    for section in merged_sections {
        let flags = section.header.characteristics;
        let len = section.data.map(|d| d.len()).unwrap_or_default() as u32;

        if flags.contains(SectionCharacteristics::CNT_CODE) {
            code_size += len;
        }

        if flags.contains(SectionCharacteristics::CNT_INITIALIZED_DATA) {
            init_data_size += len;
        }

        if flags.contains(SectionCharacteristics::CNT_UNINITIALIZED_DATA) {
            uninit_data_size += len;
        }
    }

    (code_size, init_data_size, uninit_data_size)
}

fn collect_global_symbols(object_files: &[CoffFile]) -> anyhow::Result<GlobalSymbolTable> {
    let mut global_symbols = GlobalSymbolTable::new();

    for (idx, obj_file) in object_files.iter().enumerate() {
        global_symbols.add(&obj_file.symbol_table, obj_file.string_table.as_ref(), idx)?;
    }

    Ok(global_symbols)
}

fn order_and_merge_sections(
    mut sections: Vec<coff::CoffSection<'_>>,
) -> anyhow::Result<Vec<coff::CoffSection<'_>>> {
    sections.sort_by(|s1, s2| {
        // sort sections by name
        return s1.header.name.cmp(&s2.header.name);
    });

    // merge sections with same name
    let mut merged_sections: Vec<coff::CoffSection<'_>> = vec![];
    let mut prev: Option<coff::CoffSection<'_>> = None;

    for next in sections {
        if let Some(prev) = &mut prev {
            let prev_image_section_name = match prev.header.name.split_once('$') {
                Some((group_name, _)) => group_name,
                None => &prev.header.name,
            };

            let next_image_section_name = match next.header.name.split_once('$') {
                Some((group_name, _)) => group_name,
                None => &next.header.name,
            };

            if prev_image_section_name != next_image_section_name {
                let prev = std::mem::replace(prev, next);
                merged_sections.push(prev);
                continue;
            }

            let content_flags = SectionCharacteristics::CNT_CODE
                | SectionCharacteristics::CNT_INITIALIZED_DATA
                | SectionCharacteristics::CNT_UNINITIALIZED_DATA;
            let prev_content_flags = prev.header.characteristics & content_flags;
            let next_content_flags = next.header.characteristics & content_flags;

            if prev_content_flags != next_content_flags {
                bail!(
                    "cannot merge sections {:?} and {:?}: incompatible characteristics {:?} and {:?}",
                    prev.header.name,
                    next.header.name,
                    prev_content_flags,
                    next_content_flags
                );
            }

            // TODO: copy here shouldn't really be necessary, but it causes
            // lifetime issues if we don't do it
            prev.header.name = Cow::from(next_image_section_name.to_owned());
        } else {
            prev = Some(next);
        }
    }

    merged_sections.extend(prev);
    Ok(merged_sections)
}
