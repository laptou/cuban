use std::collections::HashMap;
use std::ops::Deref;
use std::{borrow::Cow, path::PathBuf, str::FromStr};

use anyhow::{bail, Context};
use clap::Parser;
use coff::archive::CoffArchive;
use coff::relocations::{I386RelocationType, RelocationType};
use coff::symbol_table::SymbolTableEntry;
use coff::{CoffFile, CoffSection, CoffSectionId, ObjectIdx, SectionIdx};
use flags::{DllCharacteristics, FileCharacteristics, SectionCharacteristics};
use itertools::Itertools;
use link::symbol_table::{GlobalSymbolTable, LocalSymbol};
use parse::{Layout, Parse, Write};
use pe::{DosHeader, PeFile};

mod coff;
mod flags;
mod link;
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
    section_rva: u64,
    all_sections: &[CoffSection<'a>],
) -> anyhow::Result<()> {
    let section_map: HashMap<_, _> = all_sections.iter().map(|s| (s.id, s)).collect();

    fn resolve_local_symbol<'a: 'b, 'b>(
        local_symbol: &LocalSymbol<'a>,
        section_map: &'b HashMap<CoffSectionId, &CoffSection<'a>>,
        object_idx: ObjectIdx,
    ) -> anyhow::Result<(&'a SymbolTableEntry, &'b CoffSection<'a>)> {
        match local_symbol {
            LocalSymbol::External { entry, resolution } => {
                // is this external symbol defined in this object?
                if entry.section_number > 0 {
                    let section_id = CoffSectionId {
                        object_idx,
                        section_idx: SectionIdx(entry.section_number as usize - 1),
                    };

                    // yes, grab the relevant section
                    let section = section_map
                        .get(&section_id)
                        .context("could not resolve target section")?;

                    return Ok((*entry, section));
                } else {
                    // no, use the resolution
                    let gs = resolution
                        .as_ref()
                        .context("external symbol is not resolved")?;

                    let section_id = CoffSectionId {
                        object_idx: gs.object_idx,
                        section_idx: gs.section_idx,
                    };

                    let section = section_map
                        .get(&section_id)
                        .context("could not resolve target section")?;

                    return Ok((gs.entry, section));
                }
            }
            LocalSymbol::Static { entry } => {
                let section_id = CoffSectionId {
                    object_idx,
                    section_idx: SectionIdx(entry.section_number as usize - 1),
                };

                let section = section_map
                    .get(&section_id)
                    .context("could not resolve target section")?;

                return Ok((*entry, section));
            }
            LocalSymbol::Weak {
                resolution,
                alternate,
                ..
            } => {
                // for weak symbols, use the resolution if we have one,
                // otherwise fall back to the local alternate
                if let Some(resolution) = resolution.as_ref() {
                    let section_id = CoffSectionId {
                        object_idx: resolution.object_idx,
                        section_idx: resolution.section_idx,
                    };

                    let section = section_map
                        .get(&section_id)
                        .context("could not resolve target section")?;

                    return Ok((resolution.entry, section));
                }

                let section_id = CoffSectionId {
                    object_idx,
                    section_idx: SectionIdx(alternate.section_number as usize - 1),
                };

                let section = section_map
                    .get(&section_id)
                    .context("could not resolve target section")?;

                return Ok((*alternate, section));
            }
        }
    }

    // Skip if no relocations
    if section.relocations.is_empty() {
        return Ok(());
    }

    // Section must have data to relocate
    let data = section
        .data
        .as_mut()
        .context("section has relocations but no data")?;

    // Process each relocation
    for reloc in &section.relocations {
        // Get the symbol being referenced
        let local_symbol = global_symbols
            .get_local_symbol(section.id.object_idx, coff::SymbolIdx(reloc.symbol_table_index as usize))
            .with_context(|| format!(
                "invalid symbol reference in relocation: {reloc:?} object_idx = {:?} symbol_table_idx = {:?}",
                section.id.object_idx, reloc.symbol_table_index
            ))?;

        // local symbol might be weak, external, etc., so we need to resolve
        let (target_symbol, target_section) =
            resolve_local_symbol(&local_symbol, &section_map, section.id.object_idx)?;

        let target_address =
            image_base + target_section.header.virtual_address as u64 + target_symbol.value as u64;

        // Apply relocation at offset
        match reloc.relocation_type {
            RelocationType::I386(ty) => match ty {
                I386RelocationType::Absolute => {
                    // No-op relocation
                }
                I386RelocationType::Dir32 => {
                    // Write 32-bit VA
                    let offset = reloc.virtual_address as usize;
                    let value = target_address as u32;
                    data.to_mut()[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
                }
                I386RelocationType::Dir32NB => {
                    // Write 32-bit RVA (relative to image base)
                    let offset = reloc.virtual_address as usize;
                    let value = (target_address - image_base) as u32;
                    data.to_mut()[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
                }
                I386RelocationType::Rel32 => {
                    // Write 32-bit relative offset from next instruction
                    let offset = reloc.virtual_address as usize;
                    let source_va = image_base + section_rva + (offset as u64 + 4);
                    let value = ((target_address as i64) - (source_va as i64)) as u32;
                    data.to_mut()[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
                }
                other => bail!("unsupported i386 relocation type {other:?}"),
            },
            other => bail!("unsupported relocation type {other:?}"),
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

    let mut new_sections = vec![];

    // Process relocations using VAs from headers
    for section in sections.iter() {
        if section.relocations.is_empty() {
            new_sections.push(section.clone());
            continue;
        }

        let mut new_section = section.clone();

        process_section_relocations(
            &mut new_section,
            global_symbols,
            image_base,
            section.header.virtual_address as u64,
            sections,
        )?;

        new_sections.push(new_section);
    }

    sections.clone_from_slice(&new_sections);

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let file_data: Vec<_> = cli
        .input_files
        .into_iter()
        .map(|file_path| std::fs::read(&file_path).map(|data| (file_path, data)))
        .try_collect()?;

    let mut object_files = file_data
        .iter()
        .map(|(file_path, file_data)| -> anyhow::Result<Vec<CoffFile>> {
            match file_path
                .extension()
                .map(|s| s.to_string_lossy())
                .as_deref()
            {
                Some("lib") => {
                    let archive = CoffArchive::parse(&mut file_data.as_slice())
                        .map_err(|e| anyhow::anyhow!(e))
                        .with_context(|| format!("error parsing archive {file_path:?}"))?;

                    Ok(archive
                        .members
                        .into_iter()
                        .map(|m| {
                            CoffFile::parse(&mut &m.data[..])
                                .map_err(|e| anyhow::anyhow!(e))
                                .with_context(|| {
                                    format!("error parsing archive member of {file_path:?}")
                                })
                        })
                        .try_collect()?)
                }
                Some("obj") => {
                    let obj = CoffFile::parse(&mut file_data.as_slice())
                        .map_err(|e| anyhow::anyhow!(e))
                        .with_context(|| format!("error parsing object {file_path:?}"))?;

                    Ok(vec![obj])
                }
                other => bail!("unknown extension {other:?}"),
            }
        })
        .flatten_ok()
        .collect::<Result<Vec<_>, _>>()?;

    for (object_file_idx, object_file) in object_files.iter_mut().enumerate() {
        for section in &mut object_file.sections {
            section.id.object_idx = ObjectIdx(object_file_idx);
        }
    }

    // println!("{object_files:#?}");

    // Collect all symbols into global symbol table
    let global_symbols = collect_global_symbols(&object_files)?;
    // dbg!(&global_symbols);

    let mut sections = object_files
        .iter()
        .flat_map(|o| o.sections.clone())
        .collect_vec();

    process_all_relocations(
        &mut sections,
        &global_symbols,
        0x400000, // Image base
        0x1000,   // Section alignment
    )?;

    let merged_sections = order_and_merge_sections(sections)?;
    let (code_size, init_data_size, uninit_data_size) = count_section_totals(&merged_sections);

    dbg!(&merged_sections);

    let package_version = clap::crate_version!();
    let (package_major_version, package_minor_version, _) =
        package_version.splitn(3, '.').collect_tuple().unwrap();
    let package_major_version = u8::from_str(package_major_version).unwrap();
    let package_minor_version = u8::from_str(package_minor_version).unwrap();

    let mut pe_file = PeFile {
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

    let pe_file_len = pe_file.fix_layout();

    let output_file = std::fs::File::open("out.exe")?;
    output_file.set_len(pe_file_len as u64)?;

    let mut output_file_buf = unsafe { memmap::MmapMut::map_mut(&output_file)? };
    pe_file.write(&mut output_file_buf)?;

    Ok(())
}

/// Counts the total amount of (code, initialized data, uninitialized data)
fn count_section_totals(merged_sections: &[coff::CoffSection<'_>]) -> (u32, u32, u32) {
    let mut code_size = 0;
    let mut init_data_size = 0;
    let mut uninit_data_size = 0;

    for section in merged_sections {
        let flags = section.header.characteristics;
        let len = section.data.as_deref().map(|d| d.len()).unwrap_or_default() as u32;

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

fn collect_global_symbols<'a, 'b: 'a>(
    object_files: &'b [CoffFile<'a>],
) -> anyhow::Result<GlobalSymbolTable<'a>> {
    let mut global_symbols = GlobalSymbolTable::new();

    for (idx, obj_file) in object_files.into_iter().enumerate() {
        if let Some(symbol_table) = &obj_file.symbol_table {
            global_symbols.add_all(
                symbol_table,
                obj_file.string_table.as_ref(),
                coff::ObjectIdx(idx),
            )?;
        }
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
