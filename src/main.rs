use std::collections::HashMap;
use std::ops::Deref;
use std::{borrow::Cow, path::PathBuf, str::FromStr};

use anyhow::{bail, Context};
use clap::Parser;
use coff::archive::CoffArchive;
use coff::relocations::{I386RelocationType, RelocationType};
use coff::symbol_table::SymbolTableEntry;
use coff::{CoffFile, CoffSection, ObjectIdx, SectionId, SectionIdx};
use flags::{DllCharacteristics, FileCharacteristics, SectionCharacteristics};
use itertools::Itertools;
use link::relocations::apply_relocations;
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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let file_data: Vec<_> = cli
        .input_files
        .into_iter()
        .map(|file_path| std::fs::read(&file_path).map(|data| (file_path, data)))
        .try_collect()?;

    let mut input_object_files = vec![];
    let mut library_object_files = vec![];

    for (file_path, file_data) in &file_data {
        match file_path
            .extension()
            .map(|s| s.to_string_lossy())
            .as_deref()
        {
            Some("lib") => {
                let archive = CoffArchive::parse(&mut file_data.as_slice())
                    .map_err(|e| anyhow::anyhow!(e))
                    .with_context(|| format!("error parsing archive {file_path:?}"))?;

                for member in archive.members {
                    let library_object = CoffFile::parse(&mut &member.data[..])
                        .map_err(|e| anyhow::anyhow!(e))
                        .with_context(|| {
                            format!("error parsing archive member of {file_path:?}")
                        })?;

                    library_object_files.push(library_object);
                }
            }
            Some("obj") => {
                let obj = CoffFile::parse(&mut file_data.as_slice())
                    .map_err(|e| anyhow::anyhow!(e))
                    .with_context(|| format!("error parsing object {file_path:?}"))?;

                input_object_files.push(obj)
            }
            other => bail!("unknown extension {other:?}"),
        }
    }

    for (object_file_idx, object_file) in input_object_files.iter_mut().enumerate() {
        for section in &mut object_file.sections {
            section.id.object_idx = ObjectIdx(object_file_idx);
        }
    }

    // Collect all symbols into global symbol table
    let mut global_symbols = collect_global_symbols(&input_object_files)?;

    // Build map of string tables
    let string_tables: HashMap<_, _> = input_object_files
        .iter()
        .enumerate()
        .filter_map(|(idx, obj)| obj.string_table.as_ref().map(|st| (ObjectIdx(idx), st)))
        .collect();

    // Resolve all symbol references
    global_symbols.resolve_symbols(&string_tables)?;

    let mut sections = input_object_files
        .iter()
        .flat_map(|o| o.sections.clone())
        .collect_vec();

    apply_relocations(
        &mut sections,
        &global_symbols,
        0x400000, // Image base
        0x1000,   // Section alignment
    )?;

    let merged_sections = order_and_merge_sections(sections)?;
    let (code_size, init_data_size, uninit_data_size) = count_section_totals(&merged_sections);

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
            let section_map = obj_file.sections.iter().map(|s| (s.id, s)).collect();

            global_symbols.add_all(
                symbol_table,
                obj_file.string_table.as_ref(),
                &section_map,
                ObjectIdx(idx),
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
