use std::collections::{HashMap, HashSet};
use std::io::{stdin, IsTerminal};
use std::ops::Deref;
use std::{borrow::Cow, path::PathBuf, str::FromStr};

use anyhow::{bail, Context};
use clap::Parser;
use coff::archive::{Archive, ArchiveMemberContent};
use coff::relocations::{I386RelocationType, RelocationType};
use coff::string_table::StringTable;
use coff::symbol_table::{StorageClass, SymbolTableEntry};
use coff::{LibraryIdx, Object, ObjectIdx, Section, SectionId, SectionIdx, SymbolIdx};
use flags::{DllCharacteristics, FileCharacteristics, SectionCharacteristics};
use itertools::Itertools;
use link::relocations::apply_relocations;
use link::symbol_table::{
    GlobalSymbolDefinition, GlobalSymbolTable, LocalSymbol, SymbolResolutionError,
};
use parse::{Layout, Parse, Write};
use pe::{DosHeader, PeFile};
use tracing::{debug, debug_span, error, info, trace, Level};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

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

#[derive(Debug, Clone)]
struct Library<'a> {
    pub idx: LibraryIdx,
    pub archive: Archive<'a>,
    pub path: PathBuf,
    pub objects: HashMap<ObjectIdx, Object<'a>>,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
        // .with_ansi(stdin().is_terminal())
        .with_ansi(false)
        .finish()
        .init();

    let cli = Cli::parse();

    let file_data: Vec<_> = cli
        .input_files
        .into_iter()
        .map(|file_path| std::fs::read(&file_path).map(|data| (file_path, data)))
        .try_collect()?;

    let mut input_object_files: Vec<Object<'_>> = vec![];
    let mut libraries: Vec<Library<'_>> = vec![];
    let mut symbol_to_library_map: HashMap<&str, Vec<(LibraryIdx, ObjectIdx)>> = HashMap::new();

    let mut library_idx = 0;
    let mut object_idx = 0;

    for (file_path, file_data) in &file_data {
        match file_path
            .extension()
            .map(|s| s.to_string_lossy())
            .as_deref()
        {
            Some("lib") => {
                let library_idx = LibraryIdx({
                    // would love it if rust had ++ operator
                    let tmp = library_idx;
                    library_idx += 1;
                    tmp
                });

                let archive = Archive::parse(&mut file_data.as_slice())
                    .map_err(|e| anyhow::anyhow!(e))
                    .with_context(|| format!("error parsing archive {file_path:?}"))?;

                let mut objects = HashMap::new();
                // allows mapping from local object indices to global object indices
                let mut members_indices = vec![];
                // allows mapping from file offsets to object indices
                let mut members_offsets = HashMap::new();

                for (idx, member) in archive.members.iter().enumerate() {
                    let member_content = ArchiveMemberContent::parse(&mut &member.data[..])
                        .map_err(|e| anyhow::anyhow!(e))
                        .with_context(|| {
                            format!("error parsing archive member {idx} of {file_path:?}")
                        })?;

                    match member_content {
                        ArchiveMemberContent::Object(mut obj) => {
                            obj.idx = ObjectIdx(object_idx);

                            for section in &mut obj.sections {
                                section.id.object_idx = obj.idx;
                            }

                            object_idx += 1;
                            members_indices.push(Some(obj.idx));
                            members_offsets.insert(member.offset, Some(obj.idx));

                            objects.insert(obj.idx, obj);
                        }
                        ArchiveMemberContent::ShortImportLibrary(_) => {
                            // TODO
                            members_indices.push(None);
                            members_offsets.insert(member.offset, None);
                        }
                    }
                }

                // Build symbol map from linker members
                if let Some(linker) = &archive.second_linker {
                    // debug!("path = {file_path:?}");
                    // debug!("members_indices = {members_indices:#?}");
                    // debug!("members_offsets = {members_offsets:#?}");
                    // debug!("linker = {linker:#?}");

                    for (obj_idx, name) in &linker.symbols {
                        // these indices are 1-based for some reason
                        let obj_idx = *obj_idx - 1;
                        if let Some(global_obj_idx) = members_indices[obj_idx as usize] {
                            symbol_to_library_map
                                .entry(name)
                                .or_default()
                                .push((library_idx, global_obj_idx));
                        }
                    }
                } else if let Some(linker) = &archive.first_linker {
                    for &(offset, name) in &linker.symbols {
                        let entry = *members_offsets.get(&(offset as usize)).context("malformed library file: symbol offset does not match any member offset")?;

                        if let Some(global_obj_idx) = entry {
                            symbol_to_library_map
                                .entry(name)
                                .or_default()
                                .push((library_idx, global_obj_idx));
                        }
                    }
                } else {
                    bail!("no linker members");
                }

                libraries.push(Library {
                    idx: library_idx,
                    archive,
                    path: file_path.to_owned(),
                    objects,
                });
            }
            Some("obj") => {
                let mut obj = Object::parse(&mut file_data.as_slice())
                    .map_err(|e| anyhow::anyhow!(e))
                    .with_context(|| format!("error parsing object {file_path:?}"))?;

                obj.idx = ObjectIdx(object_idx);

                for section in &mut obj.sections {
                    section.id.object_idx = obj.idx;
                }

                object_idx += 1;

                input_object_files.push(obj)
            }
            other => bail!("unknown extension {other:?}"),
        }
    }

    // debug!("objects = {input_object_files:#?}");
    // debug!("libraries = {libraries:#?}");

    for library in &libraries {
        let _span = debug_span!("library", library_idx = ?library.idx).entered();

        for (object_idx, object) in &library.objects {
            trace!("object {object_idx:?}");
        }
    }

    for (symbol, locations) in &symbol_to_library_map {
        trace!("symbol {symbol:?} locations {locations:?}");
    }

    let mut used_library_object_idxs = HashSet::new();

    // Collect all symbols into global symbol table
    let mut global_symbols = collect_global_symbols(&input_object_files)?;

    // Build string tables map
    let mut string_tables: HashMap<_, _> = input_object_files
        .iter()
        .enumerate()
        .filter_map(|(idx, obj)| obj.string_table.as_ref().map(|st| (ObjectIdx(idx), st)))
        .collect();

    let _ = global_symbols.resolve_symbols(&string_tables);

    // Find entry point and trace symbol usage
    let (_, mut symbol_usage) =
        find_entry_point(&input_object_files, &global_symbols, &string_tables)?;

    // Keep resolving symbols until no more undefined symbols or no more resolutions possible
    loop {
        debug!("symbol usage: {symbol_usage:#?}");

        match global_symbols.resolve_symbols(&string_tables) {
            Ok(_) => break, // All symbols resolved
            Err(SymbolResolutionError::Other(other)) => return Err(other),
            Err(SymbolResolutionError::UnresolvedSymbols {
                undefined_symbols, ..
            }) => {
                // // Check if we made any progress
                // if successful_resolutions == 0 {
                //     // could not resolve any new symbols since the last cycle, bail
                //     error!("unresolved symbols: {:?}", undefined_symbols);
                //     bail!("unresolved symbols");
                // } else {
                // }
                debug!("unresolved symbols: {:?}", undefined_symbols);

                // we only want the undefined symbols that are actually being
                // used
                let undefined_symbols = undefined_symbols
                    .into_iter()
                    .filter(|s| symbol_usage.undefined_symbols.contains(s))
                    .collect_vec();

                if undefined_symbols.is_empty() {
                    break;
                }

                // Search libraries using symbol map
                for undefined_symbol in undefined_symbols {
                    let _span = debug_span!("searching for symbol", undefined_symbol).entered();

                    if !symbol_usage.undefined_symbols.contains(undefined_symbol) {
                        debug!("unresolved symbol is not used, ignoring");
                        continue;
                    }

                    let matches =
                        symbol_to_library_map
                            .get(undefined_symbol)
                            .with_context(|| {
                                format!("could not resolve symbol {undefined_symbol:?}")
                            })?;

                    for &(lib_idx, object_idx) in matches {
                        let library = &libraries[lib_idx.0];
                        let obj = library.objects.get(&object_idx).unwrap();

                        debug!("found symbol {undefined_symbol:?} in library {lib_idx:?} ({:?}) object {object_idx:?}", library.path);

                        // Skip if we've already included this object
                        if used_library_object_idxs.contains(&object_idx) {
                            debug!("object is already included, skipping");
                            continue;
                        }

                        if let Some(symbol_table) = &obj.symbol_table {
                            let string_table = obj.string_table.as_ref();

                            let symbol = symbol_table.entries
                                .iter()
                                .find(|entry| entry.name.as_str(string_table) == Some(undefined_symbol))
                                .with_context(|| format!("expected to find undefined symbol {undefined_symbol:?} in library {lib_idx:?} object {object_idx:?} but it wasn't there"))?;

                            if symbol.section_number <= 0 {
                                debug!("symbol is declared here, but not defined, continuing");
                                continue;
                            }

                            let section_map = obj.sections.iter().map(|s| (s.id, s)).collect();

                            // Add this object to symbol table
                            global_symbols.add_all(
                                symbol_table,
                                string_table,
                                &section_map,
                                object_idx,
                            )?;

                            if let Some(string_table) = string_table {
                                string_tables.insert(object_idx, string_table);
                            }

                            trace_symbol_usage(
                                symbol,
                                &global_symbols,
                                string_table,
                                &section_map,
                                object_idx,
                                &mut symbol_usage,
                            )?;

                            symbol_usage.used_symbols.insert(undefined_symbol);
                            symbol_usage.undefined_symbols.remove(undefined_symbol);

                            used_library_object_idxs.insert(object_idx);
                            break;
                        }
                    }
                }
            }
        }
    }

    info!("symbol resolution complete");

    global_symbols.select_comdat_symbols();

    let mut used_object_files = input_object_files.clone();
    // Add used library objects
    for library in &libraries {
        used_object_files.extend(
            library
                .objects
                .values()
                .filter(|o| used_library_object_idxs.contains(&o.idx))
                .cloned(),
        );
    }

    let mut sections = used_object_files
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

    // Find entry point and trace symbol usage
    let (entry_point_def, symbol_usage) =
        find_entry_point(&used_object_files, &global_symbols, &string_tables)?;

    // println!("Used symbols: {:?}", symbol_usage.used_symbols);
    // println!("Undefined symbols: {:?}", symbol_usage.undefined_symbols);

    // let entry_point = match entry_point_def {
    //     link::symbol_table::GlobalSymbolDefinition::Simple(simple) => simple.entry.value,
    //     _ => bail!("entry point has unexpected definition type"),
    // };

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

            address_of_entry_point: 0,
            // address_of_entry_point: entry_point,
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
fn count_section_totals(merged_sections: &[coff::Section<'_>]) -> (u32, u32, u32) {
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
    object_files: &'b [Object<'a>],
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

#[derive(Debug, Default)]
struct SymbolUsage<'a> {
    // Symbols that are defined and used
    used_symbols: HashSet<&'a str>,
    // Symbols that are used but not defined
    undefined_symbols: HashSet<&'a str>,
}

#[tracing::instrument(skip_all, level = Level::DEBUG)]
fn trace_symbol_usage<'a: 'b, 'b>(
    symbol: &'a SymbolTableEntry,
    global_symbols: &'b GlobalSymbolTable<'a>,
    string_table: Option<&'b StringTable<'a>>,
    section_map: &HashMap<SectionId, &Section<'a>>,
    object_idx: ObjectIdx,
    usage: &mut SymbolUsage<'a>,
) -> anyhow::Result<()> {
    // Get symbol name
    let name = symbol
        .name
        .as_str(string_table)
        .context("could not resolve symbol name")?;

    let section_idx = if symbol.section_number <= 0 {
        usage.undefined_symbols.insert(name);
        return Ok(());
    } else {
        SectionIdx(symbol.section_number as usize - 1)
    };

    let section_id = SectionId {
        section_idx,
        object_idx,
    };

    let section = section_map
        .get(&section_id)
        .context("could not find section for symbol")?;

    // Skip if we've already processed this symbol
    if !usage.used_symbols.insert(name) {
        return Ok(());
    }

    // Process relocations that reference other symbols
    for reloc in &section.relocations {
        let symbol_idx = SymbolIdx(reloc.symbol_table_index as usize);

        debug!(
            "processing relocation for symbol {name} ({symbol_idx:x?}, {:?})",
            section.id
        );

        let reloc_target_sym = global_symbols
            .get_local_symbol(object_idx, symbol_idx)
            .with_context(|| format!("could not find local symbol in table {global_symbols:#?}"))?;

        let reloc_target_entry = match reloc_target_sym {
            LocalSymbol::External { entry, .. }
            | LocalSymbol::Static { entry, .. }
            | LocalSymbol::ComdatStatic { entry, .. } => entry,
            LocalSymbol::Weak { alternate, .. } => alternate,
        };

        trace!(
            "symbol {name} references local symbol {:?}",
            reloc_target_entry.name.as_str(string_table)
        );

        trace_symbol_usage(
            reloc_target_entry,
            global_symbols,
            string_table,
            section_map,
            object_idx,
            usage,
        )?;
    }

    Ok(())
}

#[tracing::instrument(skip_all, level = Level::INFO)]
fn find_entry_point<'a: 'b, 'b>(
    object_files: &'b [Object<'a>],
    global_symbols: &'b GlobalSymbolTable<'a>,
    string_tables: &'b HashMap<ObjectIdx, &'b StringTable<'a>>,
) -> anyhow::Result<(SectionId, SymbolUsage<'a>)> {
    // Look for _main or mainCRTStartup symbol
    for name in ["_main", "mainCRTStartup"] {
        if let Some(symbol) = global_symbols.get_global(name) {
            if let Some(def) = &symbol.definition {
                debug!("found defined potential entrypoint {name}");

                match def {
                    GlobalSymbolDefinition::Simple(simple) => {
                        let string_table =
                            string_tables.get(&simple.section_id.object_idx).copied();

                        // Found entry point symbol - trace its usage
                        let mut usage = SymbolUsage::default();

                        // Find the section containing this symbol
                        for obj in object_files {
                            let section_map = obj.sections.iter().map(|s| (s.id, s)).collect();

                            trace_symbol_usage(
                                simple.entry,
                                global_symbols,
                                string_table,
                                &section_map,
                                obj.idx,
                                &mut usage,
                            )?;

                            return Ok((simple.section_id, usage));
                        }
                    }
                    GlobalSymbolDefinition::Comdat(_) => unimplemented!(),
                }
            }
        }
    }

    bail!("could not find entry point symbol (_main or mainCRTStartup)")
}

fn order_and_merge_sections(
    mut sections: Vec<coff::Section<'_>>,
) -> anyhow::Result<Vec<coff::Section<'_>>> {
    sections.sort_by(|s1, s2| {
        // sort sections by name
        return s1.header.name.cmp(&s2.header.name);
    });

    // merge sections with same name
    let mut merged_sections: Vec<coff::Section<'_>> = vec![];
    let mut prev: Option<coff::Section<'_>> = None;

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
