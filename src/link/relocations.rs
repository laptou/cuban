use std::collections::HashMap;

use anyhow::{bail, Context};

use crate::coff::{
    relocations::{I386RelocationType, RelocationType},
    symbol_table::SymbolTableEntry,
    CoffSection, ObjectIdx, SectionId, SectionIdx, SymbolIdx,
};

use super::symbol_table::{GlobalSymbolTable, LocalSymbol};

pub fn process_all_relocations<'a>(
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

    let section_map: HashMap<_, _> = sections.iter().map(|s| (s.id, s)).collect();

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
            &section_map,
        )?;

        new_sections.push(new_section);
    }

    sections.clone_from_slice(&new_sections);

    Ok(())
}

fn process_section_relocations<'a>(
    section: &mut CoffSection<'a>,
    global_symbols: &GlobalSymbolTable<'a>,
    image_base: u64,
    section_rva: u64,
    section_map: &HashMap<SectionId, &CoffSection<'a>>,
) -> anyhow::Result<()> {
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
            .get_local_symbol(section.id.object_idx, SymbolIdx(reloc.symbol_table_index as usize))
            .with_context(|| format!(
                "invalid symbol reference in relocation: {reloc:?} object_idx = {:?} symbol_table_idx = {:?}",
                section.id.object_idx, reloc.symbol_table_index
            ))?;

        // local symbol might be weak, external, etc., so we need to resolve
        let (target_symbol, target_section) =
            resolve_local_symbol(&local_symbol, section_map, section.id.object_idx)?;

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

fn resolve_local_symbol<'a: 'b, 'b>(
    local_symbol: &LocalSymbol<'a>,
    section_map: &'b HashMap<SectionId, &CoffSection<'a>>,
    object_idx: ObjectIdx,
) -> anyhow::Result<(&'a SymbolTableEntry, &'b CoffSection<'a>)> {
    match local_symbol {
        LocalSymbol::External { entry, resolution } => {
            // is this external symbol defined in this object?
            if entry.section_number > 0 {
                let section_id = SectionId {
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

                let section_id = SectionId {
                    object_idx: gs.object_idx,
                    section_idx: gs.section_idx,
                };

                let section = section_map
                    .get(&section_id)
                    .context("could not resolve target section")?;

                return Ok((gs.entry, section));
            }
        }
        LocalSymbol::Weak {
            resolution,
            alternate,
            ..
        } => {
            // for weak symbols, use the resolution if we have one,
            // otherwise fall back to the local alternate
            if let Some(resolution) = resolution.as_ref() {
                let section_id = SectionId {
                    object_idx: resolution.object_idx,
                    section_idx: resolution.section_idx,
                };

                let section = section_map
                    .get(&section_id)
                    .context("could not resolve target section")?;

                return Ok((resolution.entry, section));
            }

            let section_id = SectionId {
                object_idx,
                section_idx: SectionIdx(alternate.section_number as usize - 1),
            };

            let section = section_map
                .get(&section_id)
                .context("could not resolve target section")?;

            return Ok((*alternate, section));
        }
        LocalSymbol::Static { entry } => {
            let section_id = SectionId {
                object_idx,
                section_idx: SectionIdx(entry.section_number as usize - 1),
            };

            let section = section_map
                .get(&section_id)
                .context("could not resolve target section")?;

            return Ok((*entry, section));
        }
        LocalSymbol::ComdatStatic { entry, .. } => {
            let section_id = SectionId {
                object_idx,
                section_idx: SectionIdx(entry.section_number as usize - 1),
            };

            let section = section_map
                .get(&section_id)
                .context("could not resolve target section")?;

            return Ok((*entry, section));
        }
    }
}
