use std::{borrow::Cow, collections::{HashMap, HashSet}};

use anyhow::Context;

#[derive(Debug)]
pub struct UnresolvedSymbolsError<'a> {
    pub undefined_symbols: HashSet<&'a str>,
}
use derive_more::From;

use crate::{
    coff::{
        string_table::StringTable,
        symbol_table::{
            AuxSymbolRecord, AuxSymbolRecordSection, AuxSymbolRecordWeakExternal, ComdatSelection,
            Name, StorageClass, SymbolTable, SymbolTableEntry, WeakExternalCharacteristics,
        },
        CoffSection, ObjectIdx, SectionId, SectionIdx, SymbolIdx,
    },
    flags::SectionCharacteristics,
};

#[derive(Debug, Clone, Default)]
pub struct LocalSymbolTable<'a> {
    symbols: Vec<LocalSymbol<'a>>,
    comdat_symbols: HashMap<SectionIdx, &'a SymbolTableEntry>, // name_map: HashMap<&'a str, &'a SymbolTableEntry>,
}

#[derive(Debug, Clone)]
pub enum LocalSymbol<'a> {
    Static {
        entry: &'a SymbolTableEntry,
    },
    ComdatStatic {
        entry: &'a SymbolTableEntry,
    },
    External {
        entry: &'a SymbolTableEntry,
        resolution: Option<GlobalSymbolSimpleDefinition<'a>>,
    },
    Weak {
        name: &'a str,
        /// The symbol to use if the weak symbol is not found
        alternate: &'a SymbolTableEntry,

        /// Set after symbol resolution is complete
        resolution: Option<GlobalSymbolSimpleDefinition<'a>>,
        characteristics: WeakExternalCharacteristics,
    },
}

impl<'a> LocalSymbolTable<'a> {
    fn insert(&mut self, entry: LocalSymbol<'a>) -> anyhow::Result<()> {
        if let LocalSymbol::ComdatStatic { entry } = &entry {
            let section_idx = SectionIdx(entry.section_number as usize - 1);

            println!("found COMDAT symbol at {section_idx:?}");

            self.comdat_symbols.insert(section_idx, *entry);
        }

        self.symbols.push(entry);

        if !undefined_symbols.is_empty() {
            Err(UnresolvedSymbolsError { undefined_symbols })
        } else {
            Ok(())
        }
    }

    fn get_idx(&self, symbol_idx: SymbolIdx) -> Option<LocalSymbol<'a>> {
        self.symbols.get(symbol_idx.0).cloned()
    }

    fn get_comdat(&self, section_idx: SectionIdx) -> Option<&'a SymbolTableEntry> {
        self.comdat_symbols.get(&section_idx).copied()
    }
}

#[derive(Debug, Clone)]
pub struct GlobalSymbolTable<'a> {
    // Map from symbol name to symbol definition
    global_symbols: HashMap<&'a str, GlobalSymbol<'a>>,

    local_symbols: HashMap<ObjectIdx, LocalSymbolTable<'a>>,
}

#[derive(Debug, Clone)]
pub struct GlobalSymbol<'a> {
    /// The name of this symbol
    pub name: &'a str,
    pub definition: Option<GlobalSymbolDefinition<'a>>,
}

#[derive(Debug, Clone, From)]
pub enum GlobalSymbolDefinition<'a> {
    Simple(GlobalSymbolSimpleDefinition<'a>),
    Comdat(GlobalSymbolComdatDefinition<'a>),
}

#[derive(Debug, Clone, Copy)]
pub struct GlobalSymbolSimpleDefinition<'a> {
    /// The entry in the symbol table that provides a definition for this symbol
    pub entry: &'a SymbolTableEntry,
    pub section_id: SectionId,
}

#[derive(Debug, Clone)]
pub struct GlobalSymbolComdatDefinition<'a> {
    pub definitions: Vec<(ComdatInfo, GlobalSymbolSimpleDefinition<'a>)>,
    pub selection_mode: ComdatSelection,
    pub selection: Option<SectionId>,
}

#[derive(Debug, Clone, Copy)]
pub struct ComdatInfo {
    pub section_len: usize,

    pub section_checksum: u32,

    /// if this is set, the associated section must be selected for this section
    /// to be selected
    pub association: Option<SectionId>,

    pub selection_mode: ComdatSelection,
}

fn get_comdat_info(
    entry: &SymbolTableEntry,
    section_map: &HashMap<SectionId, &CoffSection<'_>>,
    object_idx: ObjectIdx,
) -> anyhow::Result<Option<ComdatInfo>> {
    // is this a section symbol? if so, we need to check for COMDAT sections
    if let Some(section_info) = entry.section_info() {
        let section_id = SectionId {
            object_idx,
            section_idx: SectionIdx(entry.section_number as usize - 1),
        };

        let section = section_map
            .get(&section_id)
            .context("could not find section for symbol")?;

        let flags = section.header.characteristics;

        if flags.contains(SectionCharacteristics::LNK_COMDAT) {
            // we have a COMDAT section
            return Ok(Some(ComdatInfo {
                selection_mode: section_info.selection,
                section_len: section_info.length as usize,
                section_checksum: section_info.checksum,
                association: match section_info.selection {
                    ComdatSelection::Associative => Some(SectionId {
                        object_idx,
                        section_idx: SectionIdx(section_info.number as usize - 1),
                    }),
                    _ => None,
                },
            }));
        }
    }

    Ok(None)
}

impl<'a> GlobalSymbolTable<'a> {
    pub fn retain_used(&mut self, used_symbols: &HashSet<&'a str>) {
        self.global_symbols.retain(|name, _| used_symbols.contains(name));
    }

    pub fn new() -> Self {
        Self {
            global_symbols: HashMap::new(),
            local_symbols: HashMap::new(),
        }
    }

    pub fn add_all(
        &mut self,
        symbol_table: &'a SymbolTable,
        string_table: Option<&'a StringTable<'a>>,
        section_map: &HashMap<SectionId, &CoffSection<'a>>,
        object_idx: ObjectIdx,
    ) -> anyhow::Result<()> {
        // Process each symbol in the table
        for entry in &symbol_table.entries {
            // Resolve the symbol name
            let name = entry
                .name
                .as_str(string_table)
                .context("could not resolve symbol name")?;

            println!(
                "processing symbol {name} with storage class {:?}",
                entry.storage_class
            );

            match entry.storage_class {
                StorageClass::External => {
                    // external symbols are global but aren't necessarily defined,
                    // add them to GST and check for conflict
                    let is_defined = entry.section_number > 0;

                    if is_defined {
                        let gs = self.global_symbols.entry(name).or_insert(GlobalSymbol {
                            name,
                            definition: None,
                        });

                        // section_number uses 1-based indexing
                        let section_idx = SectionIdx(entry.section_number as usize - 1);

                        let new_def = GlobalSymbolSimpleDefinition {
                            section_id: SectionId {
                                object_idx,
                                section_idx,
                            },
                            entry,
                        };

                        let comdat_info = self
                            .local_symbols
                            .get(&object_idx)
                            .and_then(|ls| ls.get_comdat(section_idx))
                            .and_then(|comdat_entry| {
                                get_comdat_info(comdat_entry, section_map, object_idx).transpose()
                            })
                            .transpose()?;

                        if let Some(comdat_info) = comdat_info {
                            println!(
                                "found COMDAT info for symbol {name} at {:?}: {comdat_info:?}",
                                new_def.section_id
                            );

                            match &mut gs.definition {
                                Some(GlobalSymbolDefinition::Simple(..)) => {
                                    bail!("found both COMDAT and non-COMDAT sections for the symbol {name}");
                                }
                                Some(GlobalSymbolDefinition::Comdat(existing_comdat_def)) => {
                                    if existing_comdat_def.selection_mode
                                        != comdat_info.selection_mode
                                    {
                                        bail!("found conflicting COMDAT selection rules for the symbol {name}");
                                    }

                                    match comdat_info.selection_mode {
                                        ComdatSelection::NoDuplicates => {
                                            bail!(
                                                "found conflicting global definitions for COMDAT symbol {name}"
                                            );
                                        }
                                        ComdatSelection::ExactMatch => {
                                            // existing def must have same checksum
                                            let (existing_def_comdat_info, _) =
                                                existing_comdat_def.definitions.last().unwrap();
                                            if existing_def_comdat_info.section_checksum
                                                != comdat_info.section_checksum
                                            {
                                                bail!(
                                                    "found conflicting global definitions for COMDAT symbol {name} (COMDAT checksums did not match)"
                                                );
                                            }
                                        }
                                        ComdatSelection::SameSize => {
                                            // existing def must have same size
                                            let (existing_def_comdat_info, _) =
                                                existing_comdat_def.definitions.last().unwrap();
                                            if existing_def_comdat_info.section_len
                                                != comdat_info.section_len
                                            {
                                                bail!(
                                                    "found conflicting global definitions for COMDAT symbol {name} (COMDAT section lengths did not match)"
                                                );
                                            }
                                        }
                                        ComdatSelection::Any
                                        | ComdatSelection::Associative
                                        | ComdatSelection::Largest => {}
                                    }

                                    existing_comdat_def.definitions.push((comdat_info, new_def));
                                }
                                def @ None => {
                                    def.replace(
                                        GlobalSymbolComdatDefinition {
                                            selection_mode: comdat_info.selection_mode,
                                            selection: None,
                                            definitions: vec![(comdat_info, new_def)],
                                        }
                                        .into(),
                                    );
                                }
                            }
                        } else {
                            println!(
                                "did not find COMDAT info for symbol {name} at {:?}",
                                new_def.section_id
                            );

                            // Add this definition
                            let existing_def = gs.definition.replace(new_def.into());

                            if existing_def.is_some() {
                                bail!("conflicting global definitions for non-COMDAT symbol {name} (section {:?})", new_def.section_id)
                            }
                        }
                    } else {
                        if !self.global_symbols.contains_key(name) {
                            println!("symbol {name} is undefined");
                            // put a stub in the GST
                            self.global_symbols.insert(
                                name,
                                GlobalSymbol {
                                    name,
                                    definition: None,
                                },
                            );
                        } else {
                            println!("symbol {name} is undefined here, but already defined elsewhere");
                        }
                    }

                    self.local_symbols.entry(object_idx).or_default().insert(
                        LocalSymbol::External {
                            entry,
                            resolution: None,
                        },
                    )?;
                }
                StorageClass::WeakExternal => {
                    // weak external symbols are local
                    let &[AuxSymbolRecord::WeakExternal(AuxSymbolRecordWeakExternal {
                        tag_index,
                        characteristics,
                    })] = &entry.aux_symbols[..]
                    else {
                        bail!(
                            "weak external signal has unexpected aux symbols: {:?}",
                            entry.aux_symbols
                        )
                    };

                    let alternate_idx = SymbolIdx(tag_index as usize);

                    self.local_symbols.entry(object_idx).or_default().insert(
                        LocalSymbol::Weak {
                            name,
                            resolution: None,
                            alternate: symbol_table
                                .entries
                                .iter()
                                .find(|e| e.offset == alternate_idx)
                                .with_context(|| {
                                    format!("could not resolve alternate symbol for {name:?}")
                                })?,
                            characteristics,
                        },
                    )?;
                }
                StorageClass::Static | StorageClass::Label | StorageClass::Section => {
                    // is this a section symbol? if so, we need to check for COMDAT sections
                    if let Some(_) = entry.section_info() {
                        println!("symbol {name} is a section symbol");
                        if let Some(_) = get_comdat_info(entry, section_map, object_idx)? {
                            println!("symbol {name} is a COMDAT symbol");
                            self.local_symbols
                                .entry(object_idx)
                                .or_default()
                                .insert(LocalSymbol::ComdatStatic { entry })?;

                            continue;
                        }
                    }

                    // static symbols are local
                    self.local_symbols
                        .entry(object_idx)
                        .or_default()
                        .insert(LocalSymbol::Static { entry })?;
                }
                StorageClass::Function => {
                    // TODO
                }
                StorageClass::File => {
                    // ignore
                }
                other => bail!("unsupported symbol storage class {other:?}"),
            }
        }

        Ok(())
    }

    // Get a symbol by name
    pub fn get_global(&self, name: &str) -> Option<&GlobalSymbol<'a>> {
        self.global_symbols.get(name)
    }

    pub fn get_local_symbols(&self, object_idx: ObjectIdx) -> Option<&LocalSymbolTable> {
        self.local_symbols.get(&object_idx)
    }

    // Get a symbol by index from its original symbol table
    pub fn get_local_symbol(
        &self,
        object_idx: ObjectIdx,
        symbol_idx: SymbolIdx,
    ) -> Option<LocalSymbol> {
        match self.local_symbols.get(&object_idx) {
            Some(obj_symbols) => obj_symbols.get_idx(symbol_idx),
            None => None,
        }
    }

    pub fn resolve_symbols(
        &mut self,
        string_tables: &HashMap<ObjectIdx, &'a StringTable<'a>>,
    ) -> Result<(), UnresolvedSymbolsError<'a>> {
        let mut undefined_symbols = HashSet::new();
        // Resolve any global COMDAT symbols first
        for symbol in self.global_symbols.values_mut() {
            symbol.definition = Some(match symbol.definition.clone() {
                Some(def @ GlobalSymbolDefinition::Simple(_)) => {
                    // no action needed
                    def
                }
                Some(GlobalSymbolDefinition::Comdat(mut comdat_def)) => {
                    // we need to pick one of the available definitions of this
                    // symbol
                    GlobalSymbolDefinition::Simple(match comdat_def.definitions.len() {
                        0 => unreachable!(),
                        1 => {
                            // only one definition, we're done unless this is an
                            // associative definition
                            match comdat_def.selection_mode {
                                ComdatSelection::Associative => todo!(),
                                _ => {
                                    let (_, single_def) = comdat_def.definitions.pop().unwrap();
                                    single_def
                                }
                            }
                        }
                        _ => {
                            // multiple definitions, select one according to
                            // rule
                            match comdat_def.selection_mode {
                                ComdatSelection::Associative => todo!(),
                                // we don't even allow duplicates with the
                                // NoDuplicates mode to get added to the symbol
                                // table in the first place
                                ComdatSelection::NoDuplicates => unreachable!(),
                                // we validate whether these rules are satisfied
                                // when the symbol is added to the table, so
                                // just pick an arbitrary definition
                                ComdatSelection::Any
                                | ComdatSelection::ExactMatch
                                | ComdatSelection::SameSize => {
                                    let (_, last_def) = comdat_def.definitions.pop().unwrap();
                                    last_def
                                }
                                ComdatSelection::Largest => {
                                    let (_, largest_def) = comdat_def
                                        .definitions
                                        .into_iter()
                                        .max_by_key(|(comdat_info, _)| comdat_info.section_len)
                                        .unwrap();
                                    largest_def
                                }
                            }
                        }
                    })
                }
                None => {
                    undefined_symbols.insert(symbol.name);
                    continue;
                }
            })
        }

        // Clone the local_symbols keys since we need to modify the map while iterating
        let object_indices: Vec<_> = self.local_symbols.keys().cloned().collect();

        for object_idx in object_indices {
            let local_table = self.local_symbols.get_mut(&object_idx).unwrap();

            // Need to process each symbol in the local table
            for symbol in &mut local_table.symbols {
                match symbol {
                    LocalSymbol::External { entry, resolution } => {
                        if resolution.is_none() {
                            // Get symbol name
                            let name = entry
                                .name
                                .as_str(string_tables.get(&object_idx).copied())
                                .context("could not resolve external symbol name")?;

                            // Look up in global symbols table
                            if let Some(global_sym) = self.global_symbols.get(name) {
                                let global_def = global_sym.definition.clone().unwrap();
                                let GlobalSymbolDefinition::Simple(global_def) = global_def else {
                                    unreachable!()
                                };

                                resolution.replace(global_def);
                            } else {
                                undefined_symbols.insert(name);
                            }
                        }
                    }
                    LocalSymbol::Weak {
                        name,
                        resolution,
                        characteristics,
                        ..
                    } => {
                        // Look up in global symbols table
                        if let Some(global_sym) = self.global_symbols.get(name) {
                            if let Some(global_def) = &global_sym.definition {
                                let GlobalSymbolDefinition::Simple(global_def) = global_def else {
                                    unreachable!()
                                };

                                match characteristics {
                                    WeakExternalCharacteristics::NoLibrarySearch => {
                                        // Only resolve if symbol is from the same object file
                                        if global_def.section_id.object_idx == object_idx {
                                            *resolution = Some(global_def.clone());
                                        }
                                    }
                                    WeakExternalCharacteristics::LibrarySearch => {
                                        // Resolve from any object file
                                        *resolution = Some(global_def.clone());
                                    }
                                    WeakExternalCharacteristics::Alias => {
                                        // Don't resolve - alternate symbol will be used directly
                                    }
                                }
                            }
                        }
                    }
                    LocalSymbol::Static { .. } | LocalSymbol::ComdatStatic { .. } => {
                        // Static symbols don't need resolution
                    }
                }
            }
        }

        Ok(())
    }
}
