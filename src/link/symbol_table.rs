use std::{borrow::Cow, collections::HashMap};

use anyhow::{bail, Context};

use crate::coff::{
    string_table::StringTable,
    symbol_table::{
        AuxSymbolRecord, Name, StorageClass, SymbolTable, SymbolTableEntry,
        WeakExternalCharacteristics,
    },
    ObjectIdx, SectionIdx, SymbolIdx,
};

#[derive(Debug, Clone, Default)]
pub struct LocalSymbolTable<'a> {
    symbols: Vec<LocalSymbol<'a>>,
    // name_map: HashMap<&'a str, &'a SymbolTableEntry>,
}

#[derive(Debug, Clone)]
pub enum LocalSymbol<'a> {
    Static {
        entry: &'a SymbolTableEntry,
    },
    External {
        entry: &'a SymbolTableEntry,
        resolution: Option<GlobalSymbolDefinition<'a>>,
    },
    Weak {
        name: &'a str,

        /// Set after symbol resolution is complete
        resolution: Option<GlobalSymbolDefinition<'a>>,

        /// The symbol to use if the weak symbol is not found
        alternate: &'a SymbolTableEntry,

        characteristics: WeakExternalCharacteristics,
    },
}

impl<'a> LocalSymbolTable<'a> {
    fn insert(&mut self, entry: LocalSymbol<'a>) -> anyhow::Result<()> {
        self.symbols.push(entry);

        Ok(())
    }

    fn get_idx(&self, symbol_idx: SymbolIdx) -> Option<LocalSymbol<'a>> {
        self.symbols.get(symbol_idx.0).cloned()
    }

    // fn get_named(&self, name: &str) -> Option<&'a SymbolTableEntry> {
    //     self.name_map.get(&Cow::Borrowed(name)).copied()
    // }
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
    /// Multiple definitions for COMDAT symbols
    pub definitions: Vec<GlobalSymbolDefinition<'a>>,
    /// Optional COMDAT selection mode
    pub comdat_selection: Option<ComdatSelection>,
}

#[derive(Debug, Clone)]
pub struct GlobalSymbolDefinition<'a> {
    /// The entry in the symbol table that provides a definition for this symbol
    pub entry: &'a SymbolTableEntry,

    pub section_idx: SectionIdx,

    /// The object file index this symbol came from
    pub object_idx: ObjectIdx,
}

impl<'a> GlobalSymbolTable<'a> {
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
        object_idx: ObjectIdx,
    ) -> anyhow::Result<()> {
        // Process each symbol in the table
        for entry in &symbol_table.entries {
            // Resolve the symbol name
            let name = entry
                .name
                .as_str(string_table)
                .context("could not resolve symbol name")?;

            match entry.storage_class {
                StorageClass::External => {
                    // external symbols are global but aren't necessarily defined,
                    // add them to GST and check for conflict
                    let is_defined = entry.section_number > 0;

                    if is_defined {
                        let gs = self.global_symbols.entry(name).or_insert(GlobalSymbol {
                            name,
                            definitions: Vec::new(),
                            comdat_selection: None,
                        });

                        // Add this definition
                        gs.definitions.push(GlobalSymbolDefinition {
                            // section_number uses 1-based indexing
                            section_idx: SectionIdx(entry.section_number as usize - 1),
                            object_idx,
                            entry,
                        });
                    } else {
                        // put a stub in the GST
                        self.global_symbols.insert(
                            name,
                            GlobalSymbol {
                                name,
                                definitions: Vec::new(),
                                comdat_selection: None,
                            },
                        );
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
                    let &[AuxSymbolRecord::WeakExternal {
                        tag_index,
                        characteristics,
                    }] = &entry.aux_symbols[..]
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
                StorageClass::Static | StorageClass::Label => {
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
    ) -> anyhow::Result<()> {
        // Clone the local_symbols keys since we need to modify the map while iterating
        let object_indices: Vec<_> = self.local_symbols.keys().cloned().collect();

        for object_idx in object_indices {
            let local_table = self.local_symbols.get_mut(&object_idx).unwrap();
            
            // Need to process each symbol in the local table
            for symbol in &mut local_table.symbols {
                match symbol {
                    LocalSymbol::External { entry, resolution } => {
                        // Get symbol name
                        let name = entry.name.as_str(string_tables.get(&object_idx).copied())
                            .context("could not resolve external symbol name")?;
                        
                        // Look up in global symbols table
                        if let Some(global_sym) = self.global_symbols.get(name) {
                            if !global_sym.definitions.is_empty() {
                                // Select definition based on COMDAT selection mode or require exactly one
                                let selected_def = match global_sym.comdat_selection {
                                    Some(ComdatSelection::Any) => {
                                        // Pick first definition
                                        Some(global_sym.definitions[0].clone())
                                    }
                                    Some(ComdatSelection::Largest) => {
                                        // Pick definition with largest size
                                        global_sym.definitions.iter()
                                            .max_by_key(|def| def.entry.value)
                                            .cloned()
                                    }
                                    Some(ComdatSelection::SameSize) => {
                                        // Check all definitions have same size
                                        let first_size = global_sym.definitions[0].entry.value;
                                        if global_sym.definitions.iter().all(|def| def.entry.value == first_size) {
                                            Some(global_sym.definitions[0].clone())
                                        } else {
                                            bail!("COMDAT symbol {name} has definitions with different sizes");
                                        }
                                    }
                                    Some(ComdatSelection::ExactMatch) => {
                                        // TODO: Implement exact content matching
                                        bail!("COMDAT ExactMatch selection not implemented");
                                    }
                                    Some(ComdatSelection::NoDuplicates) => {
                                        if global_sym.definitions.len() > 1 {
                                            bail!("COMDAT symbol {name} has multiple definitions with NoDuplicates selection");
                                        }
                                        Some(global_sym.definitions[0].clone())
                                    }
                                    Some(ComdatSelection::Associative) => {
                                        // TODO: Implement associative selection
                                        bail!("COMDAT Associative selection not implemented");
                                    }
                                    None => {
                                        // No COMDAT - require exactly one definition
                                        if global_sym.definitions.len() != 1 {
                                            bail!("non-COMDAT symbol {name} has multiple definitions");
                                        }
                                        Some(global_sym.definitions[0].clone())
                                    }
                                }?;
                                
                                *resolution = Some(selected_def);
                            }
                        }
                    }
                    LocalSymbol::Weak { name, resolution, characteristics, .. } => {
                        // Look up in global symbols table
                        if let Some(global_sym) = self.global_symbols.get(name) {
                            if let Some(def) = &global_sym.definition {
                                match characteristics {
                                    WeakExternalCharacteristics::NoLibrarySearch => {
                                        // Only resolve if symbol is from the same object file
                                        if def.object_idx == object_idx {
                                            *resolution = Some(def.clone());
                                        }
                                    }
                                    WeakExternalCharacteristics::LibrarySearch => {
                                        // Resolve from any object file
                                        *resolution = Some(def.clone());
                                    }
                                    WeakExternalCharacteristics::Alias => {
                                        // Don't resolve - alternate symbol will be used directly
                                    }
                                }
                            }
                        }
                    }
                    LocalSymbol::Static { .. } => {
                        // Static symbols don't need resolution
                    }
                }
            }
        }

        Ok(())
    }
}
