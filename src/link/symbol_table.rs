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
    pub definition: Option<GlobalSymbolDefinition<'a>>,
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
                            definition: None,
                        });

                        match gs.definition {
                            Some(_) => bail!("external symbol {name:?} is defined twice"),
                            None => {
                                gs.definition = Some(GlobalSymbolDefinition {
                                    // section_number uses 1-based indexing
                                    section_idx: SectionIdx(entry.section_number as usize - 1),
                                    object_idx,
                                    entry,
                                })
                            }
                        }
                    } else {
                        // put a stub in the GST
                        self.global_symbols.insert(
                            name,
                            GlobalSymbol {
                                name,
                                definition: None,
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
                StorageClass::Static => {
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

    // // Get a symbol by index from its original symbol table
    // pub fn get_local_symbol_named(
    //     &self,
    //     object_idx: ObjectIdx,
    //     name: &str,
    // ) -> Option<&SymbolTableEntry> {
    //     match self.local_symbols.get(&object_idx) {
    //         Some(obj_symbols) => obj_symbols.get_named(name),
    //         None => None,
    //     }
    // }
}
