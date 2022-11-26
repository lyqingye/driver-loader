use anyhow::Result;
use memmap::Mmap;
use pdb::{FallibleIterator, ItemFinder, TypeIndex, ItemIter};
use std::{any::Any, collections::HashMap, hash::Hash, ops::Deref, path::Path};

#[allow(dead_code)]
#[derive(Debug)]
pub struct SymbolManager<'a> {
    pdb: pdb::PDB<'a, std::io::Cursor<Mmap>>,
    symbol_table: pdb::SymbolTable<'a>,
    address_map: pdb::AddressMap<'a>,
    type_information: pdb::TypeInformation<'a>,
    class_info_cache: HashMap<String, ClassInfo>,
}

#[derive(Debug, Clone)]
pub struct ClassInfo {
    pub name: String,
    pub size: usize,
    pub type_index: TypeIndex,
    pub fileds: HashMap<String, ClassField>,
}

#[derive(Debug, Clone)]
pub struct ClassField {
    pub offset: usize,
    pub type_index: TypeIndex,
}

impl<'a> SymbolManager<'a> {
    pub fn find_symbol_offset_by_name(&mut self, symbol_name: &str) -> Result<usize> {
        let mut symbols = self.symbol_table.iter();
        while let Ok(Some(symbol)) = symbols.next() {
            match symbol.parse() {
                Ok(pdb::SymbolData::Public(data)) => {
                    // we found the location of a function!
                    let rva = data.offset.to_rva(&self.address_map).unwrap_or_default();
                    if data.name.to_string() == symbol_name {
                        return Ok(rva.0 as usize);
                    }
                }
                _ => {}
            }
        }
        Err(anyhow::anyhow!("symbol: {} not found", symbol_name))
    }

    pub fn find_class_by_name(&mut self, class_name: &str) -> Result<ClassInfo> {
        if let Some(cached) = self.class_info_cache.get(class_name) {
            return Ok(cached.to_owned());
        }
        let mut type_iter = self.type_information.iter();
        let mut finder = self.type_information.finder();
        while let Ok(Some(typ)) = type_iter.next() {
            // keep building the index
            finder.update(&type_iter);
            if let Ok(pdb::TypeData::Class(class)) = typ.parse() {
                if class.name.to_string() == class_name && !class.properties.forward_reference() {
                    let mut clazz = ClassInfo {
                        name: class_name.to_owned(),
                        type_index: typ.index(),
                        size: class.size as usize,
                        fileds: HashMap::new(),
                    };
                    if let Some(index) = class.fields {
                        match finder.find(index)?.parse()? {
                            pdb::TypeData::FieldList(fields) => {
                                for el in fields.fields {
                                    match el {
                                        pdb::TypeData::Member(m) => {
                                            let member_name = m.name.to_string().to_string();
                                            clazz.fileds.insert(
                                                member_name,
                                                ClassField {
                                                    offset: m.offset as usize,
                                                    type_index: m.field_type,
                                                },
                                            );
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    self.class_info_cache
                        .insert(class_name.to_owned(), clazz.clone());
                    return Ok(clazz);
                }
            }
        }
        Err(anyhow::anyhow!("symbol: {} not found", class_name))
    }

    pub fn new(pdb_path: String) -> Result<SymbolManager<'a>> {
        let pdb_file = std::fs::OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .open(pdb_path)?;

        // load exe file by using mmap
        let pdb_file_data = unsafe { memmap::MmapOptions::new().map(&pdb_file)? };
        let cursor = std::io::Cursor::new(pdb_file_data);
        let mut pdb = pdb::PDB::open(cursor)?;
        let symbol_table = pdb.global_symbols()?;
        let address_map = pdb.address_map()?;
        let type_information = pdb.type_information()?;
        Ok(SymbolManager {
            pdb,
            symbol_table,
            address_map,
            type_information,
            class_info_cache: HashMap::new(),
        })
    }

}


#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_find_symbol() {
        let mut manager = SymbolManager::new(
            "F:\\windbgsymbols\\ntkrnlmp.pdb\\35A038B1F6E2E8CAF642111E6EC66F571\\ntkrnlmp.pdb"
                .to_string(),
        )
        .unwrap();
        let offset = manager.find_symbol_offset_by_name("PspCidTable").unwrap();
        println!("{:x}", offset);
    }

    #[test]
    fn test_find_class() {
        let mut manager =  SymbolManager::new(
            "F:\\windbgsymbols\\ntkrnlmp.pdb\\35A038B1F6E2E8CAF642111E6EC66F571\\ntkrnlmp.pdb"
                .to_string(),
        )
        .unwrap();
        let clazz = manager
            .find_class_by_name("_OBJECT_TYPE")
            .unwrap();
        println!("{:?}", clazz);

    }
}
