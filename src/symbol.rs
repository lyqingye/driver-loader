use anyhow::Result;
use memmap::Mmap;
use pdb::FallibleIterator;
use std::{any::Any, collections::HashMap, ops::Deref, path::Path};

#[allow(dead_code)]
#[derive(Debug)]
pub struct SymbolManager<'a> {
    pdb: pdb::PDB<'a, std::io::Cursor<Mmap>>,
    symbol_table: pdb::SymbolTable<'a>,
    address_map: pdb::AddressMap<'a>,
    type_information: pdb::TypeInformation<'a>,
}

#[derive(Debug)]
pub struct ClassInfo {
    pub name: String,
    pub size: usize,
    pub fileds: HashMap<String, ClassField>,
}

#[derive(Debug)]
pub struct ClassField {
    pub offset: usize,
}

impl<'a> SymbolManager<'a> {
    pub fn find_symbol_offset_by_name(&mut self, symbol_name: String) -> Option<u64> {
        let mut symbols = self.symbol_table.iter();
        while let Ok(Some(symbol)) = symbols.next() {
            match symbol.parse() {
                Ok(pdb::SymbolData::Public(data)) => {
                    // we found the location of a function!
                    let rva = data.offset.to_rva(&self.address_map).unwrap_or_default();
                    if data.name.to_string() == symbol_name {
                        return Some(rva.0.into());
                    }
                }
                _ => {}
            }
        }
        None
    }

    pub fn find_class_by_name(&mut self, class_name: String) -> Option<ClassInfo> {
        let mut type_iter = self.type_information.iter();
        let mut finder = self.type_information.finder();
        while let Ok(Some(typ)) = type_iter.next() {
            // keep building the index
            finder.update(&type_iter);
            if let Ok(pdb::TypeData::Class(class)) = typ.parse() {
                if class.name.to_string() == class_name.clone()
                    && !class.properties.forward_reference()
                {
                    let mut clazz = ClassInfo {
                        name: class_name.clone(),
                        size: class.size as usize,
                        fileds: HashMap::new(),
                    };
                    if let Some(index) = class.fields {
                        match finder.find(index).ok()?.parse().ok()? {
                            pdb::TypeData::FieldList(fields) => {
                                for el in fields.fields {
                                    match el {
                                        pdb::TypeData::Member(m) => {
                                            let member_name = m.name.to_string().to_string();
                                            clazz.fileds.insert(
                                                member_name,
                                                ClassField {
                                                    offset: m.offset as usize,
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
                    return Some(clazz);
                }
            }
        }
        None
    }
}

pub fn new<P: AsRef<Path> + ?Sized>(pdb_path: &P) -> Result<SymbolManager> {
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
    })
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_find_symbol() {
        let mut manager =
            new("F:\\windbgsymbols\\ntkrnlmp.pdb\\35A038B1F6E2E8CAF642111E6EC66F571\\ntkrnlmp.pdb")
                .unwrap();
        let offset = manager
            .find_symbol_offset_by_name("PspCidTable".to_owned())
            .unwrap();
        println!("{:x}", offset);
    }

    #[test]
    fn test_find_class() {
        let mut manager =
            new("F:\\windbgsymbols\\ntkrnlmp.pdb\\35A038B1F6E2E8CAF642111E6EC66F571\\ntkrnlmp.pdb")
                .unwrap();
        let clazz = manager
            .find_class_by_name("_HANDLE_TABLE".to_string())
            .unwrap();
        println!("{:?}", clazz);
    }
}
