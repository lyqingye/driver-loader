use anyhow::Result;
use goblin::pe::PE;
use std::{fs::OpenOptions, path::Path};

pub fn download<P: AsRef<Path> + ?Sized>(exe_path: &P, output_path: &P) -> Result<()> {
    let pdb_file = OpenOptions::new()
        .read(true)
        .write(false)
        .create(false)
        .open(exe_path)?;
    
    // load exe file by using mmap
    let pdb_file_data = unsafe { memmap::MmapOptions::new().map(&pdb_file)? };

    // parse pe file to get debug info
    let pe = PE::parse(pdb_file_data.as_ref())?;
    let debug_data = pe
        .debug_data
        .ok_or(anyhow::anyhow!("debug data not found"))?;
    let codeview_info = debug_data
        .codeview_pdb70_debug_info
        .ok_or(anyhow::anyhow!("code view debug info not found"))?;

    // build download url by codeview info
    let file = codeview_info.filename;
    let age = codeview_info.age;
    let guid = codeview_info.signature;
    let guid_str = format!("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:X}",
                        guid[3], guid[2], guid[1], guid[0], guid[5], guid[4], guid[7], guid[6],
                        guid[8],guid[9],guid[10],guid[11],guid[12],guid[13],guid[14], guid[15], age);
    let file = std::ffi::CStr::from_bytes_with_nul(file)?.to_str()?;
    let url = format!(
        "{}/{}/{}/{}",
        "https://msdl.microsoft.com/download/symbols", file, guid_str, file
    );

    // download and write pdb file
    let mut response = reqwest::blocking::Client::new()
        .get(url)
        .header(
            reqwest::header::USER_AGENT,
            "Microsoft-Symbol-Server/6.11.0001.402",
        )
        .send()?;
    let mut output_file = std::fs::File::create(output_path)?;
    response.copy_to(&mut output_file)?;
    Ok(())
}

#[cfg(test)]
mod test {
    use std::fs::remove_file;

    use super::*;
    use pdb::{FallibleIterator, TypeData};

    #[test]
    fn test_download_pdb() {
        assert!(download("C:\\Windows\\System32\\ntoskrnl.exe", "download.bin").is_ok());
        remove_file("download.bin").unwrap();
    }

    #[test]
    fn test_pdb() {
        let file = std::fs::File::open(
            "F:\\windbgsymbols\\ntkrnlmp.pdb\\35A038B1F6E2E8CAF642111E6EC66F571\\ntkrnlmp.pdb",
        )
        .unwrap();
        let mut pdb = pdb::PDB::open(file).unwrap();
        // pdb.pdb_information().unwrap();
        let type_information = pdb.type_information().unwrap();
        let mut type_finder = type_information.finder();

        let mut type_iter = type_information.iter();
        while let Some(typ) = type_iter.next().unwrap() {
            // keep building the index
            type_finder.update(&type_iter);

            if let Ok(pdb::TypeData::Class(class)) = typ.parse() {
                if class.name.as_bytes().eq(b"_HANDLE_TABLE")
                    && !class.properties.forward_reference()
                {
                    println!("{:?} {:x}", class.name.to_string(), class.size);
                    match type_finder
                        .find(class.fields.unwrap())
                        .unwrap()
                        .parse()
                        .unwrap()
                    {
                        pdb::TypeData::Class(data) => {
                            println!("{:?}", data);
                        }
                        pdb::TypeData::Enumeration(data) => {
                            println!("{:?}", data);
                        }
                        pdb::TypeData::FieldList(fields) => {
                            for ele in fields.fields {
                                match ele {
                                    TypeData::Member(f) => {
                                        println!("{:?} + {:x}", f.name.to_string(), f.offset);
                                    }
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        let symbol_table = pdb.global_symbols().unwrap();
        let address_map = pdb.address_map().unwrap();
        let mut symbols = symbol_table.iter();
        while let Some(symbol) = symbols.next().unwrap() {
            match symbol.parse() {
                Ok(pdb::SymbolData::Public(data)) => {
                    // we found the location of a function!
                    let rva = data.offset.to_rva(&address_map).unwrap_or_default();
                    if data.name.to_string() == "PspCidTable" {
                        println!("{} is {}", rva, data.name);
                    }
                    if data.name.to_string() == "ExBlockOnAddressPushLock" {
                        println!("{} is {}", rva, data.name);
                    }
                    if data.name.to_string() == "ExfUnblockPushLock" {
                        println!("{} is {}", rva, data.name);
                    }
                    if data.name.to_string() == "_HANDLE_TABLE" {
                        println!("{} is {}", rva, data.name);
                    }
                    // println!("{} is {} {:?}", rva, data.name,data);
                }
                Ok(pdb::SymbolData::RegisterRelative(data)) => {
                    println!("{} ", data.name);
                }

                _ => {}
            }
        }
    }
}
