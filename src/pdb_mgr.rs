use crate::error::{DrvLdrError, Result};
use goblin::pe::PE;
use std::{fmt::Debug, fs::OpenOptions, path::Path, str::FromStr};

use crate::sym_mgr::{self, SymbolManager};

#[derive(Debug)]
pub struct PDBManager {
    cache_dir: String,
}

impl<'a> PDBManager {
    pub fn get_symbol_manager<P: AsRef<Path> + ?Sized>(
        &self,
        exe_path: &P,
    ) -> Result<SymbolManager<'a>> {
        let debug_info = self.get_pe_debug_info(exe_path)?;
        let pdb = format!("{}\\{}", self.cache_dir, debug_info.to_pdb_file_path());
        let pdb_path = std::path::PathBuf::from_str(pdb.as_str())?;
        if !pdb_path.exists() {
            self.download_pdb_file(&debug_info)?;
        }
        let mut result = sym_mgr::SymbolManager::new(pdb.clone());
        if result.is_err() {
            // retry
            std::fs::remove_file(pdb_path)?;
            self.download_pdb_file(&debug_info)?;
        }
        result = sym_mgr::SymbolManager::new(pdb);
        result
    }

    fn download_pdb_file(&self, debug_info: &DebugInfo) -> Result<()> {
        let url = debug_info.to_pdb_download_url();
        // download and write pdb file
        let mut response = reqwest::blocking::Client::new()
            .get(url)
            .header(
                reqwest::header::USER_AGENT,
                "Microsoft-Symbol-Server/6.11.0001.402",
            )
            .send()?;
        println!(
            "download file: {}",
            format!("{}\\{}", self.cache_dir, debug_info.to_pdb_file_path())
        );
        let dir = std::path::PathBuf::from(format!(
            "{}\\{}",
            self.cache_dir,
            debug_info.to_pdb_file_dir()
        ));
        if !dir.exists() {
            std::fs::create_dir_all(dir.clone())?;
        }

        let mut output_file = std::fs::File::create(format!(
            "{}\\{}",
            dir.to_string_lossy().to_string(),
            debug_info.filename
        ))?;
        response.copy_to(&mut output_file)?;
        Ok(())
    }

    fn get_pe_debug_info<P: AsRef<Path> + ?Sized>(&self, exe_path: &P) -> Result<DebugInfo> {
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
        let filename = std::ffi::CStr::from_bytes_with_nul(file)?
            .to_str()?
            .to_string();
        Ok(DebugInfo {
            age,
            guid_str,
            filename,
        })
    }
}

pub fn new(symbols_cache_dir: String) -> Result<PDBManager> {
    let dir_path = std::path::PathBuf::from_str(symbols_cache_dir.as_str())?;
    if dir_path.exists() && !dir_path.is_dir() {
        return Err(DrvLdrError::InvalidPdbCacheDir(symbols_cache_dir));
    } else if !dir_path.exists() {
        std::fs::create_dir_all(dir_path)?;
    }
    Ok(PDBManager {
        cache_dir: symbols_cache_dir,
    })
}

pub struct DebugInfo {
    pub age: u32,
    pub guid_str: String,
    pub filename: String,
}
impl DebugInfo {
    pub fn to_pdb_download_url(&self) -> String {
        format!(
            "https://msdl.microsoft.com/download/symbols/{}/{}/{}",
            self.filename, self.guid_str, self.filename
        )
    }

    pub fn to_pdb_file_path(&self) -> String {
        format!("{}\\{}\\{}", self.filename, self.guid_str, self.filename)
    }

    pub fn to_pdb_file_dir(&self) -> String {
        format!("{}\\{}", self.filename, self.guid_str)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_download_pdb() {
        let dir = format!(
            "{}\\{}",
            std::env::current_dir().unwrap().to_string_lossy(),
            "symbols_cache"
        );
        let mgr = new(dir).unwrap();
        mgr.get_symbol_manager("C:\\Windows\\System32\\ntoskrnl.exe")
            .unwrap();
        std::fs::remove_dir_all("symbols_cache").unwrap();
    }
}
