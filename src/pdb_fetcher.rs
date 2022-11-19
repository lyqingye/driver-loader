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
    use super::*;
    use std::fs::remove_file;

    #[test]
    fn test_download_pdb() {
        assert!(download("C:\\Windows\\System32\\ntoskrnl.exe", "download.bin").is_ok());
        remove_file("download.bin").unwrap();
    }
}
