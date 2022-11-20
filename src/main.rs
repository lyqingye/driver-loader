use std::io::{stdin, stdout, Read, Write};

use anyhow::Result;
use winapi::{
    shared::ntdef::UNICODE_STRING,
    um::winioctl::{CTL_CODE, FILE_ANY_ACCESS, FILE_DEVICE_UNKNOWN, METHOD_BUFFERED},
};
use windows::Win32::{Foundation::GetLastError, System::SystemInformation::GetSystemDirectoryW};

use crate::symbol::SymbolManager;

pub mod driver_controler;
pub mod driver_loader;
pub mod pdb;
pub mod symbol;

fn main() -> Result<()> {
    let mut ldr = driver_loader::new(
        "\\\\vmware-host\\Shared Folders\\Driver\\KMDFDriver2.sys".to_owned(),
        "driver3".to_owned(),
        "driver3".to_owned(),
    );
    // ldr.stop_service().unwrap();
    // ldr.uninstall_serviec().unwrap();
    ldr.install_service().unwrap();
    ldr.start_service().unwrap();
    let mut controler = driver_controler::new("\\??\\WindowsKernelResearch".to_owned());
    controler.conn().unwrap();
    let module_information = controler.qeury_kernel_module_info().unwrap();
    println!("base: {:x}", module_information.image_base);
    let full_path = unsafe {
        std::slice::from_raw_parts(
            module_information.full_path_name.as_ptr().cast::<u16>(),
            module_information.full_path_name.len() / 2,
        )
    };
    println!("full path {:}", String::from_utf16_lossy(full_path));
    println!("{:?}", module_information);

    let mut buffer = vec![0u16; 255];
    unsafe { GetSystemDirectoryW(Some(buffer.as_mut_slice())) };
    let path = String::from_utf16_lossy(full_path).replace(
        "\\SystemRoot\\system32",
        String::from_utf16_lossy(buffer.as_slice()).as_str(),
    );

    // let mgr = symbol::new(&path).unwrap();
    pause();
    Ok(())
}

fn pause() {
    let mut stdout = stdout();
    stdout.write(b"Press Enter to continue...").unwrap();
    stdout.flush().unwrap();
    stdin().read(&mut [0]).unwrap();
}

#[cfg(test)]
mod test {
    use windows::Win32::System::SystemInformation::GetSystemDirectoryW;

    use crate::p;

    #[test]
    fn test() {
        unsafe {
            let mut buffer = vec![0u16; 255];
            GetSystemDirectoryW(Some(buffer.as_mut_slice()));
            let path = "\\SystemRoot\\system32\\ntoskrnl.exe".replace(
                "\\SystemRoot\\system32",
                String::from_utf16_lossy(buffer.as_slice()).as_str(),
            );
            println!("{}", path);
        }
    }
}
