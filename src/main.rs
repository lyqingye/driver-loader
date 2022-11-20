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
pub mod pdb_manager;
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
    controler.init_global_context().unwrap();
    pause();
    Ok(())
}

fn pause() {
    let mut stdout = stdout();
    stdout.write(b"Press Enter to continue...").unwrap();
    stdout.flush().unwrap();
    stdin().read(&mut [0]).unwrap();
}
