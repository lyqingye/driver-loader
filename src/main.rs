use std::io::{stdin, stdout, Read, Write};

use anyhow::Result;

pub mod driver_controler;
pub mod driver_loader;
pub mod error;
pub mod pdb_manager;
pub mod symbol_manager;

fn main() -> Result<()> {
    env_logger::Builder::from_default_env()
        .format_target(false)
        .format_module_path(true)
        .filter_module("goblin", log::LevelFilter::Error)
        .init();
    let mgr = driver_loader::DrvLdr::new(
        "driver3",
        "driver3",
        "\\\\vmware-host\\Shared Folders\\Driver\\Driver.sys",
    )?;
    mgr.install_service().unwrap();
    mgr.start_service_and_wait().unwrap();
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
