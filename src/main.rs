use error::Result;
use std::io::{stdin, stdout, Read, Write};

pub mod controller;
pub mod error;
pub mod loader;
pub mod pdb_mgr;
pub mod sym_mgr;

fn main() -> Result<()> {
    env_logger::Builder::from_default_env()
        .format_target(false)
        .format_module_path(true)
        .filter_module("goblin", log::LevelFilter::Error)
        .init();
    let ldr = loader::DrvLdr::new(
        "driver3",
        "driver3",
        // "\\\\vmware-host\\Shared Folders\\Driver\\Driver.sys",
         "c:\\Users\\ex\\Desktop\\Driver.sys",
        true,
    )?;
    ldr.install_service().unwrap();
    ldr.start_service_and_wait().unwrap();
    let mut controller = controller::new("\\??\\WindowsKernelResearch".to_owned());
    controller.conn().unwrap();
    log::info!("init global context");
    controller.init_global_context().unwrap();
    pause();
    Ok(())
}

fn pause() {
    let mut stdout = stdout();
    stdout.write(b"Press Enter to continue...").unwrap();
    stdout.flush().unwrap();
    stdin().read(&mut [0]).unwrap();
}
