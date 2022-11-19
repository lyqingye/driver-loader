use anyhow::Result;
use winapi::um::winioctl::{FILE_DEVICE_UNKNOWN, METHOD_BUFFERED, FILE_ANY_ACCESS, CTL_CODE};
use windows::Win32::Foundation::GetLastError;

pub mod driver_controler;
pub mod driver_loader;
pub mod pdb_fetcher;
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
    if let Err(e) = controler.conn() {
        println!("{:?}", e);
        unsafe {
            println!("{:?}", GetLastError());
        }
    } else {
        let data = "我操你妈的".to_owned();
        let data_len = data.len();
        let code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);
        let result = controler.send(code, data.into_bytes(), 0).unwrap();
        unsafe {
            println!("{:?}", result);
            let string = String::from_utf8(result.data).unwrap();
            println!("{}", string);
        }
    }
    Ok(())
}
