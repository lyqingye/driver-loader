use crate::{p, pdb_manager};
use anyhow::{Ok, Result};
use lazy_static::lazy_static;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::{mem::size_of, ops::Add};
use winapi::um::winioctl::{CTL_CODE, FILE_ANY_ACCESS, FILE_DEVICE_UNKNOWN, METHOD_BUFFERED};
use windows::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_NONE,
        OPEN_EXISTING,
    },
    System::{self, SystemInformation::GetSystemDirectoryW, IO::DeviceIoControl},
};

//
// Driver CTL Codes
//
lazy_static! {
    static ref CTL_CODE_ECHO: u32 =
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);
    static ref CTL_CODE_INIT_CONTEXT: u32 =
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);
    static ref CTL_CODE_QUERY_KERNEL_MODULE_INFO: u32 =
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS);
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, IntoPrimitive, TryFromPrimitive)]
#[repr(u32)]
pub enum ErrorCode {
    ERR_SUCCESS,
    ERR_INVALID_PARAMS,
    ERR_CONTEXT_DESERIALZE_INVALID_BUFFER,
    ERR_CONTEXT_INVALID,
    ERR_CONTEXT_KERNEL_BASE_NOT_FOUND,
}
impl Default for ErrorCode {
    fn default() -> Self {
        ErrorCode::ERR_SUCCESS
    }
}

impl ErrorCode {
    pub fn to_err(&self) -> anyhow::Error {
        anyhow::anyhow!("{:?}", self)
    }
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct GlobalContext {
    driver_object: usize,
    ntos_krnl_base: usize,

    // undocuments
    pfn_ex_block_on_address_push_lock: usize,
    pfn_exf_unblock_push_lock: usize,
    ps_loaded_module_list: usize,
    ps_loaded_module_resource: usize,
    ob_type_index_table: usize,
    ob_header_cookie: usize,
    obp_root_directory_object: usize,
}

impl Into<Vec<u8>> for GlobalContext {
    fn into(self) -> Vec<u8> {
        unsafe {
            let ptr = &self as *const GlobalContext as *const u8;
            std::slice::from_raw_parts(ptr, std::mem::size_of::<GlobalContext>()).to_vec()
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct SystemModuleEntry {
    pub image_base: usize,
    pub image_size: u32,
    pub full_path_name: [u8; 256],
}

impl SystemModuleEntry {
    pub fn full_path(&self) -> String {
        let path = unsafe {
            String::from_utf16_lossy(std::slice::from_raw_parts(
                self.full_path_name.as_ptr().cast::<u16>(),
                self.full_path_name.len() / 2,
            ))
            .trim_matches(char::from(0))
            .to_string()
        };
        let mut buffer = vec![0u16; 255];
        unsafe { GetSystemDirectoryW(Some(buffer.as_mut_slice())) };
        path.replace(
            "\\SystemRoot\\system32",
            String::from_utf16_lossy(buffer.as_slice()).trim_matches(char::from(0)),
        )
    }
}

impl TryFrom<Vec<u8>> for SystemModuleEntry {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        assert_eq!(272, size_of::<SystemModuleEntry>());
        if value.len() < size_of::<SystemModuleEntry>() {
            return Err(anyhow::anyhow!("SystemModuleEntry buffer to small"));
        }
        Ok(unsafe { (value.as_ptr() as *const SystemModuleEntry).read() })
    }
}

#[derive(Debug, Default)]
pub struct CallResult {
    pub err: ErrorCode,
    pub data: Vec<u8>,
}

impl CallResult {
    pub fn is_success(&self) -> bool {
        self.err == ErrorCode::ERR_SUCCESS
    }

    pub fn to_err(&self) -> anyhow::Error {
        self.err.to_err()
    }
}

pub fn parse_call_result_from_buffer(buffer: &[u8]) -> Result<CallResult> {
    let size_of_meta = size_of::<ErrorCode>() + size_of::<usize>();

    if buffer.len() < size_of_meta {
        return Err(anyhow::anyhow!("buffer size to small"));
    }
    let ptr = buffer.as_ptr();
    let error = ErrorCode::try_from_primitive(unsafe { (ptr as *const u32).read() })?;
    let size_of_data = unsafe { ((ptr.add(size_of::<ErrorCode>())) as *const usize).read() };

    let data;
    if buffer.len() >= (size_of_meta + size_of_data) {
        data = buffer[size_of_meta..(size_of_meta + size_of_data)].to_vec();
    } else {
        data = vec![];
    }

    Ok(CallResult { err: error, data })
}

pub struct DriverControler {
    device_name: String,
    hdevice: HANDLE,
}

impl DriverControler {
    pub fn conn(&mut self) -> Result<()> {
        unsafe {
            self.hdevice = CreateFileW(
                p!(self.device_name),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )?;
        }
        Ok(())
    }

    pub fn send(&self, code: u32, input: Vec<u8>, size_of_output: usize) -> Result<CallResult> {
        const SIZE_OF_META: usize = size_of::<ErrorCode>() + size_of::<usize>();
        let mut bytes_return = 0;
        if size_of_output > 0 {
            let mut result = vec![0; SIZE_OF_META + size_of_output];
            if unsafe {
                DeviceIoControl(
                    self.hdevice,
                    code,
                    Some(input.as_ptr() as _),
                    input.len() as u32,
                    Some(result.as_mut_ptr() as _),
                    (SIZE_OF_META + size_of_output) as u32,
                    Some(&mut bytes_return),
                    None,
                )
            } == true
            {
                return parse_call_result_from_buffer(result.as_slice());
            }
        } else {
            // if size_of_output not specified, try to get actual output size
            let mut result = vec![0; SIZE_OF_META];
            if unsafe {
                DeviceIoControl(
                    self.hdevice,
                    code,
                    Some(input.as_ptr() as _),
                    input.len() as u32,
                    Some(result.as_mut_ptr() as _),
                    SIZE_OF_META as u32,
                    Some(&mut bytes_return),
                    None,
                )
            } == true
            {
                if bytes_return == 0 {
                    // actual output is empty
                    return parse_call_result_from_buffer(result.as_slice());
                }
                // retry get output by actual output size
                let mut result = vec![0; SIZE_OF_META + bytes_return as usize];
                if unsafe {
                    DeviceIoControl(
                        self.hdevice,
                        code,
                        Some(input.as_ptr() as _),
                        input.len() as u32,
                        Some(result.as_mut_ptr() as _),
                        bytes_return,
                        Some(&mut bytes_return),
                        None,
                    )
                } == true
                {
                    return parse_call_result_from_buffer(result.as_slice());
                }
            }
        }
        unsafe {
            Err(anyhow::anyhow!(
                "device io control faild {:?} {:?} ",
                GetLastError(),
                GetLastError().to_hresult().message()
            ))
        }
    }

    pub fn init_global_context(&self) -> Result<CallResult> {
        let kernel_module = self.qeury_kernel_module_info()?;
        let cache_dir = format!("{}\\symbols", std::env::temp_dir().to_string_lossy());
        let pdb_mgr = pdb_manager::new(cache_dir)?;
        let mut symbol = pdb_mgr.get_symbol_manager(&kernel_module.full_path())?;
        let mut context = GlobalContext::default();
        context.pfn_ex_block_on_address_push_lock = symbol
            .find_symbol_offset_by_name("ExBlockOnAddressPushLock".to_owned())
            .ok_or(anyhow::anyhow!(
                "symbol: ExBlockOnAddressPushLock not found!"
            ))?;
        context.pfn_exf_unblock_push_lock = symbol
            .find_symbol_offset_by_name("ExfUnblockPushLock".to_owned())
            .ok_or(anyhow::anyhow!("symbol: ExfUnblockPushLock not found!"))?;
        context.ps_loaded_module_list = symbol
            .find_symbol_offset_by_name("PsLoadedModuleList".to_owned())
            .ok_or(anyhow::anyhow!("symbol: PsLoadedModuleList not found!"))?;
        context.ps_loaded_module_resource = symbol
            .find_symbol_offset_by_name("PsLoadedModuleResource".to_owned())
            .ok_or(anyhow::anyhow!("symbol: PsLoadedModuleResource not found!"))?;
        context.ob_type_index_table = symbol
            .find_symbol_offset_by_name("ObTypeIndexTable".to_owned())
            .ok_or(anyhow::anyhow!("symbol: ObTypeIndexTable not found!"))?;
        context.ob_header_cookie = symbol
            .find_symbol_offset_by_name("ObHeaderCookie".to_owned())
            .ok_or(anyhow::anyhow!("symbol: ObHeaderCookie not found!"))?;
        context.obp_root_directory_object = symbol
            .find_symbol_offset_by_name("ObpRootDirectoryObject".to_owned())
            .ok_or(anyhow::anyhow!("symbol: ObpRootDirectoryObject not found!"))?;

        // call driver
        self.send(*CTL_CODE_INIT_CONTEXT, context.into(), 0)
    }

    pub fn qeury_kernel_module_info(&self) -> Result<SystemModuleEntry> {
        let call_result = self.send(
            *CTL_CODE_QUERY_KERNEL_MODULE_INFO,
            vec![],
            size_of::<SystemModuleEntry>(),
        )?;
        if call_result.is_success() {
            SystemModuleEntry::try_from(call_result.data)
        } else {
            Err(call_result.to_err())
        }
    }
}

impl Drop for DriverControler {
    fn drop(&mut self) {
        if !self.hdevice.is_invalid() {
            unsafe {
                CloseHandle(self.hdevice);
            }
        }
    }
}

pub fn new(device_name: String) -> DriverControler {
    DriverControler {
        device_name: device_name,
        hdevice: INVALID_HANDLE_VALUE,
    }
}

#[cfg(test)]
mod test {
    use super::{parse_call_result_from_buffer, ErrorCode};

    #[test]
    fn test_parse_call_result() {
        let mut buffer = Vec::new();
        let code: u32 = ErrorCode::ERR_CONTEXT_DESERIALZE_INVALID_BUFFER.into();
        for ele in code.to_le_bytes() {
            buffer.push(ele);
        }
        for ele in 10usize.to_le_bytes() {
            buffer.push(ele);
        }
        let mut data = Vec::new();
        for i in 0..10 {
            buffer.push(i as u8);
            data.push(i as u8);
        }
        println!("buffer len: {}", buffer.len());

        let result = parse_call_result_from_buffer(buffer.as_slice()).unwrap();
        assert_eq!(ErrorCode::ERR_CONTEXT_DESERIALZE_INVALID_BUFFER, result.err);
        assert_eq!(data, result.data);
    }
}
