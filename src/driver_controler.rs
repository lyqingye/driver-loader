use crate::{p, pdb_manager};
use anyhow::{Ok, Result};
use lazy_static::lazy_static;
use std::{mem::size_of, ops::Add};
use winapi::um::winioctl::{CTL_CODE, FILE_ANY_ACCESS, FILE_DEVICE_UNKNOWN, METHOD_BUFFERED};
use windows::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, NTSTATUS},
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_NONE,
        OPEN_EXISTING,
    },
    System::{SystemInformation::GetSystemDirectoryW, IO::DeviceIoControl},
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

#[repr(C)]
#[derive(Debug, Default)]
pub struct GlobalContext {
    // functions
    pfn_exp_block_on_locked_handle_entry: usize,
    pfn_exf_unblock_push_lock: usize,

    // global variable
    psp_cid_table: usize,
    ps_loaded_module_list: usize,
    ps_loaded_module_resource: usize,
    ob_type_index_table: usize,
    ob_header_cookie: usize,
    obp_root_directory_object: usize,

    // class field offset
    sizeof_object_header: usize,
    offset_type_index_of_object_header: usize,
    offset_type_name_of_object_type: usize,
    offset_type_info_of_object_type: usize,

    offset_dump_proc_of_object_type_initializer: usize,
    offset_open_proc_of_object_type_initializer: usize,
    offset_close_proc_of_object_type_initializer: usize,
    offset_delete_proc_of_object_type_initializer: usize,
    offset_parse_proc_of_object_type_initializer: usize,
    offset_parse_ex_proc_of_object_type_initializer: usize,
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
        if value.len() < size_of::<SystemModuleEntry>() {
            return Err(anyhow::anyhow!("SystemModuleEntry buffer to small"));
        }
        Ok(unsafe { (value.as_ptr() as *const SystemModuleEntry).read() })
    }
}

#[derive(Debug, Default)]
pub struct CallResult {
    pub status: NTSTATUS,
    pub data: Vec<u8>,
}

impl CallResult {
    pub fn is_success(&self) -> bool {
        self.status.is_ok()
    }

    pub fn to_err(&self) -> anyhow::Error {
        anyhow::anyhow!("{:?}", self.status.to_hresult())
    }
}

pub fn parse_call_result_from_buffer(buffer: &[u8]) -> Result<CallResult> {
    let size_of_meta = size_of::<NTSTATUS>() + size_of::<usize>();

    if buffer.len() < size_of_meta {
        return Err(anyhow::anyhow!("buffer size to small"));
    }
    let ptr = buffer.as_ptr();
    let status = unsafe { (ptr as *const NTSTATUS).read() };
    let size_of_data = unsafe { ((ptr.add(size_of::<NTSTATUS>())) as *const usize).read() };

    let data;
    if buffer.len() >= (size_of_meta + size_of_data) {
        data = buffer[size_of_meta..(size_of_meta + size_of_data)].to_vec();
    } else {
        data = vec![];
    }

    Ok(CallResult { status, data })
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
        const SIZE_OF_META: usize = size_of::<NTSTATUS>() + size_of::<usize>();
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
                if bytes_return == SIZE_OF_META as u32 {
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
        let mut symbol_mgr = pdb_mgr.get_symbol_manager(&kernel_module.full_path())?;
        let mut ctx = GlobalContext::default();

        ctx.pfn_exp_block_on_locked_handle_entry =
            symbol_mgr.find_symbol_offset_by_name("ExpBlockOnLockedHandleEntry")?;

        ctx.pfn_exf_unblock_push_lock =
            symbol_mgr.find_symbol_offset_by_name("ExfUnblockPushLock")?;

        ctx.psp_cid_table = symbol_mgr.find_symbol_offset_by_name("PspCidTable")?;

        ctx.ps_loaded_module_list = symbol_mgr.find_symbol_offset_by_name("PsLoadedModuleList")?;

        ctx.ps_loaded_module_resource =
            symbol_mgr.find_symbol_offset_by_name("PsLoadedModuleResource")?;

        ctx.ob_type_index_table = symbol_mgr.find_symbol_offset_by_name("ObTypeIndexTable")?;
        ctx.ob_header_cookie = symbol_mgr.find_symbol_offset_by_name("ObHeaderCookie")?;

        ctx.obp_root_directory_object =
            symbol_mgr.find_symbol_offset_by_name("ObpRootDirectoryObject")?;

        let clazz_object_header = symbol_mgr.find_class_by_name("_OBJECT_HEADER")?;

        ctx.sizeof_object_header = clazz_object_header.size;
        ctx.offset_type_index_of_object_header = clazz_object_header
            .fileds
            .get("TypeIndex")
            .ok_or(anyhow::anyhow!(
                "symbol: _OBJECT_HEADER.TypeIndex not found!"
            ))?
            .offset;

        let clazz_object_type = symbol_mgr.find_class_by_name("_OBJECT_TYPE")?;

        ctx.offset_type_name_of_object_type = clazz_object_type
            .fileds
            .get("Name")
            .ok_or(anyhow::anyhow!("symbol: _OBJECT_TYPE.Name not found!"))?
            .offset;
        ctx.offset_type_info_of_object_type = clazz_object_type
            .fileds
            .get("TypeInfo")
            .ok_or(anyhow::anyhow!("symbol: _OBJECT_TYPE.TypeInfo not found!"))?
            .offset;

        let clazz_object_type_initializer =
            symbol_mgr.find_class_by_name("_OBJECT_TYPE_INITIALIZER")?;

        ctx.offset_dump_proc_of_object_type_initializer = clazz_object_type_initializer
            .fileds
            .get("DumpProcedure")
            .ok_or(anyhow::anyhow!(
                "symbol: _OBJECT_TYPE_INITIALIZER.DumpProcedure not found!"
            ))?
            .offset;

        ctx.offset_open_proc_of_object_type_initializer = clazz_object_type_initializer
            .fileds
            .get("OpenProcedure")
            .ok_or(anyhow::anyhow!(
                "symbol: _OBJECT_TYPE_INITIALIZER.OpenProcedure not found!"
            ))?
            .offset;

        ctx.offset_close_proc_of_object_type_initializer = clazz_object_type_initializer
            .fileds
            .get("CloseProcedure")
            .ok_or(anyhow::anyhow!(
                "symbol: _OBJECT_TYPE_INITIALIZER.CloseProcedure not found!"
            ))?
            .offset;

        ctx.offset_delete_proc_of_object_type_initializer = clazz_object_type_initializer
            .fileds
            .get("DeleteProcedure")
            .ok_or(anyhow::anyhow!(
                "symbol: _OBJECT_TYPE_INITIALIZER.DeleteProcedure not found!"
            ))?
            .offset;

        ctx.offset_parse_proc_of_object_type_initializer = clazz_object_type_initializer
            .fileds
            .get("ParseProcedure")
            .ok_or(anyhow::anyhow!(
                "symbol: _OBJECT_TYPE_INITIALIZER.ParseProcedure not found!"
            ))?
            .offset;

        ctx.offset_parse_ex_proc_of_object_type_initializer = clazz_object_type_initializer
            .fileds
            .get("ParseProcedureEx")
            .ok_or(anyhow::anyhow!(
                "symbol: _OBJECT_TYPE_INITIALIZER.ParseProcedureEx not found!"
            ))?
            .offset;

        // call driver
        self.send(*CTL_CODE_INIT_CONTEXT, ctx.into(), 0)
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
    use windows::Win32::Foundation::STATUS_SUCCESS;

    use super::parse_call_result_from_buffer;

    #[test]
    fn test_parse_call_result() {
        let mut buffer = Vec::new();
        let code: i32 = STATUS_SUCCESS.0;
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
        assert_eq!(STATUS_SUCCESS, result.status);
        assert_eq!(data, result.data);
    }
}
