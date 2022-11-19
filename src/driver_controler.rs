use std::{mem::size_of, ops::Add};
use num_enum::{TryFromPrimitive,IntoPrimitive};
use crate::p;
use anyhow::{Result, Ok};
use windows::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_NONE,
        OPEN_EXISTING,
    },
    System::IO::DeviceIoControl,
};

#[allow(non_camel_case_types)]
#[derive(Debug,PartialEq,IntoPrimitive,TryFromPrimitive)]
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

#[repr(C)]
#[derive(Debug,Default)]
pub struct GlobalContext{
    driver_object: usize,
    pfn_ex_block_on_address_push_lock: usize,
    ntos_krnl_base: usize,
    ps_loaded_module_list: usize,
    ps_loaded_module_resource: usize,
    ob_type_index_table: usize,
    ob_header_cookie: usize,
    obp_root_directory_object: usize,
}

#[derive(Debug,Default)]
pub struct CallResult {
    pub err: ErrorCode,
    pub data: Vec<u8>,
}

impl CallResult {
    pub fn is_success(&self) -> bool {
        self.err == ErrorCode::ERR_SUCCESS
    }
}

pub fn parse_call_result_from_buffer(buffer: &[u8]) -> Result<CallResult> {
    let size_of_meta = size_of::<ErrorCode>() + size_of::<usize>();
    
    if buffer.len() < size_of_meta {
        return Err(anyhow::anyhow!("buffer size to small"));
    }
    let ptr = buffer.as_ptr();
    let error = ErrorCode::try_from_primitive(unsafe {(ptr as *const u32).read()})?;
    let size_of_data = unsafe{((ptr.add(size_of::<ErrorCode>())) as *const usize).read()};

    let data;
    if buffer.len() >= (size_of_meta + size_of_data) {
        data = buffer[size_of_meta .. (size_of_meta + size_of_data)].to_vec();
    }else {
        data = vec![];
    }

    Ok(CallResult{
        err: error,
        data,
    })
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

    pub fn send_init_global_context() -> Result<CallResult> {
        Ok(CallResult::default())
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
    fn test_parse_call_result () {
        let mut buffer = Vec::new();
        let code: u32 = ErrorCode::ERR_CONTEXT_DESERIALZE_INVALID_BUFFER.into();
        for ele in code.to_le_bytes() {
            buffer.push(ele);
        }
        for ele in 10usize.to_le_bytes() {
            buffer.push(ele);
        }
        let mut data = Vec::new();
        for i in 0..10  {
            buffer.push(i as u8);
            data.push(i as u8);
        }
        println!("buffer len: {}", buffer.len());

        let result = parse_call_result_from_buffer(buffer.as_slice()).unwrap();
        assert_eq!(ErrorCode::ERR_CONTEXT_DESERIALZE_INVALID_BUFFER,result.err);
        assert_eq!(data,result.data);
    }
}