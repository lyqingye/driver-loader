use windows::Win32::{
    Foundation::{
        GetLastError, ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_DOES_NOT_EXIST,
        ERROR_SERVICE_EXISTS, ERROR_SERVICE_MARKED_FOR_DELETE,
    },
    Security::SC_HANDLE,
    System::{
        Services::{
            CloseServiceHandle, ControlService, CreateServiceW, DeleteService, OpenSCManagerW,
            OpenServiceW, QueryServiceStatusEx, StartServiceW, SC_MANAGER_ALL_ACCESS,
            SC_STATUS_PROCESS_INFO, SERVICE_ALL_ACCESS, SERVICE_CONTROL_STOP, SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL, SERVICE_KERNEL_DRIVER, SERVICE_RUNNING, SERVICE_START_PENDING,
            SERVICE_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOPPED, SERVICE_STOP_PENDING,
        },
        SystemInformation::GetTickCount,
    },
};

use crate::error::{DrvLdrError, Result};

#[macro_export]
macro_rules! pcwstr {
    ($str: expr) => {
        windows::core::PCWSTR::from_raw(
            $str.encode_utf16()
                .chain([0])
                .collect::<Vec<u16>>()
                .as_ptr(),
        )
    };
}

unsafe fn to_buffer_mut<T: Sized>(ptr: &mut T) -> &mut [u8] {
    std::slice::from_raw_parts_mut((ptr as *mut T) as *mut u8, ::std::mem::size_of::<T>())
}

#[derive(Debug)]
pub struct DrvLdr {
    handle: SC_HANDLE,
    service_name: String,
    display_name: String,
    file_path: String,
    auto_unload: bool,
}

impl DrvLdr {
    pub fn new(
        service_name: &str,
        display_name: &str,
        file_path: &str,
        auto_unload: bool,
    ) -> Result<DrvLdr> {
        if let Ok(handle) = unsafe { OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS) } {
            Ok(DrvLdr {
                handle,
                service_name: service_name.to_owned(),
                display_name: display_name.to_owned(),
                file_path: file_path.to_owned(),
                auto_unload,
            })
        } else {
            Err(DrvLdrError::OpenSCManagerErr(unsafe {
                GetLastError().to_hresult().message()
            }))
        }
    }

    pub fn install_service(&self) -> Result<()> {
        log::debug!("install {} service", self.service_name);
        if let Ok(hservice) = unsafe {
            CreateServiceW(
                self.handle,
                pcwstr!(self.service_name),
                pcwstr!(self.display_name),
                SC_MANAGER_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                pcwstr!(self.file_path),
                None,
                None,
                None,
                None,
                None,
            )
        } {
            unsafe { CloseServiceHandle(hservice) };
            Ok(())
        } else {
            let last_error = unsafe { GetLastError() };
            if last_error == ERROR_SERVICE_EXISTS {
                log::debug!("service {} already exists", self.service_name);
                return Ok(());
            }
            Err(DrvLdrError::CreateServiceErr(
                last_error.to_hresult().message(),
            ))
        }
    }

    pub fn open_service(&self) -> Result<Service> {
        if let Ok(hservice) =
            unsafe { OpenServiceW(self.handle, pcwstr!(self.service_name), SERVICE_ALL_ACCESS) }
        {
            Ok(Service(hservice))
        } else {
            let last_error = unsafe { GetLastError() };
            if last_error == ERROR_SERVICE_DOES_NOT_EXIST {
                Err(DrvLdrError::ServiceNotExists(unsafe {
                    GetLastError().to_hresult().message()
                }))
            } else {
                Err(DrvLdrError::OpenServiceErr(unsafe {
                    GetLastError().to_hresult().message()
                }))
            }
        }
    }

    pub fn uninstall_service(&self) -> Result<()> {
        log::debug!("uninstall {} service", self.service_name);
        match self.open_service() {
            Ok(service) => {
                if unsafe { DeleteService(service.0) } == true {
                    Ok(())
                } else {
                    let last_error = unsafe { GetLastError() };
                    if last_error == ERROR_SERVICE_MARKED_FOR_DELETE {
                        log::debug!("service {} marked for delete", self.service_name);
                        return Ok(());
                    }
                    Err(DrvLdrError::DelServiceErr(
                        last_error.to_hresult().message(),
                    ))
                }
            }
            Err(DrvLdrError::ServiceNotExists(_)) => {
                log::debug!("service {} not exists", self.service_name);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn start_service_and_wait(&self) -> Result<Service> {
        log::debug!("start {} service", self.service_name);
        let service = self.open_service()?;
        // start service
        service.start()?;

        let mut ssp = service.query_status_ex()?;

        // service already running
        if ssp.dwCurrentState != SERVICE_STOPPED && ssp.dwCurrentState != SERVICE_STOP_PENDING {
            log::debug!("service {} already running", self.service_name);
            return Ok(service);
        }

        // save the tick count and initial checkpoint
        let mut start_tick_count = unsafe { GetTickCount() };
        let mut old_checkpoint = ssp.dwCheckPoint;

        // wait for the service to stop before attempting to start it.
        while ssp.dwCurrentState == SERVICE_STOP_PENDING {
            log::debug!("service {} stop pending, wait for the service to stop before attempting to start it",self.service_name);
            // wait seconds
            let mut wait_time = ssp.dwWaitHint / 10;
            if wait_time < 1000 {
                wait_time = 1000;
            } else if wait_time > 10000 {
                wait_time = 10000;
            }
            std::thread::sleep(std::time::Duration::from_millis(wait_time as u64));
            ssp = service.query_status_ex()?;

            if ssp.dwCheckPoint > old_checkpoint {
                // continue to wait and check
                start_tick_count = unsafe { GetTickCount() };
                old_checkpoint = ssp.dwCheckPoint;
            } else {
                if (unsafe { GetTickCount() } - start_tick_count) > ssp.dwWaitHint {
                    log::debug!("start service {} timeout", self.service_name);
                    return Err(DrvLdrError::StartServiceTimeoutErr(unsafe {
                        GetLastError().to_hresult().message()
                    }));
                }
            }
        }

        log::debug!("attempt to start service {}", self.service_name);
        // attempt to start the service
        service.start()?;

        // check the status until the service is no longer start pending.
        ssp = service.query_status_ex()?;

        // save the tick count and initial checkpoint.
        start_tick_count = unsafe { GetTickCount() };
        old_checkpoint = ssp.dwCheckPoint;
        while ssp.dwCurrentState == SERVICE_START_PENDING {
            log::debug!("service {} start pending", self.service_name);
            // wait seconds
            let mut wait_time = ssp.dwWaitHint / 10;
            if wait_time < 1000 {
                wait_time = 1000;
            } else if wait_time > 10000 {
                wait_time = 10000;
            }
            std::thread::sleep(std::time::Duration::from_millis(wait_time as u64));
            ssp = service.query_status_ex()?;

            if ssp.dwCheckPoint > old_checkpoint {
                // continue to wait and check
                start_tick_count = unsafe { GetTickCount() };
                old_checkpoint = ssp.dwCheckPoint;
            } else {
                if (unsafe { GetTickCount() } - start_tick_count) > ssp.dwWaitHint {
                    break;
                }
            }
        }

        if ssp.dwCurrentState == SERVICE_RUNNING {
            log::debug!("service {} is running", self.service_name);
            return Ok(service);
        }

        // start service fail
        Err(DrvLdrError::StartServiceErr(unsafe {
            GetLastError().to_hresult().message()
        }))
    }

    pub fn stop_service_and_wait(&self) -> Result<()> {
        log::debug!("stop service {}", self.service_name);
        match self.open_service() {
            Ok(service) => {
                let mut ssp = SERVICE_STATUS_PROCESS::default();
                // service stopped
                if ssp.dwCurrentState == SERVICE_STOP_PENDING {
                    log::debug!("service {} stop pending", self.service_name);
                    // service stop pending
                    let start_time = unsafe { GetTickCount() };
                    while ssp.dwCurrentState == SERVICE_STOP_PENDING {
                        let mut wait_time = ssp.dwWaitHint / 10;
                        if wait_time < 1000 {
                            wait_time = 1000;
                        } else if wait_time > 10000 {
                            wait_time = 10000;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(wait_time as u64));
                        ssp = service.query_status_ex()?;
                        if (unsafe { GetTickCount() } - start_time) > 30000 {
                            log::debug!("stop service {} timeout", self.service_name);
                            return Err(DrvLdrError::StopServiceTimeoutErr(unsafe {
                                GetLastError().to_hresult().message()
                            }));
                        }
                    }
                } else {
                    // stop service
                    let _ = service.stop()?;
                    std::thread::sleep(std::time::Duration::from_millis(ssp.dwWaitHint as u64));
                    ssp = service.query_status_ex()?;
                    let start_time = unsafe { GetTickCount() };
                    while ssp.dwCurrentState == SERVICE_STOP_PENDING {
                        log::debug!("service {} stop pending", self.service_name);
                        let mut wait_time = ssp.dwWaitHint / 10;
                        if wait_time < 1000 {
                            wait_time = 1000;
                        } else if wait_time > 10000 {
                            wait_time = 10000;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(wait_time as u64));
                        ssp = service.query_status_ex()?;
                        if (unsafe { GetTickCount() } - start_time) > 30000 {
                            log::debug!("stop service {} timeout", self.service_name);
                            return Err(DrvLdrError::StopServiceTimeoutErr(unsafe {
                                GetLastError().to_hresult().message()
                            }));
                        }
                    }
                }
                Ok(())
            }
            Err(DrvLdrError::ServiceNotExists(_)) => {
                log::debug!("service {} not exists", self.service_name);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

impl Drop for DrvLdr {
    fn drop(&mut self) {
        log::debug!("drv ldr auto unload");
        if self.auto_unload {
            let _ = self.stop_service_and_wait();
            let _ = self.uninstall_service();
        }
        if !self.handle.is_invalid() {
            unsafe {
                CloseServiceHandle(self.handle);
            }
        }
    }
}

pub struct Service(SC_HANDLE);

impl Drop for Service {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                CloseServiceHandle(self.0);
            }
        }
    }
}

impl Service {
    pub fn start(&self) -> Result<()> {
        if unsafe { StartServiceW(self.0, None) } == true {
            Ok(())
        } else {
            let last_error = unsafe { GetLastError() };
            if last_error == ERROR_SERVICE_ALREADY_RUNNING {
                return Ok(());
            } else {
                Err(DrvLdrError::StartServiceErr(unsafe {
                    GetLastError().to_hresult().message()
                }))
            }
        }
    }

    pub fn stop(&self) -> Result<SERVICE_STATUS> {
        let mut ss = SERVICE_STATUS::default();
        if unsafe { ControlService(self.0, SERVICE_CONTROL_STOP, &mut ss) } == true {
            Ok(ss)
        } else {
            Err(DrvLdrError::StopServiceErr(unsafe {
                GetLastError().to_hresult().message()
            }))
        }
    }

    pub fn query_status_ex(&self) -> Result<SERVICE_STATUS_PROCESS> {
        let mut ssp = SERVICE_STATUS_PROCESS::default();
        let mut bytes_need: u32 = 0;
        if unsafe {
            QueryServiceStatusEx(
                self.0,
                SC_STATUS_PROCESS_INFO,
                Some(to_buffer_mut::<SERVICE_STATUS_PROCESS>(&mut ssp)),
                &mut bytes_need,
            )
        } == true
        {
            Ok(ssp)
        } else {
            Err(DrvLdrError::QueryServiceStatusErr(unsafe {
                GetLastError().to_hresult().message()
            }))
        }
    }
}
