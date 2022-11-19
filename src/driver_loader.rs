use anyhow::Result;
use windows::Win32::{
    Foundation::{
        GetLastError, ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_DOES_NOT_EXIST,
        ERROR_SERVICE_EXISTS, ERROR_SERVICE_MARKED_FOR_DELETE,
    },
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

#[macro_export]
macro_rules! p {
    ($str: expr) => {
        windows::core::PCWSTR::from_raw(
            $str.encode_utf16()
                .chain([0])
                .collect::<Vec<u16>>()
                .as_ptr(),
        )
    };
}

unsafe fn to_buffer<T: Sized>(ptr: &T) -> &[u8] {
    std::slice::from_raw_parts((ptr as *const T) as *const u8, ::std::mem::size_of::<T>())
}

unsafe fn to_buffer_mut<T: Sized>(ptr: &mut T) -> &mut [u8] {
    std::slice::from_raw_parts_mut((ptr as *mut T) as *mut u8, ::std::mem::size_of::<T>())
}

#[derive(Debug, Clone)]
pub struct DriverLoader {
    file_path: String,
    service_name: String,
    display_name: String,
}

impl DriverLoader {
    pub fn install_service(&mut self) -> Result<()> {
        unsafe {
            let hmanager = OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)?;
            println!("{:?}", p!(self.file_path).to_string().unwrap());
            if let Ok(hservice) = CreateServiceW(
                hmanager,
                p!(self.service_name),
                p!(self.display_name),
                SC_MANAGER_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                p!(self.file_path),
                None,
                None,
                None,
                None,
                None,
            ) {
                CloseServiceHandle(hservice);
                CloseServiceHandle(hmanager);
                Ok(())
            } else {
                CloseServiceHandle(hmanager);
                if GetLastError() == ERROR_SERVICE_EXISTS {
                    return Ok(());
                }
                Err(anyhow::anyhow!(
                    "install service failed {:?}",
                    GetLastError().to_hresult().message()
                ))
            }
        }
    }

    pub fn uninstall_serviec(&mut self) -> Result<()> {
        unsafe {
            let hmanager = OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)?;
            if let Ok(hservice) = OpenServiceW(hmanager, p!(self.service_name), SERVICE_ALL_ACCESS)
            {
                if !DeleteService(hservice).as_bool() {
                    CloseServiceHandle(hmanager);
                    CloseServiceHandle(hservice);
                    if GetLastError() == ERROR_SERVICE_MARKED_FOR_DELETE {
                        return Ok(());
                    }
                    return Err(anyhow::anyhow!(
                        "delete service failed {:?}",
                        GetLastError()
                    ));
                }
                CloseServiceHandle(hservice);
            } else {
                CloseServiceHandle(hmanager);
                let err = GetLastError();
                if err == ERROR_SERVICE_DOES_NOT_EXIST {
                    return Ok(());
                }
                return Err(anyhow::anyhow!(
                    "open service failed {:?} {:?}",
                    err,
                    err.to_hresult().message()
                ));
            }
            CloseServiceHandle(hmanager);
        }
        Ok(())
    }

    pub fn start_service(&mut self) -> Result<()> {
        unsafe {
            let hmanager = OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)?;
            if let Ok(hservice) = OpenServiceW(hmanager, p!(self.service_name), SERVICE_ALL_ACCESS)
            {
                if StartServiceW(hservice, None) == false {
                    CloseServiceHandle(hservice);
                    CloseServiceHandle(hmanager);
                    if GetLastError() == ERROR_SERVICE_ALREADY_RUNNING {
                        return Ok(());
                    }
                    return Err(anyhow::anyhow!(
                        "start service failed {:?}",
                        GetLastError().to_hresult().message()
                    ));
                }
                let mut ssp = SERVICE_STATUS_PROCESS::default();
                let mut bytesneed: u32 = 0;

                if !QueryServiceStatusEx(
                    hservice,
                    SC_STATUS_PROCESS_INFO,
                    Some(to_buffer_mut::<SERVICE_STATUS_PROCESS>(&mut ssp)),
                    &mut bytesneed,
                )
                .as_bool()
                {
                    CloseServiceHandle(hservice);
                    CloseServiceHandle(hmanager);
                    return Err(anyhow::anyhow!(
                        "query service status failed {:?}",
                        GetLastError().to_hresult().message()
                    ));
                }

                // service already running
                if ssp.dwCurrentState != SERVICE_STOPPED
                    && ssp.dwCurrentState != SERVICE_STOP_PENDING
                {
                    CloseServiceHandle(hservice);
                    CloseServiceHandle(hmanager);
                    return Ok(());
                }

                // save the tick count and initial checkpoint
                let mut start_tick_count = GetTickCount();
                let mut old_checkpoint = ssp.dwCheckPoint;

                // wait for the service to stop before attempting to start it.
                while ssp.dwCurrentState == SERVICE_STOP_PENDING {
                    // wait seconds
                    let mut wait_time = ssp.dwWaitHint / 10;
                    if wait_time < 1000 {
                        wait_time = 1000;
                    } else if wait_time > 10000 {
                        wait_time = 10000;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(wait_time as u64));

                    if !QueryServiceStatusEx(
                        hservice,
                        SC_STATUS_PROCESS_INFO,
                        Some(to_buffer_mut::<SERVICE_STATUS_PROCESS>(&mut ssp)),
                        &mut bytesneed,
                    )
                    .as_bool()
                    {
                        CloseServiceHandle(hservice);
                        CloseServiceHandle(hmanager);
                        return Err(anyhow::anyhow!(
                            "query service status failed {:?}",
                            GetLastError().to_hresult().message()
                        ));
                    }

                    if ssp.dwCheckPoint > old_checkpoint {
                        // continue to wait and check
                        start_tick_count = GetTickCount();
                        old_checkpoint = ssp.dwCheckPoint;
                    } else {
                        if (GetTickCount() - start_tick_count) > ssp.dwWaitHint {
                            CloseServiceHandle(hservice);
                            CloseServiceHandle(hmanager);
                            return Err(anyhow::anyhow!("timeout watting for service to stop"));
                        }
                    }
                }

                // attempt to start the service
                if !StartServiceW(hservice, None).as_bool() {
                    CloseServiceHandle(hservice);
                    CloseServiceHandle(hmanager);
                    return Err(anyhow::anyhow!(
                        "start service failed {:?}",
                        GetLastError().to_hresult().message()
                    ));
                }

                // check the status until the service is no longer start pending.
                if !QueryServiceStatusEx(
                    hservice,
                    SC_STATUS_PROCESS_INFO,
                    Some(to_buffer_mut::<SERVICE_STATUS_PROCESS>(&mut ssp)),
                    &mut bytesneed,
                )
                .as_bool()
                {
                    CloseServiceHandle(hservice);
                    CloseServiceHandle(hmanager);
                    return Err(anyhow::anyhow!(
                        "query service status failed {:?}",
                        GetLastError()
                    ));
                }

                // save the tick count and initial checkpoint.
                start_tick_count = GetTickCount();
                old_checkpoint = ssp.dwCheckPoint;
                while ssp.dwCurrentState == SERVICE_START_PENDING {
                    // wait seconds
                    let mut wait_time = ssp.dwWaitHint / 10;
                    if wait_time < 1000 {
                        wait_time = 1000;
                    } else if wait_time > 10000 {
                        wait_time = 10000;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(wait_time as u64));

                    if !QueryServiceStatusEx(
                        hservice,
                        SC_STATUS_PROCESS_INFO,
                        Some(to_buffer_mut::<SERVICE_STATUS_PROCESS>(&mut ssp)),
                        &mut bytesneed,
                    )
                    .as_bool()
                    {
                        break;
                    }

                    if ssp.dwCheckPoint > old_checkpoint {
                        // continue to wait and check
                        start_tick_count = GetTickCount();
                        old_checkpoint = ssp.dwCheckPoint;
                    } else {
                        if (GetTickCount() - start_tick_count) > ssp.dwWaitHint {
                            CloseServiceHandle(hservice);
                            CloseServiceHandle(hmanager);
                            break;
                        }
                    }
                }

                CloseServiceHandle(hservice);
                CloseServiceHandle(hmanager);

                if ssp.dwCurrentState == SERVICE_RUNNING {
                    return Ok(());
                }

                return Err( anyhow::anyhow!("service not started. current state: {:?}, exit code {}, check point: {}, wait hint: {}, error: {:?}", 
                ssp.dwCurrentState, ssp.dwWin32ExitCode, ssp.dwCheckPoint, ssp.dwWaitHint, GetLastError()));
            }
            CloseServiceHandle(hmanager);
            return Err(anyhow::anyhow!("{:?}", GetLastError()));
        }
    }

    pub fn stop_service(&mut self) -> Result<()> {
        unsafe {
            let hmanager = OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)?;
            if let Ok(hservice) = OpenServiceW(hmanager, p!(self.service_name), SERVICE_ALL_ACCESS)
            {
                let mut ssp = SERVICE_STATUS_PROCESS::default();
                let mut bytesneed: u32 = 0;

                if !QueryServiceStatusEx(
                    hservice,
                    SC_STATUS_PROCESS_INFO,
                    Some(to_buffer_mut::<SERVICE_STATUS_PROCESS>(&mut ssp)),
                    &mut bytesneed,
                )
                .as_bool()
                {
                    CloseServiceHandle(hservice);
                    CloseServiceHandle(hmanager);
                    return Err(anyhow::anyhow!(
                        "query service status failed {:?}",
                        GetLastError()
                    ));
                }

                // service stopped
                if ssp.dwCurrentState == SERVICE_STOP_PENDING {
                    println!(
                        "service not stoped, waitting stopping current_state{:?}",
                        ssp.dwCurrentState
                    );
                    // service stop pendign
                    let start_time = GetTickCount();
                    while ssp.dwCurrentState == SERVICE_STOP_PENDING {
                        let mut wait_time = ssp.dwWaitHint / 10;
                        if wait_time < 1000 {
                            wait_time = 1000;
                        } else if wait_time > 10000 {
                            wait_time = 10000;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(wait_time as u64));

                        if !QueryServiceStatusEx(
                            hservice,
                            SC_STATUS_PROCESS_INFO,
                            Some(to_buffer_mut::<SERVICE_STATUS_PROCESS>(&mut ssp)),
                            &mut bytesneed,
                        )
                        .as_bool()
                        {
                            CloseServiceHandle(hservice);
                            CloseServiceHandle(hmanager);
                            return Err(anyhow::anyhow!(
                                "query service status failed {:?}",
                                GetLastError()
                            ));
                        }

                        if (GetTickCount() - start_time) > 30000 {
                            CloseServiceHandle(hservice);
                            CloseServiceHandle(hmanager);
                            return Err(anyhow::anyhow!("stop service timeout"));
                        }
                    }
                } else {
                    // stop srevice
                    let mut ss = SERVICE_STATUS::default();
                    println!("control stop service");
                    if ControlService(hservice, SERVICE_CONTROL_STOP, &mut ss) == true {
                        ssp.dwCheckPoint = ss.dwCheckPoint;
                        ssp.dwControlsAccepted = ss.dwControlsAccepted;
                        ssp.dwCurrentState = ss.dwCurrentState;
                        ssp.dwWaitHint = ss.dwWaitHint;
                        std::thread::sleep(std::time::Duration::from_millis(ssp.dwWaitHint as u64));
                        let start_time = GetTickCount();
                        while ssp.dwCurrentState == SERVICE_STOP_PENDING {
                            let mut wait_time = ssp.dwWaitHint / 10;
                            if wait_time < 1000 {
                                wait_time = 1000;
                            } else if wait_time > 10000 {
                                wait_time = 10000;
                            }
                            std::thread::sleep(std::time::Duration::from_millis(wait_time as u64));

                            if !QueryServiceStatusEx(
                                hservice,
                                SC_STATUS_PROCESS_INFO,
                                Some(to_buffer_mut::<SERVICE_STATUS_PROCESS>(&mut ssp)),
                                &mut bytesneed,
                            )
                            .as_bool()
                            {
                                CloseServiceHandle(hservice);
                                CloseServiceHandle(hmanager);
                                return Err(anyhow::anyhow!(
                                    "query service status failed {:?}",
                                    GetLastError()
                                ));
                            }

                            if (GetTickCount() - start_time) > 30000 {
                                CloseServiceHandle(hservice);
                                CloseServiceHandle(hmanager);
                                return Err(anyhow::anyhow!("stop service timeout"));
                            }
                        }
                        println!("service stoped");
                    } else {
                        CloseServiceHandle(hservice);
                        CloseServiceHandle(hmanager);
                        return Err(anyhow::anyhow!("stop service failed {:?}", GetLastError()));
                    }
                }
                CloseServiceHandle(hservice);
                CloseServiceHandle(hmanager);
                Ok(())
            } else {
                CloseServiceHandle(hmanager);
                if GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST {
                    return Ok(());
                }
                Err(anyhow::anyhow!("{:?}", GetLastError()))
            }
        }
    }
}

impl Drop for DriverLoader {
    fn drop(&mut self) {
        let _ = self.stop_service();
        let _ = self.uninstall_serviec();
    }
}

pub fn new(file_path: String, service_name: String, display_name: String) -> DriverLoader {
    DriverLoader {
        file_path,
        service_name,
        display_name,
    }
}
