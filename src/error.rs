use thiserror::Error;
use windows::{core::HSTRING, Win32::Foundation::WIN32_ERROR};

#[derive(Error, Debug, PartialEq)]
pub enum DrvLdrError {
    #[error("Open SCManager fail! {0}")]
    OpenSCManagerErr(HSTRING),

    #[error("Create Service fail! {0}")]
    CreateServiceErr(HSTRING),

    #[error("Open Service fail! {0}")]
    OpenServiceErr(HSTRING),

    #[error("Service not exists! {0}")]
    ServiceNotExists(HSTRING),

    #[error("Delete Service fail! {0}")]
    DelServiceErr(HSTRING),

    #[error("Start Service fail! {0}")]
    StartServiceErr(HSTRING),

    #[error("Start Service Timeout! {0}")]
    StartServiceTimeoutErr(HSTRING),

    #[error("Stop Service fail! {0}")]
    StopServiceErr(HSTRING),

    #[error("Stop Service Timeout! {0}")]
    StopServiceTimeoutErr(HSTRING),

    #[error("Query Service Status fail! {0}")]
    QueryServiceStatusErr(HSTRING),

    #[error("{0}")]
    Win32Error(String),
}

impl From<WIN32_ERROR> for DrvLdrError {
    fn from(value: WIN32_ERROR) -> Self {
        Self::Win32Error(format!(
            "code: {} message: {}",
            value.0,
            value.to_hresult().message()
        ))
    }
}
