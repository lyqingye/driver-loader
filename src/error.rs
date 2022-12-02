use std::ffi::FromBytesWithNulError;
use std::str::Utf8Error;
use thiserror::Error;
use windows::{core::HSTRING, Win32::Foundation::WIN32_ERROR};

pub type Result<T, E = DrvLdrError> = core::result::Result<T, E>;

#[derive(Error, Debug)]
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

    #[error("call driver buffer to small")]
    CallDrvBufferToSmall,

    #[error("call driver fail! {0}")]
    CallDrvErr(HSTRING),

    #[error("symbol {0} not found ")]
    SymbolNotFound(String),

    #[error("invalid pdb cache dir {0}")]
    InvalidPdbCacheDir(String),

    #[error("{0}")]
    OtherError(#[from] anyhow::Error),

    #[error("{0}")]
    IoError(#[from] std::io::Error),

    #[error("{0}")]
    PdbErr(#[from] pdb::Error),

    #[error("{0}")]
    HttpErr(#[from] reqwest::Error),

    #[error("{0}")]
    PEErr(#[from] goblin::error::Error),

    #[error("{0}")]
    OtherErr(#[from] core::convert::Infallible),

    #[error("{0}")]
    FFIErr(#[from] FromBytesWithNulError),

    #[error("{0}")]
    FFIEncodeErr(#[from] Utf8Error),
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

impl From<windows::core::Error> for DrvLdrError {
    fn from(value: windows::core::Error) -> Self {
        Self::Win32Error(format!(
            "code: {} message: {}",
            value.code().0,
            value.code().message()
        ))
    }
}
