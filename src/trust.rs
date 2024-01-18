extern crate windows_sys;

use std::mem;
use std::ffi::c_void;
use windows_sys::core::{GUID, PWSTR};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::Security::WinTrust::*;

const TRUST_E_SYSTEM_ERROR: u32 = 0x80096001;
const TRUST_E_NO_SIGNER_CERT: u32 = 0x80096002;
const TRUST_E_COUNTER_SIGNER: u32 = 0x80096003;
const TRUST_E_CERT_SIGNATURE: u32 = 0x80096004;
const TRUST_E_TIME_STAMP: u32 = 0x80096005;
const TRUST_E_BAD_DIGEST: u32 = 0x80096010;
const TRUST_E_BASIC_CONSTRAINTS: u32 = 0x80096019;
const TRUST_E_FINANCIAL_CRITERIA: u32 = 0x8009601E;
const TRUST_E_PROVIDER_UNKNOWN: u32 = 0x800B0001;
const TRUST_E_ACTION_UNKNOWN: u32 = 0x800B0002;
const TRUST_E_SUBJECT_FORM_UNKNOWN: u32 = 0x800B0003;
const TRUST_E_SUBJECT_NOT_TRUSTED: u32 = 0x800B0004;
const TRUST_E_NOSIGNATURE: u32 = 0x800B0100;
const CERT_E_UNTRUSTEDROOT: u32 = 0x800B0109;
const TRUST_E_FAIL: u32 = 0x800B010B;
const TRUST_E_EXPLICIT_DISTRUST: u32 = 0x800B0111;
const CERT_E_CHAINING: u32 = 0x800B010A;
const CRYPT_E_FILE_ERROR: u32 = 0x80092003;
const SUCCESS: u32 = 0;

pub struct TrustData {
    pub valid: bool,
    pub message: String,
}

pub unsafe fn check_cert(path: &str) -> Result<TrustData, String> {
    let mut utf16_path = path.encode_utf16().collect::<Vec<u16>>();
    utf16_path.push(0);
    let mut file_data = WINTRUST_FILE_INFO {
        hFile: 0,
        pcwszFilePath: utf16_path.as_mut_ptr(),
        pgKnownSubject: 0 as *mut GUID,
        cbStruct: mem::size_of::<WINTRUST_FILE_INFO> as u32,
    };

    let wintrust_data_0 = WINTRUST_DATA_0 {
        pFile: &mut file_data
    };

    let mut wintrust_data = WINTRUST_DATA {
        cbStruct: mem::size_of::<WINTRUST_DATA> as u32,
        pPolicyCallbackData: 0 as *mut c_void,
        pSIPClientData: 0 as *mut c_void,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: wintrust_data_0,
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: 0,
        pwszURLReference: 0 as PWSTR,
        dwProvFlags: 0,
        dwUIContext: 0,
        pSignatureSettings: 0 as *mut WINTRUST_SIGNATURE_SETTINGS,
    };

    let state_ptr: *mut c_void = &mut wintrust_data as *mut _ as *mut c_void;
    let result: Result<TrustData, String>;

    let status = WinVerifyTrust(0, &mut WINTRUST_ACTION_GENERIC_VERIFY_V2.clone(), state_ptr);
    match status as u32 {
        SUCCESS => result = Ok(TrustData { valid: true, message: String::new() }),
        TRUST_E_NO_SIGNER_CERT => result = Ok(TrustData { valid: false, message: String::from("Invalid cert found: result TRUST_E_NO_SIGNER_CERT") }),
        TRUST_E_COUNTER_SIGNER => result = Ok(TrustData { valid: false, message: String::from("Invalid cert found: result TRUST_E_COUNTER_SIGNER") }),
        TRUST_E_CERT_SIGNATURE => result = Ok(TrustData { valid: false, message: String::from("Invalid cert found: result TRUST_E_CERT_SIGNATURE") }),
        TRUST_E_TIME_STAMP => result = Ok(TrustData { valid: false, message: String::from("Expired cert found: result TRUST_E_TIME_STAMP") }),
        TRUST_E_BAD_DIGEST => result = Ok(TrustData { valid: false, message: String::from("Invalid cert found: result TRUST_E_BAD_DIGEST") }),
        TRUST_E_BASIC_CONSTRAINTS => result = Ok(TrustData { valid: false, message: String::from("Invalid cert found: result TRUST_E_BASIC_CONSTRAINTS") }),
        TRUST_E_FINANCIAL_CRITERIA => result = Ok(TrustData { valid: false, message: String::from("Invalid cert found: result TRUST_E_FINANCIAL_CRITERIA") }),
        TRUST_E_PROVIDER_UNKNOWN => result = Ok(TrustData { valid: false, message: String::from("Invalid cert found: result TRUST_E_PROVIDER_UNKNOWN") }),
        TRUST_E_ACTION_UNKNOWN => result = Ok(TrustData { valid: false, message: String::from("Invalid cert found: result TRUST_E_ACTION_UNKNOWN") }),
        TRUST_E_SUBJECT_FORM_UNKNOWN => result = Ok(TrustData { valid: false, message: String::from("Invalid cert found: result TRUST_E_SUBJECT_FORM_UNKNOWN") }),
        TRUST_E_SUBJECT_NOT_TRUSTED => result = Ok(TrustData { valid: false, message: String::from("Invalid cert found: result TRUST_E_SUBJECT_NOT_TRUSTED") }),
        TRUST_E_NOSIGNATURE => result = Ok(TrustData { valid: false, message: String::from("Unsigned PE found: result TRUST_E_NOSIGNATURE") }),
        CERT_E_UNTRUSTEDROOT => result = Ok(TrustData { valid: false, message: String::from("Invalid cert found: result CERT_E_UNTRUSTEDROOT") }),
        TRUST_E_FAIL => result = Ok(TrustData { valid: false, message: String::from("Invalid cert found: result TRUST_E_FAIL") }),
        TRUST_E_EXPLICIT_DISTRUST => result = Ok(TrustData { valid: false, message: String::from("Explicitly untrusted cert found: result TRUST_E_EXPLICIT_DISTRUST") }),
        CERT_E_CHAINING => result = Ok(TrustData { valid: false, message: String::from("Invalid cert found: result CERT_E_CHAINING") }),
        TRUST_E_SYSTEM_ERROR => result = Err(String::from("Error: result TRUST_E_SYSTEM_ERROR")),
        CRYPT_E_FILE_ERROR => {
            result = Err(String::from("Error: CRYPT_E_FILE_ERROR - couldn't read file - check manually"));
        }
        _ => result = Err(String::from(format!("Unknown error: code: 0x{:X}", status))),
    }

    wintrust_data.dwStateAction = WTD_STATEACTION_CLOSE;

    WinVerifyTrust(HWND::default(), &mut WINTRUST_ACTION_GENERIC_VERIFY_V2.clone(), state_ptr);

    return result;
}