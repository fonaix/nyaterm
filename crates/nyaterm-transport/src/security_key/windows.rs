//! System WebAuthn owns PIN entry. Load it dynamically so older Windows builds
//! can still run the application and report unsupported hardware authentication.
use super::{DeviceSignature, POLL, SecurityKeyError, SigningRequest, interaction::Interaction};
use std::sync::mpsc;
use windows_sys::Win32::Foundation::{FreeLibrary, HWND};
use windows_sys::Win32::Networking::WindowsWebServices::{
    WEBAUTHN_ASSERTION, WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS, WEBAUTHN_CLIENT_DATA, WEBAUTHN_CREDENTIAL,
    WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY, WEBAUTHN_CREDENTIALS, WEBAUTHN_HASH_ALGORITHM_SHA_256,
    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::core::{GUID, HRESULT, PCWSTR};

type GetAssertion = unsafe extern "system" fn(
    HWND,
    PCWSTR,
    *const WEBAUTHN_CLIENT_DATA,
    *const WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
    *mut *mut WEBAUTHN_ASSERTION,
) -> HRESULT;
type FreeAssertion = unsafe extern "system" fn(*const WEBAUTHN_ASSERTION);
type CancellationId = unsafe extern "system" fn(*mut GUID) -> HRESULT;
type Cancel = unsafe extern "system" fn(*const GUID) -> HRESULT;
type Version = unsafe extern "system" fn() -> u32;

struct Api {
    module: usize,
    get: GetAssertion,
    free: FreeAssertion,
    cancellation_id: CancellationId,
    cancel: Cancel,
}
impl Drop for Api {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.module as _);
        }
    }
}
impl Api {
    fn load() -> Result<Self, SecurityKeyError> {
        // Only the Windows system directory is searched, never the working directory.
        let module = unsafe {
            LoadLibraryExW(
                windows_sys::w!("webauthn.dll"),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return Err(SecurityKeyError::Unavailable);
        }
        let result = (|| {
            macro_rules! symbol {
                ($name:literal, $ty:ty) => {{
                    let address = unsafe { GetProcAddress(module, concat!($name, "\0").as_ptr()) }
                        .ok_or(SecurityKeyError::Unavailable)?;
                    // Each signature below matches the Windows SDK declaration.
                    unsafe {
                        std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(address)
                    }
                }};
            }
            let version = symbol!("WebAuthNGetApiVersionNumber", Version);
            if unsafe { version() } == 0 {
                return Err(SecurityKeyError::Unavailable);
            }
            Ok(Self {
                module: module as usize,
                get: symbol!("WebAuthNAuthenticatorGetAssertion", GetAssertion),
                free: symbol!("WebAuthNFreeAssertion", FreeAssertion),
                cancellation_id: symbol!("WebAuthNGetCancellationId", CancellationId),
                cancel: symbol!("WebAuthNCancelCurrentOperation", Cancel),
            })
        })();
        if result.is_err() {
            unsafe {
                FreeLibrary(module);
            }
        }
        result
    }
}

pub(super) fn sign(
    request: &SigningRequest,
    interaction: &mut Interaction,
) -> Result<DeviceSignature, SecurityKeyError> {
    let api = Api::load()?;
    let owner = interaction.parent_window()?;
    let mut cancellation = GUID::from_u128(0);
    if unsafe { (api.cancellation_id)(&mut cancellation) } < 0 {
        return Err(SecurityKeyError::Unavailable);
    }
    let timeout = interaction.remaining_ms().min(u32::MAX as u64) as u32;
    std::thread::scope(|scope| {
        let (tx, rx) = mpsc::sync_channel(1);
        let api_ref = &api;
        let cancellation_ref = &cancellation;
        let worker = scope.spawn(move || {
            let result = get_assertion(api_ref, request, owner, cancellation_ref, timeout);
            let _ = tx.send(result);
        });
        let mut cancelled = None;
        let result = loop {
            if cancelled.is_none() {
                cancelled = interaction.check().err();
            }
            if cancelled.is_some() {
                // Repeat to cover cancellation racing with entry into GetAssertion.
                unsafe {
                    (api.cancel)(&cancellation);
                }
            }
            match rx.recv_timeout(POLL) {
                Ok(result) => break cancelled.map_or(result, Err),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break Err(SecurityKeyError::Worker),
            }
        };
        worker.join().map_err(|_| SecurityKeyError::Worker)?;
        result
    })
}

fn get_assertion(
    api: &Api,
    request: &SigningRequest,
    owner: usize,
    cancellation: &GUID,
    timeout: u32,
) -> Result<DeviceSignature, SecurityKeyError> {
    let rp: Vec<u16> = request.application.encode_utf16().chain(Some(0)).collect();
    let mut credential = WEBAUTHN_CREDENTIAL {
        dwVersion: 1,
        cbId: request
            .credential
            .len()
            .try_into()
            .map_err(|_| SecurityKeyError::InvalidKey)?,
        pbId: request.credential.as_ptr().cast_mut(),
        pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
    };
    // WebAuthn hashes these bytes once; SSH uses its binary authentication buffer
    // as client data, not browser-generated JSON and not an already computed hash.
    let data = WEBAUTHN_CLIENT_DATA {
        dwVersion: 1,
        cbClientDataJSON: request
            .message
            .len()
            .try_into()
            .map_err(|_| SecurityKeyError::InvalidKey)?,
        pbClientDataJSON: request.message.as_ptr().cast_mut(),
        pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
    };
    let options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
        dwVersion: 3,
        dwTimeoutMilliseconds: timeout,
        CredentialList: WEBAUTHN_CREDENTIALS {
            cCredentials: 1,
            pCredentials: &mut credential,
        },
        dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
        dwUserVerificationRequirement: if request.verification_required {
            WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED
        } else {
            WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED
        },
        pCancellationId: std::ptr::from_ref(cancellation).cast_mut(),
        ..Default::default()
    };
    let mut result = std::ptr::null_mut();
    let status = unsafe { (api.get)(owner as HWND, rp.as_ptr(), &data, &options, &mut result) };
    struct Assertion<'a>(&'a Api, *mut WEBAUTHN_ASSERTION);
    impl Drop for Assertion<'_> {
        fn drop(&mut self) {
            if !self.1.is_null() {
                unsafe {
                    (self.0.free)(self.1);
                }
            }
        }
    }
    let result = Assertion(api, result);
    if status < 0 {
        return Err(match status as u32 {
            0x800704c7 | 0x80090036 => SecurityKeyError::Cancelled,
            0x800705b4 => SecurityKeyError::TimedOut,
            0x80090029 => SecurityKeyError::Unavailable,
            _ => SecurityKeyError::Device,
        });
    }
    if result.1.is_null() {
        return Err(SecurityKeyError::InvalidSignature);
    }
    let assertion = unsafe { &*result.1 };
    // No extensions were requested. SSH's signature format carries precisely the
    // RP hash, flags and counter; do not silently strip additional signed bytes.
    if assertion.cbAuthenticatorData != 37
        || assertion.pbAuthenticatorData.is_null()
        || assertion.cbSignature == 0
        || assertion.cbSignature > 256
        || assertion.pbSignature.is_null()
        || assertion.Credential.cbId == 0
        || assertion.Credential.cbId > 65536
        || assertion.Credential.pbId.is_null()
    {
        return Err(SecurityKeyError::InvalidSignature);
    }
    let auth = unsafe { std::slice::from_raw_parts(assertion.pbAuthenticatorData, 37) };
    Ok(DeviceSignature {
        credential: Some(
            unsafe {
                std::slice::from_raw_parts(
                    assertion.Credential.pbId,
                    assertion.Credential.cbId as usize,
                )
            }
            .to_vec(),
        ),
        rp_hash: auth[..32]
            .try_into()
            .map_err(|_| SecurityKeyError::InvalidSignature)?,
        flags: auth[32],
        counter: u32::from_be_bytes(
            auth[33..37]
                .try_into()
                .map_err(|_| SecurityKeyError::InvalidSignature)?,
        ),
        signature: unsafe {
            std::slice::from_raw_parts(assertion.pbSignature, assertion.cbSignature as usize)
        }
        .to_vec(),
    })
}
