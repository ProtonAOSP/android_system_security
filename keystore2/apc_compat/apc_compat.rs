// Copyright 2020, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This crate implements a safe wrapper around the ConfirmationUI HIDL spec, which
//! is the backend for Android Protected Confirmation (APC).
//!
//! It provides a safe wrapper around a C++ implementation of ConfirmationUI
//! client.

use keystore2_apc_compat_bindgen::{
    abortUserConfirmation, closeUserConfirmationService, promptUserConfirmation, size_t,
    tryGetUserConfirmationService, ApcCompatCallback, ApcCompatServiceHandle,
};
pub use keystore2_apc_compat_bindgen::{
    ApcCompatUiOptions, APC_COMPAT_ERROR_ABORTED, APC_COMPAT_ERROR_CANCELLED,
    APC_COMPAT_ERROR_IGNORED, APC_COMPAT_ERROR_OK, APC_COMPAT_ERROR_OPERATION_PENDING,
    APC_COMPAT_ERROR_SYSTEM_ERROR, INVALID_SERVICE_HANDLE,
};
use std::{ffi::CString, slice};

/// Safe wrapper around the ConfirmationUI HIDL spec.
///
/// # Example
/// ```
/// struct Cb();
/// impl ApcHalCallback for Cb {
///     fn result(
///         &self,
///         rc: u32,
///         message: Option<&[u8]>,
///         token: Option<&[u8]>,
///     ) {
///         println!("Callback called with rc: {}, message: {}, token: {}", rc, message, token);
///     }
/// };
///
/// fn prompt() -> Result<(), u32> {
///     let hal = ApcHal::try_get_service()?;
///     hal.prompt_user_confirmation(Box::new(Cb()), "Do you agree?", b"extra data", "en", 0)?;
/// }
///
/// ```
pub struct ApcHal(ApcCompatServiceHandle);

unsafe impl Send for ApcHal {}
unsafe impl Sync for ApcHal {}

impl Drop for ApcHal {
    fn drop(&mut self) {
        // # Safety:
        // This ends the life cycle of the contained `ApcCompatServiceHandle` owned by this
        // `ApcHal` object.
        //
        // `ApcHal` objects are only created if a valid handle was acquired so self.0 is
        // always valid when dropped.
        unsafe {
            closeUserConfirmationService(self.0);
        }
    }
}

type Callback = dyn FnOnce(u32, Option<&[u8]>, Option<&[u8]>);

extern "C" fn confirmation_result_callback(
    handle: *mut ::std::os::raw::c_void,
    rc: u32,
    tbs_message: *const u8,
    tbs_message_size: size_t,
    confirmation_token: *const u8,
    confirmation_token_size: size_t,
) {
    // # Safety:
    // The C/C++ implementation must pass to us the handle that was created
    // and assigned to the `ApcCompatCallback::data` field in
    // `ApcHal::prompt_user_confirmation` below. Also we consume the handle,
    // by letting `hal_cb` go out of scope with this function call. So
    // the C/C++ implementation must assure that each `ApcCompatCallback` is only used once.
    let hal_cb: Box<Box<Callback>> = unsafe { Box::from_raw(handle as *mut Box<Callback>) };
    let tbs_message = match (tbs_message.is_null(), tbs_message_size) {
        (true, _) | (_, 0) => None,
        (false, s) => Some(
            // # Safety:
            // If the pointer and size is not nullptr and not 0 respectively, the C/C++
            // implementation must pass a valid pointer to an allocation of at least size bytes,
            // and the pointer must be valid until this function returns.
            unsafe { slice::from_raw_parts(tbs_message, s as usize) },
        ),
    };
    let confirmation_token = match (confirmation_token.is_null(), confirmation_token_size) {
        (true, _) | (_, 0) => None,
        (false, s) => Some(
            // # Safety:
            // If the pointer and size is not nullptr and not 0 respectively, the C/C++
            // implementation must pass a valid pointer to an allocation of at least size bytes,
            // and the pointer must be valid until this function returns.
            unsafe { slice::from_raw_parts(confirmation_token, s as usize) },
        ),
    };
    hal_cb(rc, tbs_message, confirmation_token)
}

impl ApcHal {
    /// Attempts to connect to the APC (confirmationui) backend. On success, it returns an
    /// initialized `ApcHal` object.
    pub fn try_get_service() -> Option<Self> {
        // # Safety:
        // `tryGetUserConfirmationService` returns a valid handle or INVALID_SERVICE_HANDLE.
        // On success, `ApcHal` takes ownership of this handle and frees it with
        // `closeUserConfirmationService` when dropped.
        let handle = unsafe { tryGetUserConfirmationService() };
        match handle {
            h if h == unsafe { INVALID_SERVICE_HANDLE } => None,
            h => Some(Self(h)),
        }
    }

    /// Attempts to start a confirmation prompt. The given callback is consumed, and it is
    /// guaranteed to be called eventually IFF this function returns `APC_COMPAT_ERROR_OK`.
    ///
    /// The callback has the following arguments:
    /// rc: u32 - The reason for the termination which takes one of the values.
    ///       * `APC_COMPAT_ERROR_OK` - The user confirmed the prompted message.
    ///       * `APC_COMPAT_ERROR_CANCELLED` - The user rejected the prompted message.
    ///       * `APC_COMPAT_ERROR_ABORTED` - The prompt was aborted either because the client
    ///          aborted. the session or an asynchronous system event occurred that ended the
    ///          prompt prematurely.
    ///       * `APC_COMPAT_ERROR_SYSTEMERROR` - An unspecified system error occurred. Logs may
    ///          have more information.
    ///
    /// data_confirmed: Option<&[u8]> and
    /// confirmation_token: Option<&[u8]> hold the confirmed message and the confirmation token
    /// respectively. They must be `Some()` if `rc == APC_COMPAT_ERROR_OK` and `None` otherwise.
    ///
    /// `cb` does not get called if this function returns an error.
    /// (Thus the allow(unused_must_use))
    #[allow(unused_must_use)]
    pub fn prompt_user_confirmation<F>(
        &self,
        prompt_text: &str,
        extra_data: &[u8],
        locale: &str,
        ui_opts: ApcCompatUiOptions,
        cb: F,
    ) -> Result<(), u32>
    where
        F: FnOnce(u32, Option<&[u8]>, Option<&[u8]>) + 'static,
    {
        let cb_data_ptr = Box::into_raw(Box::new(Box::new(cb) as Box<Callback>));
        let cb = ApcCompatCallback {
            data: cb_data_ptr as *mut std::ffi::c_void,
            result: Some(confirmation_result_callback),
        };
        let prompt_text = CString::new(prompt_text).unwrap();
        let locale = CString::new(locale).unwrap();
        // # Safety:
        // The `ApcCompatCallback` object (`cb`) is passed to the callee by value, and with it
        // ownership of the `data` field pointer. The data pointer is guaranteed to be valid
        // until the C/C++ implementation calls the callback. Calling the callback consumes
        // the data pointer. The C/C++ implementation must not access it after calling the
        // callback and it must not call the callback a second time.
        //
        // The C/C++ must make no assumptions about the life time of the other parameters after
        // the function returns.
        let rc = unsafe {
            promptUserConfirmation(
                self.0,
                cb,
                prompt_text.as_ptr(),
                extra_data.as_ptr(),
                extra_data.len() as size_t,
                locale.as_ptr(),
                ui_opts,
            )
        };
        match rc {
            APC_COMPAT_ERROR_OK => Ok(()),
            rc => {
                // # Safety:
                // If promptUserConfirmation does not succeed, it must not take ownership of the
                // callback, so we must destroy it.
                unsafe { Box::from_raw(cb_data_ptr) };
                Err(rc)
            }
        }
    }

    /// Aborts a running confirmation session, or no-op if none is running.
    pub fn abort(&self) {
        // # Safety:
        // It is always safe to call `abortUserConfirmation`, because spurious calls are ignored.
        // The handle argument must be valid, but this is an invariant of `ApcHal`.
        unsafe { abortUserConfirmation(self.0) }
    }
}
