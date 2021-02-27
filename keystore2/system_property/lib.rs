// Copyright 2021, The Android Open Source Project
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

//! This crate provides the PropertyWatcher type, which watches for changes
//! in Android system properties.

use std::os::raw::c_char;
use std::ptr::null_mut;
use std::{
    ffi::{c_void, CStr, CString},
    str::Utf8Error,
};
use thiserror::Error;

/// Errors this crate can generate
#[derive(Error, Debug)]
pub enum PropertyWatcherError {
    /// We can't watch for a property whose name contains a NUL character.
    #[error("Cannot convert name to C string")]
    BadNameError(#[from] std::ffi::NulError),
    /// We can only watch for properties that exist when the watcher is created.
    #[error("System property is absent")]
    SystemPropertyAbsent,
    /// __system_property_wait timed out despite being given no timeout.
    #[error("Wait failed")]
    WaitFailed,
    /// read callback was not called
    #[error("__system_property_read_callback did not call callback")]
    ReadCallbackNotCalled,
    /// read callback gave us a NULL pointer
    #[error("__system_property_read_callback gave us a NULL pointer instead of a string")]
    MissingCString,
    /// read callback gave us a bad C string
    #[error("__system_property_read_callback gave us a non-UTF8 C string")]
    BadCString(#[from] Utf8Error),
    /// read callback returned an error
    #[error("Callback failed")]
    CallbackError(#[from] anyhow::Error),
}

/// Result type specific for this crate.
pub type Result<T> = std::result::Result<T, PropertyWatcherError>;

/// PropertyWatcher takes the name of an Android system property such
/// as `keystore.boot_level`; it can report the current value of this
/// property, or wait for it to change.
pub struct PropertyWatcher {
    prop_info: *const keystore2_system_property_bindgen::prop_info,
    serial: keystore2_system_property_bindgen::__uint32_t,
}

impl PropertyWatcher {
    /// Create a PropertyWatcher for the named system property.
    pub fn new(name: &str) -> Result<Self> {
        let cstr = CString::new(name)?;
        // Unsafe FFI call. We generate the CStr in this function
        // and so ensure it is valid during call.
        // Returned pointer is valid for the lifetime of the program.
        let prop_info =
            unsafe { keystore2_system_property_bindgen::__system_property_find(cstr.as_ptr()) };
        if prop_info.is_null() {
            Err(PropertyWatcherError::SystemPropertyAbsent)
        } else {
            Ok(Self { prop_info, serial: 0 })
        }
    }

    fn read_raw(&self, mut f: impl FnOnce(Option<&CStr>, Option<&CStr>)) {
        // Unsafe function converts values passed to us by
        // __system_property_read_callback to Rust form
        // and pass them to inner callback.
        unsafe extern "C" fn callback(
            res_p: *mut c_void,
            name: *const c_char,
            value: *const c_char,
            _: keystore2_system_property_bindgen::__uint32_t,
        ) {
            let name = if name.is_null() { None } else { Some(CStr::from_ptr(name)) };
            let value = if value.is_null() { None } else { Some(CStr::from_ptr(value)) };
            let f = &mut *res_p.cast::<&mut dyn FnMut(Option<&CStr>, Option<&CStr>)>();
            f(name, value);
        }

        let mut f: &mut dyn FnOnce(Option<&CStr>, Option<&CStr>) = &mut f;

        // Unsafe block for FFI call. We convert the FnOnce
        // to a void pointer, and unwrap it in our callback.
        unsafe {
            keystore2_system_property_bindgen::__system_property_read_callback(
                self.prop_info,
                Some(callback),
                &mut f as *mut _ as *mut c_void,
            )
        }
    }

    /// Call the passed function, passing it the name and current value
    /// of this system property. See documentation for
    /// `__system_property_read_callback` for details.
    pub fn read<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&str, &str) -> anyhow::Result<T>,
    {
        let mut result = Err(PropertyWatcherError::ReadCallbackNotCalled);
        self.read_raw(|name, value| {
            // use a wrapping closure as an erzatz try block.
            result = (|| {
                let name = name.ok_or(PropertyWatcherError::MissingCString)?.to_str()?;
                let value = value.ok_or(PropertyWatcherError::MissingCString)?.to_str()?;
                f(name, value).map_err(PropertyWatcherError::CallbackError)
            })()
        });
        result
    }

    /// Wait for the system property to change. This
    /// records the serial number of the last change, so
    /// race conditions are avoided.
    pub fn wait(&mut self) -> Result<()> {
        let mut new_serial = self.serial;
        // Unsafe block to call __system_property_wait.
        // All arguments are private to PropertyWatcher so we
        // can be confident they are valid.
        if !unsafe {
            keystore2_system_property_bindgen::__system_property_wait(
                self.prop_info,
                self.serial,
                &mut new_serial,
                null_mut(),
            )
        } {
            return Err(PropertyWatcherError::WaitFailed);
        }
        self.serial = new_serial;
        Ok(())
    }
}
