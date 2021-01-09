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

// This suppresses the compiler's complaint about converting tv_sec to i64 in method
// get_current_time_in_seconds.
#![allow(clippy::useless_conversion)]

//! This module implements utility functions used by the Keystore 2.0 service
//! implementation.

use crate::error::Error;
use crate::permission;
use crate::permission::{KeyPerm, KeyPermSet, KeystorePerm};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    KeyCharacteristics::KeyCharacteristics, SecurityLevel::SecurityLevel,
};
use android_security_apc::aidl::android::security::apc::{
    IProtectedConfirmation::{FLAG_UI_OPTION_INVERTED, FLAG_UI_OPTION_MAGNIFIED},
    ResponseCode::ResponseCode as ApcResponseCode,
};
use android_system_keystore2::aidl::android::system::keystore2::{
    Authorization::Authorization, KeyDescriptor::KeyDescriptor,
};
use anyhow::{anyhow, Context};
use binder::{FromIBinder, SpIBinder, ThreadState};
use keystore2_apc_compat::{
    ApcCompatUiOptions, APC_COMPAT_ERROR_ABORTED, APC_COMPAT_ERROR_CANCELLED,
    APC_COMPAT_ERROR_IGNORED, APC_COMPAT_ERROR_OK, APC_COMPAT_ERROR_OPERATION_PENDING,
    APC_COMPAT_ERROR_SYSTEM_ERROR,
};
use std::convert::TryFrom;
use std::sync::Mutex;

/// This function uses its namesake in the permission module and in
/// combination with with_calling_sid from the binder crate to check
/// if the caller has the given keystore permission.
pub fn check_keystore_permission(perm: KeystorePerm) -> anyhow::Result<()> {
    ThreadState::with_calling_sid(|calling_sid| {
        permission::check_keystore_permission(
            &calling_sid.ok_or_else(Error::sys).context(
                "In check_keystore_permission: Cannot check permission without calling_sid.",
            )?,
            perm,
        )
    })
}

/// This function uses its namesake in the permission module and in
/// combination with with_calling_sid from the binder crate to check
/// if the caller has the given grant permission.
pub fn check_grant_permission(access_vec: KeyPermSet, key: &KeyDescriptor) -> anyhow::Result<()> {
    ThreadState::with_calling_sid(|calling_sid| {
        permission::check_grant_permission(
            &calling_sid.ok_or_else(Error::sys).context(
                "In check_grant_permission: Cannot check permission without calling_sid.",
            )?,
            access_vec,
            key,
        )
    })
}

/// This function uses its namesake in the permission module and in
/// combination with with_calling_sid from the binder crate to check
/// if the caller has the given key permission.
pub fn check_key_permission(
    perm: KeyPerm,
    key: &KeyDescriptor,
    access_vector: &Option<KeyPermSet>,
) -> anyhow::Result<()> {
    ThreadState::with_calling_sid(|calling_sid| {
        permission::check_key_permission(
            &calling_sid
                .ok_or_else(Error::sys)
                .context("In check_key_permission: Cannot check permission without calling_sid.")?,
            perm,
            key,
            access_vector,
        )
    })
}

/// Thread safe wrapper around SpIBinder. It is safe to have SpIBinder smart pointers to the
/// same object in multiple threads, but cloning a SpIBinder is not thread safe.
/// Keystore frequently hands out binder tokens to the security level interface. If this
/// is to happen from a multi threaded thread pool, the SpIBinder needs to be protected by a
/// Mutex.
#[derive(Debug)]
pub struct Asp(Mutex<SpIBinder>);

impl Asp {
    /// Creates a new instance owning a SpIBinder wrapped in a Mutex.
    pub fn new(i: SpIBinder) -> Self {
        Self(Mutex::new(i))
    }

    /// Clones the owned SpIBinder and attempts to convert it into the requested interface.
    pub fn get_interface<T: FromIBinder + ?Sized>(&self) -> anyhow::Result<Box<T>> {
        // We can use unwrap here because we never panic when locked, so the mutex
        // can never be poisoned.
        let lock = self.0.lock().unwrap();
        (*lock)
            .clone()
            .into_interface()
            .map_err(|e| anyhow!(format!("get_interface failed with error code {:?}", e)))
    }
}

impl Clone for Asp {
    fn clone(&self) -> Self {
        let lock = self.0.lock().unwrap();
        Self(Mutex::new((*lock).clone()))
    }
}

/// Converts a set of key characteristics as returned from KeyMint into the internal
/// representation of the keystore service.
/// The parameter `hw_security_level` indicates which security level shall be used for
/// parameters found in the hardware enforced parameter list.
pub fn key_characteristics_to_internal(
    key_characteristics: KeyCharacteristics,
    hw_security_level: SecurityLevel,
) -> Vec<crate::key_parameter::KeyParameter> {
    key_characteristics
        .hardwareEnforced
        .into_iter()
        .map(|aidl_kp| crate::key_parameter::KeyParameter::new(aidl_kp.into(), hw_security_level))
        .chain(key_characteristics.softwareEnforced.into_iter().map(|aidl_kp| {
            crate::key_parameter::KeyParameter::new(aidl_kp.into(), SecurityLevel::SOFTWARE)
        }))
        .collect()
}

/// Converts a set of key characteristics from the internal representation into a set of
/// Authorizations as they are used to convey key characteristics to the clients of keystore.
pub fn key_parameters_to_authorizations(
    parameters: Vec<crate::key_parameter::KeyParameter>,
) -> Vec<Authorization> {
    parameters.into_iter().map(|p| p.into_authorization()).collect()
}

/// This returns the current time (in seconds) as an instance of a monotonic clock, by invoking the
/// system call since Rust does not support getting monotonic time instance as an integer.
pub fn get_current_time_in_seconds() -> i64 {
    let mut current_time = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // Following unsafe block includes one system call to get monotonic time.
    // Therefore, it is not considered harmful.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &mut current_time) };
    // It is safe to unwrap here because try_from() returns std::convert::Infallible, which is
    // defined to be an error that can never happen (i.e. the result is always ok).
    i64::try_from(current_time.tv_sec).unwrap()
}

/// Converts a response code as returned by the Android Protected Confirmation HIDL compatibility
/// module (keystore2_apc_compat) into a ResponseCode as defined by the APC AIDL
/// (android.security.apc) spec.
pub fn compat_2_response_code(rc: u32) -> ApcResponseCode {
    match rc {
        APC_COMPAT_ERROR_OK => ApcResponseCode::OK,
        APC_COMPAT_ERROR_CANCELLED => ApcResponseCode::CANCELLED,
        APC_COMPAT_ERROR_ABORTED => ApcResponseCode::ABORTED,
        APC_COMPAT_ERROR_OPERATION_PENDING => ApcResponseCode::OPERATION_PENDING,
        APC_COMPAT_ERROR_IGNORED => ApcResponseCode::IGNORED,
        APC_COMPAT_ERROR_SYSTEM_ERROR => ApcResponseCode::SYSTEM_ERROR,
        _ => ApcResponseCode::SYSTEM_ERROR,
    }
}

/// Converts the UI Options flags as defined by the APC AIDL (android.security.apc) spec into
/// UI Options flags as defined by the Android Protected Confirmation HIDL compatibility
/// module (keystore2_apc_compat).
pub fn ui_opts_2_compat(opt: i32) -> ApcCompatUiOptions {
    ApcCompatUiOptions {
        inverted: (opt & FLAG_UI_OPTION_INVERTED) != 0,
        magnified: (opt & FLAG_UI_OPTION_MAGNIFIED) != 0,
    }
}

/// AID offset for uid space partitioning.
/// TODO: Replace with bindgen generated from libcutils. b/175619259
pub const AID_USER_OFFSET: u32 = 100000;

/// Extracts the android user from the given uid.
pub fn uid_to_android_user(uid: u32) -> u32 {
    uid / AID_USER_OFFSET
}
