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

//! Keystore error provides convenience methods and types for Keystore error handling.
//! Clients of Keystore expect one of two error codes, i.e., a Keystore ResponseCode as
//! defined by the Keystore AIDL interface, or a Keymint ErrorCode as defined by
//! the Keymint HAL specification.
//! This crate provides `Error` which can wrap both. It is to be used
//! internally by Keystore to diagnose error conditions that need to be reported to
//! the client. To report the error condition to the client the Keystore AIDL
//! interface defines a wire type `Result` which is distinctly different from Rust's
//! `enum Result<T,E>`.
//!
//! This crate provides the convenience method `map_or_log_err` to convert `anyhow::Error`
//! into this wire type. In addition to handling the conversion of `Error`
//! to the `Result` wire type it handles any other error by mapping it to
//! `ResponseCode::SystemError` and logs any error condition.
//!
//! Keystore functions should use `anyhow::Result` to return error conditions, and
//! context should be added every time an error is forwarded.

use std::cmp::PartialEq;

pub use android_hardware_keymint::aidl::android::hardware::keymint::ErrorCode as Ec;
pub use android_security_keystore2::aidl::android::security::keystore2::ResponseCode as Rc;

use android_hardware_keymint::aidl::android::hardware::keymint::ErrorCode::ErrorCode;
use android_security_keystore2::aidl::android::security::keystore2::ResponseCode::ResponseCode;

use keystore2_selinux as selinux;

use android_security_keystore2::binder::{Result as BinderResult, Status as BinderStatus};

/// This is the main Keystore error type. It wraps the Keystore `ResponseCode` generated
/// from AIDL in the `Rc` variant and Keymint `ErrorCode` in the Km variant.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum Error {
    /// Wraps a Keystore `ResponseCode` as defined by the Keystore AIDL interface specification.
    #[error("Error::Rc({0:?})")]
    Rc(ResponseCode),
    /// Wraps a Keymint `ErrorCode` as defined by the Keymint AIDL interface specification.
    #[error("Error::Km({0:?})")]
    Km(ErrorCode),
}

impl Error {
    /// Short hand for `Error::Rc(ResponseCode::SystemError)`
    pub fn sys() -> Self {
        Error::Rc(Rc::SystemError)
    }

    /// Short hand for `Error::Rc(ResponseCode::PermissionDenied`
    pub fn perm() -> Self {
        Error::Rc(Rc::PermissionDenied)
    }
}

/// This function should be used by Keystore service calls to translate error conditions
/// into `android.security.keystore2.Result` which is imported here as `aidl::Result`
/// and newtyped as AidlResult.
/// All error conditions get logged by this function.
/// All `Error::Rc(x)` variants get mapped onto `aidl::Result{x, 0}`.
/// All `Error::Km(x)` variants get mapped onto
/// `aidl::Result{aidl::ResponseCode::KeymintErrorCode, x}`.
/// `selinux::Error::perm()` is mapped on `aidl::Result{aidl::ResponseCode::PermissionDenied, 0}`.
///
/// All non `Error` error conditions get mapped onto
/// `aidl::Result{aidl::ResponseCode::SystemError}`.
///
/// `handle_ok` will be called if `result` is `Ok(value)` where `value` will be passed
/// as argument to `handle_ok`. `handle_ok` must generate an `AidlResult`, typically
/// `AidlResult::ok()`, but other response codes may be used, e.g.,
/// `aidl::ResponseCode::OpAuthNeeded` which does not required logging.
///
/// # Examples
///
/// ```
/// fn loadKey() -> anyhow::Result<aidl::ResponseCode> {
///     if (good_but_auth_required) {
///         Ok(aidl::ResponseCode::OpAuthRequired)
///     } else {
///         Err(anyhow!(Error::Rc(aidl::ResponseCode::KeyNotFound)))
///     }
/// }
///
/// aidl_result_ = map_or_log_err(loadKey(), |r| { some_side_effect(); AidlResult::rc(r) });
/// ```
pub fn map_or_log_err<T, U, F>(result: anyhow::Result<U>, handle_ok: F) -> BinderResult<T>
where
    F: FnOnce(U) -> BinderResult<T>,
{
    result.map_or_else(
        |e| {
            log::error!("{:?}", e);
            let root_cause = e.root_cause();
            let rc = match root_cause.downcast_ref::<Error>() {
                Some(Error::Rc(rcode)) => *rcode,
                Some(Error::Km(ec)) => *ec,
                None => match root_cause.downcast_ref::<selinux::Error>() {
                    Some(selinux::Error::PermissionDenied) => Rc::PermissionDenied,
                    _ => Rc::SystemError,
                },
            };
            Err(BinderStatus::new_service_specific_error(rc, None))
        },
        handle_ok,
    )
}

#[cfg(test)]
pub mod tests {

    use super::*;
    use anyhow::{anyhow, Context};

    fn nested_nested_rc(rc: ResponseCode) -> anyhow::Result<()> {
        Err(anyhow!(Error::Rc(rc))).context("nested nested rc")
    }

    fn nested_rc(rc: ResponseCode) -> anyhow::Result<()> {
        nested_nested_rc(rc).context("nested rc")
    }

    fn nested_nested_ec(ec: ErrorCode) -> anyhow::Result<()> {
        Err(anyhow!(Error::Km(ec))).context("nested nested ec")
    }

    fn nested_ec(ec: ErrorCode) -> anyhow::Result<()> {
        nested_nested_ec(ec).context("nested ec")
    }

    fn nested_nested_ok(rc: ResponseCode) -> anyhow::Result<ResponseCode> {
        Ok(rc)
    }

    fn nested_ok(rc: ResponseCode) -> anyhow::Result<ResponseCode> {
        nested_nested_ok(rc).context("nested ok")
    }

    fn nested_nested_selinux_perm() -> anyhow::Result<()> {
        Err(anyhow!(selinux::Error::perm())).context("nested nexted selinux permission denied")
    }

    fn nested_selinux_perm() -> anyhow::Result<()> {
        nested_nested_selinux_perm().context("nested selinux permission denied")
    }

    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error("TestError::Fail")]
        Fail = 0,
    }

    fn nested_nested_other_error() -> anyhow::Result<()> {
        Err(anyhow!(TestError::Fail)).context("nested nested other error")
    }

    fn nested_other_error() -> anyhow::Result<()> {
        nested_nested_other_error().context("nested other error")
    }

    #[test]
    fn keystore_error_test() -> anyhow::Result<(), String> {
        android_logger::init_once(
            android_logger::Config::default()
                .with_tag("keystore_error_tests")
                .with_min_level(log::Level::Debug),
        );
        // All Error::Rc(x) get mapped on a service specific error
        // code of x.
        for rc in Rc::Ok..Rc::BackendBusy {
            assert_eq!(
                Result::<(), i32>::Err(rc),
                map_or_log_err(nested_rc(rc), |_| Err(BinderStatus::ok()))
                    .map_err(|s| s.service_specific_error())
            );
        }

        // All KeystoreKerror::Km(x) get mapped on a service
        // specific error of x.
        for ec in Ec::UNKNOWN_ERROR..Ec::ROOT_OF_TRUST_ALREADY_SET {
            assert_eq!(
                Result::<(), i32>::Err(ec),
                map_or_log_err(nested_ec(ec), |_| Err(BinderStatus::ok()))
                    .map_err(|s| s.service_specific_error())
            );
        }

        // selinux::Error::Perm() needs to be mapped to Rc::PermissionDenied
        assert_eq!(
            Result::<(), i32>::Err(Rc::PermissionDenied),
            map_or_log_err(nested_selinux_perm(), |_| Err(BinderStatus::ok()))
                .map_err(|s| s.service_specific_error())
        );

        // All other errors get mapped on System Error.
        assert_eq!(
            Result::<(), i32>::Err(Rc::SystemError),
            map_or_log_err(nested_other_error(), |_| Err(BinderStatus::ok()))
                .map_err(|s| s.service_specific_error())
        );

        // Result::Ok variants get passed to the ok handler.
        assert_eq!(Ok(Rc::OpAuthNeeded), map_or_log_err(nested_ok(Rc::OpAuthNeeded), Ok));
        assert_eq!(Ok(Rc::Ok), map_or_log_err(nested_ok(Rc::Ok), Ok));

        Ok(())
    }

    //Helper function to test whether error cases are handled as expected.
    pub fn check_result_contains_error_string<T>(
        result: anyhow::Result<T>,
        expected_error_string: &str,
    ) {
        let error_str = format!(
            "{:#?}",
            result.err().unwrap_or_else(|| panic!("Expected the error: {}", expected_error_string))
        );
        assert!(
            error_str.contains(expected_error_string),
            "The string \"{}\" should contain \"{}\"",
            error_str,
            expected_error_string
        );
    }
} // mod tests
