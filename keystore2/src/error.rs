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
//! `ResponseCode::SYSTEM_ERROR` and logs any error condition.
//!
//! Keystore functions should use `anyhow::Result` to return error conditions, and
//! context should be added every time an error is forwarded.

use std::cmp::PartialEq;

pub use android_hardware_security_keymint::aidl::android::hardware::security::keymint::ErrorCode::ErrorCode;
pub use android_system_keystore2::aidl::android::system::keystore2::ResponseCode::ResponseCode;

use keystore2_selinux as selinux;

use android_system_keystore2::binder::{
    ExceptionCode, Result as BinderResult, Status as BinderStatus, StatusCode,
};

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
    /// Wraps a Binder exception code other than a service specific exception.
    #[error("Binder exception code {0:?}, {1:?}")]
    Binder(ExceptionCode, i32),
    /// Wraps a Binder status code.
    #[error("Binder transaction error {0:?}")]
    BinderTransaction(StatusCode),
    /// Wraps a Remote Provisioning ErrorCode as defined by the IRemotelyProvisionedComponent
    /// AIDL interface spec.
    #[error("Error::Rp({0:?})")]
    Rp(ErrorCode),
}

impl Error {
    /// Short hand for `Error::Rc(ResponseCode::SYSTEM_ERROR)`
    pub fn sys() -> Self {
        Error::Rc(ResponseCode::SYSTEM_ERROR)
    }

    /// Short hand for `Error::Rc(ResponseCode::PERMISSION_DENIED`
    pub fn perm() -> Self {
        Error::Rc(ResponseCode::PERMISSION_DENIED)
    }
}

/// Helper function to map the binder status we get from calls into KeyMint
/// to a Keystore Error. We don't create an anyhow error here to make
/// it easier to evaluate KeyMint errors, which we must do in some cases, e.g.,
/// when diagnosing authentication requirements, update requirements, and running
/// out of operation slots.
pub fn map_km_error<T>(r: BinderResult<T>) -> Result<T, Error> {
    r.map_err(|s| {
        match s.exception_code() {
            ExceptionCode::SERVICE_SPECIFIC => {
                let se = s.service_specific_error();
                if se < 0 {
                    // Negative service specific errors are KM error codes.
                    Error::Km(ErrorCode(s.service_specific_error()))
                } else {
                    // Non negative error codes cannot be KM error codes.
                    // So we create an `Error::Binder` variant to preserve
                    // the service specific error code for logging.
                    // `map_or_log_err` will map this on a system error,
                    // but not before logging the details to logcat.
                    Error::Binder(ExceptionCode::SERVICE_SPECIFIC, se)
                }
            }
            // We create `Error::Binder` to preserve the exception code
            // for logging.
            // `map_or_log_err` will map this on a system error.
            e_code => Error::Binder(e_code, 0),
        }
    })
}

/// Helper function to map the binder status we get from calls into a RemotelyProvisionedComponent
/// to a Keystore Error. We don't create an anyhow error here to make
/// it easier to evaluate service specific errors.
pub fn map_rem_prov_error<T>(r: BinderResult<T>) -> Result<T, Error> {
    r.map_err(|s| match s.exception_code() {
        ExceptionCode::SERVICE_SPECIFIC => Error::Rp(ErrorCode(s.service_specific_error())),
        e_code => Error::Binder(e_code, 0),
    })
}

/// This function is similar to map_km_error only that we don't expect
/// any KeyMint error codes, we simply preserve the exception code and optional
/// service specific exception.
pub fn map_binder_status<T>(r: BinderResult<T>) -> Result<T, Error> {
    r.map_err(|s| match s.exception_code() {
        ExceptionCode::SERVICE_SPECIFIC => {
            let se = s.service_specific_error();
            Error::Binder(ExceptionCode::SERVICE_SPECIFIC, se)
        }
        ExceptionCode::TRANSACTION_FAILED => {
            let e = s.transaction_error();
            Error::BinderTransaction(e)
        }
        e_code => Error::Binder(e_code, 0),
    })
}

/// This function maps a status code onto a Keystore Error.
pub fn map_binder_status_code<T>(r: Result<T, StatusCode>) -> Result<T, Error> {
    r.map_err(Error::BinderTransaction)
}

/// This function should be used by Keystore service calls to translate error conditions
/// into service specific exceptions.
///
/// All error conditions get logged by this function.
///
/// All `Error::Rc(x)` and `Error::Km(x)` variants get mapped onto a service specific error
/// code of x. This is possible because KeyMint `ErrorCode` errors are always negative and
/// `ResponseCode` codes are always positive.
/// `selinux::Error::PermissionDenied` is mapped on `ResponseCode::PERMISSION_DENIED`.
///
/// All non `Error` error conditions and the Error::Binder variant get mapped onto
/// ResponseCode::SYSTEM_ERROR`.
///
/// `handle_ok` will be called if `result` is `Ok(value)` where `value` will be passed
/// as argument to `handle_ok`. `handle_ok` must generate a `BinderResult<T>`, but it
/// typically returns Ok(value).
///
/// # Examples
///
/// ```
/// fn loadKey() -> anyhow::Result<Vec<u8>> {
///     if (good_but_auth_required) {
///         Ok(vec!['k', 'e', 'y'])
///     } else {
///         Err(anyhow!(Error::Rc(ResponseCode::KEY_NOT_FOUND)))
///     }
/// }
///
/// map_or_log_err(loadKey(), Ok)
/// ```
pub fn map_or_log_err<T, U, F>(result: anyhow::Result<U>, handle_ok: F) -> BinderResult<T>
where
    F: FnOnce(U) -> BinderResult<T>,
{
    map_err_with(
        result,
        |e| {
            log::error!("{:?}", e);
            e
        },
        handle_ok,
    )
}

/// This function behaves similar to map_or_log_error, but it does not log the errors, instead
/// it calls map_err on the error before mapping it to a binder result allowing callers to
/// log or transform the error before mapping it.
pub fn map_err_with<T, U, F1, F2>(
    result: anyhow::Result<U>,
    map_err: F1,
    handle_ok: F2,
) -> BinderResult<T>
where
    F1: FnOnce(anyhow::Error) -> anyhow::Error,
    F2: FnOnce(U) -> BinderResult<T>,
{
    result.map_or_else(
        |e| {
            let e = map_err(e);
            let rc = get_error_code(&e);
            Err(BinderStatus::new_service_specific_error(rc, None))
        },
        handle_ok,
    )
}

/// Returns the error code given a reference to the error
pub fn get_error_code(e: &anyhow::Error) -> i32 {
    let root_cause = e.root_cause();
    match root_cause.downcast_ref::<Error>() {
        Some(Error::Rc(rcode)) => rcode.0,
        Some(Error::Km(ec)) => ec.0,
        Some(Error::Rp(_)) => ResponseCode::SYSTEM_ERROR.0,
        // If an Error::Binder reaches this stage we report a system error.
        // The exception code and possible service specific error will be
        // printed in the error log above.
        Some(Error::Binder(_, _)) | Some(Error::BinderTransaction(_)) => {
            ResponseCode::SYSTEM_ERROR.0
        }
        None => match root_cause.downcast_ref::<selinux::Error>() {
            Some(selinux::Error::PermissionDenied) => ResponseCode::PERMISSION_DENIED.0,
            _ => ResponseCode::SYSTEM_ERROR.0,
        },
    }
}

#[cfg(test)]
pub mod tests {

    use super::*;
    use android_system_keystore2::binder::{
        ExceptionCode, Result as BinderResult, Status as BinderStatus,
    };
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

    fn binder_sse_error(sse: i32) -> BinderResult<()> {
        Err(BinderStatus::new_service_specific_error(sse, None))
    }

    fn binder_exception(ex: ExceptionCode) -> BinderResult<()> {
        Err(BinderStatus::new_exception(ex, None))
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
        for rc in ResponseCode::LOCKED.0..ResponseCode::BACKEND_BUSY.0 {
            assert_eq!(
                Result::<(), i32>::Err(rc),
                map_or_log_err(nested_rc(ResponseCode(rc)), |_| Err(BinderStatus::ok()))
                    .map_err(|s| s.service_specific_error())
            );
        }

        // All Keystore Error::Km(x) get mapped on a service
        // specific error of x.
        for ec in ErrorCode::UNKNOWN_ERROR.0..ErrorCode::ROOT_OF_TRUST_ALREADY_SET.0 {
            assert_eq!(
                Result::<(), i32>::Err(ec),
                map_or_log_err(nested_ec(ErrorCode(ec)), |_| Err(BinderStatus::ok()))
                    .map_err(|s| s.service_specific_error())
            );
        }

        // All Keymint errors x received through a Binder Result get mapped on
        // a service specific error of x.
        for ec in ErrorCode::UNKNOWN_ERROR.0..ErrorCode::ROOT_OF_TRUST_ALREADY_SET.0 {
            assert_eq!(
                Result::<(), i32>::Err(ec),
                map_or_log_err(
                    map_km_error(binder_sse_error(ec))
                        .with_context(|| format!("Km error code: {}.", ec)),
                    |_| Err(BinderStatus::ok())
                )
                .map_err(|s| s.service_specific_error())
            );
        }

        // map_km_error creates an Error::Binder variant storing
        // ExceptionCode::SERVICE_SPECIFIC and the given
        // service specific error.
        let sse = map_km_error(binder_sse_error(1));
        assert_eq!(Err(Error::Binder(ExceptionCode::SERVICE_SPECIFIC, 1)), sse);
        // map_or_log_err then maps it on a service specific error of ResponseCode::SYSTEM_ERROR.
        assert_eq!(
            Result::<(), ResponseCode>::Err(ResponseCode::SYSTEM_ERROR),
            map_or_log_err(sse.context("Non negative service specific error."), |_| Err(
                BinderStatus::ok()
            ))
            .map_err(|s| ResponseCode(s.service_specific_error()))
        );

        // map_km_error creates a Error::Binder variant storing the given exception code.
        let binder_exception = map_km_error(binder_exception(ExceptionCode::TRANSACTION_FAILED));
        assert_eq!(Err(Error::Binder(ExceptionCode::TRANSACTION_FAILED, 0)), binder_exception);
        // map_or_log_err then maps it on a service specific error of ResponseCode::SYSTEM_ERROR.
        assert_eq!(
            Result::<(), ResponseCode>::Err(ResponseCode::SYSTEM_ERROR),
            map_or_log_err(binder_exception.context("Binder Exception."), |_| Err(
                BinderStatus::ok()
            ))
            .map_err(|s| ResponseCode(s.service_specific_error()))
        );

        // selinux::Error::Perm() needs to be mapped to ResponseCode::PERMISSION_DENIED
        assert_eq!(
            Result::<(), ResponseCode>::Err(ResponseCode::PERMISSION_DENIED),
            map_or_log_err(nested_selinux_perm(), |_| Err(BinderStatus::ok()))
                .map_err(|s| ResponseCode(s.service_specific_error()))
        );

        // All other errors get mapped on System Error.
        assert_eq!(
            Result::<(), ResponseCode>::Err(ResponseCode::SYSTEM_ERROR),
            map_or_log_err(nested_other_error(), |_| Err(BinderStatus::ok()))
                .map_err(|s| ResponseCode(s.service_specific_error()))
        );

        // Result::Ok variants get passed to the ok handler.
        assert_eq!(Ok(ResponseCode::LOCKED), map_or_log_err(nested_ok(ResponseCode::LOCKED), Ok));
        assert_eq!(
            Ok(ResponseCode::SYSTEM_ERROR),
            map_or_log_err(nested_ok(ResponseCode::SYSTEM_ERROR), Ok)
        );

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
