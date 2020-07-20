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
use std::convert::From;

use keystore_aidl_generated as aidl;
use keystore_aidl_generated::ResponseCode as AidlRc;

pub use aidl::ResponseCode;

/// AidlResult wraps the `android.security.keystore2.Result` generated from AIDL
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AidlResult(aidl::Result);

impl AidlResult {
    /// Creates an instance of AidlResult indicating no error has occurred.
    pub fn ok() -> Self {
        Self(aidl::Result { rc: AidlRc::Ok, km_error_code: 0 })
    }

    /// Creates an instance of AidlResult indicating the given ResponseCode.
    pub fn rc(rc: AidlRc) -> Self {
        Self(aidl::Result { rc, km_error_code: 0 })
    }

    /// Creates an instance of AidlResult indicating the given KM ErrorCode.
    pub fn ec(ec: aidl::ErrorCode) -> Self {
        Self(aidl::Result { rc: AidlRc::KeymintErrorCode, km_error_code: ec })
    }
}

/// This is the main Keystore error type. It wraps the Keystore `ResponseCode` generated
/// from AIDL in the `Rc` variant and Keymint `ErrorCode` in the Km variant.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum Error {
    /// Wraps a Keystore `ResponseCode` as defined by the Keystore AIDL interface specification.
    #[error("Error::Rc({0:?})")]
    Rc(AidlRc),
    /// Wraps a Keymint `ErrorCode` as defined by the Keymint AIDL interface specification.
    #[error("Error::Km({0:?})")]
    Km(aidl::ErrorCode), // TODO Keymint ErrorCode is a generated AIDL type.
}

impl Error {
    /// Short hand for `Error::Rc(ResponseCode::SystemError)`
    pub fn sys() -> Self {
        Error::Rc(AidlRc::SystemError)
    }

    /// Short hand for `Error::Rc(ResponseCode::PermissionDenied`
    pub fn perm() -> Self {
        Error::Rc(AidlRc::PermissionDenied)
    }
}

impl From<anyhow::Error> for AidlResult {
    fn from(error: anyhow::Error) -> Self {
        let root_cause = error.root_cause();
        match root_cause.downcast_ref::<Error>() {
            Some(Error::Rc(rcode)) => AidlResult::rc(*rcode),
            Some(Error::Km(ec)) => AidlResult::ec(*ec),
            None => AidlResult::rc(AidlRc::SystemError),
        }
    }
}

/// This function should be used by Keystore service calls to translate error conditions
/// into `android.security.keystore2.Result` which is imported here as `aidl::Result`
/// and newtyped as AidlResult.
/// All error conditions get logged by this function.
/// All `Error::Rc(x)` variants get mapped onto `aidl::Result{x, 0}`.
/// All `Error::Km(x)` variants get mapped onto
/// `aidl::Result{aidl::ResponseCode::KeymintErrorCode, x}`.
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
pub fn map_or_log_err<T>(
    result: anyhow::Result<T>,
    handle_ok: impl FnOnce(T) -> AidlResult,
) -> AidlResult {
    result.map_or_else(
        |e| {
            log::error!("{:?}", e);
            e.into()
        },
        handle_ok,
    )
}

#[cfg(test)]
mod tests {

    use anyhow::{anyhow, Context};

    use super::aidl::ErrorCode;
    use super::*;

    fn nested_nested_rc(rc: AidlRc) -> anyhow::Result<()> {
        Err(anyhow!(Error::Rc(rc))).context("nested nested rc")
    }

    fn nested_rc(rc: AidlRc) -> anyhow::Result<()> {
        nested_nested_rc(rc).context("nested rc")
    }

    fn nested_nested_ec(ec: ErrorCode) -> anyhow::Result<()> {
        Err(anyhow!(Error::Km(ec))).context("nested nested ec")
    }

    fn nested_ec(ec: ErrorCode) -> anyhow::Result<()> {
        nested_nested_ec(ec).context("nested ec")
    }

    fn nested_nested_ok(rc: AidlRc) -> anyhow::Result<AidlRc> {
        Ok(rc)
    }

    fn nested_ok(rc: AidlRc) -> anyhow::Result<AidlRc> {
        nested_nested_ok(rc).context("nested ok")
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
        // All Error::Rc(x) get mapped on aidl::Result{x, 0}
        assert_eq!(
            AidlResult::rc(AidlRc::Ok),
            map_or_log_err(nested_rc(AidlRc::Ok), |_| AidlResult::ec(0))
        );
        assert_eq!(
            AidlResult::rc(AidlRc::Locked),
            map_or_log_err(nested_rc(AidlRc::Locked), |_| AidlResult::ec(0))
        );
        assert_eq!(
            AidlResult::rc(AidlRc::Uninitialized),
            map_or_log_err(nested_rc(AidlRc::Uninitialized), |_| AidlResult::ec(0))
        );
        assert_eq!(
            AidlResult::rc(AidlRc::SystemError),
            map_or_log_err(nested_rc(AidlRc::SystemError), |_| AidlResult::ec(0))
        );
        assert_eq!(
            AidlResult::rc(AidlRc::PermissionDenied),
            map_or_log_err(nested_rc(AidlRc::PermissionDenied), |_| AidlResult::ec(0))
        );
        assert_eq!(
            AidlResult::rc(AidlRc::KeyNotFound),
            map_or_log_err(nested_rc(AidlRc::KeyNotFound), |_| AidlResult::ec(0))
        );
        assert_eq!(
            AidlResult::rc(AidlRc::ValueCorrupted),
            map_or_log_err(nested_rc(AidlRc::ValueCorrupted), |_| AidlResult::ec(0))
        );
        assert_eq!(
            AidlResult::rc(AidlRc::WrongPassword),
            map_or_log_err(nested_rc(AidlRc::WrongPassword), |_| AidlResult::ec(0))
        );
        assert_eq!(
            AidlResult::rc(AidlRc::OpAuthNeeded),
            map_or_log_err(nested_rc(AidlRc::OpAuthNeeded), |_| AidlResult::ec(0))
        );
        assert_eq!(
            AidlResult::rc(AidlRc::KeyPermanentlyInvalidated),
            map_or_log_err(nested_rc(AidlRc::KeyPermanentlyInvalidated), |_| AidlResult::ec(0))
        );
        assert_eq!(
            AidlResult::rc(AidlRc::NoSuchSecurityLevel),
            map_or_log_err(nested_rc(AidlRc::NoSuchSecurityLevel), |_| AidlResult::ec(0))
        );
        assert_eq!(
            AidlResult::rc(AidlRc::KeymintErrorCode),
            map_or_log_err(nested_rc(AidlRc::KeymintErrorCode), |_| AidlResult::ec(0))
        );
        assert_eq!(
            AidlResult::rc(AidlRc::BackendBusy),
            map_or_log_err(nested_rc(AidlRc::BackendBusy), |_| AidlResult::ec(0))
        );

        // All KeystoreKerror::Km(x) get mapped on
        // aidl::Result{AidlRc::KeymintErrorCode, x}
        assert_eq!(
            AidlResult::ec(-7),
            map_or_log_err(nested_ec(-7), |_| AidlResult::rc(AidlRc::SystemError))
        );

        // All other get mapped on System Error.
        assert_eq!(
            AidlResult::rc(AidlRc::SystemError),
            map_or_log_err(nested_other_error(), |_| AidlResult::ec(0))
        );

        // Result::Ok variants get passed to the ok handler.
        assert_eq!(
            AidlResult::rc(AidlRc::OpAuthNeeded),
            map_or_log_err(nested_ok(AidlRc::OpAuthNeeded), AidlResult::rc)
        );
        assert_eq!(AidlResult::ok(), map_or_log_err(nested_ok(AidlRc::Ok), AidlResult::rc));

        Ok(())
    }
} // mod tests
