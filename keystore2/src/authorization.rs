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

//! This module implements IKeystoreAuthorization AIDL interface.

use crate::error::Error as KeystoreError;
use crate::globals::{ENFORCEMENTS, SUPER_KEY, DB, LEGACY_MIGRATOR};
use crate::permission::KeystorePerm;
use crate::super_key::UserState;
use crate::utils::check_keystore_permission;
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    HardwareAuthToken::HardwareAuthToken,
};
use android_security_authorization::binder::{ExceptionCode, Interface, Result as BinderResult,
     Strong, Status as BinderStatus};
use android_security_authorization::aidl::android::security::authorization::{
    IKeystoreAuthorization::BnKeystoreAuthorization, IKeystoreAuthorization::IKeystoreAuthorization,
    LockScreenEvent::LockScreenEvent, AuthorizationTokens::AuthorizationTokens,
    ResponseCode::ResponseCode,
};
use android_system_keystore2::aidl::android::system::keystore2::{
    ResponseCode::ResponseCode as KsResponseCode };
use anyhow::{Context, Result};
use binder::IBinderInternal;
use keystore2_crypto::Password;
use keystore2_selinux as selinux;

/// This is the Authorization error type, it wraps binder exceptions and the
/// Authorization ResponseCode
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum Error {
    /// Wraps an IKeystoreAuthorization response code as defined by
    /// android.security.authorization AIDL interface specification.
    #[error("Error::Rc({0:?})")]
    Rc(ResponseCode),
    /// Wraps a Binder exception code other than a service specific exception.
    #[error("Binder exception code {0:?}, {1:?}")]
    Binder(ExceptionCode, i32),
}

/// This function should be used by authorization service calls to translate error conditions
/// into service specific exceptions.
///
/// All error conditions get logged by this function.
///
/// `Error::Rc(x)` variants get mapped onto a service specific error code of `x`.
/// Certain response codes may be returned from keystore/ResponseCode.aidl by the keystore2 modules,
/// which are then converted to the corresponding response codes of android.security.authorization
/// AIDL interface specification.
///
/// `selinux::Error::perm()` is mapped on `ResponseCode::PERMISSION_DENIED`.
///
/// All non `Error` error conditions get mapped onto ResponseCode::SYSTEM_ERROR`.
///
/// `handle_ok` will be called if `result` is `Ok(value)` where `value` will be passed
/// as argument to `handle_ok`. `handle_ok` must generate a `BinderResult<T>`, but it
/// typically returns Ok(value).
pub fn map_or_log_err<T, U, F>(result: Result<U>, handle_ok: F) -> BinderResult<T>
where
    F: FnOnce(U) -> BinderResult<T>,
{
    result.map_or_else(
        |e| {
            log::error!("{:#?}", e);
            let root_cause = e.root_cause();
            if let Some(KeystoreError::Rc(ks_rcode)) = root_cause.downcast_ref::<KeystoreError>() {
                let rc = match *ks_rcode {
                    // Although currently keystore2/ResponseCode.aidl and
                    // authorization/ResponseCode.aidl share the same integer values for the
                    // common response codes, this may deviate in the future, hence the
                    // conversion here.
                    KsResponseCode::SYSTEM_ERROR => ResponseCode::SYSTEM_ERROR.0,
                    KsResponseCode::KEY_NOT_FOUND => ResponseCode::KEY_NOT_FOUND.0,
                    KsResponseCode::VALUE_CORRUPTED => ResponseCode::VALUE_CORRUPTED.0,
                    KsResponseCode::INVALID_ARGUMENT => ResponseCode::INVALID_ARGUMENT.0,
                    // If the code paths of IKeystoreAuthorization aidl's methods happen to return
                    // other error codes from KsResponseCode in the future, they should be converted
                    // as well.
                    _ => ResponseCode::SYSTEM_ERROR.0,
                };
                return Err(BinderStatus::new_service_specific_error(rc, None));
            }
            let rc = match root_cause.downcast_ref::<Error>() {
                Some(Error::Rc(rcode)) => rcode.0,
                Some(Error::Binder(_, _)) => ResponseCode::SYSTEM_ERROR.0,
                None => match root_cause.downcast_ref::<selinux::Error>() {
                    Some(selinux::Error::PermissionDenied) => ResponseCode::PERMISSION_DENIED.0,
                    _ => ResponseCode::SYSTEM_ERROR.0,
                },
            };
            Err(BinderStatus::new_service_specific_error(rc, None))
        },
        handle_ok,
    )
}

/// This struct is defined to implement the aforementioned AIDL interface.
/// As of now, it is an empty struct.
pub struct AuthorizationManager;

impl AuthorizationManager {
    /// Create a new instance of Keystore Authorization service.
    pub fn new_native_binder() -> Result<Strong<dyn IKeystoreAuthorization>> {
        let result = BnKeystoreAuthorization::new_binder(Self);
        result.as_binder().set_requesting_sid(true);
        Ok(result)
    }

    fn add_auth_token(&self, auth_token: &HardwareAuthToken) -> Result<()> {
        //check keystore permission
        check_keystore_permission(KeystorePerm::add_auth()).context("In add_auth_token.")?;

        ENFORCEMENTS.add_auth_token(auth_token.clone())?;
        Ok(())
    }

    fn on_lock_screen_event(
        &self,
        lock_screen_event: LockScreenEvent,
        user_id: i32,
        password: Option<Password>,
    ) -> Result<()> {
        match (lock_screen_event, password) {
            (LockScreenEvent::UNLOCK, Some(password)) => {
                //This corresponds to the unlock() method in legacy keystore API.
                //check permission
                check_keystore_permission(KeystorePerm::unlock())
                    .context("In on_lock_screen_event: Unlock with password.")?;
                ENFORCEMENTS.set_device_locked(user_id, false);

                DB.with(|db| {
                    SUPER_KEY.unlock_screen_lock_bound_key(
                        &mut db.borrow_mut(),
                        user_id as u32,
                        &password,
                    )
                })
                .context("In on_lock_screen_event: unlock_screen_lock_bound_key failed")?;

                // Unlock super key.
                if let UserState::Uninitialized = DB
                    .with(|db| {
                        UserState::get_with_password_unlock(
                            &mut db.borrow_mut(),
                            &LEGACY_MIGRATOR,
                            &SUPER_KEY,
                            user_id as u32,
                            &password,
                        )
                    })
                    .context("In on_lock_screen_event: Unlock with password.")?
                {
                    log::info!(
                        "In on_lock_screen_event. Trying to unlock when LSKF is uninitialized."
                    );
                }

                Ok(())
            }
            (LockScreenEvent::UNLOCK, None) => {
                check_keystore_permission(KeystorePerm::unlock())
                    .context("In on_lock_screen_event: Unlock.")?;
                ENFORCEMENTS.set_device_locked(user_id, false);
                Ok(())
            }
            (LockScreenEvent::LOCK, None) => {
                check_keystore_permission(KeystorePerm::lock())
                    .context("In on_lock_screen_event: Lock")?;
                ENFORCEMENTS.set_device_locked(user_id, true);
                SUPER_KEY.lock_screen_lock_bound_key(user_id as u32);

                Ok(())
            }
            _ => {
                // Any other combination is not supported.
                Err(Error::Rc(ResponseCode::INVALID_ARGUMENT))
                    .context("In on_lock_screen_event: Unknown event.")
            }
        }
    }

    fn get_auth_tokens_for_credstore(
        &self,
        challenge: i64,
        secure_user_id: i64,
        auth_token_max_age_millis: i64,
    ) -> Result<AuthorizationTokens> {
        // Check permission. Function should return if this failed. Therefore having '?' at the end
        // is very important.
        check_keystore_permission(KeystorePerm::get_auth_token())
            .context("In get_auth_tokens_for_credstore.")?;

        // if the challenge is zero, return error
        if challenge == 0 {
            return Err(Error::Rc(ResponseCode::INVALID_ARGUMENT))
                .context("In get_auth_tokens_for_credstore. Challenge can not be zero.");
        }
        // Obtain the auth token and the timestamp token from the enforcement module.
        let (auth_token, ts_token) =
            ENFORCEMENTS.get_auth_tokens(challenge, secure_user_id, auth_token_max_age_millis)?;
        Ok(AuthorizationTokens { authToken: auth_token, timestampToken: ts_token })
    }
}

impl Interface for AuthorizationManager {}

impl IKeystoreAuthorization for AuthorizationManager {
    fn addAuthToken(&self, auth_token: &HardwareAuthToken) -> BinderResult<()> {
        map_or_log_err(self.add_auth_token(auth_token), Ok)
    }

    fn onLockScreenEvent(
        &self,
        lock_screen_event: LockScreenEvent,
        user_id: i32,
        password: Option<&[u8]>,
    ) -> BinderResult<()> {
        map_or_log_err(
            self.on_lock_screen_event(lock_screen_event, user_id, password.map(|pw| pw.into())),
            Ok,
        )
    }

    fn getAuthTokensForCredStore(
        &self,
        challenge: i64,
        secure_user_id: i64,
        auth_token_max_age_millis: i64,
    ) -> binder::public_api::Result<AuthorizationTokens> {
        map_or_log_err(
            self.get_auth_tokens_for_credstore(
                challenge,
                secure_user_id,
                auth_token_max_age_millis,
            ),
            Ok,
        )
    }
}
