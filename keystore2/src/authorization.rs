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
use crate::error::map_or_log_err;
use crate::globals::{DB, ENFORCEMENTS, LEGACY_BLOB_LOADER, SUPER_KEY};
use crate::permission::KeystorePerm;
use crate::utils::check_keystore_permission;
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    HardwareAuthToken::HardwareAuthToken, HardwareAuthenticatorType::HardwareAuthenticatorType,
};
use android_hardware_security_secureclock::aidl::android::hardware::security::secureclock::{
    Timestamp::Timestamp,
};
use android_security_authorization::binder::{Interface, Result as BinderResult, Strong};
use android_security_authorization::aidl::android::security::authorization::IKeystoreAuthorization::{
        BnKeystoreAuthorization, IKeystoreAuthorization,
};
use android_security_authorization:: aidl::android::security::authorization::LockScreenEvent::LockScreenEvent;
use android_system_keystore2::aidl::android::system::keystore2::ResponseCode::ResponseCode;
use anyhow::{Context, Result};
use binder::IBinder;

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

        //TODO: Keymint's HardwareAuthToken aidl needs to implement Copy/Clone
        let auth_token_copy = HardwareAuthToken {
            challenge: auth_token.challenge,
            userId: auth_token.userId,
            authenticatorId: auth_token.authenticatorId,
            authenticatorType: HardwareAuthenticatorType(auth_token.authenticatorType.0),
            timestamp: Timestamp { milliSeconds: auth_token.timestamp.milliSeconds },
            mac: auth_token.mac.clone(),
        };
        ENFORCEMENTS.add_auth_token(auth_token_copy)?;
        Ok(())
    }

    fn on_lock_screen_event(
        &self,
        lock_screen_event: LockScreenEvent,
        user_id: i32,
        password: Option<&[u8]>,
    ) -> Result<()> {
        match (lock_screen_event, password) {
            (LockScreenEvent::UNLOCK, Some(user_password)) => {
                //This corresponds to the unlock() method in legacy keystore API.
                //check permission
                check_keystore_permission(KeystorePerm::unlock())
                    .context("In on_lock_screen_event: Unlock with password.")?;
                ENFORCEMENTS.set_device_locked(user_id, false);
                // Unlock super key.
                DB.with::<_, Result<()>>(|db| {
                    let mut db = db.borrow_mut();
                    //TODO - b/176123105 - Once the user management API is implemented, unlock is
                    //allowed only if the user is added. Then the two tasks handled by the
                    //unlock_user_key will be split into two methods. For now, unlock_user_key
                    //method is used as it is, which created a super key for the user if one does
                    //not exists, in addition to unlocking the existing super key of the user/
                    SUPER_KEY.unlock_user_key(
                        user_id as u32,
                        user_password,
                        &mut db,
                        &LEGACY_BLOB_LOADER,
                    )?;
                    Ok(())
                })
                .context("In on_lock_screen_event.")?;

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
                Ok(())
            }
            _ => {
                // Any other combination is not supported.
                Err(KeystoreError::Rc(ResponseCode::INVALID_ARGUMENT))
                    .context("In on_lock_screen_event: Unknown event.")
            }
        }
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
        map_or_log_err(self.on_lock_screen_event(lock_screen_event, user_id, password), Ok)
    }
}
