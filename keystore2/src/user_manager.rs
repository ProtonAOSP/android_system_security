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

//! This module implements IKeystoreUserManager AIDL interface.

use crate::error::map_or_log_err;
use crate::error::Error as KeystoreError;
use crate::globals::{DB, LEGACY_MIGRATOR, SUPER_KEY};
use crate::permission::KeystorePerm;
use crate::super_key::UserState;
use crate::utils::check_keystore_permission;
use android_security_usermanager::aidl::android::security::usermanager::IKeystoreUserManager::{
    BnKeystoreUserManager, IKeystoreUserManager,
};
use android_security_usermanager::binder::{Interface, Result as BinderResult};
use android_system_keystore2::aidl::android::system::keystore2::ResponseCode::ResponseCode;
use anyhow::{Context, Result};
use binder::{IBinder, Strong};

/// This struct is defined to implement the aforementioned AIDL interface.
/// As of now, it is an empty struct.
pub struct UserManager;

impl UserManager {
    /// Create a new instance of Keystore User Manager service.
    pub fn new_native_binder() -> Result<Strong<dyn IKeystoreUserManager>> {
        let result = BnKeystoreUserManager::new_binder(Self);
        result.as_binder().set_requesting_sid(true);
        Ok(result)
    }

    fn on_user_password_changed(user_id: i32, password: Option<&[u8]>) -> Result<()> {
        //Check permission. Function should return if this failed. Therefore having '?' at the end
        //is very important.
        check_keystore_permission(KeystorePerm::change_password())
            .context("In on_user_password_changed.")?;

        match DB
            .with(|db| {
                UserState::get_with_password_changed(
                    &mut db.borrow_mut(),
                    &LEGACY_MIGRATOR,
                    &SUPER_KEY,
                    user_id as u32,
                    password,
                )
            })
            .context("In on_user_password_changed.")?
        {
            UserState::LskfLocked => {
                // Error - password can not be changed when the device is locked
                Err(KeystoreError::Rc(ResponseCode::LOCKED))
                    .context("In on_user_password_changed. Device is locked.")
            }
            _ => {
                // LskfLocked is the only error case for password change
                Ok(())
            }
        }
    }

    fn add_or_remove_user(user_id: i32) -> Result<()> {
        // Check permission. Function should return if this failed. Therefore having '?' at the end
        // is very important.
        check_keystore_permission(KeystorePerm::change_user()).context("In add_or_remove_user.")?;
        DB.with(|db| {
            UserState::reset_user(
                &mut db.borrow_mut(),
                &SUPER_KEY,
                &LEGACY_MIGRATOR,
                user_id as u32,
                false,
            )
        })
        .context("In add_or_remove_user: Trying to delete keys from db.")
    }
}

impl Interface for UserManager {}

impl IKeystoreUserManager for UserManager {
    fn onUserPasswordChanged(&self, user_id: i32, password: Option<&[u8]>) -> BinderResult<()> {
        map_or_log_err(Self::on_user_password_changed(user_id, password), Ok)
    }

    fn onUserAdded(&self, user_id: i32) -> BinderResult<()> {
        map_or_log_err(Self::add_or_remove_user(user_id), Ok)
    }

    fn onUserRemoved(&self, user_id: i32) -> BinderResult<()> {
        map_or_log_err(Self::add_or_remove_user(user_id), Ok)
    }
}
