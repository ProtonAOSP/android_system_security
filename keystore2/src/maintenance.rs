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

//! This module implements IKeystoreMaintenance AIDL interface.

use crate::error::Error as KeystoreError;
use crate::globals::{DB, LEGACY_MIGRATOR, SUPER_KEY};
use crate::permission::KeystorePerm;
use crate::super_key::UserState;
use crate::utils::check_keystore_permission;
use crate::{database::MonotonicRawTime, error::map_or_log_err};
use android_security_maintenance::aidl::android::security::maintenance::{
    IKeystoreMaintenance::{BnKeystoreMaintenance, IKeystoreMaintenance},
    UserState::UserState as AidlUserState,
};
use android_security_maintenance::binder::{Interface, Result as BinderResult};
use android_system_keystore2::aidl::android::system::keystore2::Domain::Domain;
use android_system_keystore2::aidl::android::system::keystore2::ResponseCode::ResponseCode;
use anyhow::{Context, Result};
use binder::{IBinderInternal, Strong};
use keystore2_crypto::Password;

/// This struct is defined to implement the aforementioned AIDL interface.
/// As of now, it is an empty struct.
pub struct Maintenance;

impl Maintenance {
    /// Create a new instance of Keystore User Manager service.
    pub fn new_native_binder() -> Result<Strong<dyn IKeystoreMaintenance>> {
        let result = BnKeystoreMaintenance::new_binder(Self);
        result.as_binder().set_requesting_sid(true);
        Ok(result)
    }

    fn on_user_password_changed(user_id: i32, password: Option<Password>) -> Result<()> {
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
                    password.as_ref(),
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

    fn clear_namespace(domain: Domain, nspace: i64) -> Result<()> {
        // Permission check. Must return on error. Do not touch the '?'.
        check_keystore_permission(KeystorePerm::clear_uid()).context("In clear_namespace.")?;

        LEGACY_MIGRATOR
            .bulk_delete_uid(domain, nspace)
            .context("In clear_namespace: Trying to delete legacy keys.")?;
        DB.with(|db| db.borrow_mut().unbind_keys_for_namespace(domain, nspace))
            .context("In clear_namespace: Trying to delete keys from db.")
    }

    fn get_state(user_id: i32) -> Result<AidlUserState> {
        // Check permission. Function should return if this failed. Therefore having '?' at the end
        // is very important.
        check_keystore_permission(KeystorePerm::get_state()).context("In get_state.")?;
        let state = DB
            .with(|db| {
                UserState::get(&mut db.borrow_mut(), &LEGACY_MIGRATOR, &SUPER_KEY, user_id as u32)
            })
            .context("In get_state. Trying to get UserState.")?;

        match state {
            UserState::Uninitialized => Ok(AidlUserState::UNINITIALIZED),
            UserState::LskfUnlocked(_) => Ok(AidlUserState::LSKF_UNLOCKED),
            UserState::LskfLocked => Ok(AidlUserState::LSKF_LOCKED),
        }
    }

    fn on_device_off_body() -> Result<()> {
        // Security critical permission check. This statement must return on fail.
        check_keystore_permission(KeystorePerm::report_off_body())
            .context("In on_device_off_body.")?;

        DB.with(|db| db.borrow_mut().update_last_off_body(MonotonicRawTime::now()))
            .context("In on_device_off_body: Trying to update last off body time.")
    }
}

impl Interface for Maintenance {}

impl IKeystoreMaintenance for Maintenance {
    fn onUserPasswordChanged(&self, user_id: i32, password: Option<&[u8]>) -> BinderResult<()> {
        map_or_log_err(Self::on_user_password_changed(user_id, password.map(|pw| pw.into())), Ok)
    }

    fn onUserAdded(&self, user_id: i32) -> BinderResult<()> {
        map_or_log_err(Self::add_or_remove_user(user_id), Ok)
    }

    fn onUserRemoved(&self, user_id: i32) -> BinderResult<()> {
        map_or_log_err(Self::add_or_remove_user(user_id), Ok)
    }

    fn clearNamespace(&self, domain: Domain, nspace: i64) -> BinderResult<()> {
        map_or_log_err(Self::clear_namespace(domain, nspace), Ok)
    }

    fn getState(&self, user_id: i32) -> BinderResult<AidlUserState> {
        map_or_log_err(Self::get_state(user_id), Ok)
    }

    fn onDeviceOffBody(&self) -> BinderResult<()> {
        map_or_log_err(Self::on_device_off_body(), Ok)
    }
}
