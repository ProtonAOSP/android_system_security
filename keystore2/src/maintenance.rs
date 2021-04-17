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

use crate::database::{KeyEntryLoadBits, KeyType, MonotonicRawTime};
use crate::error::map_km_error;
use crate::error::map_or_log_err;
use crate::error::Error;
use crate::globals::get_keymint_device;
use crate::globals::{DB, LEGACY_MIGRATOR, SUPER_KEY};
use crate::permission::{KeyPerm, KeystorePerm};
use crate::super_key::UserState;
use crate::utils::{check_key_permission, check_keystore_permission};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::IKeyMintDevice::IKeyMintDevice;
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
use android_security_maintenance::aidl::android::security::maintenance::{
    IKeystoreMaintenance::{BnKeystoreMaintenance, IKeystoreMaintenance},
    UserState::UserState as AidlUserState,
};
use android_security_maintenance::binder::{Interface, Result as BinderResult};
use android_system_keystore2::aidl::android::system::keystore2::ResponseCode::ResponseCode;
use android_system_keystore2::aidl::android::system::keystore2::{
    Domain::Domain, KeyDescriptor::KeyDescriptor,
};
use anyhow::{Context, Result};
use binder::{IBinderInternal, Strong, ThreadState};
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

        if let Some(pw) = password.as_ref() {
            DB.with(|db| {
                SUPER_KEY.unlock_screen_lock_bound_key(&mut db.borrow_mut(), user_id as u32, pw)
            })
            .context("In on_user_password_changed: unlock_screen_lock_bound_key failed")?;
        }

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
                Err(Error::Rc(ResponseCode::LOCKED))
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

    fn early_boot_ended_help(sec_level: &SecurityLevel) -> Result<()> {
        let (dev, _, _) =
            get_keymint_device(sec_level).context("In early_boot_ended: getting keymint device")?;
        let km_dev: Strong<dyn IKeyMintDevice> =
            dev.get_interface().context("In early_boot_ended: getting keymint device interface")?;
        map_km_error(km_dev.earlyBootEnded())
            .context("In keymint device: calling earlyBootEnded")?;
        Ok(())
    }

    fn early_boot_ended() -> Result<()> {
        check_keystore_permission(KeystorePerm::early_boot_ended())
            .context("In early_boot_ended. Checking permission")?;
        log::info!("In early_boot_ended.");

        if let Err(e) = DB.with(|db| SUPER_KEY.set_up_boot_level_cache(&mut db.borrow_mut())) {
            log::error!("SUPER_KEY.set_up_boot_level_cache failed:\n{:?}\n:(", e);
        }

        let sec_levels = [
            (SecurityLevel::TRUSTED_ENVIRONMENT, "TRUSTED_ENVIRONMENT"),
            (SecurityLevel::STRONGBOX, "STRONGBOX"),
        ];
        sec_levels.iter().fold(Ok(()), |result, (sec_level, sec_level_string)| {
            let curr_result = Maintenance::early_boot_ended_help(sec_level);
            if curr_result.is_err() {
                log::error!(
                    "Call to earlyBootEnded failed for security level {}.",
                    &sec_level_string
                );
            }
            result.and(curr_result)
        })
    }

    fn on_device_off_body() -> Result<()> {
        // Security critical permission check. This statement must return on fail.
        check_keystore_permission(KeystorePerm::report_off_body())
            .context("In on_device_off_body.")?;

        DB.with(|db| db.borrow_mut().update_last_off_body(MonotonicRawTime::now()))
            .context("In on_device_off_body: Trying to update last off body time.")
    }

    fn migrate_key_namespace(source: &KeyDescriptor, destination: &KeyDescriptor) -> Result<()> {
        let caller_uid = ThreadState::get_calling_uid();

        DB.with(|db| {
            let key_id_guard = match source.domain {
                Domain::APP | Domain::SELINUX | Domain::KEY_ID => {
                    let (key_id_guard, _) = LEGACY_MIGRATOR
                        .with_try_migrate(&source, caller_uid, || {
                            db.borrow_mut().load_key_entry(
                                &source,
                                KeyType::Client,
                                KeyEntryLoadBits::NONE,
                                caller_uid,
                                |k, av| {
                                    check_key_permission(KeyPerm::use_(), k, &av)?;
                                    check_key_permission(KeyPerm::delete(), k, &av)?;
                                    check_key_permission(KeyPerm::grant(), k, &av)
                                },
                            )
                        })
                        .context("In migrate_key_namespace: Failed to load key blob.")?;
                    key_id_guard
                }
                _ => {
                    return Err(Error::Rc(ResponseCode::INVALID_ARGUMENT)).context(concat!(
                        "In migrate_key_namespace: ",
                        "Source domain must be one of APP, SELINUX, or KEY_ID."
                    ))
                }
            };

            db.borrow_mut().migrate_key_namespace(key_id_guard, destination, caller_uid, |k| {
                check_key_permission(KeyPerm::rebind(), k, &None)
            })
        })
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

    fn earlyBootEnded(&self) -> BinderResult<()> {
        map_or_log_err(Self::early_boot_ended(), Ok)
    }

    fn onDeviceOffBody(&self) -> BinderResult<()> {
        map_or_log_err(Self::on_device_off_body(), Ok)
    }

    fn migrateKeyNamespace(
        &self,
        source: &KeyDescriptor,
        destination: &KeyDescriptor,
    ) -> BinderResult<()> {
        map_or_log_err(Self::migrate_key_namespace(source, destination), Ok)
    }
}
