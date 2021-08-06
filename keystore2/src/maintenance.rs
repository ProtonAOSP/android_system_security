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
use crate::utils::{check_key_permission, check_keystore_permission, watchdog as wd};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::IKeyMintDevice::IKeyMintDevice;
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
use android_security_maintenance::aidl::android::security::maintenance::{
    IKeystoreMaintenance::{BnKeystoreMaintenance, IKeystoreMaintenance},
    UserState::UserState as AidlUserState,
};
use android_security_maintenance::binder::{
    BinderFeatures, Interface, Result as BinderResult, Strong, ThreadState,
};
use android_system_keystore2::aidl::android::system::keystore2::KeyDescriptor::KeyDescriptor;
use android_system_keystore2::aidl::android::system::keystore2::ResponseCode::ResponseCode;
use anyhow::{Context, Result};
use keystore2_crypto::Password;

/// Reexport Domain for the benefit of DeleteListener
pub use android_system_keystore2::aidl::android::system::keystore2::Domain::Domain;

/// The Maintenance module takes a delete listener argument which observes user and namespace
/// deletion events.
pub trait DeleteListener {
    /// Called by the maintenance module when an app/namespace is deleted.
    fn delete_namespace(&self, domain: Domain, namespace: i64) -> Result<()>;
    /// Called by the maintenance module when a user is deleted.
    fn delete_user(&self, user_id: u32) -> Result<()>;
}

/// This struct is defined to implement the aforementioned AIDL interface.
pub struct Maintenance {
    delete_listener: Box<dyn DeleteListener + Send + Sync + 'static>,
}

impl Maintenance {
    /// Create a new instance of Keystore Maintenance service.
    pub fn new_native_binder(
        delete_listener: Box<dyn DeleteListener + Send + Sync + 'static>,
    ) -> Result<Strong<dyn IKeystoreMaintenance>> {
        Ok(BnKeystoreMaintenance::new_binder(
            Self { delete_listener },
            BinderFeatures { set_requesting_sid: true, ..BinderFeatures::default() },
        ))
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

    fn add_or_remove_user(&self, user_id: i32) -> Result<()> {
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
        .context("In add_or_remove_user: Trying to delete keys from db.")?;
        self.delete_listener
            .delete_user(user_id as u32)
            .context("In add_or_remove_user: While invoking the delete listener.")
    }

    fn clear_namespace(&self, domain: Domain, nspace: i64) -> Result<()> {
        // Permission check. Must return on error. Do not touch the '?'.
        check_keystore_permission(KeystorePerm::clear_uid()).context("In clear_namespace.")?;

        LEGACY_MIGRATOR
            .bulk_delete_uid(domain, nspace)
            .context("In clear_namespace: Trying to delete legacy keys.")?;
        DB.with(|db| db.borrow_mut().unbind_keys_for_namespace(domain, nspace))
            .context("In clear_namespace: Trying to delete keys from db.")?;
        self.delete_listener
            .delete_namespace(domain, nspace)
            .context("In clear_namespace: While invoking the delete listener.")
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

    fn call_with_watchdog<F>(sec_level: SecurityLevel, name: &'static str, op: &F) -> Result<()>
    where
        F: Fn(Strong<dyn IKeyMintDevice>) -> binder::public_api::Result<()>,
    {
        let (dev, _, _) = get_keymint_device(&sec_level)
            .context("In call_with_watchdog: getting keymint device")?;
        let km_dev: Strong<dyn IKeyMintDevice> = dev
            .get_interface()
            .context("In call_with_watchdog: getting keymint device interface")?;

        let _wp = wd::watch_millis_with("In call_with_watchdog", 500, move || {
            format!("Seclevel: {:?} Op: {}", sec_level, name)
        });
        map_km_error(op(km_dev)).with_context(|| format!("In keymint device: calling {}", name))?;
        Ok(())
    }

    fn call_on_all_security_levels<F>(name: &'static str, op: F) -> Result<()>
    where
        F: Fn(Strong<dyn IKeyMintDevice>) -> binder::public_api::Result<()>,
    {
        let sec_levels = [
            (SecurityLevel::TRUSTED_ENVIRONMENT, "TRUSTED_ENVIRONMENT"),
            (SecurityLevel::STRONGBOX, "STRONGBOX"),
        ];
        sec_levels.iter().fold(Ok(()), move |result, (sec_level, sec_level_string)| {
            let curr_result = Maintenance::call_with_watchdog(*sec_level, name, &op);
            match curr_result {
                Ok(()) => log::info!(
                    "Call to {} succeeded for security level {}.",
                    name,
                    &sec_level_string
                ),
                Err(ref e) => log::error!(
                    "Call to {} failed for security level {}: {}.",
                    name,
                    &sec_level_string,
                    e
                ),
            }
            result.and(curr_result)
        })
    }

    fn early_boot_ended() -> Result<()> {
        check_keystore_permission(KeystorePerm::early_boot_ended())
            .context("In early_boot_ended. Checking permission")?;
        log::info!("In early_boot_ended.");

        if let Err(e) = DB.with(|db| SUPER_KEY.set_up_boot_level_cache(&mut db.borrow_mut())) {
            log::error!("SUPER_KEY.set_up_boot_level_cache failed:\n{:?}\n:(", e);
        }
        Maintenance::call_on_all_security_levels("earlyBootEnded", |dev| dev.earlyBootEnded())
    }

    fn on_device_off_body() -> Result<()> {
        // Security critical permission check. This statement must return on fail.
        check_keystore_permission(KeystorePerm::report_off_body())
            .context("In on_device_off_body.")?;

        DB.with(|db| db.borrow_mut().update_last_off_body(MonotonicRawTime::now()));
        Ok(())
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

    fn delete_all_keys() -> Result<()> {
        // Security critical permission check. This statement must return on fail.
        check_keystore_permission(KeystorePerm::delete_all_keys())
            .context("In delete_all_keys. Checking permission")?;
        log::info!("In delete_all_keys.");

        Maintenance::call_on_all_security_levels("deleteAllKeys", |dev| dev.deleteAllKeys())
    }
}

impl Interface for Maintenance {}

impl IKeystoreMaintenance for Maintenance {
    fn onUserPasswordChanged(&self, user_id: i32, password: Option<&[u8]>) -> BinderResult<()> {
        let _wp = wd::watch_millis("IKeystoreMaintenance::onUserPasswordChanged", 500);
        map_or_log_err(Self::on_user_password_changed(user_id, password.map(|pw| pw.into())), Ok)
    }

    fn onUserAdded(&self, user_id: i32) -> BinderResult<()> {
        let _wp = wd::watch_millis("IKeystoreMaintenance::onUserAdded", 500);
        map_or_log_err(self.add_or_remove_user(user_id), Ok)
    }

    fn onUserRemoved(&self, user_id: i32) -> BinderResult<()> {
        let _wp = wd::watch_millis("IKeystoreMaintenance::onUserRemoved", 500);
        map_or_log_err(self.add_or_remove_user(user_id), Ok)
    }

    fn clearNamespace(&self, domain: Domain, nspace: i64) -> BinderResult<()> {
        let _wp = wd::watch_millis("IKeystoreMaintenance::clearNamespace", 500);
        map_or_log_err(self.clear_namespace(domain, nspace), Ok)
    }

    fn getState(&self, user_id: i32) -> BinderResult<AidlUserState> {
        let _wp = wd::watch_millis("IKeystoreMaintenance::getState", 500);
        map_or_log_err(Self::get_state(user_id), Ok)
    }

    fn earlyBootEnded(&self) -> BinderResult<()> {
        let _wp = wd::watch_millis("IKeystoreMaintenance::earlyBootEnded", 500);
        map_or_log_err(Self::early_boot_ended(), Ok)
    }

    fn onDeviceOffBody(&self) -> BinderResult<()> {
        let _wp = wd::watch_millis("IKeystoreMaintenance::onDeviceOffBody", 500);
        map_or_log_err(Self::on_device_off_body(), Ok)
    }

    fn migrateKeyNamespace(
        &self,
        source: &KeyDescriptor,
        destination: &KeyDescriptor,
    ) -> BinderResult<()> {
        let _wp = wd::watch_millis("IKeystoreMaintenance::migrateKeyNamespace", 500);
        map_or_log_err(Self::migrate_key_namespace(source, destination), Ok)
    }

    fn deleteAllKeys(&self) -> BinderResult<()> {
        let _wp = wd::watch_millis("IKeystoreMaintenance::deleteAllKeys", 500);
        map_or_log_err(Self::delete_all_keys(), Ok)
    }
}
