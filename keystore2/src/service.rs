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

// TODO remove when fully implemented.
#![allow(unused_variables)]

//! This crate implement the core Keystore 2.0 service API as defined by the Keystore 2.0
//! AIDL spec.

use crate::error::{self, map_or_log_err, ErrorCode};
use crate::globals::DB;
use crate::permission;
use crate::permission::{KeyPerm, KeystorePerm};
use crate::security_level::KeystoreSecurityLevel;
use crate::utils::{
    check_grant_permission, check_key_permission, check_keystore_permission,
    key_parameters_to_authorizations, Asp,
};
use crate::{
    database::{KeyEntryLoadBits, KeyType, SubComponentType},
    error::ResponseCode,
};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
use android_system_keystore2::aidl::android::system::keystore2::{
    Domain::Domain, IKeystoreSecurityLevel::IKeystoreSecurityLevel,
    IKeystoreService::BnKeystoreService, IKeystoreService::IKeystoreService,
    KeyDescriptor::KeyDescriptor, KeyEntryResponse::KeyEntryResponse, KeyMetadata::KeyMetadata,
};
use anyhow::{anyhow, Context, Result};
use binder::{IBinder, Interface, ThreadState};
use error::Error;
use keystore2_selinux as selinux;

/// Implementation of the IKeystoreService.
pub struct KeystoreService {
    sec_level_tee: Asp,
    sec_level_strongbox: Option<Asp>,
}

impl KeystoreService {
    /// Create a new instance of the Keystore 2.0 service.
    pub fn new_native_binder() -> Result<impl IKeystoreService> {
        let tee = KeystoreSecurityLevel::new_native_binder(SecurityLevel::TRUSTED_ENVIRONMENT)
            .map(|tee| Asp::new(tee.as_binder()))
            .context(concat!(
                "In KeystoreService::new_native_binder: ",
                "Trying to construct mendatory security level TEE."
            ))?;
        // Strongbox is optional, so we ignore errors and turn the result into an Option.
        let strongbox =
            KeystoreSecurityLevel::new_native_binder(SecurityLevel::TRUSTED_ENVIRONMENT)
                .map(|tee| Asp::new(tee.as_binder()))
                .ok();

        let result = BnKeystoreService::new_binder(Self {
            sec_level_tee: tee,
            sec_level_strongbox: strongbox,
        });
        result.as_binder().set_requesting_sid(true);
        Ok(result)
    }

    fn get_security_level_internal(
        &self,
        security_level: SecurityLevel,
    ) -> Result<Option<Box<dyn IKeystoreSecurityLevel>>> {
        Ok(match (security_level, &self.sec_level_strongbox) {
            (SecurityLevel::TRUSTED_ENVIRONMENT, _) => Some(self.sec_level_tee.get_interface().context(
                "In get_security_level_internal: Failed to get IKeystoreSecurityLevel (TEE).",
            )?),
            (SecurityLevel::STRONGBOX, Some(strongbox)) => Some(strongbox.get_interface().context(
                "In get_security_level_internal: Failed to get IKeystoreSecurityLevel (Strongbox).",
            )?),
            _ => None,
        })
    }

    fn get_security_level(
        &self,
        security_level: SecurityLevel,
    ) -> Result<Box<dyn IKeystoreSecurityLevel>> {
        self.get_security_level_internal(security_level)
            .context("In get_security_level.")?
            .ok_or_else(|| anyhow!(error::Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE)))
    }

    fn get_key_entry(&self, key: &KeyDescriptor) -> Result<KeyEntryResponse> {
        let (key_id_guard, mut key_entry) = DB
            .with(|db| {
                db.borrow_mut().load_key_entry(
                    key.clone(),
                    KeyType::Client,
                    KeyEntryLoadBits::PUBLIC,
                    ThreadState::get_calling_uid(),
                    |k, av| check_key_permission(KeyPerm::get_info(), k, &av),
                )
            })
            .context("In get_key_entry, while trying to load key info.")?;

        let i_sec_level = self
            .get_security_level_internal(key_entry.sec_level())
            .context("In get_key_entry.")?
            .ok_or_else(|| {
                anyhow!(error::Error::sys()).context(format!(
                    concat!(
                        "Found key with security level {:?} ",
                        "but no KeyMint instance of that security level."
                    ),
                    key_entry.sec_level()
                ))
            })?;

        Ok(KeyEntryResponse {
            iSecurityLevel: Some(i_sec_level),
            metadata: KeyMetadata {
                key: KeyDescriptor {
                    domain: Domain::KEY_ID,
                    nspace: key_id_guard.id(),
                    ..Default::default()
                },
                keySecurityLevel: key_entry.sec_level(),
                certificate: key_entry.take_cert(),
                certificateChain: key_entry.take_cert_chain(),
                modificationTimeMs: key_entry
                    .metadata()
                    .creation_date()
                    .map(|d| d.to_millis_epoch())
                    .ok_or(Error::Rc(ResponseCode::VALUE_CORRUPTED))
                    .context("In get_key_entry: Trying to get creation date.")?,
                authorizations: key_parameters_to_authorizations(key_entry.into_key_parameters()),
            },
        })
    }

    fn update_subcomponent(
        &self,
        key: &KeyDescriptor,
        public_cert: Option<&[u8]>,
        certificate_chain: Option<&[u8]>,
    ) -> Result<()> {
        DB.with::<_, Result<()>>(|db| {
            let mut db = db.borrow_mut();
            let (key_id_guard, key_entry) = db
                .load_key_entry(
                    key.clone(),
                    KeyType::Client,
                    KeyEntryLoadBits::NONE,
                    ThreadState::get_calling_uid(),
                    |k, av| {
                        check_key_permission(KeyPerm::update(), k, &av)
                            .context("In update_subcomponent.")
                    },
                )
                .context("Failed to load key_entry.")?;

            if let Some(cert) = public_cert {
                db.insert_blob(&key_id_guard, SubComponentType::CERT, cert)
                    .context("Failed to update cert subcomponent.")?;
            }

            if let Some(cert_chain) = certificate_chain {
                db.insert_blob(&key_id_guard, SubComponentType::CERT_CHAIN, cert_chain)
                    .context("Failed to update cert chain subcomponent.")?;
            }
            Ok(())
        })
        .context("In update_subcomponent.")
    }

    fn list_entries(&self, domain: Domain, namespace: i64) -> Result<Vec<KeyDescriptor>> {
        let mut k = match domain {
            Domain::APP => KeyDescriptor {
                domain,
                nspace: ThreadState::get_calling_uid() as u64 as i64,
                ..Default::default()
            },
            Domain::SELINUX => KeyDescriptor{domain, nspace: namespace, ..Default::default()},
            _ => return Err(Error::perm()).context(
                "In list_entries: List entries is only supported for Domain::APP and Domain::SELINUX."
            ),
        };

        // First we check if the caller has the info permission for the selected domain/namespace.
        // By default we use the calling uid as namespace if domain is Domain::APP.
        // If the first check fails we check if the caller has the list permission allowing to list
        // any namespace. In that case we also adjust the queried namespace if a specific uid was
        // selected.
        match check_key_permission(KeyPerm::get_info(), &k, &None) {
            Err(e) => {
                if let Some(selinux::Error::PermissionDenied) =
                    e.root_cause().downcast_ref::<selinux::Error>()
                {
                    check_keystore_permission(KeystorePerm::list())
                        .context("In list_entries: While checking keystore permission.")?;
                    if namespace != -1 {
                        k.nspace = namespace;
                    }
                } else {
                    return Err(e).context("In list_entries: While checking key permission.")?;
                }
            }
            Ok(()) => {}
        };

        DB.with(|db| {
            let mut db = db.borrow_mut();
            db.list(k.domain, k.nspace)
        })
    }

    fn delete_key(&self, key: &KeyDescriptor) -> Result<()> {
        let caller_uid = ThreadState::get_calling_uid();
        DB.with(|db| {
            db.borrow_mut().unbind_key(key.clone(), KeyType::Client, caller_uid, |k, av| {
                check_key_permission(KeyPerm::delete(), k, &av).context("During delete_key.")
            })
        })
        .context("In delete_key: Trying to unbind the key.")?;
        Ok(())
    }

    fn grant(
        &self,
        key: &KeyDescriptor,
        grantee_uid: i32,
        access_vector: permission::KeyPermSet,
    ) -> Result<KeyDescriptor> {
        DB.with(|db| {
            db.borrow_mut().grant(
                key.clone(),
                ThreadState::get_calling_uid(),
                grantee_uid as u32,
                access_vector,
                |k, av| check_grant_permission(*av, k).context("During grant."),
            )
        })
        .context("In KeystoreService::grant.")
    }

    fn ungrant(&self, key: &KeyDescriptor, grantee_uid: i32) -> Result<()> {
        DB.with(|db| {
            db.borrow_mut().ungrant(
                key.clone(),
                ThreadState::get_calling_uid(),
                grantee_uid as u32,
                |k| check_key_permission(KeyPerm::grant(), k, &None),
            )
        })
        .context("In KeystoreService::ungrant.")
    }
}

impl binder::Interface for KeystoreService {}

// Implementation of IKeystoreService. See AIDL spec at
// system/security/keystore2/binder/android/security/keystore2/IKeystoreService.aidl
impl IKeystoreService for KeystoreService {
    fn getSecurityLevel(
        &self,
        security_level: SecurityLevel,
    ) -> binder::public_api::Result<Box<dyn IKeystoreSecurityLevel>> {
        map_or_log_err(self.get_security_level(SecurityLevel(security_level.0)), Ok)
    }
    fn getKeyEntry(&self, key: &KeyDescriptor) -> binder::public_api::Result<KeyEntryResponse> {
        map_or_log_err(self.get_key_entry(key), Ok)
    }
    fn updateSubcomponent(
        &self,
        key: &KeyDescriptor,
        public_cert: Option<&[u8]>,
        certificate_chain: Option<&[u8]>,
    ) -> binder::public_api::Result<()> {
        map_or_log_err(self.update_subcomponent(key, public_cert, certificate_chain), Ok)
    }
    fn listEntries(
        &self,
        domain: Domain,
        namespace: i64,
    ) -> binder::public_api::Result<Vec<KeyDescriptor>> {
        map_or_log_err(self.list_entries(domain, namespace), Ok)
    }
    fn deleteKey(&self, key: &KeyDescriptor) -> binder::public_api::Result<()> {
        map_or_log_err(self.delete_key(key), Ok)
    }
    fn grant(
        &self,
        key: &KeyDescriptor,
        grantee_uid: i32,
        access_vector: i32,
    ) -> binder::public_api::Result<KeyDescriptor> {
        map_or_log_err(self.grant(key, grantee_uid, access_vector.into()), Ok)
    }
    fn ungrant(&self, key: &KeyDescriptor, grantee_uid: i32) -> binder::public_api::Result<()> {
        map_or_log_err(self.ungrant(key, grantee_uid), Ok)
    }
}
