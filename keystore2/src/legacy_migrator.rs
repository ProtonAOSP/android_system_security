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

//! This module acts as a bridge between the legacy key database and the keystore2 database.

use crate::error::Error;
use crate::key_parameter::KeyParameterValue;
use crate::legacy_blob::BlobValue;
use crate::utils::uid_to_android_user;
use crate::{async_task::AsyncTask, legacy_blob::LegacyBlobLoader};
use crate::{
    database::{
        BlobMetaData, BlobMetaEntry, CertificateInfo, DateTime, EncryptedBy, KeyMetaData,
        KeyMetaEntry, KeystoreDB, Uuid, KEYSTORE_UUID,
    },
    super_key::USER_SUPER_KEY,
};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
use android_system_keystore2::aidl::android::system::keystore2::{
    Domain::Domain, KeyDescriptor::KeyDescriptor, ResponseCode::ResponseCode,
};
use anyhow::{Context, Result};
use core::ops::Deref;
use keystore2_crypto::{Password, ZVec};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};

/// Represents LegacyMigrator.
pub struct LegacyMigrator {
    async_task: Arc<AsyncTask>,
    initializer: Mutex<
        Option<
            Box<
                dyn FnOnce() -> (KeystoreDB, HashMap<SecurityLevel, Uuid>, Arc<LegacyBlobLoader>)
                    + Send
                    + 'static,
            >,
        >,
    >,
    /// This atomic is used for cheap interior mutability. It is intended to prevent
    /// expensive calls into the legacy migrator when the legacy database is empty.
    /// When transitioning from READY to EMPTY, spurious calls may occur for a brief period
    /// of time. This is tolerable in favor of the common case.
    state: AtomicU8,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct RecentMigration {
    uid: u32,
    alias: String,
}

impl RecentMigration {
    fn new(uid: u32, alias: String) -> Self {
        Self { uid, alias }
    }
}

enum BulkDeleteRequest {
    Uid(u32),
    User(u32),
}

struct LegacyMigratorState {
    recently_migrated: HashSet<RecentMigration>,
    recently_migrated_super_key: HashSet<u32>,
    legacy_loader: Arc<LegacyBlobLoader>,
    sec_level_to_km_uuid: HashMap<SecurityLevel, Uuid>,
    db: KeystoreDB,
}

impl LegacyMigrator {
    const WIFI_NAMESPACE: i64 = 102;
    const AID_WIFI: u32 = 1010;

    const STATE_UNINITIALIZED: u8 = 0;
    const STATE_READY: u8 = 1;
    const STATE_EMPTY: u8 = 2;

    /// Constructs a new LegacyMigrator using the given AsyncTask object as migration
    /// worker.
    pub fn new(async_task: Arc<AsyncTask>) -> Self {
        Self {
            async_task,
            initializer: Default::default(),
            state: AtomicU8::new(Self::STATE_UNINITIALIZED),
        }
    }

    /// The legacy migrator must be initialized deferred, because keystore starts very early.
    /// At this time the data partition may not be mounted. So we cannot open database connections
    /// until we get actual key load requests. This sets the function that the legacy loader
    /// uses to connect to the database.
    pub fn set_init<F>(&self, f_init: F) -> Result<()>
    where
        F: FnOnce() -> (KeystoreDB, HashMap<SecurityLevel, Uuid>, Arc<LegacyBlobLoader>)
            + Send
            + 'static,
    {
        let mut initializer = self.initializer.lock().expect("Failed to lock initializer.");

        // If we are not uninitialized we have no business setting the initializer.
        if self.state.load(Ordering::Relaxed) != Self::STATE_UNINITIALIZED {
            return Ok(());
        }

        // Only set the initializer if it hasn't been set before.
        if initializer.is_none() {
            *initializer = Some(Box::new(f_init))
        }

        Ok(())
    }

    /// This function is called by the migration requestor to check if it is worth
    /// making a migration request. It also transitions the state from UNINITIALIZED
    /// to READY or EMPTY on first use. The deferred initialization is necessary, because
    /// Keystore 2.0 runs early during boot, where data may not yet be mounted.
    /// Returns Ok(STATE_READY) if a migration request is worth undertaking and
    /// Ok(STATE_EMPTY) if the database is empty. An error is returned if the loader
    /// was not initialized and cannot be initialized.
    fn check_state(&self) -> Result<u8> {
        let mut first_try = true;
        loop {
            match (self.state.load(Ordering::Relaxed), first_try) {
                (Self::STATE_EMPTY, _) => {
                    return Ok(Self::STATE_EMPTY);
                }
                (Self::STATE_UNINITIALIZED, true) => {
                    // If we find the legacy loader uninitialized, we grab the initializer lock,
                    // check if the legacy database is empty, and if not, schedule an initialization
                    // request. Coming out of the initializer lock, the state is either EMPTY or
                    // READY.
                    let mut initializer = self.initializer.lock().unwrap();

                    if let Some(initializer) = initializer.take() {
                        let (db, sec_level_to_km_uuid, legacy_loader) = (initializer)();

                        if legacy_loader.is_empty().context(
                            "In check_state: Trying to check if the legacy database is empty.",
                        )? {
                            self.state.store(Self::STATE_EMPTY, Ordering::Relaxed);
                            return Ok(Self::STATE_EMPTY);
                        }

                        self.async_task.queue_hi(move |shelf| {
                            shelf.get_or_put_with(|| LegacyMigratorState {
                                recently_migrated: Default::default(),
                                recently_migrated_super_key: Default::default(),
                                legacy_loader,
                                sec_level_to_km_uuid,
                                db,
                            });
                        });

                        // It is safe to set this here even though the async task may not yet have
                        // run because any thread observing this will not be able to schedule a
                        // task that can run before the initialization.
                        // Also we can only transition out of this state while having the
                        // initializer lock and having found an initializer.
                        self.state.store(Self::STATE_READY, Ordering::Relaxed);
                        return Ok(Self::STATE_READY);
                    } else {
                        // There is a chance that we just lost the race from state.load() to
                        // grabbing the initializer mutex. If that is the case the state must
                        // be EMPTY or READY after coming out of the lock. So we can give it
                        // one more try.
                        first_try = false;
                        continue;
                    }
                }
                (Self::STATE_UNINITIALIZED, false) => {
                    // Okay, tough luck. The legacy loader was really completely uninitialized.
                    return Err(Error::sys()).context(
                        "In check_state: Legacy loader should not be called uninitialized.",
                    );
                }
                (Self::STATE_READY, _) => return Ok(Self::STATE_READY),
                (s, _) => panic!("Unknown legacy migrator state. {} ", s),
            }
        }
    }

    /// List all aliases for uid in the legacy database.
    pub fn list_uid(&self, domain: Domain, namespace: i64) -> Result<Vec<KeyDescriptor>> {
        let uid = match (domain, namespace) {
            (Domain::APP, namespace) => namespace as u32,
            (Domain::SELINUX, Self::WIFI_NAMESPACE) => Self::AID_WIFI,
            _ => return Ok(Vec::new()),
        };
        self.do_serialized(move |state| state.list_uid(uid)).unwrap_or_else(|| Ok(Vec::new())).map(
            |v| {
                v.into_iter()
                    .map(|alias| KeyDescriptor {
                        domain,
                        nspace: namespace,
                        alias: Some(alias),
                        blob: None,
                    })
                    .collect()
            },
        )
    }

    /// Sends the given closure to the migrator thread for execution after calling check_state.
    /// Returns None if the database was empty and the request was not executed.
    /// Otherwise returns Some with the result produced by the migration request.
    /// The loader state may transition to STATE_EMPTY during the execution of this function.
    fn do_serialized<F, T: Send + 'static>(&self, f: F) -> Option<Result<T>>
    where
        F: FnOnce(&mut LegacyMigratorState) -> Result<T> + Send + 'static,
    {
        // Short circuit if the database is empty or not initialized (error case).
        match self.check_state().context("In do_serialized: Checking state.") {
            Ok(LegacyMigrator::STATE_EMPTY) => return None,
            Ok(LegacyMigrator::STATE_READY) => {}
            Err(e) => return Some(Err(e)),
            Ok(s) => panic!("Unknown legacy migrator state. {} ", s),
        }

        // We have established that there may be a key in the legacy database.
        // Now we schedule a migration request.
        let (sender, receiver) = channel();
        self.async_task.queue_hi(move |shelf| {
            // Get the migrator state from the shelf.
            // There may not be a state. This can happen if this migration request was scheduled
            // before a previous request established that the legacy database was empty
            // and removed the state from the shelf. Since we know now that the database
            // is empty, we can return None here.
            let (new_state, result) = if let Some(legacy_migrator_state) =
                shelf.get_downcast_mut::<LegacyMigratorState>()
            {
                let result = f(legacy_migrator_state);
                (legacy_migrator_state.check_empty(), Some(result))
            } else {
                (Self::STATE_EMPTY, None)
            };

            // If the migration request determined that the database is now empty, we discard
            // the state from the shelf to free up the resources we won't need any longer.
            if result.is_some() && new_state == Self::STATE_EMPTY {
                shelf.remove_downcast_ref::<LegacyMigratorState>();
            }

            // Send the result to the requester.
            if let Err(e) = sender.send((new_state, result)) {
                log::error!("In do_serialized. Error in sending the result. {:?}", e);
            }
        });

        let (new_state, result) = match receiver.recv() {
            Err(e) => {
                return Some(Err(e).context("In do_serialized. Failed to receive from the sender."))
            }
            Ok(r) => r,
        };

        // We can only transition to EMPTY but never back.
        // The migrator never creates any legacy blobs.
        if new_state == Self::STATE_EMPTY {
            self.state.store(Self::STATE_EMPTY, Ordering::Relaxed)
        }

        result
    }

    /// Runs the key_accessor function and returns its result. If it returns an error and the
    /// root cause was KEY_NOT_FOUND, tries to migrate a key with the given parameters from
    /// the legacy database to the new database and runs the key_accessor function again if
    /// the migration request was successful.
    pub fn with_try_migrate<F, T>(
        &self,
        key: &KeyDescriptor,
        caller_uid: u32,
        key_accessor: F,
    ) -> Result<T>
    where
        F: Fn() -> Result<T>,
    {
        // Access the key and return on success.
        match key_accessor() {
            Ok(result) => return Ok(result),
            Err(e) => match e.root_cause().downcast_ref::<Error>() {
                Some(&Error::Rc(ResponseCode::KEY_NOT_FOUND)) => {}
                _ => return Err(e),
            },
        }

        // Filter inputs. We can only load legacy app domain keys and some special rules due
        // to which we migrate keys transparently to an SELINUX domain.
        let uid = match key {
            KeyDescriptor { domain: Domain::APP, alias: Some(_), .. } => caller_uid,
            KeyDescriptor { domain: Domain::SELINUX, nspace, alias: Some(_), .. } => {
                match *nspace {
                    Self::WIFI_NAMESPACE => Self::AID_WIFI,
                    _ => {
                        return Err(Error::Rc(ResponseCode::KEY_NOT_FOUND))
                            .context(format!("No legacy keys for namespace {}", nspace))
                    }
                }
            }
            _ => {
                return Err(Error::Rc(ResponseCode::KEY_NOT_FOUND))
                    .context("No legacy keys for key descriptor.")
            }
        };

        let key_clone = key.clone();
        let result = self
            .do_serialized(move |migrator_state| migrator_state.check_and_migrate(uid, key_clone));

        if let Some(result) = result {
            result?;
            // After successful migration try again.
            key_accessor()
        } else {
            Err(Error::Rc(ResponseCode::KEY_NOT_FOUND)).context("Legacy database is empty.")
        }
    }

    /// Calls key_accessor and returns the result on success. In the case of a KEY_NOT_FOUND error
    /// this function makes a migration request and on success retries the key_accessor.
    pub fn with_try_migrate_super_key<F, T>(
        &self,
        user_id: u32,
        pw: &Password,
        mut key_accessor: F,
    ) -> Result<Option<T>>
    where
        F: FnMut() -> Result<Option<T>>,
    {
        match key_accessor() {
            Ok(Some(result)) => return Ok(Some(result)),
            Ok(None) => {}
            Err(e) => return Err(e),
        }
        let pw = pw.try_clone().context("In with_try_migrate_super_key: Cloning password.")?;
        let result = self.do_serialized(move |migrator_state| {
            migrator_state.check_and_migrate_super_key(user_id, &pw)
        });

        if let Some(result) = result {
            result?;
            // After successful migration try again.
            key_accessor()
        } else {
            Ok(None)
        }
    }

    /// Deletes all keys belonging to the given namespace, migrating them into the database
    /// for subsequent garbage collection if necessary.
    pub fn bulk_delete_uid(&self, domain: Domain, nspace: i64) -> Result<()> {
        let uid = match (domain, nspace) {
            (Domain::APP, nspace) => nspace as u32,
            (Domain::SELINUX, Self::WIFI_NAMESPACE) => Self::AID_WIFI,
            // Nothing to do.
            _ => return Ok(()),
        };

        let result = self.do_serialized(move |migrator_state| {
            migrator_state.bulk_delete(BulkDeleteRequest::Uid(uid), false)
        });

        result.unwrap_or(Ok(()))
    }

    /// Deletes all keys belonging to the given android user, migrating them into the database
    /// for subsequent garbage collection if necessary.
    pub fn bulk_delete_user(
        &self,
        user_id: u32,
        keep_non_super_encrypted_keys: bool,
    ) -> Result<()> {
        let result = self.do_serialized(move |migrator_state| {
            migrator_state
                .bulk_delete(BulkDeleteRequest::User(user_id), keep_non_super_encrypted_keys)
        });

        result.unwrap_or(Ok(()))
    }

    /// Queries the legacy database for the presence of a super key for the given user.
    pub fn has_super_key(&self, user_id: u32) -> Result<bool> {
        let result =
            self.do_serialized(move |migrator_state| migrator_state.has_super_key(user_id));
        result.unwrap_or(Ok(false))
    }
}

impl LegacyMigratorState {
    fn get_km_uuid(&self, is_strongbox: bool) -> Result<Uuid> {
        let sec_level = if is_strongbox {
            SecurityLevel::STRONGBOX
        } else {
            SecurityLevel::TRUSTED_ENVIRONMENT
        };

        self.sec_level_to_km_uuid.get(&sec_level).copied().ok_or_else(|| {
            anyhow::anyhow!(Error::sys()).context("In get_km_uuid: No KM instance for blob.")
        })
    }

    fn list_uid(&mut self, uid: u32) -> Result<Vec<String>> {
        self.legacy_loader
            .list_keystore_entries_for_uid(uid)
            .context("In list_uid: Trying to list legacy entries.")
    }

    /// This is a key migration request that must run in the migrator thread. This must
    /// be passed to do_serialized.
    fn check_and_migrate(&mut self, uid: u32, mut key: KeyDescriptor) -> Result<()> {
        let alias = key.alias.clone().ok_or_else(|| {
            anyhow::anyhow!(Error::sys()).context(concat!(
                "In check_and_migrate: Must be Some because ",
                "our caller must not have called us otherwise."
            ))
        })?;

        if self.recently_migrated.contains(&RecentMigration::new(uid, alias.clone())) {
            return Ok(());
        }

        if key.domain == Domain::APP {
            key.nspace = uid as i64;
        }

        // If the key is not found in the cache, try to load from the legacy database.
        let (km_blob_params, user_cert, ca_cert) = self
            .legacy_loader
            .load_by_uid_alias(uid, &alias, None)
            .context("In check_and_migrate: Trying to load legacy blob.")?;
        let result = match km_blob_params {
            Some((km_blob, params)) => {
                let is_strongbox = km_blob.is_strongbox();
                let (blob, mut blob_metadata) = match km_blob.take_value() {
                    BlobValue::Encrypted { iv, tag, data } => {
                        // Get super key id for user id.
                        let user_id = uid_to_android_user(uid as u32);

                        let super_key_id = match self
                            .db
                            .load_super_key(&USER_SUPER_KEY, user_id)
                            .context("In check_and_migrate: Failed to load super key")?
                        {
                            Some((_, entry)) => entry.id(),
                            None => {
                                // This might be the first time we access the super key,
                                // and it may not have been migrated. We cannot import
                                // the legacy super_key key now, because we need to reencrypt
                                // it which we cannot do if we are not unlocked, which we are
                                // not because otherwise the key would have been migrated.
                                // We can check though if the key exists. If it does,
                                // we can return Locked. Otherwise, we can delete the
                                // key and return NotFound, because the key will never
                                // be unlocked again.
                                if self.legacy_loader.has_super_key(user_id) {
                                    return Err(Error::Rc(ResponseCode::LOCKED)).context(concat!(
                                        "In check_and_migrate: Cannot migrate super key of this ",
                                        "key while user is locked."
                                    ));
                                } else {
                                    self.legacy_loader.remove_keystore_entry(uid, &alias).context(
                                        concat!(
                                            "In check_and_migrate: ",
                                            "Trying to remove obsolete key."
                                        ),
                                    )?;
                                    return Err(Error::Rc(ResponseCode::KEY_NOT_FOUND))
                                        .context("In check_and_migrate: Obsolete key.");
                                }
                            }
                        };

                        let mut blob_metadata = BlobMetaData::new();
                        blob_metadata.add(BlobMetaEntry::Iv(iv.to_vec()));
                        blob_metadata.add(BlobMetaEntry::AeadTag(tag.to_vec()));
                        blob_metadata
                            .add(BlobMetaEntry::EncryptedBy(EncryptedBy::KeyId(super_key_id)));
                        (LegacyBlob::Vec(data), blob_metadata)
                    }
                    BlobValue::Decrypted(data) => (LegacyBlob::ZVec(data), BlobMetaData::new()),
                    _ => {
                        return Err(Error::Rc(ResponseCode::KEY_NOT_FOUND))
                            .context("In check_and_migrate: Legacy key has unexpected type.")
                    }
                };

                let km_uuid = self
                    .get_km_uuid(is_strongbox)
                    .context("In check_and_migrate: Trying to get KM UUID")?;
                blob_metadata.add(BlobMetaEntry::KmUuid(km_uuid));

                let mut metadata = KeyMetaData::new();
                let creation_date = DateTime::now()
                    .context("In check_and_migrate: Trying to make creation time.")?;
                metadata.add(KeyMetaEntry::CreationDate(creation_date));

                // Store legacy key in the database.
                self.db
                    .store_new_key(
                        &key,
                        &params,
                        &(&blob, &blob_metadata),
                        &CertificateInfo::new(user_cert, ca_cert),
                        &metadata,
                        &km_uuid,
                    )
                    .context("In check_and_migrate.")?;
                Ok(())
            }
            None => {
                if let Some(ca_cert) = ca_cert {
                    self.db
                        .store_new_certificate(&key, &ca_cert, &KEYSTORE_UUID)
                        .context("In check_and_migrate: Failed to insert new certificate.")?;
                    Ok(())
                } else {
                    Err(Error::Rc(ResponseCode::KEY_NOT_FOUND))
                        .context("In check_and_migrate: Legacy key not found.")
                }
            }
        };

        match result {
            Ok(()) => {
                // Add the key to the migrated_keys list.
                self.recently_migrated.insert(RecentMigration::new(uid, alias.clone()));
                // Delete legacy key from the file system
                self.legacy_loader
                    .remove_keystore_entry(uid, &alias)
                    .context("In check_and_migrate: Trying to remove migrated key.")?;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn check_and_migrate_super_key(&mut self, user_id: u32, pw: &Password) -> Result<()> {
        if self.recently_migrated_super_key.contains(&user_id) {
            return Ok(());
        }

        if let Some(super_key) = self
            .legacy_loader
            .load_super_key(user_id, &pw)
            .context("In check_and_migrate_super_key: Trying to load legacy super key.")?
        {
            let (blob, blob_metadata) =
                crate::super_key::SuperKeyManager::encrypt_with_password(&super_key, pw)
                    .context("In check_and_migrate_super_key: Trying to encrypt super key.")?;

            self.db
                .store_super_key(
                    user_id,
                    &USER_SUPER_KEY,
                    &blob,
                    &blob_metadata,
                    &KeyMetaData::new(),
                )
                .context(concat!(
                    "In check_and_migrate_super_key: ",
                    "Trying to insert legacy super_key into the database."
                ))?;
            self.legacy_loader.remove_super_key(user_id);
            self.recently_migrated_super_key.insert(user_id);
            Ok(())
        } else {
            Err(Error::Rc(ResponseCode::KEY_NOT_FOUND))
                .context("In check_and_migrate_super_key: No key found do migrate.")
        }
    }

    /// Key migrator request to be run by do_serialized.
    /// See LegacyMigrator::bulk_delete_uid and LegacyMigrator::bulk_delete_user.
    fn bulk_delete(
        &mut self,
        bulk_delete_request: BulkDeleteRequest,
        keep_non_super_encrypted_keys: bool,
    ) -> Result<()> {
        let (aliases, user_id) = match bulk_delete_request {
            BulkDeleteRequest::Uid(uid) => (
                self.legacy_loader
                    .list_keystore_entries_for_uid(uid)
                    .context("In bulk_delete: Trying to get aliases for uid.")
                    .map(|aliases| {
                        let mut h = HashMap::<u32, HashSet<String>>::new();
                        h.insert(uid, aliases.into_iter().collect());
                        h
                    })?,
                uid_to_android_user(uid),
            ),
            BulkDeleteRequest::User(user_id) => (
                self.legacy_loader
                    .list_keystore_entries_for_user(user_id)
                    .context("In bulk_delete: Trying to get aliases for user_id.")?,
                user_id,
            ),
        };

        let super_key_id = self
            .db
            .load_super_key(&USER_SUPER_KEY, user_id)
            .context("In bulk_delete: Failed to load super key")?
            .map(|(_, entry)| entry.id());

        for (uid, alias) in aliases
            .into_iter()
            .map(|(uid, aliases)| aliases.into_iter().map(move |alias| (uid, alias)))
            .flatten()
        {
            let (km_blob_params, _, _) = self
                .legacy_loader
                .load_by_uid_alias(uid, &alias, None)
                .context("In bulk_delete: Trying to load legacy blob.")?;

            // Determine if the key needs special handling to be deleted.
            let (need_gc, is_super_encrypted) = km_blob_params
                .as_ref()
                .map(|(blob, params)| {
                    (
                        params.iter().any(|kp| {
                            KeyParameterValue::RollbackResistance == *kp.key_parameter_value()
                        }),
                        blob.is_encrypted(),
                    )
                })
                .unwrap_or((false, false));

            if keep_non_super_encrypted_keys && !is_super_encrypted {
                continue;
            }

            if need_gc {
                let mark_deleted = match km_blob_params
                    .map(|(blob, _)| (blob.is_strongbox(), blob.take_value()))
                {
                    Some((is_strongbox, BlobValue::Encrypted { iv, tag, data })) => {
                        let mut blob_metadata = BlobMetaData::new();
                        if let (Ok(km_uuid), Some(super_key_id)) =
                            (self.get_km_uuid(is_strongbox), super_key_id)
                        {
                            blob_metadata.add(BlobMetaEntry::KmUuid(km_uuid));
                            blob_metadata.add(BlobMetaEntry::Iv(iv.to_vec()));
                            blob_metadata.add(BlobMetaEntry::AeadTag(tag.to_vec()));
                            blob_metadata
                                .add(BlobMetaEntry::EncryptedBy(EncryptedBy::KeyId(super_key_id)));
                            Some((LegacyBlob::Vec(data), blob_metadata))
                        } else {
                            // Oh well - we tried our best, but if we cannot determine which
                            // KeyMint instance we have to send this blob to, we cannot
                            // do more than delete the key from the file system.
                            // And if we don't know which key wraps this key we cannot
                            // unwrap it for KeyMint either.
                            None
                        }
                    }
                    Some((_, BlobValue::Decrypted(data))) => {
                        Some((LegacyBlob::ZVec(data), BlobMetaData::new()))
                    }
                    _ => None,
                };

                if let Some((blob, blob_metadata)) = mark_deleted {
                    self.db.set_deleted_blob(&blob, &blob_metadata).context(concat!(
                        "In bulk_delete: Trying to insert deleted ",
                        "blob into the database for garbage collection."
                    ))?;
                }
            }

            self.legacy_loader
                .remove_keystore_entry(uid, &alias)
                .context("In bulk_delete: Trying to remove migrated key.")?;
        }
        Ok(())
    }

    fn has_super_key(&mut self, user_id: u32) -> Result<bool> {
        Ok(self.recently_migrated_super_key.contains(&user_id)
            || self.legacy_loader.has_super_key(user_id))
    }

    fn check_empty(&self) -> u8 {
        if self.legacy_loader.is_empty().unwrap_or(false) {
            LegacyMigrator::STATE_EMPTY
        } else {
            LegacyMigrator::STATE_READY
        }
    }
}

enum LegacyBlob {
    Vec(Vec<u8>),
    ZVec(ZVec),
}

impl Deref for LegacyBlob {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Vec(v) => &v,
            Self::ZVec(v) => &v,
        }
    }
}
