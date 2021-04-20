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

//! Offer keys based on the "boot level" for superencryption.

use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, BeginResult::BeginResult, Digest::Digest, ErrorCode::ErrorCode,
    IKeyMintDevice::IKeyMintDevice, IKeyMintOperation::IKeyMintOperation,
    KeyParameter::KeyParameter, KeyPurpose::KeyPurpose, SecurityLevel::SecurityLevel,
};
use android_system_keystore2::aidl::android::system::keystore2::{
    Domain::Domain, KeyDescriptor::KeyDescriptor, ResponseCode::ResponseCode,
};
use anyhow::{Context, Result};
use binder::Strong;
use keystore2_crypto::{hkdf_expand, ZVec, AES_256_KEY_LENGTH};
use std::{collections::VecDeque, convert::TryFrom};

use crate::{
    database::{
        BlobMetaData, BlobMetaEntry, CertificateInfo, DateTime, KeyEntry, KeyEntryLoadBits,
        KeyIdGuard, KeyMetaData, KeyMetaEntry, KeyType, KeystoreDB, SubComponentType, Uuid,
    },
    error::{map_km_error, Error},
    globals::get_keymint_device,
    key_parameter::KeyParameterValue,
    super_key::KeyBlob,
    utils::{key_characteristics_to_internal, Asp, AID_KEYSTORE},
};

/// Wrapper for operating directly on a KeyMint device.
/// These methods often mirror methods in [`crate::security_level`]. However
/// the functions in [`crate::security_level`] make assumptions that hold, and has side effects
/// that make sense, only if called by an external client through binder.
/// In addition we are trying to maintain a separation between interface services
/// so that the architecture is compatible with a future move to multiple thread pools.
/// So the simplest approach today is to write new implementations of them for internal use.
/// Because these methods run very early, we don't even try to cooperate with
/// the operation slot database; we assume there will be plenty of slots.
struct KeyMintDevice {
    asp: Asp,
    km_uuid: Uuid,
}

impl KeyMintDevice {
    fn get(security_level: SecurityLevel) -> Result<KeyMintDevice> {
        let (asp, _hw_info, km_uuid) = get_keymint_device(&security_level)
            .context("In KeyMintDevice::get: get_keymint_device failed")?;
        Ok(KeyMintDevice { asp, km_uuid })
    }

    /// Generate a KM key and store in the database.
    fn generate_and_store_key(
        &self,
        db: &mut KeystoreDB,
        key_desc: &KeyDescriptor,
        params: &[KeyParameter],
    ) -> Result<()> {
        let km_dev: Strong<dyn IKeyMintDevice> = self
            .asp
            .get_interface()
            .context("In generate_and_store_key: Failed to get KeyMint device")?;
        let creation_result = map_km_error(km_dev.generateKey(params, None))
            .context("In generate_and_store_key: generateKey failed")?;
        let key_parameters = key_characteristics_to_internal(creation_result.keyCharacteristics);

        let creation_date =
            DateTime::now().context("In generate_and_store_key: DateTime::now() failed")?;

        let mut key_metadata = KeyMetaData::new();
        key_metadata.add(KeyMetaEntry::CreationDate(creation_date));
        let mut blob_metadata = BlobMetaData::new();
        blob_metadata.add(BlobMetaEntry::KmUuid(self.km_uuid));

        db.store_new_key(
            &key_desc,
            &key_parameters,
            &(&creation_result.keyBlob, &blob_metadata),
            &CertificateInfo::new(None, None),
            &key_metadata,
            &self.km_uuid,
        )
        .context("In generate_and_store_key: store_new_key failed")?;
        Ok(())
    }

    /// This does the lookup and store in separate transactions; caller must
    /// hold a lock before calling.
    fn lookup_or_generate_key(
        &self,
        db: &mut KeystoreDB,
        key_desc: &KeyDescriptor,
        params: &[KeyParameter],
    ) -> Result<(KeyIdGuard, KeyEntry)> {
        // We use a separate transaction for the lookup than for the store
        // - to keep the code simple
        // - because the caller needs to hold a lock in any case
        // - because it avoids holding database locks during slow
        //   KeyMint operations
        let lookup = db.load_key_entry(
            &key_desc,
            KeyType::Client,
            KeyEntryLoadBits::KM,
            AID_KEYSTORE,
            |_, _| Ok(()),
        );
        match lookup {
            Ok(result) => return Ok(result),
            Err(e) => match e.root_cause().downcast_ref::<Error>() {
                Some(&Error::Rc(ResponseCode::KEY_NOT_FOUND)) => {}
                _ => return Err(e),
            },
        }
        self.generate_and_store_key(db, &key_desc, &params)
            .context("In lookup_or_generate_key: generate_and_store_key failed")?;
        db.load_key_entry(&key_desc, KeyType::Client, KeyEntryLoadBits::KM, AID_KEYSTORE, |_, _| {
            Ok(())
        })
        .context("In lookup_or_generate_key: load_key_entry failed")
    }

    /// Call the passed closure; if it returns `KEY_REQUIRES_UPGRADE`, call upgradeKey, and
    /// write the upgraded key to the database.
    fn upgrade_keyblob_if_required_with<T, F>(
        &self,
        db: &mut KeystoreDB,
        km_dev: &Strong<dyn IKeyMintDevice>,
        key_id_guard: KeyIdGuard,
        key_blob: &KeyBlob,
        f: F,
    ) -> Result<T>
    where
        F: Fn(&[u8]) -> Result<T, Error>,
    {
        match f(key_blob) {
            Err(Error::Km(ErrorCode::KEY_REQUIRES_UPGRADE)) => {
                let upgraded_blob = map_km_error(km_dev.upgradeKey(key_blob, &[]))
                    .context("In upgrade_keyblob_if_required_with: Upgrade failed")?;

                let mut new_blob_metadata = BlobMetaData::new();
                new_blob_metadata.add(BlobMetaEntry::KmUuid(self.km_uuid));

                db.set_blob(
                    &key_id_guard,
                    SubComponentType::KEY_BLOB,
                    Some(&upgraded_blob),
                    Some(&new_blob_metadata),
                )
                .context(concat!(
                    "In upgrade_keyblob_if_required_with: ",
                    "Failed to insert upgraded blob into the database"
                ))?;

                Ok(f(&upgraded_blob).context(concat!(
                    "In upgrade_keyblob_if_required_with: ",
                    "Closure failed after upgrade"
                ))?)
            }
            result => Ok(result.context("In upgrade_keyblob_if_required_with: Closure failed")?),
        }
    }

    /// Use the created key in an operation that can be done with
    /// a call to begin followed by a call to finish.
    fn use_key_in_one_step(
        &self,
        db: &mut KeystoreDB,
        key_id_guard: KeyIdGuard,
        key_entry: &KeyEntry,
        purpose: KeyPurpose,
        operation_parameters: &[KeyParameter],
        input: &[u8],
    ) -> Result<Vec<u8>> {
        let km_dev: Strong<dyn IKeyMintDevice> = self
            .asp
            .get_interface()
            .context("In use_key_in_one_step: Failed to get KeyMint device")?;

        let (key_blob, _blob_metadata) = key_entry
            .key_blob_info()
            .as_ref()
            .ok_or_else(Error::sys)
            .context("use_key_in_one_step: Keyblob missing")?;
        let key_blob = KeyBlob::Ref(&key_blob);

        let begin_result: BeginResult = self
            .upgrade_keyblob_if_required_with(db, &km_dev, key_id_guard, &key_blob, |blob| {
                map_km_error(km_dev.begin(purpose, blob, operation_parameters, &Default::default()))
            })
            .context("In use_key_in_one_step: Failed to begin operation.")?;
        let operation: Strong<dyn IKeyMintOperation> = begin_result
            .operation
            .ok_or_else(Error::sys)
            .context("In use_key_in_one_step: Operation missing")?;
        map_km_error(operation.finish(Some(input), None, None, None, None))
            .context("In use_key_in_one_step: Failed to finish operation.")
    }
}

/// This is not thread safe; caller must hold a lock before calling.
/// In practice the caller is SuperKeyManager and the lock is the
/// Mutex on its internal state.
pub fn get_level_zero_key(db: &mut KeystoreDB) -> Result<ZVec> {
    let key_desc = KeyDescriptor {
        domain: Domain::APP,
        nspace: AID_KEYSTORE as i64,
        alias: Some("boot_level_key".to_string()),
        blob: None,
    };
    let params = [
        KeyParameterValue::Algorithm(Algorithm::HMAC).into(),
        KeyParameterValue::Digest(Digest::SHA_2_256).into(),
        KeyParameterValue::KeySize(256).into(),
        KeyParameterValue::MinMacLength(256).into(),
        KeyParameterValue::KeyPurpose(KeyPurpose::SIGN).into(),
        KeyParameterValue::NoAuthRequired.into(),
        KeyParameterValue::MaxUsesPerBoot(1).into(),
    ];
    // We use TRUSTED_ENVIRONMENT here because it is the authority on when
    // the device has rebooted.
    let km_dev: KeyMintDevice = KeyMintDevice::get(SecurityLevel::TRUSTED_ENVIRONMENT)
        .context("In get_level_zero_key: KeyMintDevice::get failed")?;
    let (key_id_guard, key_entry) = km_dev
        .lookup_or_generate_key(db, &key_desc, &params)
        .context("In get_level_zero_key: lookup_or_generate_key failed")?;

    let params = [KeyParameterValue::MacLength(256).into()];
    let level_zero_key = km_dev
        .use_key_in_one_step(
            db,
            key_id_guard,
            &key_entry,
            KeyPurpose::SIGN,
            &params,
            b"Create boot level key",
        )
        .context("In get_level_zero_key: use_key_in_one_step failed")?;
    // TODO: this is rather unsatisfactory, we need a better way to handle
    // sensitive binder returns.
    let level_zero_key = ZVec::try_from(level_zero_key)
        .context("In get_level_zero_key: conversion to ZVec failed")?;
    Ok(level_zero_key)
}

/// Holds the key for the current boot level, and a cache of future keys generated as required.
/// When the boot level advances, keys prior to the current boot level are securely dropped.
pub struct BootLevelKeyCache {
    /// Least boot level currently accessible, if any is.
    current: usize,
    /// Invariant: cache entry *i*, if it exists, holds the HKDF key for boot level
    /// *i* + `current`. If the cache is non-empty it can be grown forwards, but it cannot be
    /// grown backwards, so keys below `current` are inaccessible.
    /// `cache.clear()` makes all keys inaccessible.
    cache: VecDeque<ZVec>,
}

impl BootLevelKeyCache {
    const HKDF_ADVANCE: &'static [u8] = b"Advance KDF one step";
    const HKDF_AES: &'static [u8] = b"Generate AES-256-GCM key";
    const HKDF_KEY_SIZE: usize = 32;

    /// Initialize the cache with the level zero key.
    pub fn new(level_zero_key: ZVec) -> Self {
        let mut cache: VecDeque<ZVec> = VecDeque::new();
        cache.push_back(level_zero_key);
        Self { current: 0, cache }
    }

    /// Report whether the key for the given level can be inferred.
    pub fn level_accessible(&self, boot_level: usize) -> bool {
        // If the requested boot level is lower than the current boot level
        // or if we have reached the end (`cache.empty()`) we can't retrieve
        // the boot key.
        boot_level >= self.current && !self.cache.is_empty()
    }

    /// Get the HKDF key for boot level `boot_level`. The key for level *i*+1
    /// is calculated from the level *i* key using `hkdf_expand`.
    fn get_hkdf_key(&mut self, boot_level: usize) -> Result<Option<&ZVec>> {
        if !self.level_accessible(boot_level) {
            return Ok(None);
        }
        // `self.cache.len()` represents the first entry not in the cache,
        // so `self.current + self.cache.len()` is the first boot level not in the cache.
        let first_not_cached = self.current + self.cache.len();

        // Grow the cache forwards until it contains the desired boot level.
        for _level in first_not_cached..=boot_level {
            // We check at the start that cache is non-empty and future iterations only push,
            // so this must unwrap.
            let highest_key = self.cache.back().unwrap();
            let next_key = hkdf_expand(Self::HKDF_KEY_SIZE, highest_key, Self::HKDF_ADVANCE)
                .context("In BootLevelKeyCache::get_hkdf_key: Advancing key one step")?;
            self.cache.push_back(next_key);
        }

        // If we reach this point, we should have a key at index boot_level - current.
        Ok(Some(self.cache.get(boot_level - self.current).unwrap()))
    }

    /// Drop keys prior to the given boot level, while retaining the ability to generate keys for
    /// that level and later.
    pub fn advance_boot_level(&mut self, new_boot_level: usize) -> Result<()> {
        if !self.level_accessible(new_boot_level) {
            log::error!(
                concat!(
                    "In BootLevelKeyCache::advance_boot_level: ",
                    "Failed to advance boot level to {}, current is {}, cache size {}"
                ),
                new_boot_level,
                self.current,
                self.cache.len()
            );
            return Ok(());
        }

        // We `get` the new boot level for the side effect of advancing the cache to a point
        // where the new boot level is present.
        self.get_hkdf_key(new_boot_level)
            .context("In BootLevelKeyCache::advance_boot_level: Advancing cache")?;

        // Then we split the queue at the index of the new boot level and discard the front,
        // keeping only the keys with the current boot level or higher.
        self.cache = self.cache.split_off(new_boot_level - self.current);

        // The new cache has the new boot level at index 0, so we set `current` to
        // `new_boot_level`.
        self.current = new_boot_level;

        Ok(())
    }

    /// Drop all keys, effectively raising the current boot level to infinity; no keys can
    /// be inferred from this point on.
    pub fn finish(&mut self) {
        self.cache.clear();
    }

    fn expand_key(
        &mut self,
        boot_level: usize,
        out_len: usize,
        info: &[u8],
    ) -> Result<Option<ZVec>> {
        self.get_hkdf_key(boot_level)
            .context("In BootLevelKeyCache::expand_key: Looking up HKDF key")?
            .map(|k| hkdf_expand(out_len, k, info))
            .transpose()
            .context("In BootLevelKeyCache::expand_key: Calling hkdf_expand")
    }

    /// Return the AES-256-GCM key for the current boot level.
    pub fn aes_key(&mut self, boot_level: usize) -> Result<Option<ZVec>> {
        self.expand_key(boot_level, AES_256_KEY_LENGTH, BootLevelKeyCache::HKDF_AES)
            .context("In BootLevelKeyCache::aes_key: expand_key failed")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_output_is_consistent() -> Result<()> {
        let initial_key = b"initial key";
        let mut blkc = BootLevelKeyCache::new(ZVec::try_from(initial_key as &[u8])?);
        assert_eq!(true, blkc.level_accessible(0));
        assert_eq!(true, blkc.level_accessible(9));
        assert_eq!(true, blkc.level_accessible(10));
        assert_eq!(true, blkc.level_accessible(100));
        let v0 = blkc.aes_key(0).unwrap().unwrap();
        let v10 = blkc.aes_key(10).unwrap().unwrap();
        assert_eq!(Some(&v0), blkc.aes_key(0)?.as_ref());
        assert_eq!(Some(&v10), blkc.aes_key(10)?.as_ref());
        blkc.advance_boot_level(5)?;
        assert_eq!(false, blkc.level_accessible(0));
        assert_eq!(true, blkc.level_accessible(9));
        assert_eq!(true, blkc.level_accessible(10));
        assert_eq!(true, blkc.level_accessible(100));
        assert_eq!(None, blkc.aes_key(0)?);
        assert_eq!(Some(&v10), blkc.aes_key(10)?.as_ref());
        blkc.advance_boot_level(10)?;
        assert_eq!(false, blkc.level_accessible(0));
        assert_eq!(false, blkc.level_accessible(9));
        assert_eq!(true, blkc.level_accessible(10));
        assert_eq!(true, blkc.level_accessible(100));
        assert_eq!(None, blkc.aes_key(0)?);
        assert_eq!(Some(&v10), blkc.aes_key(10)?.as_ref());
        blkc.advance_boot_level(0)?;
        assert_eq!(false, blkc.level_accessible(0));
        assert_eq!(false, blkc.level_accessible(9));
        assert_eq!(true, blkc.level_accessible(10));
        assert_eq!(true, blkc.level_accessible(100));
        assert_eq!(None, blkc.aes_key(0)?);
        assert_eq!(Some(v10), blkc.aes_key(10)?);
        blkc.finish();
        assert_eq!(false, blkc.level_accessible(0));
        assert_eq!(false, blkc.level_accessible(9));
        assert_eq!(false, blkc.level_accessible(10));
        assert_eq!(false, blkc.level_accessible(100));
        assert_eq!(None, blkc.aes_key(0)?);
        assert_eq!(None, blkc.aes_key(10)?);
        Ok(())
    }
}
