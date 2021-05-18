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

use crate::{database::KeystoreDB, key_parameter::KeyParameterValue, raw_device::KeyMintDevice};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, Digest::Digest, KeyPurpose::KeyPurpose, SecurityLevel::SecurityLevel,
};
use anyhow::{Context, Result};
use keystore2_crypto::{hkdf_expand, ZVec, AES_256_KEY_LENGTH};
use std::{collections::VecDeque, convert::TryFrom};

fn get_preferred_km_instance_for_level_zero_key() -> Result<KeyMintDevice> {
    let tee = KeyMintDevice::get(SecurityLevel::TRUSTED_ENVIRONMENT)
        .context("In get_preferred_km_instance_for_level_zero_key: Get TEE instance failed.")?;
    if tee.version() >= KeyMintDevice::KEY_MASTER_V4_1 {
        Ok(tee)
    } else {
        match KeyMintDevice::get_or_none(SecurityLevel::STRONGBOX).context(
            "In get_preferred_km_instance_for_level_zero_key: Get Strongbox instance failed.",
        )? {
            Some(strongbox) if strongbox.version() >= KeyMintDevice::KEY_MASTER_V4_1 => {
                Ok(strongbox)
            }
            _ => Ok(tee),
        }
    }
}

/// This is not thread safe; caller must hold a lock before calling.
/// In practice the caller is SuperKeyManager and the lock is the
/// Mutex on its internal state.
pub fn get_level_zero_key(db: &mut KeystoreDB) -> Result<ZVec> {
    let km_dev = get_preferred_km_instance_for_level_zero_key()
        .context("In get_level_zero_key: get preferred KM instance failed")?;

    let key_desc = KeyMintDevice::internal_descriptor("boot_level_key".to_string());
    let mut params = vec![
        KeyParameterValue::Algorithm(Algorithm::HMAC).into(),
        KeyParameterValue::Digest(Digest::SHA_2_256).into(),
        KeyParameterValue::KeySize(256).into(),
        KeyParameterValue::MinMacLength(256).into(),
        KeyParameterValue::KeyPurpose(KeyPurpose::SIGN).into(),
        KeyParameterValue::NoAuthRequired.into(),
    ];

    if km_dev.version() >= KeyMintDevice::KEY_MASTER_V4_1 {
        params.push(KeyParameterValue::EarlyBootOnly.into());
    } else {
        params.push(KeyParameterValue::MaxUsesPerBoot(1).into())
    }

    let (key_id_guard, key_entry) = km_dev
        .lookup_or_generate_key(db, &key_desc, &params)
        .context("In get_level_zero_key: lookup_or_generate_key failed")?;

    let params = [KeyParameterValue::MacLength(256).into()];
    let level_zero_key = km_dev
        .use_key_in_one_step(
            db,
            &key_id_guard,
            &key_entry,
            KeyPurpose::SIGN,
            &params,
            None,
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
