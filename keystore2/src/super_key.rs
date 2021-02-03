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

#![allow(dead_code)]

use crate::{
    database::EncryptedBy, database::KeyMetaData, database::KeyMetaEntry, database::KeystoreDB,
    error::Error, error::ResponseCode, legacy_blob::LegacyBlobLoader,
};
use android_system_keystore2::aidl::android::system::keystore2::Domain::Domain;
use anyhow::{Context, Result};
use keystore2_crypto::{
    aes_gcm_decrypt, aes_gcm_encrypt, derive_key_from_password, generate_salt, ZVec,
    AES_256_KEY_LENGTH,
};
use std::{
    collections::HashMap,
    sync::Arc,
    sync::{Mutex, Weak},
};

type UserId = u32;

#[derive(Default)]
struct UserSuperKeys {
    /// The per boot key is used for LSKF binding of authentication bound keys. There is one
    /// key per android user. The key is stored on flash encrypted with a key derived from a
    /// secret, that is itself derived from the user's lock screen knowledge factor (LSKF).
    /// When the user unlocks the device for the first time, this key is unlocked, i.e., decrypted,
    /// and stays memory resident until the device reboots.
    per_boot: Option<Arc<ZVec>>,
    /// The screen lock key works like the per boot key with the distinction that it is cleared
    /// from memory when the screen lock is engaged.
    /// TODO the life cycle is not fully implemented at this time.
    screen_lock: Option<Arc<ZVec>>,
}

#[derive(Default)]
struct SkmState {
    user_keys: HashMap<UserId, UserSuperKeys>,
    key_index: HashMap<i64, Weak<ZVec>>,
}

#[derive(Default)]
pub struct SuperKeyManager {
    data: Mutex<SkmState>,
}

impl SuperKeyManager {
    pub fn new() -> Self {
        Self { data: Mutex::new(Default::default()) }
    }

    pub fn forget_screen_lock_key_for_user(&self, user: UserId) {
        let mut data = self.data.lock().unwrap();
        if let Some(usk) = data.user_keys.get_mut(&user) {
            usk.screen_lock = None;
        }
    }

    pub fn forget_screen_lock_keys(&self) {
        let mut data = self.data.lock().unwrap();
        for (_, usk) in data.user_keys.iter_mut() {
            usk.screen_lock = None;
        }
    }

    pub fn forget_all_keys_for_user(&self, user: UserId) {
        let mut data = self.data.lock().unwrap();
        data.user_keys.remove(&user);
    }

    pub fn forget_all_keys(&self) {
        let mut data = self.data.lock().unwrap();
        data.user_keys.clear();
        data.key_index.clear();
    }

    fn install_per_boot_key_for_user(&self, user: UserId, key_id: i64, key: ZVec) {
        let mut data = self.data.lock().unwrap();
        let key = Arc::new(key);
        data.key_index.insert(key_id, Arc::downgrade(&key));
        data.user_keys.entry(user).or_default().per_boot = Some(key);
    }

    fn get_key(&self, key_id: &i64) -> Option<Arc<ZVec>> {
        self.data.lock().unwrap().key_index.get(key_id).and_then(|k| k.upgrade())
    }

    pub fn get_per_boot_key_by_user_id(&self, user_id: u32) -> Option<Arc<ZVec>> {
        let data = self.data.lock().unwrap();
        data.user_keys.get(&user_id).map(|e| e.per_boot.clone()).flatten()
    }

    /// This function unlocks the super keys for a given user.
    /// This means the key is loaded from the database, decrypted and placed in the
    /// super key cache. If there is no such key a new key is created, encrypted with
    /// a key derived from the given password and stored in the database.
    pub fn unlock_user_key(
        &self,
        user: UserId,
        pw: &[u8],
        db: &mut KeystoreDB,
        legacy_blob_loader: &LegacyBlobLoader,
    ) -> Result<()> {
        let (_, entry) = db
            .get_or_create_key_with(
                Domain::APP,
                user as u64 as i64,
                &"USER_SUPER_KEY",
                crate::database::KEYSTORE_UUID,
                || {
                    // For backward compatibility we need to check if there is a super key present.
                    let super_key = legacy_blob_loader
                        .load_super_key(user, pw)
                        .context("In create_new_key: Failed to load legacy key blob.")?;
                    let super_key = match super_key {
                        None => {
                            // No legacy file was found. So we generate a new key.
                            keystore2_crypto::generate_aes256_key()
                                .context("In create_new_key: Failed to generate AES 256 key.")?
                        }
                        Some(key) => key,
                    };
                    // Regardless of whether we loaded an old AES128 key or a new AES256 key,
                    // we derive a AES256 key and re-encrypt the key before we insert it in the
                    // database. The length of the key is preserved by the encryption so we don't
                    // need any extra flags to inform us which algorithm to use it with.
                    let salt =
                        generate_salt().context("In create_new_key: Failed to generate salt.")?;
                    let derived_key = derive_key_from_password(pw, Some(&salt), AES_256_KEY_LENGTH)
                        .context("In create_new_key: Failed to derive password.")?;
                    let mut metadata = KeyMetaData::new();
                    metadata.add(KeyMetaEntry::EncryptedBy(EncryptedBy::Password));
                    metadata.add(KeyMetaEntry::Salt(salt));
                    let (encrypted_key, iv, tag) = aes_gcm_encrypt(&super_key, &derived_key)
                        .context("In create_new_key: Failed to encrypt new super key.")?;
                    metadata.add(KeyMetaEntry::Iv(iv));
                    metadata.add(KeyMetaEntry::AeadTag(tag));
                    Ok((encrypted_key, metadata))
                },
            )
            .context("In unlock_user_key: Failed to get key id.")?;

        let metadata = entry.metadata();
        let super_key = match (
            metadata.encrypted_by(),
            metadata.salt(),
            metadata.iv(),
            metadata.aead_tag(),
            entry.km_blob(),
        ) {
            (Some(&EncryptedBy::Password), Some(salt), Some(iv), Some(tag), Some(blob)) => {
                let key = derive_key_from_password(pw, Some(salt), AES_256_KEY_LENGTH)
                    .context("In unlock_user_key: Failed to generate key from password.")?;

                aes_gcm_decrypt(blob, iv, tag, &key)
                    .context("In unlock_user_key: Failed to decrypt key blob.")?
            }
            (enc_by, salt, iv, tag, blob) => {
                return Err(Error::Rc(ResponseCode::VALUE_CORRUPTED)).context(format!(
                    concat!(
                        "In unlock_user_key: Super key has incomplete metadata.",
                        "Present: encrypted_by: {}, salt: {}, iv: {}, aead_tag: {}, blob: {}."
                    ),
                    enc_by.is_some(),
                    salt.is_some(),
                    iv.is_some(),
                    tag.is_some(),
                    blob.is_some()
                ));
            }
        };

        self.install_per_boot_key_for_user(user, entry.id(), super_key);

        Ok(())
    }

    /// Unwraps an encrypted key blob given metadata identifying the encryption key.
    /// The function queries `metadata.encrypted_by()` to determine the encryption key.
    /// It then check if the required key is memory resident, and if so decrypts the
    /// blob.
    pub fn unwrap_key(&self, blob: &[u8], metadata: &KeyMetaData) -> Result<ZVec> {
        match metadata.encrypted_by() {
            Some(EncryptedBy::KeyId(key_id)) => match self.get_key(key_id) {
                Some(key) => {
                    Self::unwrap_key_with_key(blob, metadata, &key).context("In unwrap_key.")
                }
                None => Err(Error::Rc(ResponseCode::LOCKED))
                    .context("In unwrap_key: Key is not usable until the user entered their LSKF."),
            },
            _ => Err(Error::Rc(ResponseCode::VALUE_CORRUPTED))
                .context("In unwrap_key: Cannot determined wrapping key."),
        }
    }

    /// Unwraps an encrypted key blob given an encryption key.
    fn unwrap_key_with_key(blob: &[u8], metadata: &KeyMetaData, key: &[u8]) -> Result<ZVec> {
        match (metadata.iv(), metadata.aead_tag()) {
            (Some(iv), Some(tag)) => aes_gcm_decrypt(blob, iv, tag, key)
                .context("In unwrap_key_with_key: Failed to decrypt the key blob."),
            (iv, tag) => Err(Error::Rc(ResponseCode::VALUE_CORRUPTED)).context(format!(
                concat!(
                    "In unwrap_key_with_key: Key has incomplete metadata.",
                    "Present: iv: {}, aead_tag: {}."
                ),
                iv.is_some(),
                tag.is_some(),
            )),
        }
    }
}
