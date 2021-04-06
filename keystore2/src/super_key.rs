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

use crate::{
    boot_level_keys::{get_level_zero_key, BootLevelKeyCache},
    database::BlobMetaData,
    database::BlobMetaEntry,
    database::EncryptedBy,
    database::KeyEntry,
    database::KeyType,
    database::{KeyMetaData, KeyMetaEntry, KeystoreDB},
    ec_crypto::ECDHPrivateKey,
    enforcements::Enforcements,
    error::Error,
    error::ResponseCode,
    key_parameter::KeyParameter,
    legacy_blob::LegacyBlobLoader,
    legacy_migrator::LegacyMigrator,
    try_insert::TryInsert,
};
use android_system_keystore2::aidl::android::system::keystore2::Domain::Domain;
use anyhow::{Context, Result};
use keystore2_crypto::{
    aes_gcm_decrypt, aes_gcm_encrypt, generate_aes256_key, generate_salt, Password, ZVec,
    AES_256_KEY_LENGTH,
};
use keystore2_system_property::PropertyWatcher;
use std::ops::Deref;
use std::{
    collections::HashMap,
    sync::Arc,
    sync::{Mutex, Weak},
};

const MAX_MAX_BOOT_LEVEL: usize = 1_000_000_000;

type UserId = u32;

/// Encryption algorithm used by a particular type of superencryption key
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuperEncryptionAlgorithm {
    /// Symmetric encryption with AES-256-GCM
    Aes256Gcm,
    /// Public-key encryption with ECDH P-256
    EcdhP256,
}

/// A particular user may have several superencryption keys in the database, each for a
/// different purpose, distinguished by alias. Each is associated with a static
/// constant of this type.
pub struct SuperKeyType {
    /// Alias used to look the key up in the `persistent.keyentry` table.
    pub alias: &'static str,
    /// Encryption algorithm
    pub algorithm: SuperEncryptionAlgorithm,
}

/// Key used for LskfLocked keys; the corresponding superencryption key is loaded in memory
/// when the user first unlocks, and remains in memory until the device reboots.
pub const USER_SUPER_KEY: SuperKeyType =
    SuperKeyType { alias: "USER_SUPER_KEY", algorithm: SuperEncryptionAlgorithm::Aes256Gcm };
/// Key used for ScreenLockBound keys; the corresponding superencryption key is loaded in memory
/// each time the user enters their LSKF, and cleared from memory each time the device is locked.
/// Symmetric.
pub const USER_SCREEN_LOCK_BOUND_KEY: SuperKeyType = SuperKeyType {
    alias: "USER_SCREEN_LOCK_BOUND_KEY",
    algorithm: SuperEncryptionAlgorithm::Aes256Gcm,
};
/// Key used for ScreenLockBound keys; the corresponding superencryption key is loaded in memory
/// each time the user enters their LSKF, and cleared from memory each time the device is locked.
/// Asymmetric, so keys can be encrypted when the device is locked.
pub const USER_SCREEN_LOCK_BOUND_ECDH_KEY: SuperKeyType = SuperKeyType {
    alias: "USER_SCREEN_LOCK_BOUND_ECDH_KEY",
    algorithm: SuperEncryptionAlgorithm::EcdhP256,
};

/// Superencryption to apply to a new key.
#[derive(Debug, Clone, Copy)]
pub enum SuperEncryptionType {
    /// Do not superencrypt this key.
    None,
    /// Superencrypt with a key that remains in memory from first unlock to reboot.
    LskfBound,
    /// Superencrypt with a key cleared from memory when the device is locked.
    ScreenLockBound,
    /// Superencrypt with a key based on the desired boot level
    BootLevel(i32),
}

#[derive(Debug, Clone, Copy)]
pub enum SuperKeyIdentifier {
    /// id of the super key in the database.
    DatabaseId(i64),
    /// Boot level of the encrypting boot level key
    BootLevel(i32),
}

impl SuperKeyIdentifier {
    fn from_metadata(metadata: &BlobMetaData) -> Option<Self> {
        if let Some(EncryptedBy::KeyId(key_id)) = metadata.encrypted_by() {
            Some(SuperKeyIdentifier::DatabaseId(*key_id))
        } else if let Some(boot_level) = metadata.max_boot_level() {
            Some(SuperKeyIdentifier::BootLevel(*boot_level))
        } else {
            None
        }
    }

    fn add_to_metadata(&self, metadata: &mut BlobMetaData) {
        match self {
            SuperKeyIdentifier::DatabaseId(id) => {
                metadata.add(BlobMetaEntry::EncryptedBy(EncryptedBy::KeyId(*id)));
            }
            SuperKeyIdentifier::BootLevel(level) => {
                metadata.add(BlobMetaEntry::MaxBootLevel(*level));
            }
        }
    }
}

pub struct SuperKey {
    algorithm: SuperEncryptionAlgorithm,
    key: ZVec,
    /// Identifier of the encrypting key, used to write an encrypted blob
    /// back to the database after re-encryption eg on a key update.
    id: SuperKeyIdentifier,
    /// ECDH is more expensive than AES. So on ECDH private keys we set the
    /// reencrypt_with field to point at the corresponding AES key, and the
    /// keys will be re-encrypted with AES on first use.
    reencrypt_with: Option<Arc<SuperKey>>,
}

impl SuperKey {
    /// For most purposes `unwrap_key` handles decryption,
    /// but legacy handling and some tests need to assume AES and decrypt directly.
    pub fn aes_gcm_decrypt(&self, data: &[u8], iv: &[u8], tag: &[u8]) -> Result<ZVec> {
        if self.algorithm == SuperEncryptionAlgorithm::Aes256Gcm {
            aes_gcm_decrypt(data, iv, tag, &self.key)
                .context("In aes_gcm_decrypt: decryption failed")
        } else {
            Err(Error::sys()).context("In aes_gcm_decrypt: Key is not an AES key")
        }
    }
}

#[derive(Default)]
struct UserSuperKeys {
    /// The per boot key is used for LSKF binding of authentication bound keys. There is one
    /// key per android user. The key is stored on flash encrypted with a key derived from a
    /// secret, that is itself derived from the user's lock screen knowledge factor (LSKF).
    /// When the user unlocks the device for the first time, this key is unlocked, i.e., decrypted,
    /// and stays memory resident until the device reboots.
    per_boot: Option<Arc<SuperKey>>,
    /// The screen lock key works like the per boot key with the distinction that it is cleared
    /// from memory when the screen lock is engaged.
    screen_lock_bound: Option<Arc<SuperKey>>,
    /// When the device is locked, screen-lock-bound keys can still be encrypted, using
    /// ECDH public-key encryption. This field holds the decryption private key.
    screen_lock_bound_private: Option<Arc<SuperKey>>,
}

#[derive(Default)]
struct SkmState {
    user_keys: HashMap<UserId, UserSuperKeys>,
    key_index: HashMap<i64, Weak<SuperKey>>,
    boot_level_key_cache: Option<BootLevelKeyCache>,
}

impl SkmState {
    fn add_key_to_key_index(&mut self, super_key: &Arc<SuperKey>) -> Result<()> {
        if let SuperKeyIdentifier::DatabaseId(id) = super_key.id {
            self.key_index.insert(id, Arc::downgrade(super_key));
            Ok(())
        } else {
            Err(Error::sys()).context(format!(
                "In add_key_to_key_index: cannot add key with ID {:?}",
                super_key.id
            ))
        }
    }
}

#[derive(Default)]
pub struct SuperKeyManager {
    data: Mutex<SkmState>,
}

impl SuperKeyManager {
    pub fn set_up_boot_level_cache(self: &Arc<Self>, db: &mut KeystoreDB) -> Result<()> {
        let mut data = self.data.lock().unwrap();
        if data.boot_level_key_cache.is_some() {
            log::info!("In set_up_boot_level_cache: called for a second time");
            return Ok(());
        }
        let level_zero_key = get_level_zero_key(db)
            .context("In set_up_boot_level_cache: get_level_zero_key failed")?;
        data.boot_level_key_cache = Some(BootLevelKeyCache::new(level_zero_key));
        log::info!("Starting boot level watcher.");
        let clone = self.clone();
        std::thread::spawn(move || {
            clone
                .watch_boot_level()
                .unwrap_or_else(|e| log::error!("watch_boot_level failed:\n{:?}", e));
        });
        Ok(())
    }

    /// Watch the `keystore.boot_level` system property, and keep boot level up to date.
    /// Blocks waiting for system property changes, so must be run in its own thread.
    fn watch_boot_level(&self) -> Result<()> {
        let mut w = PropertyWatcher::new("keystore.boot_level")
            .context("In watch_boot_level: PropertyWatcher::new failed")?;
        loop {
            let level = w
                .read(|_n, v| v.parse::<usize>().map_err(std::convert::Into::into))
                .context("In watch_boot_level: read of property failed")?;
            // watch_boot_level should only be called once data.boot_level_key_cache is Some,
            // so it's safe to unwrap in the branches below.
            if level < MAX_MAX_BOOT_LEVEL {
                log::info!("Read keystore.boot_level value {}", level);
                let mut data = self.data.lock().unwrap();
                data.boot_level_key_cache
                    .as_mut()
                    .unwrap()
                    .advance_boot_level(level)
                    .context("In watch_boot_level: advance_boot_level failed")?;
            } else {
                log::info!(
                    "keystore.boot_level {} hits maximum {}, finishing.",
                    level,
                    MAX_MAX_BOOT_LEVEL
                );
                let mut data = self.data.lock().unwrap();
                data.boot_level_key_cache.as_mut().unwrap().finish();
                break;
            }
            w.wait().context("In watch_boot_level: property wait failed")?;
        }
        Ok(())
    }

    pub fn level_accessible(&self, boot_level: i32) -> bool {
        self.data
            .lock()
            .unwrap()
            .boot_level_key_cache
            .as_ref()
            .map_or(false, |c| c.level_accessible(boot_level as usize))
    }

    pub fn forget_all_keys_for_user(&self, user: UserId) {
        let mut data = self.data.lock().unwrap();
        data.user_keys.remove(&user);
    }

    fn install_per_boot_key_for_user(&self, user: UserId, super_key: Arc<SuperKey>) -> Result<()> {
        let mut data = self.data.lock().unwrap();
        data.add_key_to_key_index(&super_key)
            .context("In install_per_boot_key_for_user: add_key_to_key_index failed")?;
        data.user_keys.entry(user).or_default().per_boot = Some(super_key);
        Ok(())
    }

    fn lookup_key(&self, key_id: &SuperKeyIdentifier) -> Result<Option<Arc<SuperKey>>> {
        let mut data = self.data.lock().unwrap();
        Ok(match key_id {
            SuperKeyIdentifier::DatabaseId(id) => data.key_index.get(id).and_then(|k| k.upgrade()),
            SuperKeyIdentifier::BootLevel(level) => data
                .boot_level_key_cache
                .as_mut()
                .map(|b| b.aes_key(*level as usize))
                .transpose()
                .context("In lookup_key: aes_key failed")?
                .flatten()
                .map(|key| {
                    Arc::new(SuperKey {
                        algorithm: SuperEncryptionAlgorithm::Aes256Gcm,
                        key,
                        id: *key_id,
                        reencrypt_with: None,
                    })
                }),
        })
    }

    pub fn get_per_boot_key_by_user_id(&self, user_id: UserId) -> Option<Arc<SuperKey>> {
        let data = self.data.lock().unwrap();
        data.user_keys.get(&user_id).and_then(|e| e.per_boot.as_ref().cloned())
    }

    /// This function unlocks the super keys for a given user.
    /// This means the key is loaded from the database, decrypted and placed in the
    /// super key cache. If there is no such key a new key is created, encrypted with
    /// a key derived from the given password and stored in the database.
    pub fn unlock_user_key(
        &self,
        db: &mut KeystoreDB,
        user: UserId,
        pw: &Password,
        legacy_blob_loader: &LegacyBlobLoader,
    ) -> Result<()> {
        let (_, entry) = db
            .get_or_create_key_with(
                Domain::APP,
                user as u64 as i64,
                &USER_SUPER_KEY.alias,
                crate::database::KEYSTORE_UUID,
                || {
                    // For backward compatibility we need to check if there is a super key present.
                    let super_key = legacy_blob_loader
                        .load_super_key(user, pw)
                        .context("In create_new_key: Failed to load legacy key blob.")?;
                    let super_key = match super_key {
                        None => {
                            // No legacy file was found. So we generate a new key.
                            generate_aes256_key()
                                .context("In create_new_key: Failed to generate AES 256 key.")?
                        }
                        Some(key) => key,
                    };
                    // Regardless of whether we loaded an old AES128 key or generated a new AES256
                    // key as the super key, we derive a AES256 key from the password and re-encrypt
                    // the super key before we insert it in the database. The length of the key is
                    // preserved by the encryption so we don't need any extra flags to inform us
                    // which algorithm to use it with.
                    Self::encrypt_with_password(&super_key, pw).context("In create_new_key.")
                },
            )
            .context("In unlock_user_key: Failed to get key id.")?;

        self.populate_cache_from_super_key_blob(user, USER_SUPER_KEY.algorithm, entry, pw)
            .context("In unlock_user_key.")?;
        Ok(())
    }

    /// Check if a given key is super-encrypted, from its metadata. If so, unwrap the key using
    /// the relevant super key.
    pub fn unwrap_key_if_required<'a>(
        &self,
        metadata: &BlobMetaData,
        blob: &'a [u8],
    ) -> Result<KeyBlob<'a>> {
        Ok(if let Some(key_id) = SuperKeyIdentifier::from_metadata(metadata) {
            let super_key = self
                .lookup_key(&key_id)
                .context("In unwrap_key: lookup_key failed")?
                .ok_or(Error::Rc(ResponseCode::LOCKED))
                .context("In unwrap_key: Required super decryption key is not in memory.")?;
            KeyBlob::Sensitive {
                key: Self::unwrap_key_with_key(blob, metadata, &super_key)
                    .context("In unwrap_key: unwrap_key_with_key failed")?,
                reencrypt_with: super_key.reencrypt_with.as_ref().unwrap_or(&super_key).clone(),
                force_reencrypt: super_key.reencrypt_with.is_some(),
            }
        } else {
            KeyBlob::Ref(blob)
        })
    }

    /// Unwraps an encrypted key blob given an encryption key.
    fn unwrap_key_with_key(blob: &[u8], metadata: &BlobMetaData, key: &SuperKey) -> Result<ZVec> {
        match key.algorithm {
            SuperEncryptionAlgorithm::Aes256Gcm => match (metadata.iv(), metadata.aead_tag()) {
                (Some(iv), Some(tag)) => key
                    .aes_gcm_decrypt(blob, iv, tag)
                    .context("In unwrap_key_with_key: Failed to decrypt the key blob."),
                (iv, tag) => Err(Error::Rc(ResponseCode::VALUE_CORRUPTED)).context(format!(
                    concat!(
                        "In unwrap_key_with_key: Key has incomplete metadata.",
                        "Present: iv: {}, aead_tag: {}."
                    ),
                    iv.is_some(),
                    tag.is_some(),
                )),
            },
            SuperEncryptionAlgorithm::EcdhP256 => {
                match (metadata.public_key(), metadata.salt(), metadata.iv(), metadata.aead_tag()) {
                    (Some(public_key), Some(salt), Some(iv), Some(aead_tag)) => {
                        ECDHPrivateKey::from_private_key(&key.key)
                            .and_then(|k| k.decrypt_message(public_key, salt, iv, blob, aead_tag))
                            .context(
                                "In unwrap_key_with_key: Failed to decrypt the key blob with ECDH.",
                            )
                    }
                    (public_key, salt, iv, aead_tag) => {
                        Err(Error::Rc(ResponseCode::VALUE_CORRUPTED)).context(format!(
                            concat!(
                                "In unwrap_key_with_key: Key has incomplete metadata.",
                                "Present: public_key: {}, salt: {}, iv: {}, aead_tag: {}."
                            ),
                            public_key.is_some(),
                            salt.is_some(),
                            iv.is_some(),
                            aead_tag.is_some(),
                        ))
                    }
                }
            }
        }
    }

    /// Checks if user has setup LSKF, even when super key cache is empty for the user.
    pub fn super_key_exists_in_db_for_user(
        db: &mut KeystoreDB,
        legacy_migrator: &LegacyMigrator,
        user_id: UserId,
    ) -> Result<bool> {
        let key_in_db = db
            .key_exists(Domain::APP, user_id as u64 as i64, &USER_SUPER_KEY.alias, KeyType::Super)
            .context("In super_key_exists_in_db_for_user.")?;

        if key_in_db {
            Ok(key_in_db)
        } else {
            legacy_migrator
                .has_super_key(user_id)
                .context("In super_key_exists_in_db_for_user: Trying to query legacy db.")
        }
    }

    /// Checks if user has already setup LSKF (i.e. a super key is persisted in the database or the
    /// legacy database). If not, return Uninitialized state.
    /// Otherwise, decrypt the super key from the password and return LskfUnlocked state.
    pub fn check_and_unlock_super_key(
        &self,
        db: &mut KeystoreDB,
        legacy_migrator: &LegacyMigrator,
        user_id: UserId,
        pw: &Password,
    ) -> Result<UserState> {
        let alias = &USER_SUPER_KEY;
        let result = legacy_migrator
            .with_try_migrate_super_key(user_id, pw, || db.load_super_key(alias, user_id))
            .context("In check_and_unlock_super_key. Failed to load super key")?;

        match result {
            Some((_, entry)) => {
                let super_key = self
                    .populate_cache_from_super_key_blob(user_id, alias.algorithm, entry, pw)
                    .context("In check_and_unlock_super_key.")?;
                Ok(UserState::LskfUnlocked(super_key))
            }
            None => Ok(UserState::Uninitialized),
        }
    }

    /// Checks if user has already setup LSKF (i.e. a super key is persisted in the database or the
    /// legacy database). If so, return LskfLocked state.
    /// If the password is provided, generate a new super key, encrypt with the password,
    /// store in the database and populate the super key cache for the new user
    /// and return LskfUnlocked state.
    /// If the password is not provided, return Uninitialized state.
    pub fn check_and_initialize_super_key(
        &self,
        db: &mut KeystoreDB,
        legacy_migrator: &LegacyMigrator,
        user_id: UserId,
        pw: Option<&Password>,
    ) -> Result<UserState> {
        let super_key_exists_in_db =
            Self::super_key_exists_in_db_for_user(db, legacy_migrator, user_id).context(
                "In check_and_initialize_super_key. Failed to check if super key exists.",
            )?;
        if super_key_exists_in_db {
            Ok(UserState::LskfLocked)
        } else if let Some(pw) = pw {
            //generate a new super key.
            let super_key = generate_aes256_key()
                .context("In check_and_initialize_super_key: Failed to generate AES 256 key.")?;
            //derive an AES256 key from the password and re-encrypt the super key
            //before we insert it in the database.
            let (encrypted_super_key, blob_metadata) = Self::encrypt_with_password(&super_key, pw)
                .context("In check_and_initialize_super_key.")?;

            let key_entry = db
                .store_super_key(
                    user_id,
                    &USER_SUPER_KEY,
                    &encrypted_super_key,
                    &blob_metadata,
                    &KeyMetaData::new(),
                )
                .context("In check_and_initialize_super_key. Failed to store super key.")?;

            let super_key = self
                .populate_cache_from_super_key_blob(
                    user_id,
                    USER_SUPER_KEY.algorithm,
                    key_entry,
                    pw,
                )
                .context("In check_and_initialize_super_key.")?;
            Ok(UserState::LskfUnlocked(super_key))
        } else {
            Ok(UserState::Uninitialized)
        }
    }

    //helper function to populate super key cache from the super key blob loaded from the database
    fn populate_cache_from_super_key_blob(
        &self,
        user_id: UserId,
        algorithm: SuperEncryptionAlgorithm,
        entry: KeyEntry,
        pw: &Password,
    ) -> Result<Arc<SuperKey>> {
        let super_key = Self::extract_super_key_from_key_entry(algorithm, entry, pw, None)
            .context(
                "In populate_cache_from_super_key_blob. Failed to extract super key from key entry",
            )?;
        self.install_per_boot_key_for_user(user_id, super_key.clone())?;
        Ok(super_key)
    }

    /// Extracts super key from the entry loaded from the database
    pub fn extract_super_key_from_key_entry(
        algorithm: SuperEncryptionAlgorithm,
        entry: KeyEntry,
        pw: &Password,
        reencrypt_with: Option<Arc<SuperKey>>,
    ) -> Result<Arc<SuperKey>> {
        if let Some((blob, metadata)) = entry.key_blob_info() {
            let key = match (
                metadata.encrypted_by(),
                metadata.salt(),
                metadata.iv(),
                metadata.aead_tag(),
            ) {
                (Some(&EncryptedBy::Password), Some(salt), Some(iv), Some(tag)) => {
                    // Note that password encryption is AES no matter the value of algorithm
                    let key = pw.derive_key(Some(salt), AES_256_KEY_LENGTH).context(
                        "In extract_super_key_from_key_entry: Failed to generate key from password.",
                    )?;

                    aes_gcm_decrypt(blob, iv, tag, &key).context(
                        "In extract_super_key_from_key_entry: Failed to decrypt key blob.",
                    )?
                }
                (enc_by, salt, iv, tag) => {
                    return Err(Error::Rc(ResponseCode::VALUE_CORRUPTED)).context(format!(
                        concat!(
                        "In extract_super_key_from_key_entry: Super key has incomplete metadata.",
                        "encrypted_by: {:?}; Present: salt: {}, iv: {}, aead_tag: {}."
                    ),
                        enc_by,
                        salt.is_some(),
                        iv.is_some(),
                        tag.is_some()
                    ));
                }
            };
            Ok(Arc::new(SuperKey {
                algorithm,
                key,
                id: SuperKeyIdentifier::DatabaseId(entry.id()),
                reencrypt_with,
            }))
        } else {
            Err(Error::Rc(ResponseCode::VALUE_CORRUPTED))
                .context("In extract_super_key_from_key_entry: No key blob info.")
        }
    }

    /// Encrypts the super key from a key derived from the password, before storing in the database.
    pub fn encrypt_with_password(
        super_key: &[u8],
        pw: &Password,
    ) -> Result<(Vec<u8>, BlobMetaData)> {
        let salt = generate_salt().context("In encrypt_with_password: Failed to generate salt.")?;
        let derived_key = pw
            .derive_key(Some(&salt), AES_256_KEY_LENGTH)
            .context("In encrypt_with_password: Failed to derive password.")?;
        let mut metadata = BlobMetaData::new();
        metadata.add(BlobMetaEntry::EncryptedBy(EncryptedBy::Password));
        metadata.add(BlobMetaEntry::Salt(salt));
        let (encrypted_key, iv, tag) = aes_gcm_encrypt(super_key, &derived_key)
            .context("In encrypt_with_password: Failed to encrypt new super key.")?;
        metadata.add(BlobMetaEntry::Iv(iv));
        metadata.add(BlobMetaEntry::AeadTag(tag));
        Ok((encrypted_key, metadata))
    }

    // Encrypt the given key blob with the user's super key, if the super key exists and the device
    // is unlocked. If the super key exists and the device is locked, or LSKF is not setup,
    // return error. Note that it is out of the scope of this function to check if super encryption
    // is required. Such check should be performed before calling this function.
    fn super_encrypt_on_key_init(
        &self,
        db: &mut KeystoreDB,
        legacy_migrator: &LegacyMigrator,
        user_id: UserId,
        key_blob: &[u8],
    ) -> Result<(Vec<u8>, BlobMetaData)> {
        match UserState::get(db, legacy_migrator, self, user_id)
            .context("In super_encrypt. Failed to get user state.")?
        {
            UserState::LskfUnlocked(super_key) => {
                Self::encrypt_with_aes_super_key(key_blob, &super_key)
                    .context("In super_encrypt_on_key_init. Failed to encrypt the key.")
            }
            UserState::LskfLocked => {
                Err(Error::Rc(ResponseCode::LOCKED)).context("In super_encrypt. Device is locked.")
            }
            UserState::Uninitialized => Err(Error::Rc(ResponseCode::UNINITIALIZED))
                .context("In super_encrypt. LSKF is not setup for the user."),
        }
    }

    //Helper function to encrypt a key with the given super key. Callers should select which super
    //key to be used. This is called when a key is super encrypted at its creation as well as at its
    //upgrade.
    fn encrypt_with_aes_super_key(
        key_blob: &[u8],
        super_key: &SuperKey,
    ) -> Result<(Vec<u8>, BlobMetaData)> {
        if super_key.algorithm != SuperEncryptionAlgorithm::Aes256Gcm {
            return Err(Error::sys())
                .context("In encrypt_with_aes_super_key: unexpected algorithm");
        }
        let mut metadata = BlobMetaData::new();
        let (encrypted_key, iv, tag) = aes_gcm_encrypt(key_blob, &(super_key.key))
            .context("In encrypt_with_aes_super_key: Failed to encrypt new super key.")?;
        metadata.add(BlobMetaEntry::Iv(iv));
        metadata.add(BlobMetaEntry::AeadTag(tag));
        super_key.id.add_to_metadata(&mut metadata);
        Ok((encrypted_key, metadata))
    }

    /// Check if super encryption is required and if so, super-encrypt the key to be stored in
    /// the database.
    #[allow(clippy::clippy::too_many_arguments)]
    pub fn handle_super_encryption_on_key_init(
        &self,
        db: &mut KeystoreDB,
        legacy_migrator: &LegacyMigrator,
        domain: &Domain,
        key_parameters: &[KeyParameter],
        flags: Option<i32>,
        user_id: UserId,
        key_blob: &[u8],
    ) -> Result<(Vec<u8>, BlobMetaData)> {
        match Enforcements::super_encryption_required(domain, key_parameters, flags) {
            SuperEncryptionType::None => Ok((key_blob.to_vec(), BlobMetaData::new())),
            SuperEncryptionType::LskfBound => self
                .super_encrypt_on_key_init(db, legacy_migrator, user_id, &key_blob)
                .context(concat!(
                    "In handle_super_encryption_on_key_init. ",
                    "Failed to super encrypt with LskfBound key."
                )),
            SuperEncryptionType::ScreenLockBound => {
                let mut data = self.data.lock().unwrap();
                let entry = data.user_keys.entry(user_id).or_default();
                if let Some(super_key) = entry.screen_lock_bound.as_ref() {
                    Self::encrypt_with_aes_super_key(key_blob, &super_key).context(concat!(
                        "In handle_super_encryption_on_key_init. ",
                        "Failed to encrypt with ScreenLockBound key."
                    ))
                } else {
                    // Symmetric key is not available, use public key encryption
                    let loaded =
                        db.load_super_key(&USER_SCREEN_LOCK_BOUND_ECDH_KEY, user_id).context(
                            "In handle_super_encryption_on_key_init: load_super_key failed.",
                        )?;
                    let (key_id_guard, key_entry) = loaded.ok_or_else(Error::sys).context(
                        "In handle_super_encryption_on_key_init: User ECDH key missing.",
                    )?;
                    let public_key =
                        key_entry.metadata().sec1_public_key().ok_or_else(Error::sys).context(
                            "In handle_super_encryption_on_key_init: sec1_public_key missing.",
                        )?;
                    let mut metadata = BlobMetaData::new();
                    let (ephem_key, salt, iv, encrypted_key, aead_tag) =
                        ECDHPrivateKey::encrypt_message(public_key, key_blob).context(concat!(
                            "In handle_super_encryption_on_key_init: ",
                            "ECDHPrivateKey::encrypt_message failed."
                        ))?;
                    metadata.add(BlobMetaEntry::PublicKey(ephem_key));
                    metadata.add(BlobMetaEntry::Salt(salt));
                    metadata.add(BlobMetaEntry::Iv(iv));
                    metadata.add(BlobMetaEntry::AeadTag(aead_tag));
                    SuperKeyIdentifier::DatabaseId(key_id_guard.id())
                        .add_to_metadata(&mut metadata);
                    Ok((encrypted_key, metadata))
                }
            }
            SuperEncryptionType::BootLevel(level) => {
                let key_id = SuperKeyIdentifier::BootLevel(level);
                let super_key = self
                    .lookup_key(&key_id)
                    .context("In handle_super_encryption_on_key_init: lookup_key failed")?
                    .ok_or(Error::Rc(ResponseCode::LOCKED))
                    .context("In handle_super_encryption_on_key_init: Boot stage key absent")?;
                Self::encrypt_with_aes_super_key(key_blob, &super_key).context(concat!(
                    "In handle_super_encryption_on_key_init: ",
                    "Failed to encrypt with BootLevel key."
                ))
            }
        }
    }

    /// Check if a given key needs re-super-encryption, from its KeyBlob type.
    /// If so, re-super-encrypt the key and return a new set of metadata,
    /// containing the new super encryption information.
    pub fn reencrypt_if_required<'a>(
        key_blob_before_upgrade: &KeyBlob,
        key_after_upgrade: &'a [u8],
    ) -> Result<(KeyBlob<'a>, Option<BlobMetaData>)> {
        match key_blob_before_upgrade {
            KeyBlob::Sensitive { reencrypt_with: super_key, .. } => {
                let (key, metadata) =
                    Self::encrypt_with_aes_super_key(key_after_upgrade, super_key)
                        .context("In reencrypt_if_required: Failed to re-super-encrypt key.")?;
                Ok((KeyBlob::NonSensitive(key), Some(metadata)))
            }
            _ => Ok((KeyBlob::Ref(key_after_upgrade), None)),
        }
    }

    /// Fetch a superencryption key from the database, or create it if it doesn't already exist.
    /// When this is called, the caller must hold the lock on the SuperKeyManager.
    /// So it's OK that the check and creation are different DB transactions.
    fn get_or_create_super_key(
        db: &mut KeystoreDB,
        user_id: UserId,
        key_type: &SuperKeyType,
        password: &Password,
        reencrypt_with: Option<Arc<SuperKey>>,
    ) -> Result<Arc<SuperKey>> {
        let loaded_key = db.load_super_key(key_type, user_id)?;
        if let Some((_, key_entry)) = loaded_key {
            Ok(Self::extract_super_key_from_key_entry(
                key_type.algorithm,
                key_entry,
                password,
                reencrypt_with,
            )?)
        } else {
            let (super_key, public_key) = match key_type.algorithm {
                SuperEncryptionAlgorithm::Aes256Gcm => (
                    generate_aes256_key()
                        .context("In get_or_create_super_key: Failed to generate AES 256 key.")?,
                    None,
                ),
                SuperEncryptionAlgorithm::EcdhP256 => {
                    let key = ECDHPrivateKey::generate()
                        .context("In get_or_create_super_key: Failed to generate ECDH key")?;
                    (
                        key.private_key()
                            .context("In get_or_create_super_key: private_key failed")?,
                        Some(
                            key.public_key()
                                .context("In get_or_create_super_key: public_key failed")?,
                        ),
                    )
                }
            };
            //derive an AES256 key from the password and re-encrypt the super key
            //before we insert it in the database.
            let (encrypted_super_key, blob_metadata) =
                Self::encrypt_with_password(&super_key, password)
                    .context("In get_or_create_super_key.")?;
            let mut key_metadata = KeyMetaData::new();
            if let Some(pk) = public_key {
                key_metadata.add(KeyMetaEntry::Sec1PublicKey(pk));
            }
            let key_entry = db
                .store_super_key(
                    user_id,
                    key_type,
                    &encrypted_super_key,
                    &blob_metadata,
                    &key_metadata,
                )
                .context("In get_or_create_super_key. Failed to store super key.")?;
            Ok(Arc::new(SuperKey {
                algorithm: key_type.algorithm,
                key: super_key,
                id: SuperKeyIdentifier::DatabaseId(key_entry.id()),
                reencrypt_with,
            }))
        }
    }

    /// Decrypt the screen-lock bound keys for this user using the password and store in memory.
    pub fn unlock_screen_lock_bound_key(
        &self,
        db: &mut KeystoreDB,
        user_id: UserId,
        password: &Password,
    ) -> Result<()> {
        let mut data = self.data.lock().unwrap();
        let entry = data.user_keys.entry(user_id).or_default();
        let aes = entry
            .screen_lock_bound
            .get_or_try_to_insert_with(|| {
                Self::get_or_create_super_key(
                    db,
                    user_id,
                    &USER_SCREEN_LOCK_BOUND_KEY,
                    password,
                    None,
                )
            })?
            .clone();
        let ecdh = entry
            .screen_lock_bound_private
            .get_or_try_to_insert_with(|| {
                Self::get_or_create_super_key(
                    db,
                    user_id,
                    &USER_SCREEN_LOCK_BOUND_ECDH_KEY,
                    password,
                    Some(aes.clone()),
                )
            })?
            .clone();
        data.add_key_to_key_index(&aes)?;
        data.add_key_to_key_index(&ecdh)?;
        Ok(())
    }

    /// Wipe the screen-lock bound keys for this user from memory.
    pub fn lock_screen_lock_bound_key(&self, user_id: UserId) {
        let mut data = self.data.lock().unwrap();
        let mut entry = data.user_keys.entry(user_id).or_default();
        entry.screen_lock_bound = None;
        entry.screen_lock_bound_private = None;
    }
}

/// This enum represents different states of the user's life cycle in the device.
/// For now, only three states are defined. More states may be added later.
pub enum UserState {
    // The user has registered LSKF and has unlocked the device by entering PIN/Password,
    // and hence the per-boot super key is available in the cache.
    LskfUnlocked(Arc<SuperKey>),
    // The user has registered LSKF, but has not unlocked the device using password, after reboot.
    // Hence the per-boot super-key(s) is not available in the cache.
    // However, the encrypted super key is available in the database.
    LskfLocked,
    // There's no user in the device for the given user id, or the user with the user id has not
    // setup LSKF.
    Uninitialized,
}

impl UserState {
    pub fn get(
        db: &mut KeystoreDB,
        legacy_migrator: &LegacyMigrator,
        skm: &SuperKeyManager,
        user_id: UserId,
    ) -> Result<UserState> {
        match skm.get_per_boot_key_by_user_id(user_id) {
            Some(super_key) => Ok(UserState::LskfUnlocked(super_key)),
            None => {
                //Check if a super key exists in the database or legacy database.
                //If so, return locked user state.
                if SuperKeyManager::super_key_exists_in_db_for_user(db, legacy_migrator, user_id)
                    .context("In get.")?
                {
                    Ok(UserState::LskfLocked)
                } else {
                    Ok(UserState::Uninitialized)
                }
            }
        }
    }

    /// Queries user state when serving password change requests.
    pub fn get_with_password_changed(
        db: &mut KeystoreDB,
        legacy_migrator: &LegacyMigrator,
        skm: &SuperKeyManager,
        user_id: UserId,
        password: Option<&Password>,
    ) -> Result<UserState> {
        match skm.get_per_boot_key_by_user_id(user_id) {
            Some(super_key) => {
                if password.is_none() {
                    //transitioning to swiping, delete only the super key in database and cache, and
                    //super-encrypted keys in database (and in KM)
                    Self::reset_user(db, skm, legacy_migrator, user_id, true).context(
                        "In get_with_password_changed: Trying to delete keys from the db.",
                    )?;
                    //Lskf is now removed in Keystore
                    Ok(UserState::Uninitialized)
                } else {
                    //Keystore won't be notified when changing to a new password when LSKF is
                    //already setup. Therefore, ideally this path wouldn't be reached.
                    Ok(UserState::LskfUnlocked(super_key))
                }
            }
            None => {
                //Check if a super key exists in the database or legacy database.
                //If so, return LskfLocked state.
                //Otherwise, i) if the password is provided, initialize the super key and return
                //LskfUnlocked state ii) if password is not provided, return Uninitialized state.
                skm.check_and_initialize_super_key(db, legacy_migrator, user_id, password)
            }
        }
    }

    /// Queries user state when serving password unlock requests.
    pub fn get_with_password_unlock(
        db: &mut KeystoreDB,
        legacy_migrator: &LegacyMigrator,
        skm: &SuperKeyManager,
        user_id: UserId,
        password: &Password,
    ) -> Result<UserState> {
        match skm.get_per_boot_key_by_user_id(user_id) {
            Some(super_key) => {
                log::info!("In get_with_password_unlock. Trying to unlock when already unlocked.");
                Ok(UserState::LskfUnlocked(super_key))
            }
            None => {
                //Check if a super key exists in the database or legacy database.
                //If not, return Uninitialized state.
                //Otherwise, try to unlock the super key and if successful,
                //return LskfUnlocked state
                skm.check_and_unlock_super_key(db, legacy_migrator, user_id, password)
                    .context("In get_with_password_unlock. Failed to unlock super key.")
            }
        }
    }

    /// Delete all the keys created on behalf of the user.
    /// If 'keep_non_super_encrypted_keys' is set to true, delete only the super key and super
    /// encrypted keys.
    pub fn reset_user(
        db: &mut KeystoreDB,
        skm: &SuperKeyManager,
        legacy_migrator: &LegacyMigrator,
        user_id: UserId,
        keep_non_super_encrypted_keys: bool,
    ) -> Result<()> {
        // mark keys created on behalf of the user as unreferenced.
        legacy_migrator
            .bulk_delete_user(user_id, keep_non_super_encrypted_keys)
            .context("In reset_user: Trying to delete legacy keys.")?;
        db.unbind_keys_for_user(user_id, keep_non_super_encrypted_keys)
            .context("In reset user. Error in unbinding keys.")?;

        //delete super key in cache, if exists
        skm.forget_all_keys_for_user(user_id);
        Ok(())
    }
}

/// This enum represents three states a KeyMint Blob can be in, w.r.t super encryption.
/// `Sensitive` holds the non encrypted key and a reference to its super key.
/// `NonSensitive` holds a non encrypted key that is never supposed to be encrypted.
/// `Ref` holds a reference to a key blob when it does not need to be modified if its
/// life time allows it.
pub enum KeyBlob<'a> {
    Sensitive {
        key: ZVec,
        /// If KeyMint reports that the key must be upgraded, we must
        /// re-encrypt the key before writing to the database; we use
        /// this key.
        reencrypt_with: Arc<SuperKey>,
        /// If this key was decrypted with an ECDH key, we want to
        /// re-encrypt it on first use whether it was upgraded or not;
        /// this field indicates that that's necessary.
        force_reencrypt: bool,
    },
    NonSensitive(Vec<u8>),
    Ref(&'a [u8]),
}

impl<'a> KeyBlob<'a> {
    pub fn force_reencrypt(&self) -> bool {
        if let KeyBlob::Sensitive { force_reencrypt, .. } = self {
            *force_reencrypt
        } else {
            false
        }
    }
}

/// Deref returns a reference to the key material in any variant.
impl<'a> Deref for KeyBlob<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Sensitive { key, .. } => &key,
            Self::NonSensitive(key) => &key,
            Self::Ref(key) => key,
        }
    }
}
