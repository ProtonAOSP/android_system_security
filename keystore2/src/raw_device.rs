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

//! Provide the [`KeyMintDevice`] wrapper for operating directly on a KeyMint device.

use crate::{
    database::{
        BlobMetaData, BlobMetaEntry, CertificateInfo, DateTime, KeyEntry, KeyEntryLoadBits,
        KeyIdGuard, KeyMetaData, KeyMetaEntry, KeyType, KeystoreDB, SubComponentType, Uuid,
    },
    error::{map_km_error, Error},
    globals::get_keymint_device,
    super_key::KeyBlob,
    utils::{key_characteristics_to_internal, watchdog as wd, Asp, AID_KEYSTORE},
};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    BeginResult::BeginResult, ErrorCode::ErrorCode, HardwareAuthToken::HardwareAuthToken,
    IKeyMintDevice::IKeyMintDevice, IKeyMintOperation::IKeyMintOperation,
    KeyCreationResult::KeyCreationResult, KeyParameter::KeyParameter, KeyPurpose::KeyPurpose,
    SecurityLevel::SecurityLevel,
};
use android_system_keystore2::aidl::android::system::keystore2::{
    Domain::Domain, KeyDescriptor::KeyDescriptor, ResponseCode::ResponseCode,
};
use anyhow::{Context, Result};
use binder::Strong;

/// Wrapper for operating directly on a KeyMint device.
/// These methods often mirror methods in [`crate::security_level`]. However
/// the functions in [`crate::security_level`] make assumptions that hold, and has side effects
/// that make sense, only if called by an external client through binder.
/// In addition we are trying to maintain a separation between interface services
/// so that the architecture is compatible with a future move to multiple thread pools.
/// So the simplest approach today is to write new implementations of them for internal use.
/// Because these methods run very early, we don't even try to cooperate with
/// the operation slot database; we assume there will be plenty of slots.
pub struct KeyMintDevice {
    asp: Asp,
    km_uuid: Uuid,
}

impl KeyMintDevice {
    /// Get a [`KeyMintDevice`] for the given [`SecurityLevel`]
    pub fn get(security_level: SecurityLevel) -> Result<KeyMintDevice> {
        let (asp, _hw_info, km_uuid) = get_keymint_device(&security_level)
            .context("In KeyMintDevice::get: get_keymint_device failed")?;
        Ok(KeyMintDevice { asp, km_uuid })
    }

    /// Create a KM key and store in the database.
    pub fn create_and_store_key<F>(
        &self,
        db: &mut KeystoreDB,
        key_desc: &KeyDescriptor,
        creator: F,
    ) -> Result<()>
    where
        F: FnOnce(Strong<dyn IKeyMintDevice>) -> Result<KeyCreationResult, binder::Status>,
    {
        let km_dev: Strong<dyn IKeyMintDevice> = self
            .asp
            .get_interface()
            .context("In create_and_store_key: Failed to get KeyMint device")?;
        let creation_result =
            map_km_error(creator(km_dev)).context("In create_and_store_key: creator failed")?;
        let key_parameters = key_characteristics_to_internal(creation_result.keyCharacteristics);

        let creation_date =
            DateTime::now().context("In create_and_store_key: DateTime::now() failed")?;

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
        .context("In create_and_store_key: store_new_key failed")?;
        Ok(())
    }

    /// Generate a KeyDescriptor for internal-use keys.
    pub fn internal_descriptor(alias: String) -> KeyDescriptor {
        KeyDescriptor {
            domain: Domain::APP,
            nspace: AID_KEYSTORE as i64,
            alias: Some(alias),
            blob: None,
        }
    }

    /// Look up an internal-use key in the database given a key descriptor.
    pub fn lookup_from_desc(
        db: &mut KeystoreDB,
        key_desc: &KeyDescriptor,
    ) -> Result<(KeyIdGuard, KeyEntry)> {
        db.load_key_entry(&key_desc, KeyType::Client, KeyEntryLoadBits::KM, AID_KEYSTORE, |_, _| {
            Ok(())
        })
        .context("In lookup_from_desc: load_key_entry failed")
    }

    /// Look up the key in the database, and return None if it is absent.
    pub fn not_found_is_none(
        lookup: Result<(KeyIdGuard, KeyEntry)>,
    ) -> Result<Option<(KeyIdGuard, KeyEntry)>> {
        match lookup {
            Ok(result) => Ok(Some(result)),
            Err(e) => match e.root_cause().downcast_ref::<Error>() {
                Some(&Error::Rc(ResponseCode::KEY_NOT_FOUND)) => Ok(None),
                _ => Err(e),
            },
        }
    }

    /// This does the lookup and store in separate transactions; caller must
    /// hold a lock before calling.
    pub fn lookup_or_generate_key(
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
        let lookup = Self::not_found_is_none(Self::lookup_from_desc(db, key_desc))
            .context("In lookup_or_generate_key: first lookup failed")?;
        if let Some(result) = lookup {
            Ok(result)
        } else {
            self.create_and_store_key(db, &key_desc, |km_dev| km_dev.generateKey(&params, None))
                .context("In lookup_or_generate_key: generate_and_store_key failed")?;
            Self::lookup_from_desc(db, key_desc)
                .context("In lookup_or_generate_key: second lookup failed")
        }
    }

    /// Call the passed closure; if it returns `KEY_REQUIRES_UPGRADE`, call upgradeKey, and
    /// write the upgraded key to the database.
    fn upgrade_keyblob_if_required_with<T, F>(
        &self,
        db: &mut KeystoreDB,
        km_dev: &Strong<dyn IKeyMintDevice>,
        key_id_guard: &KeyIdGuard,
        key_blob: &KeyBlob,
        f: F,
    ) -> Result<T>
    where
        F: Fn(&[u8]) -> Result<T, Error>,
    {
        match f(key_blob) {
            Err(Error::Km(ErrorCode::KEY_REQUIRES_UPGRADE)) => {
                let upgraded_blob = map_km_error({
                    let _wp = wd::watch_millis(
                        "In KeyMintDevice::upgrade_keyblob_if_required_with: calling upgradeKey.",
                        500,
                    );
                    km_dev.upgradeKey(key_blob, &[])
                })
                .context("In upgrade_keyblob_if_required_with: Upgrade failed")?;

                let mut new_blob_metadata = BlobMetaData::new();
                new_blob_metadata.add(BlobMetaEntry::KmUuid(self.km_uuid));

                db.set_blob(
                    key_id_guard,
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
    #[allow(clippy::too_many_arguments)]
    pub fn use_key_in_one_step(
        &self,
        db: &mut KeystoreDB,
        key_id_guard: &KeyIdGuard,
        key_entry: &KeyEntry,
        purpose: KeyPurpose,
        operation_parameters: &[KeyParameter],
        auth_token: Option<&HardwareAuthToken>,
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
                map_km_error({
                    let _wp = wd::watch_millis("In use_key_in_one_step: calling: begin", 500);
                    km_dev.begin(purpose, blob, operation_parameters, auth_token)
                })
            })
            .context("In use_key_in_one_step: Failed to begin operation.")?;
        let operation: Strong<dyn IKeyMintOperation> = begin_result
            .operation
            .ok_or_else(Error::sys)
            .context("In use_key_in_one_step: Operation missing")?;
        map_km_error({
            let _wp = wd::watch_millis("In use_key_in_one_step: calling: finish", 500);
            operation.finish(Some(input), None, None, None, None)
        })
        .context("In use_key_in_one_step: Failed to finish operation.")
    }
}
