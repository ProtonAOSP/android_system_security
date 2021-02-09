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

#![allow(unused_variables)]

//! This crate implements the IKeystoreSecurityLevel interface.

use crate::{database::Uuid, gc::Gc, globals::get_keymint_device};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, HardwareAuthenticatorType::HardwareAuthenticatorType,
    IKeyMintDevice::IKeyMintDevice, KeyCreationResult::KeyCreationResult, KeyFormat::KeyFormat,
    KeyMintHardwareInfo::KeyMintHardwareInfo, KeyParameter::KeyParameter,
    KeyParameterValue::KeyParameterValue, SecurityLevel::SecurityLevel, Tag::Tag,
};
use android_system_keystore2::aidl::android::system::keystore2::{
    AuthenticatorSpec::AuthenticatorSpec, CreateOperationResponse::CreateOperationResponse,
    Domain::Domain, IKeystoreOperation::IKeystoreOperation,
    IKeystoreSecurityLevel::BnKeystoreSecurityLevel,
    IKeystoreSecurityLevel::IKeystoreSecurityLevel, KeyDescriptor::KeyDescriptor,
    KeyMetadata::KeyMetadata, KeyParameters::KeyParameters,
};

use crate::globals::ENFORCEMENTS;
use crate::key_parameter::KeyParameter as KsKeyParam;
use crate::key_parameter::KeyParameterValue as KsKeyParamValue;
use crate::utils::{check_key_permission, uid_to_android_user, Asp};
use crate::{
    database::{CertificateInfo, KeyIdGuard},
    globals::DB,
};
use crate::{
    database::{DateTime, KeyMetaData, KeyMetaEntry, KeyType},
    permission::KeyPerm,
};
use crate::{
    database::{KeyEntry, KeyEntryLoadBits, SubComponentType},
    operation::KeystoreOperation,
    operation::OperationDb,
};
use crate::{
    error::{self, map_km_error, map_or_log_err, Error, ErrorCode},
    utils::key_characteristics_to_internal,
};
use anyhow::{anyhow, Context, Result};
use binder::{IBinder, Interface, ThreadState};

/// Implementation of the IKeystoreSecurityLevel Interface.
pub struct KeystoreSecurityLevel {
    security_level: SecurityLevel,
    keymint: Asp,
    #[allow(dead_code)]
    hw_info: KeyMintHardwareInfo,
    km_uuid: Uuid,
    operation_db: OperationDb,
}

// Blob of 32 zeroes used as empty masking key.
static ZERO_BLOB_32: &[u8] = &[0; 32];

// Per RFC 5280 4.1.2.5, an undefined expiration (not-after) field should be set to GeneralizedTime
// 999912312359559, which is 253402300799000 ms from Jan 1, 1970.
const UNDEFINED_NOT_AFTER: i64 = 253402300799000i64;

impl KeystoreSecurityLevel {
    /// Creates a new security level instance wrapped in a
    /// BnKeystoreSecurityLevel proxy object. It also
    /// calls `IBinder::set_requesting_sid` on the new interface, because
    /// we need it for checking keystore permissions.
    pub fn new_native_binder(
        security_level: SecurityLevel,
    ) -> Result<(impl IKeystoreSecurityLevel + Send, Uuid)> {
        let (dev, hw_info, km_uuid) = get_keymint_device(&security_level)
            .context("In KeystoreSecurityLevel::new_native_binder.")?;
        let result = BnKeystoreSecurityLevel::new_binder(Self {
            security_level,
            keymint: dev,
            hw_info,
            km_uuid,
            operation_db: OperationDb::new(),
        });
        result.as_binder().set_requesting_sid(true);
        Ok((result, km_uuid))
    }

    fn store_new_key(
        &self,
        key: KeyDescriptor,
        creation_result: KeyCreationResult,
        user_id: u32,
    ) -> Result<KeyMetadata> {
        let KeyCreationResult {
            keyBlob: key_blob,
            keyCharacteristics: key_characteristics,
            certificateChain: mut certificate_chain,
        } = creation_result;

        let mut cert_info: CertificateInfo = CertificateInfo::new(
            match certificate_chain.len() {
                0 => None,
                _ => Some(certificate_chain.remove(0).encodedCertificate),
            },
            match certificate_chain.len() {
                0 => None,
                _ => Some(
                    certificate_chain
                        .iter()
                        .map(|c| c.encodedCertificate.iter())
                        .flatten()
                        .copied()
                        .collect(),
                ),
            },
        );

        let mut key_parameters = key_characteristics_to_internal(key_characteristics);

        key_parameters.push(KsKeyParam::new(
            KsKeyParamValue::UserID(user_id as i32),
            SecurityLevel::SOFTWARE,
        ));

        let creation_date = DateTime::now().context("Trying to make creation time.")?;

        let key = match key.domain {
            Domain::BLOB => {
                KeyDescriptor { domain: Domain::BLOB, blob: Some(key_blob), ..Default::default() }
            }
            _ => DB
                .with::<_, Result<KeyDescriptor>>(|db| {
                    let mut metadata = KeyMetaData::new();
                    metadata.add(KeyMetaEntry::CreationDate(creation_date));

                    let mut db = db.borrow_mut();
                    let (need_gc, key_id) = db
                        .store_new_key(
                            &key,
                            &key_parameters,
                            &key_blob,
                            &cert_info,
                            &metadata,
                            &self.km_uuid,
                        )
                        .context("In store_new_key.")?;
                    if need_gc {
                        Gc::notify_gc();
                    }
                    Ok(KeyDescriptor {
                        domain: Domain::KEY_ID,
                        nspace: key_id.id(),
                        ..Default::default()
                    })
                })
                .context("In store_new_key.")?,
        };

        Ok(KeyMetadata {
            key,
            keySecurityLevel: self.security_level,
            certificate: cert_info.take_cert(),
            certificateChain: cert_info.take_cert_chain(),
            authorizations: crate::utils::key_parameters_to_authorizations(key_parameters),
            modificationTimeMs: creation_date.to_millis_epoch(),
        })
    }

    fn create_operation(
        &self,
        key: &KeyDescriptor,
        operation_parameters: &[KeyParameter],
        forced: bool,
    ) -> Result<CreateOperationResponse> {
        let caller_uid = ThreadState::get_calling_uid();
        // We use `scoping_blob` to extend the life cycle of the blob loaded from the database,
        // so that we can use it by reference like the blob provided by the key descriptor.
        // Otherwise, we would have to clone the blob from the key descriptor.
        let scoping_blob: Vec<u8>;
        let (km_blob, key_properties, key_id_guard) = match key.domain {
            Domain::BLOB => {
                check_key_permission(KeyPerm::use_(), key, &None)
                    .context("In create_operation: checking use permission for Domain::BLOB.")?;
                (
                    match &key.blob {
                        Some(blob) => blob,
                        None => {
                            return Err(Error::sys()).context(concat!(
                                "In create_operation: Key blob must be specified when",
                                " using Domain::BLOB."
                            ))
                        }
                    },
                    None,
                    None,
                )
            }
            _ => {
                let (key_id_guard, mut key_entry) = DB
                    .with::<_, Result<(KeyIdGuard, KeyEntry)>>(|db| {
                        db.borrow_mut().load_key_entry(
                            &key,
                            KeyType::Client,
                            KeyEntryLoadBits::KM,
                            caller_uid,
                            |k, av| check_key_permission(KeyPerm::use_(), k, &av),
                        )
                    })
                    .context("In create_operation: Failed to load key blob.")?;
                scoping_blob = match key_entry.take_km_blob() {
                    Some(blob) => blob,
                    None => {
                        return Err(Error::sys()).context(concat!(
                            "In create_operation: Successfully loaded key entry,",
                            " but KM blob was missing."
                        ))
                    }
                };
                (
                    &scoping_blob,
                    Some((key_id_guard.id(), key_entry.into_key_parameters())),
                    Some(key_id_guard),
                )
            }
        };

        let purpose = operation_parameters.iter().find(|p| p.tag == Tag::PURPOSE).map_or(
            Err(Error::Km(ErrorCode::INVALID_ARGUMENT))
                .context("In create_operation: No operation purpose specified."),
            |kp| match kp.value {
                KeyParameterValue::KeyPurpose(p) => Ok(p),
                _ => Err(Error::Km(ErrorCode::INVALID_ARGUMENT))
                    .context("In create_operation: Malformed KeyParameter."),
            },
        )?;

        let (immediate_hat, mut auth_info) = ENFORCEMENTS
            .authorize_create(
                purpose,
                key_properties.as_ref(),
                operation_parameters.as_ref(),
                // TODO b/178222844 Replace this with the configuration returned by
                //      KeyMintDevice::getHardwareInfo.
                //      For now we assume that strongbox implementations need secure timestamps.
                self.security_level == SecurityLevel::STRONGBOX,
            )
            .context("In create_operation.")?;

        let immediate_hat = immediate_hat.unwrap_or_default();

        let km_dev: Box<dyn IKeyMintDevice> = self
            .keymint
            .get_interface()
            .context("In create_operation: Failed to get KeyMint device")?;

        let (begin_result, upgraded_blob) = self
            .upgrade_keyblob_if_required_with(
                &*km_dev,
                key_id_guard,
                &km_blob,
                &operation_parameters,
                |blob| loop {
                    match map_km_error(km_dev.begin(
                        purpose,
                        blob,
                        &operation_parameters,
                        &immediate_hat,
                    )) {
                        Err(Error::Km(ErrorCode::TOO_MANY_OPERATIONS)) => {
                            self.operation_db.prune(caller_uid)?;
                            continue;
                        }
                        v => return v,
                    }
                },
            )
            .context("In create_operation: Failed to begin operation.")?;

        let operation_challenge = auth_info.finalize_create_authorization(begin_result.challenge);

        let operation = match begin_result.operation {
            Some(km_op) => {
                self.operation_db.create_operation(km_op, caller_uid, auth_info)
            },
            None => return Err(Error::sys()).context("In create_operation: Begin operation returned successfully, but did not return a valid operation."),
        };

        let op_binder: Box<dyn IKeystoreOperation> =
            KeystoreOperation::new_native_binder(operation)
                .as_binder()
                .into_interface()
                .context("In create_operation: Failed to create IKeystoreOperation.")?;

        Ok(CreateOperationResponse {
            iOperation: Some(op_binder),
            operationChallenge: operation_challenge,
            parameters: match begin_result.params.len() {
                0 => None,
                _ => Some(KeyParameters { keyParameter: begin_result.params }),
            },
        })
    }

    fn add_certificate_parameters(
        uid: u32,
        params: &[KeyParameter],
        key: &KeyDescriptor,
    ) -> Result<Vec<KeyParameter>> {
        let mut result = params.to_vec();
        // If there is an attestation challenge we need to get an application id.
        if params.iter().any(|kp| kp.tag == Tag::ATTESTATION_CHALLENGE) {
            let aaid = keystore2_aaid::get_aaid(uid).map_err(|e| {
                anyhow!(format!("In add_certificate_parameters: get_aaid returned status {}.", e))
            })?;
            result.push(KeyParameter {
                tag: Tag::ATTESTATION_APPLICATION_ID,
                value: KeyParameterValue::Blob(aaid),
            });
        }

        if params.iter().any(|kp| kp.tag == Tag::INCLUDE_UNIQUE_ID) {
            check_key_permission(KeyPerm::gen_unique_id(), key, &None).context(concat!(
                "In add_certificate_parameters: ",
                "Caller does not have the permission for device unique attestation."
            ))?;
        }

        // If we are generating/importing an asymmetric key, we need to make sure
        // that NOT_BEFORE and NOT_AFTER are present.
        match params.iter().find(|kp| kp.tag == Tag::ALGORITHM) {
            Some(KeyParameter { tag: _, value: KeyParameterValue::Algorithm(Algorithm::RSA) })
            | Some(KeyParameter { tag: _, value: KeyParameterValue::Algorithm(Algorithm::EC) }) => {
                if !params.iter().any(|kp| kp.tag == Tag::CERTIFICATE_NOT_BEFORE) {
                    result.push(KeyParameter {
                        tag: Tag::CERTIFICATE_NOT_BEFORE,
                        value: KeyParameterValue::DateTime(0),
                    })
                }
                if !params.iter().any(|kp| kp.tag == Tag::CERTIFICATE_NOT_AFTER) {
                    result.push(KeyParameter {
                        tag: Tag::CERTIFICATE_NOT_AFTER,
                        value: KeyParameterValue::DateTime(UNDEFINED_NOT_AFTER),
                    })
                }
            }
            _ => {}
        }
        Ok(result)
    }

    fn generate_key(
        &self,
        key: &KeyDescriptor,
        attestation_key: Option<&KeyDescriptor>,
        params: &[KeyParameter],
        flags: i32,
        entropy: &[u8],
    ) -> Result<KeyMetadata> {
        if key.domain != Domain::BLOB && key.alias.is_none() {
            return Err(error::Error::Km(ErrorCode::INVALID_ARGUMENT))
                .context("In generate_key: Alias must be specified");
        }
        let caller_uid = ThreadState::get_calling_uid();

        let key = match key.domain {
            Domain::APP => KeyDescriptor {
                domain: key.domain,
                nspace: caller_uid as i64,
                alias: key.alias.clone(),
                blob: None,
            },
            _ => key.clone(),
        };

        // generate_key requires the rebind permission.
        check_key_permission(KeyPerm::rebind(), &key, &None).context("In generate_key.")?;

        let params = Self::add_certificate_parameters(caller_uid, params, &key)
            .context("In generate_key: Trying to get aaid.")?;

        let km_dev: Box<dyn IKeyMintDevice> = self.keymint.get_interface()?;
        map_km_error(km_dev.addRngEntropy(entropy))
            .context("In generate_key: Trying to add entropy.")?;
        let creation_result = map_km_error(km_dev.generateKey(&params))
            .context("In generate_key: While generating Key")?;

        let user_id = uid_to_android_user(caller_uid);
        self.store_new_key(key, creation_result, user_id).context("In generate_key.")
    }

    fn import_key(
        &self,
        key: &KeyDescriptor,
        attestation_key: Option<&KeyDescriptor>,
        params: &[KeyParameter],
        flags: i32,
        key_data: &[u8],
    ) -> Result<KeyMetadata> {
        if key.domain != Domain::BLOB && key.alias.is_none() {
            return Err(error::Error::Km(ErrorCode::INVALID_ARGUMENT))
                .context("In import_key: Alias must be specified");
        }
        let caller_uid = ThreadState::get_calling_uid();

        let key = match key.domain {
            Domain::APP => KeyDescriptor {
                domain: key.domain,
                nspace: caller_uid as i64,
                alias: key.alias.clone(),
                blob: None,
            },
            _ => key.clone(),
        };

        // import_key requires the rebind permission.
        check_key_permission(KeyPerm::rebind(), &key, &None).context("In import_key.")?;

        let params = Self::add_certificate_parameters(caller_uid, params, &key)
            .context("In import_key: Trying to get aaid.")?;

        let format = params
            .iter()
            .find(|p| p.tag == Tag::ALGORITHM)
            .ok_or(error::Error::Km(ErrorCode::INVALID_ARGUMENT))
            .context("No KeyParameter 'Algorithm'.")
            .and_then(|p| match &p.value {
                KeyParameterValue::Algorithm(Algorithm::AES)
                | KeyParameterValue::Algorithm(Algorithm::HMAC)
                | KeyParameterValue::Algorithm(Algorithm::TRIPLE_DES) => Ok(KeyFormat::RAW),
                KeyParameterValue::Algorithm(Algorithm::RSA)
                | KeyParameterValue::Algorithm(Algorithm::EC) => Ok(KeyFormat::PKCS8),
                v => Err(error::Error::Km(ErrorCode::INVALID_ARGUMENT))
                    .context(format!("Unknown Algorithm {:?}.", v)),
            })
            .context("In import_key.")?;

        let km_dev: Box<dyn IKeyMintDevice> =
            self.keymint.get_interface().context("In import_key: Trying to get the KM device")?;
        let creation_result = map_km_error(km_dev.importKey(&params, format, key_data))
            .context("In import_key: Trying to call importKey")?;

        let user_id = uid_to_android_user(caller_uid);
        self.store_new_key(key, creation_result, user_id).context("In import_key.")
    }

    fn import_wrapped_key(
        &self,
        key: &KeyDescriptor,
        wrapping_key: &KeyDescriptor,
        masking_key: Option<&[u8]>,
        params: &[KeyParameter],
        authenticators: &[AuthenticatorSpec],
    ) -> Result<KeyMetadata> {
        let wrapped_data: &[u8] = match key {
            KeyDescriptor { domain: Domain::APP, blob: Some(ref blob), alias: Some(_), .. }
            | KeyDescriptor {
                domain: Domain::SELINUX, blob: Some(ref blob), alias: Some(_), ..
            } => blob,
            _ => {
                return Err(error::Error::Km(ErrorCode::INVALID_ARGUMENT)).context(format!(
                    concat!(
                        "In import_wrapped_key: Alias and blob must be specified ",
                        "and domain must be APP or SELINUX. {:?}"
                    ),
                    key
                ))
            }
        };

        if wrapping_key.domain == Domain::BLOB {
            return Err(error::Error::Km(ErrorCode::INVALID_ARGUMENT)).context(
                "In import_wrapped_key: Import wrapped key not supported for self managed blobs.",
            );
        }

        let caller_uid = ThreadState::get_calling_uid();
        let key = match key.domain {
            Domain::APP => KeyDescriptor {
                domain: key.domain,
                nspace: caller_uid as i64,
                alias: key.alias.clone(),
                blob: None,
            },
            Domain::SELINUX => KeyDescriptor {
                domain: Domain::SELINUX,
                nspace: key.nspace,
                alias: key.alias.clone(),
                blob: None,
            },
            _ => panic!("Unreachable."),
        };

        // import_wrapped_key requires the rebind permission for the new key.
        check_key_permission(KeyPerm::rebind(), &key, &None).context("In import_wrapped_key.")?;

        let (wrapping_key_id_guard, wrapping_key_entry) = DB
            .with(|db| {
                db.borrow_mut().load_key_entry(
                    &wrapping_key,
                    KeyType::Client,
                    KeyEntryLoadBits::KM,
                    caller_uid,
                    |k, av| check_key_permission(KeyPerm::use_(), k, &av),
                )
            })
            .context("Failed to load wrapping key.")?;
        let wrapping_key_blob = match wrapping_key_entry.km_blob() {
            Some(blob) => blob,
            None => {
                return Err(error::Error::sys()).context(concat!(
                    "No km_blob after successfully loading key.",
                    " This should never happen."
                ))
            }
        };

        // km_dev.importWrappedKey does not return a certificate chain.
        // TODO Do we assume that all wrapped keys are symmetric?
        // let certificate_chain: Vec<KmCertificate> = Default::default();

        let pw_sid = authenticators
            .iter()
            .find_map(|a| match a.authenticatorType {
                HardwareAuthenticatorType::PASSWORD => Some(a.authenticatorId),
                _ => None,
            })
            .unwrap_or(-1);

        let fp_sid = authenticators
            .iter()
            .find_map(|a| match a.authenticatorType {
                HardwareAuthenticatorType::FINGERPRINT => Some(a.authenticatorId),
                _ => None,
            })
            .unwrap_or(-1);

        let masking_key = masking_key.unwrap_or(ZERO_BLOB_32);

        let km_dev: Box<dyn IKeyMintDevice> = self.keymint.get_interface()?;
        let (creation_result, _) = self
            .upgrade_keyblob_if_required_with(
                &*km_dev,
                Some(wrapping_key_id_guard),
                wrapping_key_blob,
                &[],
                |wrapping_blob| {
                    let creation_result = map_km_error(km_dev.importWrappedKey(
                        wrapped_data,
                        wrapping_key_blob,
                        masking_key,
                        &params,
                        pw_sid,
                        fp_sid,
                    ))?;
                    Ok(creation_result)
                },
            )
            .context("In import_wrapped_key.")?;

        let user_id = uid_to_android_user(caller_uid);
        self.store_new_key(key, creation_result, user_id)
            .context("In import_wrapped_key: Trying to store the new key.")
    }

    fn upgrade_keyblob_if_required_with<T, F>(
        &self,
        km_dev: &dyn IKeyMintDevice,
        key_id_guard: Option<KeyIdGuard>,
        blob: &[u8],
        params: &[KeyParameter],
        f: F,
    ) -> Result<(T, Option<Vec<u8>>)>
    where
        F: Fn(&[u8]) -> Result<T, Error>,
    {
        match f(blob) {
            Err(Error::Km(ErrorCode::KEY_REQUIRES_UPGRADE)) => {
                let upgraded_blob = map_km_error(km_dev.upgradeKey(blob, params))
                    .context("In upgrade_keyblob_if_required_with: Upgrade failed.")?;
                key_id_guard.map_or(Ok(()), |key_id_guard| {
                    DB.with(|db| {
                        db.borrow_mut().set_blob(
                            &key_id_guard,
                            SubComponentType::KEY_BLOB,
                            Some(&upgraded_blob),
                        )
                    })
                    .context(concat!(
                        "In upgrade_keyblob_if_required_with: ",
                        "Failed to insert upgraded blob into the database.",
                    ))
                })?;
                match f(&upgraded_blob) {
                    Ok(v) => Ok((v, Some(upgraded_blob))),
                    Err(e) => Err(e).context(concat!(
                        "In upgrade_keyblob_if_required_with: ",
                        "Failed to perform operation on second try."
                    )),
                }
            }
            Err(e) => {
                Err(e).context("In upgrade_keyblob_if_required_with: Failed perform operation.")
            }
            Ok(v) => Ok((v, None)),
        }
    }
}

impl binder::Interface for KeystoreSecurityLevel {}

impl IKeystoreSecurityLevel for KeystoreSecurityLevel {
    fn createOperation(
        &self,
        key: &KeyDescriptor,
        operation_parameters: &[KeyParameter],
        forced: bool,
    ) -> binder::public_api::Result<CreateOperationResponse> {
        map_or_log_err(self.create_operation(key, operation_parameters, forced), Ok)
    }
    fn generateKey(
        &self,
        key: &KeyDescriptor,
        attestation_key: Option<&KeyDescriptor>,
        params: &[KeyParameter],
        flags: i32,
        entropy: &[u8],
    ) -> binder::public_api::Result<KeyMetadata> {
        map_or_log_err(self.generate_key(key, attestation_key, params, flags, entropy), Ok)
    }
    fn importKey(
        &self,
        key: &KeyDescriptor,
        attestation_key: Option<&KeyDescriptor>,
        params: &[KeyParameter],
        flags: i32,
        key_data: &[u8],
    ) -> binder::public_api::Result<KeyMetadata> {
        map_or_log_err(self.import_key(key, attestation_key, params, flags, key_data), Ok)
    }
    fn importWrappedKey(
        &self,
        key: &KeyDescriptor,
        wrapping_key: &KeyDescriptor,
        masking_key: Option<&[u8]>,
        params: &[KeyParameter],
        authenticators: &[AuthenticatorSpec],
    ) -> binder::public_api::Result<KeyMetadata> {
        map_or_log_err(
            self.import_wrapped_key(key, wrapping_key, masking_key, params, authenticators),
            Ok,
        )
    }
}
