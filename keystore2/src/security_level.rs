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

use android_hardware_keymint::aidl::android::hardware::keymint::{
    Algorithm::Algorithm, Certificate::Certificate as KmCertificate,
    IKeyMintDevice::IKeyMintDevice, KeyCharacteristics::KeyCharacteristics, KeyFormat::KeyFormat,
    KeyParameter::KeyParameter as KmParam, KeyPurpose::KeyPurpose, Tag::Tag,
};
use android_system_keystore2::aidl::android::system::keystore2::{
    AuthenticatorSpec::AuthenticatorSpec, AuthenticatorType::AuthenticatorType,
    CreateOperationResponse::CreateOperationResponse, Domain::Domain,
    IKeystoreOperation::IKeystoreOperation, IKeystoreSecurityLevel::BnKeystoreSecurityLevel,
    IKeystoreSecurityLevel::IKeystoreSecurityLevel, KeyDescriptor::KeyDescriptor,
    KeyMetadata::KeyMetadata, KeyParameter::KeyParameter, KeyParameters::KeyParameters,
    SecurityLevel::SecurityLevel,
};

use crate::error::{self, map_km_error, map_or_log_err, Error, ErrorCode};
use crate::globals::DB;
use crate::permission::KeyPerm;
use crate::utils::{check_key_permission, keyparam_km_to_ks, keyparam_ks_to_km, Asp};
use crate::{
    database::{KeyEntry, KeyEntryLoadBits, SubComponentType},
    operation::KeystoreOperation,
    operation::OperationDb,
};
use anyhow::{anyhow, Context, Result};
use binder::{IBinder, Interface, ThreadState};

/// Implementation of the IKeystoreSecurityLevel Interface.
pub struct KeystoreSecurityLevel {
    security_level: SecurityLevel,
    keymint: Asp,
    operation_db: OperationDb,
}

static KEYMINT_SERVICE_NAME: &str = "android.hardware.keymint.IKeyMintDevice";

// Blob of 32 zeroes used as empty masking key.
static ZERO_BLOB_32: &[u8] = &[0; 32];

impl KeystoreSecurityLevel {
    /// Creates a new security level instance wrapped in a
    /// BnKeystoreSecurityLevel proxy object. It also
    /// calls `IBinder::set_requesting_sid` on the new interface, because
    /// we need it for checking keystore permissions.
    pub fn new_native_binder(
        security_level: SecurityLevel,
    ) -> Result<impl IKeystoreSecurityLevel + Send> {
        let service_name = format!("{}/default", KEYMINT_SERVICE_NAME);
        let keymint: Box<dyn IKeyMintDevice> =
            binder::get_interface(&service_name).map_err(|e| {
                anyhow!(format!(
                    "Could not get KeyMint instance: {} failed with error code {:?}",
                    service_name, e
                ))
            })?;

        let result = BnKeystoreSecurityLevel::new_binder(Self {
            security_level,
            keymint: Asp::new(keymint.as_binder()),
            operation_db: OperationDb::new(),
        });
        result.as_binder().set_requesting_sid(true);
        Ok(result)
    }

    fn store_new_key(
        &self,
        key: KeyDescriptor,
        km_cert_chain: Option<Vec<KmCertificate>>,
        blob: Vec<u8>,
    ) -> Result<KeyMetadata> {
        let (cert, cert_chain): (Option<Vec<u8>>, Option<Vec<u8>>) = match km_cert_chain {
            Some(mut chain) => (
                match chain.len() {
                    0 => None,
                    _ => Some(chain.remove(0).encodedCertificate),
                },
                match chain.len() {
                    0 => None,
                    _ => Some(
                        chain
                            .iter()
                            .map(|c| c.encodedCertificate.iter())
                            .flatten()
                            .copied()
                            .collect(),
                    ),
                },
            ),
            None => (None, None),
        };

        let key = match key.domain {
            Domain::BLOB => {
                KeyDescriptor { domain: Domain::BLOB, blob: Some(blob), ..Default::default() }
            }
            _ => DB
                .with(|db| {
                    let mut db = db.borrow_mut();
                    let key_id = db
                        .create_key_entry(key.domain, key.nspace)
                        .context("Trying to create a key entry.")?;
                    db.insert_blob(key_id, SubComponentType::KM_BLOB, &blob, self.security_level)
                        .context("Trying to insert km blob.")?;
                    if let Some(c) = &cert {
                        db.insert_blob(key_id, SubComponentType::CERT, c, self.security_level)
                            .context("Trying to insert cert blob.")?;
                    }
                    if let Some(c) = &cert_chain {
                        db.insert_blob(
                            key_id,
                            SubComponentType::CERT_CHAIN,
                            c,
                            self.security_level,
                        )
                        .context("Trying to insert cert chain blob.")?;
                    }
                    match &key.alias {
                        Some(alias) => db
                            .rebind_alias(key_id, alias, key.domain, key.nspace)
                            .context("Failed to rebind alias.")?,
                        None => {
                            return Err(error::Error::sys()).context(
                                "Alias must be specified. (This should have been checked earlier.)",
                            )
                        }
                    }
                    Ok(KeyDescriptor {
                        domain: Domain::KEY_ID,
                        nspace: key_id,
                        ..Default::default()
                    })
                })
                .context("In store_new_key.")?,
        };

        Ok(KeyMetadata {
            key,
            keySecurityLevel: self.security_level,
            certificate: cert,
            certificateChain: cert_chain,
            // TODO initialize the authorizations.
            ..Default::default()
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
        let (km_blob, key_id) = match key.domain {
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
                )
            }
            _ => {
                let mut key_entry = DB
                    .with::<_, Result<KeyEntry>>(|db| {
                        db.borrow_mut().load_key_entry(
                            key.clone(),
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
                (&scoping_blob, Some(key_entry.id()))
            }
        };

        // TODO Authorize begin operation.
        // Check if we need an authorization token.
        // Lookup authorization token and request VerificationToken if required.

        let purpose = operation_parameters.iter().find(|p| p.tag == Tag::PURPOSE.0).map_or(
            Err(Error::Km(ErrorCode::INVALID_ARGUMENT))
                .context("In create_operation: No operation purpose specified."),
            |kp| Ok(KeyPurpose(kp.integer)),
        )?;

        let km_params =
            operation_parameters.iter().map(|p| keyparam_ks_to_km(p)).collect::<Vec<KmParam>>();

        let km_dev: Box<dyn IKeyMintDevice> = self
            .keymint
            .get_interface()
            .context("In create_operation: Failed to get KeyMint device")?;

        let (begin_result, upgraded_blob) = loop {
            match map_km_error(km_dev.begin(purpose, &km_blob, &km_params, &Default::default())) {
                Ok(result) => break (result, None),
                Err(Error::Km(ErrorCode::TOO_MANY_OPERATIONS)) => {
                    self.operation_db
                        .prune(caller_uid)
                        .context("In create_operation: Outer loop.")?;
                    continue;
                }
                Err(Error::Km(ErrorCode::KEY_REQUIRES_UPGRADE)) => {
                    let upgraded_blob = map_km_error(km_dev.upgradeKey(&km_blob, &km_params))
                        .context("In create_operation: Upgrade failed.")?;
                    break loop {
                        match map_km_error(km_dev.begin(
                            purpose,
                            &upgraded_blob,
                            &km_params,
                            &Default::default(),
                        )) {
                            Ok(result) => break (result, Some(upgraded_blob)),
                            // If Keystore 2.0 is multi threaded another request may have
                            // snatched up our previously pruned operation slot. So we might
                            // need to prune again.
                            Err(Error::Km(ErrorCode::TOO_MANY_OPERATIONS)) => {
                                self.operation_db
                                    .prune(caller_uid)
                                    .context("In create_operation: Inner loop.")?;
                                continue;
                            }
                            Err(e) => {
                                return Err(e).context(
                                    "In create_operation: Begin operation failed after upgrade.",
                                )
                            }
                        }
                    };
                }
                Err(e) => return Err(e).context("In create_operation: Begin operation failed."),
            };
        };

        if let Some(upgraded_blob) = upgraded_blob {
            if let Some(key_id) = key_id {
                DB.with(|db| {
                    db.borrow_mut().insert_blob(
                        key_id,
                        SubComponentType::KM_BLOB,
                        &upgraded_blob,
                        self.security_level,
                    )
                })
                .context(
                    "In create_operation: Failed to insert upgraded blob into the database.",
                )?;
            }
        }

        let operation = match begin_result.operation {
            Some(km_op) => self.operation_db.create_operation(km_op, caller_uid),
            None => return Err(Error::sys()).context("In create_operation: Begin operation returned successfully, but did not return a valid operation."),
        };

        let op_binder: Box<dyn IKeystoreOperation> =
            KeystoreOperation::new_native_binder(operation)
                .as_binder()
                .into_interface()
                .context("In create_operation: Failed to create IKeystoreOperation.")?;

        // TODO we need to the enforcement module to determine if we need to return the challenge.
        // We return None for now because we don't support auth bound keys yet.
        Ok(CreateOperationResponse {
            iOperation: Some(op_binder),
            operationChallenge: None,
            parameters: match begin_result.params.len() {
                0 => None,
                _ => Some(KeyParameters {
                    keyParameter: begin_result
                        .params
                        .iter()
                        .map(|p| keyparam_km_to_ks(p))
                        .collect(),
                }),
            },
        })
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

        let key = match key.domain {
            Domain::APP => KeyDescriptor {
                domain: key.domain,
                nspace: ThreadState::get_calling_uid() as i64,
                alias: key.alias.clone(),
                blob: None,
            },
            _ => key.clone(),
        };

        // generate_key requires the rebind permission.
        check_key_permission(KeyPerm::rebind(), &key, &None).context("In generate_key.")?;

        let km_dev: Box<dyn IKeyMintDevice> = self.keymint.get_interface()?;
        map_km_error(km_dev.addRngEntropy(entropy))?;
        let mut blob: Vec<u8> = Default::default();
        let mut key_characteristics: KeyCharacteristics = Default::default();
        let mut certificate_chain: Vec<KmCertificate> = Default::default();
        map_km_error(km_dev.generateKey(
            &params.iter().map(|p| keyparam_ks_to_km(p)).collect::<Vec<KmParam>>(),
            &mut blob,
            &mut key_characteristics,
            &mut certificate_chain,
        ))?;

        self.store_new_key(key, Some(certificate_chain), blob).context("In generate_key.")
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

        let key = match key.domain {
            Domain::APP => KeyDescriptor {
                domain: key.domain,
                nspace: ThreadState::get_calling_uid() as i64,
                alias: key.alias.clone(),
                blob: None,
            },
            _ => key.clone(),
        };

        // import_key requires the rebind permission.
        check_key_permission(KeyPerm::rebind(), &key, &None).context("In import_key.")?;

        let mut blob: Vec<u8> = Default::default();
        let mut key_characteristics: KeyCharacteristics = Default::default();
        let mut certificate_chain: Vec<KmCertificate> = Default::default();

        let format = params
            .iter()
            .find(|p| p.tag == Tag::ALGORITHM.0)
            .ok_or(error::Error::Km(ErrorCode::INVALID_ARGUMENT))
            .context("No KeyParameter 'Algorithm'.")
            .and_then(|p| match Algorithm(p.integer) {
                Algorithm::AES | Algorithm::HMAC | Algorithm::TRIPLE_DES => Ok(KeyFormat::RAW),
                Algorithm::RSA | Algorithm::EC => Ok(KeyFormat::PKCS8),
                algorithm => Err(error::Error::Km(ErrorCode::INVALID_ARGUMENT))
                    .context(format!("Unknown Algorithm {:?}.", algorithm)),
            })
            .context("In import_key.")?;

        let km_dev: Box<dyn IKeyMintDevice> = self.keymint.get_interface()?;
        map_km_error(km_dev.importKey(
            &params.iter().map(|p| keyparam_ks_to_km(p)).collect::<Vec<KmParam>>(),
            format,
            key_data,
            &mut blob,
            &mut key_characteristics,
            &mut certificate_chain,
        ))?;

        self.store_new_key(key, Some(certificate_chain), blob).context("In import_key.")
    }

    fn import_wrapped_key(
        &self,
        key: &KeyDescriptor,
        wrapping_key: &KeyDescriptor,
        masking_key: Option<&[u8]>,
        params: &[KeyParameter],
        authenticators: &[AuthenticatorSpec],
    ) -> Result<KeyMetadata> {
        if key.domain != Domain::BLOB && key.alias.is_none() {
            return Err(error::Error::Km(ErrorCode::INVALID_ARGUMENT))
                .context("In import_wrapped_key: Alias must be specified.");
        }

        let wrapped_data = match &key.blob {
            Some(d) => d,
            None => {
                return Err(error::Error::Km(ErrorCode::INVALID_ARGUMENT)).context(
                    "In import_wrapped_key: Blob must be specified and hold wrapped key data.",
                )
            }
        };

        let key = match key.domain {
            Domain::APP => KeyDescriptor {
                domain: key.domain,
                nspace: ThreadState::get_calling_uid() as i64,
                alias: key.alias.clone(),
                blob: None,
            },
            _ => key.clone(),
        };

        // import_wrapped_key requires the rebind permission for the new key.
        check_key_permission(KeyPerm::rebind(), &key, &None).context("In import_wrapped_key.")?;

        let wrapping_key_entry = DB
            .with(|db| {
                db.borrow_mut().load_key_entry(
                    wrapping_key.clone(),
                    KeyEntryLoadBits::KM,
                    ThreadState::get_calling_uid(),
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

        let mut blob: Vec<u8> = Default::default();
        let mut key_characteristics: KeyCharacteristics = Default::default();
        // km_dev.importWrappedKey does not return a certificate chain.
        // TODO Do we assume that all wrapped keys are symmetric?
        // let certificate_chain: Vec<KmCertificate> = Default::default();

        let pw_sid = authenticators
            .iter()
            .find_map(|a| match a.authenticatorType {
                AuthenticatorType::PASSWORD => Some(a.authenticatorId),
                _ => None,
            })
            .ok_or(error::Error::Km(ErrorCode::INVALID_ARGUMENT))
            .context("A password authenticator SID must be specified.")?;

        let fp_sid = authenticators
            .iter()
            .find_map(|a| match a.authenticatorType {
                AuthenticatorType::FINGERPRINT => Some(a.authenticatorId),
                _ => None,
            })
            .ok_or(error::Error::Km(ErrorCode::INVALID_ARGUMENT))
            .context("A fingerprint authenticator SID must be specified.")?;

        let masking_key = masking_key.unwrap_or(ZERO_BLOB_32);

        let km_dev: Box<dyn IKeyMintDevice> = self.keymint.get_interface()?;
        map_km_error(km_dev.importWrappedKey(
            wrapped_data,
            wrapping_key_blob,
            masking_key,
            &params.iter().map(|p| keyparam_ks_to_km(p)).collect::<Vec<KmParam>>(),
            pw_sid,
            fp_sid,
            &mut blob,
            &mut key_characteristics,
        ))?;

        self.store_new_key(key, None, blob).context("In import_wrapped_key.")
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
