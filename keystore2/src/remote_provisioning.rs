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

//! This is the implementation for the remote provisioning AIDL interface between
//! the network providers for remote provisioning and the system. This interface
//! allows the caller to prompt the Remote Provisioning HAL to generate keys and
//! CBOR blobs that can be ferried to a provisioning server that will return
//! certificate chains signed by some root authority and stored in a keystore SQLite
//! DB.

#![allow(clippy::from_over_into, clippy::needless_question_mark, clippy::vec_init_then_push)]

use std::collections::HashMap;

use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, AttestationKey::AttestationKey, Certificate::Certificate,
    DeviceInfo::DeviceInfo, IRemotelyProvisionedComponent::IRemotelyProvisionedComponent,
    KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue,
    MacedPublicKey::MacedPublicKey, ProtectedData::ProtectedData, SecurityLevel::SecurityLevel,
    Tag::Tag,
};
use android_security_remoteprovisioning::aidl::android::security::remoteprovisioning::{
    AttestationPoolStatus::AttestationPoolStatus, IRemoteProvisioning::BnRemoteProvisioning,
    IRemoteProvisioning::IRemoteProvisioning,
};
use android_security_remoteprovisioning::binder::Strong;
use android_system_keystore2::aidl::android::system::keystore2::{
    Domain::Domain, KeyDescriptor::KeyDescriptor,
};
use anyhow::{Context, Result};
use keystore2_crypto::parse_subject_from_certificate;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::database::{CertificateChain, KeystoreDB, Uuid};
use crate::error::{self, map_or_log_err, map_rem_prov_error, Error};
use crate::globals::{get_keymint_device, get_remotely_provisioned_component, DB};
use crate::utils::Asp;

/// Contains helper functions to check if remote provisioning is enabled on the system and, if so,
/// to assign and retrieve attestation keys and certificate chains.
#[derive(Default)]
pub struct RemProvState {
    security_level: SecurityLevel,
    km_uuid: Uuid,
    is_hal_present: AtomicBool,
}

impl RemProvState {
    /// Creates a RemProvState struct.
    pub fn new(security_level: SecurityLevel, km_uuid: Uuid) -> Self {
        Self { security_level, km_uuid, is_hal_present: AtomicBool::new(true) }
    }

    /// Checks if remote provisioning is enabled and partially caches the result. On a hybrid system
    /// remote provisioning can flip from being disabled to enabled depending on responses from the
    /// server, so unfortunately caching the presence or absence of the HAL is not enough to fully
    /// make decisions about the state of remote provisioning during runtime.
    fn check_rem_prov_enabled(&self, db: &mut KeystoreDB) -> Result<bool> {
        if !self.is_hal_present.load(Ordering::Relaxed)
            || get_remotely_provisioned_component(&self.security_level).is_err()
        {
            self.is_hal_present.store(false, Ordering::Relaxed);
            return Ok(false);
        }
        // To check if remote provisioning is enabled on a system that supports both remote
        // provisioning and factory provisioned keys, we only need to check if there are any
        // keys at all generated to indicate if the app has gotten the signal to begin filling
        // the key pool from the server.
        let pool_status = db
            .get_attestation_pool_status(0 /* date */, &self.km_uuid)
            .context("In check_rem_prov_enabled: failed to get attestation pool status.")?;
        Ok(pool_status.total != 0)
    }

    /// Fetches a remote provisioning attestation key and certificate chain inside of the
    /// returned `CertificateChain` struct if one exists for the given caller_uid. If one has not
    /// been assigned, this function will assign it. If there are no signed attestation keys
    /// available to be assigned, it will return the ResponseCode `OUT_OF_KEYS`
    fn get_rem_prov_attest_key(
        &self,
        key: &KeyDescriptor,
        caller_uid: u32,
        db: &mut KeystoreDB,
    ) -> Result<Option<CertificateChain>> {
        match key.domain {
            Domain::APP => {
                // Attempt to get an Attestation Key once. If it fails, then the app doesn't
                // have a valid chain assigned to it. The helper function will return None after
                // attempting to assign a key. An error will be thrown if the pool is simply out
                // of usable keys. Then another attempt to fetch the just-assigned key will be
                // made. If this fails too, something is very wrong.
                self.get_rem_prov_attest_key_helper(key, caller_uid, db)
                    .context("In get_rem_prov_attest_key: Failed to get a key")?
                    .map_or_else(
                        || self.get_rem_prov_attest_key_helper(key, caller_uid, db),
                        |v| Ok(Some(v)),
                    )
                    .context(concat!(
                        "In get_rem_prov_attest_key: Failed to get a key after",
                        "attempting to assign one."
                    ))?
                    .map_or_else(
                        || {
                            Err(Error::sys()).context(concat!(
                                "In get_rem_prov_attest_key: Attempted to assign a ",
                                "key and failed silently. Something is very wrong."
                            ))
                        },
                        |cert_chain| Ok(Some(cert_chain)),
                    )
            }
            _ => Ok(None),
        }
    }

    /// Returns None if an AttestationKey fails to be assigned. Errors if no keys are available.
    fn get_rem_prov_attest_key_helper(
        &self,
        key: &KeyDescriptor,
        caller_uid: u32,
        db: &mut KeystoreDB,
    ) -> Result<Option<CertificateChain>> {
        let cert_chain = db
            .retrieve_attestation_key_and_cert_chain(key.domain, caller_uid as i64, &self.km_uuid)
            .context("In get_rem_prov_attest_key_helper: Failed to retrieve a key + cert chain")?;
        match cert_chain {
            Some(cert_chain) => Ok(Some(cert_chain)),
            // Either this app needs to be assigned a key, or the pool is empty. An error will
            // be thrown if there is no key available to assign. This will indicate that the app
            // should be nudged to provision more keys so keystore can retry.
            None => {
                db.assign_attestation_key(key.domain, caller_uid as i64, &self.km_uuid)
                    .context("In get_rem_prov_attest_key_helper: Failed to assign a key")?;
                Ok(None)
            }
        }
    }

    fn is_asymmetric_key(&self, params: &[KeyParameter]) -> bool {
        params.iter().any(|kp| {
            matches!(
                kp,
                KeyParameter {
                    tag: Tag::ALGORITHM,
                    value: KeyParameterValue::Algorithm(Algorithm::RSA)
                } | KeyParameter {
                    tag: Tag::ALGORITHM,
                    value: KeyParameterValue::Algorithm(Algorithm::EC)
                }
            )
        })
    }

    /// Checks to see (1) if the key in question should be attested to based on the algorithm and
    /// (2) if remote provisioning is present and enabled on the system. If these conditions are
    /// met, it makes an attempt to fetch the attestation key assigned to the `caller_uid`.
    ///
    /// It returns the ResponseCode `OUT_OF_KEYS` if there is not one key currently assigned to the
    /// `caller_uid` and there are none available to assign.
    pub fn get_remotely_provisioned_attestation_key_and_certs(
        &self,
        key: &KeyDescriptor,
        caller_uid: u32,
        params: &[KeyParameter],
        db: &mut KeystoreDB,
    ) -> Result<Option<(AttestationKey, Certificate)>> {
        if !self.is_asymmetric_key(params) || !self.check_rem_prov_enabled(db)? {
            // There is no remote provisioning component for this security level on the
            // device. Return None so the underlying KM instance knows to use its
            // factory provisioned key instead. Alternatively, it's not an asymmetric key
            // and therefore will not be attested.
            Ok(None)
        } else {
            match self.get_rem_prov_attest_key(&key, caller_uid, db).context(concat!(
                "In get_remote_provisioning_key_and_certs: Failed to get ",
                "attestation key"
            ))? {
                Some(cert_chain) => Ok(Some((
                    AttestationKey {
                        keyBlob: cert_chain.private_key.to_vec(),
                        attestKeyParams: vec![],
                        issuerSubjectName: parse_subject_from_certificate(&cert_chain.batch_cert)
                            .context(concat!(
                            "In get_remote_provisioning_key_and_certs: Failed to ",
                            "parse subject."
                        ))?,
                    },
                    Certificate { encodedCertificate: cert_chain.cert_chain },
                ))),
                None => Ok(None),
            }
        }
    }
}
/// Implementation of the IRemoteProvisioning service.
#[derive(Default)]
pub struct RemoteProvisioningService {
    device_by_sec_level: HashMap<SecurityLevel, Asp>,
}

impl RemoteProvisioningService {
    fn get_dev_by_sec_level(
        &self,
        sec_level: &SecurityLevel,
    ) -> Result<Strong<dyn IRemotelyProvisionedComponent>> {
        if let Some(dev) = self.device_by_sec_level.get(sec_level) {
            dev.get_interface().context("In get_dev_by_sec_level.")
        } else {
            Err(error::Error::sys()).context(concat!(
                "In get_dev_by_sec_level: Remote instance for requested security level",
                " not found."
            ))
        }
    }

    /// Creates a new instance of the remote provisioning service
    pub fn new_native_binder() -> Result<Strong<dyn IRemoteProvisioning>> {
        let mut result: Self = Default::default();
        let dev = get_remotely_provisioned_component(&SecurityLevel::TRUSTED_ENVIRONMENT)
            .context("In new_native_binder: Failed to get TEE Remote Provisioner instance.")?;
        result.device_by_sec_level.insert(SecurityLevel::TRUSTED_ENVIRONMENT, dev);
        if let Ok(dev) = get_remotely_provisioned_component(&SecurityLevel::STRONGBOX) {
            result.device_by_sec_level.insert(SecurityLevel::STRONGBOX, dev);
        }
        Ok(BnRemoteProvisioning::new_binder(result))
    }

    /// Populates the AttestationPoolStatus parcelable with information about how many
    /// certs will be expiring by the date provided in `expired_by` along with how many
    /// keys have not yet been assigned.
    pub fn get_pool_status(
        &self,
        expired_by: i64,
        sec_level: SecurityLevel,
    ) -> Result<AttestationPoolStatus> {
        let (_, _, uuid) = get_keymint_device(&sec_level)?;
        DB.with::<_, Result<AttestationPoolStatus>>(|db| {
            let mut db = db.borrow_mut();
            // delete_expired_attestation_keys is always safe to call, and will remove anything
            // older than the date at the time of calling. No work should be done on the
            // attestation keys unless the pool status is checked first, so this call should be
            // enough to routinely clean out expired keys.
            db.delete_expired_attestation_keys()?;
            Ok(db.get_attestation_pool_status(expired_by, &uuid)?)
        })
    }

    /// Generates a CBOR blob which will be assembled by the calling code into a larger
    /// CBOR blob intended for delivery to a provisioning serever. This blob will contain
    /// `num_csr` certificate signing requests for attestation keys generated in the TEE,
    /// along with a server provided `eek` and `challenge`. The endpoint encryption key will
    /// be used to encrypt the sensitive contents being transmitted to the server, and the
    /// challenge will ensure freshness. A `test_mode` flag will instruct the remote provisioning
    /// HAL if it is okay to accept EEKs that aren't signed by something that chains back to the
    /// baked in root of trust in the underlying IRemotelyProvisionedComponent instance.
    #[allow(clippy::too_many_arguments)]
    pub fn generate_csr(
        &self,
        test_mode: bool,
        num_csr: i32,
        eek: &[u8],
        challenge: &[u8],
        sec_level: SecurityLevel,
        protected_data: &mut ProtectedData,
        device_info: &mut DeviceInfo,
    ) -> Result<Vec<u8>> {
        let dev = self.get_dev_by_sec_level(&sec_level)?;
        let (_, _, uuid) = get_keymint_device(&sec_level)?;
        let keys_to_sign = DB.with::<_, Result<Vec<MacedPublicKey>>>(|db| {
            let mut db = db.borrow_mut();
            Ok(db
                .fetch_unsigned_attestation_keys(num_csr, &uuid)?
                .iter()
                .map(|key| MacedPublicKey { macedKey: key.to_vec() })
                .collect())
        })?;
        let mut mac = map_rem_prov_error(dev.generateCertificateRequest(
            test_mode,
            &keys_to_sign,
            eek,
            challenge,
            device_info,
            protected_data,
        ))
        .context("In generate_csr: Failed to generate csr")?;
        let mut cose_mac_0 = Vec::<u8>::new();
        // TODO(b/180392379): Replace this manual CBOR generation with the cbor-serde crate as well.
        //                    This generates an array consisting of the mac and the public key Maps.
        //                    Just generate the actual MacedPublicKeys structure when the crate is
        //                    available.
        cose_mac_0.push((0b100_00000 | (keys_to_sign.len() + 1)) as u8);
        cose_mac_0.push(0b010_11000); //push mac
        cose_mac_0.push(mac.len() as u8);
        cose_mac_0.append(&mut mac);
        for maced_public_key in keys_to_sign {
            if maced_public_key.macedKey.len() > 83 + 8 {
                cose_mac_0.extend_from_slice(&maced_public_key.macedKey[8..83 + 8]);
            }
        }
        Ok(cose_mac_0)
    }

    /// Provisions a certificate chain for a key whose CSR was included in generate_csr. The
    /// `public_key` is used to index into the SQL database in order to insert the `certs` blob
    /// which represents a PEM encoded X.509 certificate chain. The `expiration_date` is provided
    /// as a convenience from the caller to avoid having to parse the certificates semantically
    /// here.
    pub fn provision_cert_chain(
        &self,
        public_key: &[u8],
        batch_cert: &[u8],
        certs: &[u8],
        expiration_date: i64,
        sec_level: SecurityLevel,
    ) -> Result<()> {
        DB.with::<_, Result<()>>(|db| {
            let mut db = db.borrow_mut();
            let (_, _, uuid) = get_keymint_device(&sec_level)?;
            Ok(db.store_signed_attestation_certificate_chain(
                public_key,
                batch_cert,
                certs, /* DER encoded certificate chain */
                expiration_date,
                &uuid,
            )?)
        })
    }

    /// Submits a request to the Remote Provisioner HAL to generate a signing key pair.
    /// `is_test_mode` indicates whether or not the returned public key should be marked as being
    /// for testing in order to differentiate them from private keys. If the call is successful,
    /// the key pair is then added to the database.
    pub fn generate_key_pair(&self, is_test_mode: bool, sec_level: SecurityLevel) -> Result<()> {
        let (_, _, uuid) = get_keymint_device(&sec_level)?;
        let dev = self.get_dev_by_sec_level(&sec_level)?;
        let mut maced_key = MacedPublicKey { macedKey: Vec::new() };
        let priv_key =
            map_rem_prov_error(dev.generateEcdsaP256KeyPair(is_test_mode, &mut maced_key))
                .context("In generate_key_pair: Failed to generated ECDSA keypair.")?;
        // TODO(b/180392379): This is a brittle hack that relies on the consistent formatting of
        //                    the returned CBOR blob in order to extract the public key.
        let data = &maced_key.macedKey;
        if data.len() < 85 {
            return Err(error::Error::sys()).context(concat!(
                "In generate_key_pair: CBOR blob returned from",
                "RemotelyProvisionedComponent is definitely malformatted or empty."
            ));
        }
        let mut raw_key: Vec<u8> = vec![0; 64];
        raw_key[0..32].clone_from_slice(&data[18..18 + 32]);
        raw_key[32..64].clone_from_slice(&data[53..53 + 32]);
        DB.with::<_, Result<()>>(|db| {
            let mut db = db.borrow_mut();
            Ok(db.create_attestation_key_entry(&maced_key.macedKey, &raw_key, &priv_key, &uuid)?)
        })
    }

    /// Checks the security level of each available IRemotelyProvisionedComponent hal and returns
    /// all levels in an array to the caller.
    pub fn get_security_levels(&self) -> Result<Vec<SecurityLevel>> {
        Ok(self.device_by_sec_level.keys().cloned().collect())
    }

    /// Deletes all attestation keys generated by the IRemotelyProvisionedComponent from the device,
    /// regardless of what state of the attestation key lifecycle they were in.
    pub fn delete_all_keys(&self) -> Result<i64> {
        DB.with::<_, Result<i64>>(|db| {
            let mut db = db.borrow_mut();
            Ok(db.delete_all_attestation_keys()?)
        })
    }
}

impl binder::Interface for RemoteProvisioningService {}

// Implementation of IRemoteProvisioning. See AIDL spec at
// :aidl/android/security/remoteprovisioning/IRemoteProvisioning.aidl
impl IRemoteProvisioning for RemoteProvisioningService {
    fn getPoolStatus(
        &self,
        expired_by: i64,
        sec_level: SecurityLevel,
    ) -> binder::public_api::Result<AttestationPoolStatus> {
        map_or_log_err(self.get_pool_status(expired_by, sec_level), Ok)
    }

    fn generateCsr(
        &self,
        test_mode: bool,
        num_csr: i32,
        eek: &[u8],
        challenge: &[u8],
        sec_level: SecurityLevel,
        protected_data: &mut ProtectedData,
        device_info: &mut DeviceInfo,
    ) -> binder::public_api::Result<Vec<u8>> {
        map_or_log_err(
            self.generate_csr(
                test_mode,
                num_csr,
                eek,
                challenge,
                sec_level,
                protected_data,
                device_info,
            ),
            Ok,
        )
    }

    fn provisionCertChain(
        &self,
        public_key: &[u8],
        batch_cert: &[u8],
        certs: &[u8],
        expiration_date: i64,
        sec_level: SecurityLevel,
    ) -> binder::public_api::Result<()> {
        map_or_log_err(
            self.provision_cert_chain(public_key, batch_cert, certs, expiration_date, sec_level),
            Ok,
        )
    }

    fn generateKeyPair(
        &self,
        is_test_mode: bool,
        sec_level: SecurityLevel,
    ) -> binder::public_api::Result<()> {
        map_or_log_err(self.generate_key_pair(is_test_mode, sec_level), Ok)
    }

    fn getSecurityLevels(&self) -> binder::public_api::Result<Vec<SecurityLevel>> {
        map_or_log_err(self.get_security_levels(), Ok)
    }

    fn deleteAllKeys(&self) -> binder::public_api::Result<i64> {
        map_or_log_err(self.delete_all_keys(), Ok)
    }
}
