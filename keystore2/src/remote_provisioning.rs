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

use std::collections::HashMap;

use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    IRemotelyProvisionedComponent::IRemotelyProvisionedComponent, MacedPublicKey::MacedPublicKey,
    ProtectedData::ProtectedData, SecurityLevel::SecurityLevel,
};
use android_security_remoteprovisioning::aidl::android::security::remoteprovisioning::{
    AttestationPoolStatus::AttestationPoolStatus, IRemoteProvisioning::BnRemoteProvisioning,
    IRemoteProvisioning::IRemoteProvisioning,
};
use android_security_remoteprovisioning::binder::Strong;
use anyhow::{Context, Result};

use crate::error::{self, map_or_log_err, map_rem_prov_error};
use crate::globals::{get_keymint_device, get_remotely_provisioned_component, DB};
use crate::utils::Asp;

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
    pub fn generate_csr(
        &self,
        test_mode: bool,
        num_csr: i32,
        eek: &[u8],
        challenge: &[u8],
        sec_level: SecurityLevel,
        protected_data: &mut ProtectedData,
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
        let mut mac = Vec::<u8>::with_capacity(32);
        map_rem_prov_error(dev.generateCertificateRequest(
            test_mode,
            &keys_to_sign,
            eek,
            challenge,
            &mut mac,
            protected_data,
        ))
        .context("In generate_csr: Failed to generate csr")?;
        Ok(mac)
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
    ) -> binder::public_api::Result<Vec<u8>> {
        map_or_log_err(
            self.generate_csr(test_mode, num_csr, eek, challenge, sec_level, protected_data),
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
}
