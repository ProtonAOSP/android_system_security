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

use android_hardware_security_keymint::aidl::android::hardware::security::keymint::SecurityLevel::SecurityLevel;

use android_security_remoteprovisioning::aidl::android::security::remoteprovisioning::{
    AttestationPoolStatus::AttestationPoolStatus, IRemoteProvisioning::BnRemoteProvisioning,
    IRemoteProvisioning::IRemoteProvisioning,
};
use anyhow::Result;

use crate::error::map_or_log_err;
use crate::globals::{get_keymint_device, DB};

/// Implementation of the IRemoteProvisioning service.
pub struct RemoteProvisioningService {
    // TODO(b/179222809): Add the remote provisioner hal aidl interface when available
}

impl RemoteProvisioningService {
    /// Creates a new instance of the remote provisioning service
    pub fn new_native_binder() -> Result<impl IRemoteProvisioning> {
        let result = BnRemoteProvisioning::new_binder(Self {});
        Ok(result)
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
        _test_mode: bool,
        _num_csr: i32,
        _eek: &[u8],
        _challenge: &[u8],
        _sec_level: SecurityLevel,
    ) -> Result<Vec<u8>> {
        // TODO(b/179222809): implement with actual remote provisioner AIDL when available. For now
        //       it isnice to have some junk values
        Ok(vec![0, 1, 3, 3])
    }

    /// Provisions a certificate chain for a key whose CSR was included in generate_csr. The
    /// `public_key` is used to index into the SQL database in order to insert the `certs` blob
    /// which represents a PEM encoded X.509 certificate chain. The `expiration_date` is provided
    /// as a convenience from the caller to avoid having to parse the certificates semantically
    /// here.
    pub fn provision_cert_chain(
        &self,
        public_key: &[u8],
        certs: &[u8],
        expiration_date: i64,
        sec_level: SecurityLevel,
    ) -> Result<()> {
        DB.with::<_, Result<()>>(|db| {
            let mut db = db.borrow_mut();
            let (_, _, uuid) = get_keymint_device(&sec_level)?;
            Ok(db.store_signed_attestation_certificate_chain(
                public_key,
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
    pub fn generate_key_pair(&self, _is_test_mode: bool, _sec_level: SecurityLevel) -> Result<()> {
        Ok(())
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
    ) -> binder::public_api::Result<Vec<u8>> {
        map_or_log_err(self.generate_csr(test_mode, num_csr, eek, challenge, sec_level), Ok)
    }

    fn provisionCertChain(
        &self,
        public_key: &[u8],
        certs: &[u8],
        expiration_date: i64,
        sec_level: SecurityLevel,
    ) -> binder::public_api::Result<()> {
        map_or_log_err(self.provision_cert_chain(public_key, certs, expiration_date, sec_level), Ok)
    }

    fn generateKeyPair(
        &self,
        is_test_mode: bool,
        sec_level: SecurityLevel,
    ) -> binder::public_api::Result<()> {
        map_or_log_err(self.generate_key_pair(is_test_mode, sec_level), Ok)
    }
}
