/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.security.remoteprovisioning;

import android.hardware.security.keymint.SecurityLevel;
import android.security.remoteprovisioning.AttestationPoolStatus;

/**
 * `IRemoteProvisioning` is the interface provided to use the remote provisioning functionality
 * provided through KeyStore. The intent is for a higher level system component to use these
 * functions in order to drive the process through which the device can receive functioning
 * attestation certificates.
 *
 * ## Error conditions
 * Error conditions are reported as service specific errors.
 * Positive codes correspond to `android.security.remoteprovisioning.ResponseCode`
 * and indicate error conditions diagnosed by the Keystore 2.0 service.
 * TODO: Remote Provisioning HAL error code info
 *
 * `ResponseCode::PERMISSION_DENIED` if the caller does not have the permissions
 * to use the RemoteProvisioning API. This permission is defined under access_vectors in SEPolicy
 * in the keystore2 class: remotely_provision
 *
 * `ResponseCode::SYSTEM_ERROR` for any unexpected errors like IO or IPC failures.
 *
 * @hide
 */
interface IRemoteProvisioning {

    /**
     * Returns the status of the attestation key pool in the database.
     *
     * @param expiredBy The date as seconds since epoch by which to judge expiration status of
     *                        certificates.
     *
     * @param secLevel The security level to specify which KM instance to get the pool for.
     *
     * @return The `AttestationPoolStatus` parcelable contains fields communicating information
     *                        relevant to making decisions about when to generate and provision
     *                        more attestation keys.
     */
    AttestationPoolStatus getPoolStatus(in long expiredBy, in SecurityLevel secLevel);

    /**
     * This is the primary entry point for beginning a remote provisioning flow. The caller
     * specifies how many CSRs should be generated and provides an X25519 ECDH public key along
     * with a challenge to encrypt privacy sensitive portions of the returned CBOR blob and
     * guarantee freshness of the request to the certifying third party.
     *
     * ## Error conditions
     * `ResponseCode::NO_UNSIGNED_KEYS` if there are no unsigned keypairs in the database that can
     *                         be used for the CSRs.
     *
     * A RemoteProvisioning HAL response code may indicate backend errors such as failed EEK
     *                         verification.
     *
     * @param testMode Whether or not the TA implementing the Remote Provisioning HAL should accept
     *                         any EEK (Endpoint Encryption Key), or only one signed by a chain
     *                         that verifies back to the Root of Trust baked into the TA. True
     *                         means that any key is accepted.
     *
     * @param numCsr How many certificate signing requests should be generated.
     *
     * @param eek A chain of certificates terminating in an X25519 public key, the Endpoint
     *                         Encryption Key.
     *
     * @param challenge A challenge to be included and MACed in the returned CBOR blob.
     *
     * @param secLevel The security level to specify which KM instance from which to generate a
     *                         CSR.
     *
     * @return A CBOR blob composed of various encrypted/signed elements from the TA in a byte[]
     */
    byte[] generateCsr(in boolean testMode, in int numCsr, in byte[] eek, in byte[] challenge,
        in SecurityLevel secLevel);

    /**
     * This method provides a way for the returned attestation certificate chains to be provisioned
     * to the attestation key database. When an app requests an attesation key, it will be assigned
     * one of these certificate chains along with the corresponding private key.
     *
     * @param publicKey The raw public key encoded in the leaf certificate.
     *
     * @param cert An X.509, DER encoded certificate chain.
     *
     * @param expirationDate The expiration date on the certificate chain, provided by the caller
     *                          for convenience.
     *
     * @param secLevel The security level representing the KM instance containing the key that this
     *                          chain corresponds to.
     */
    void provisionCertChain(in byte[] publicKey, in byte[] certs, in long expirationDate,
        in SecurityLevel secLevel);

    /**
     * This method allows the caller to instruct KeyStore to generate and store a key pair to be
     * used for attestation in the `generateCsr` method. The caller should handle spacing out these
     * requests so as not to jam up the KeyStore work queue.
     *
     * @param is_test_mode Instructs the underlying HAL interface to mark the generated key with a
     *                        tag to indicate that it's for testing.
     *
     * @param secLevel The security level to specify which KM instance should generate a key pair.
     */
    void generateKeyPair(in boolean is_test_mode, in SecurityLevel secLevel);
}
