/*
 * Copyright (c) 2019, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "WritableCredential"

#include <android-base/logging.h>
#include <android/hardware/identity/support/IdentityCredentialSupport.h>
#include <android/security/identity/ICredentialStore.h>
#include <binder/IPCThreadState.h>
#include <cppbor.h>
#include <cppbor_parse.h>
#include <keystore/keystore_attestation_id.h>

#include "CredentialData.h"
#include "Util.h"
#include "WritableCredential.h"

namespace android {
namespace security {
namespace identity {

using ::std::pair;

using ::android::hardware::identity::SecureAccessControlProfile;

using ::android::hardware::identity::support::chunkVector;

WritableCredential::WritableCredential(const string& dataPath, const string& credentialName,
                                       const string& docType, size_t dataChunkSize,
                                       sp<IWritableIdentityCredential> halBinder)
    : dataPath_(dataPath), credentialName_(credentialName), docType_(docType),
      dataChunkSize_(dataChunkSize), halBinder_(halBinder) {}

WritableCredential::~WritableCredential() {}

Status WritableCredential::ensureAttestationCertificateExists(const vector<uint8_t>& challenge) {
    if (!attestationCertificate_.empty()) {
        return Status::ok();
    }

    const int32_t callingUid = IPCThreadState::self()->getCallingUid();
    auto asn1AttestationId = android::security::gather_attestation_application_id(callingUid);
    if (!asn1AttestationId.isOk()) {
        LOG(ERROR) << "Failed gathering AttestionApplicationId";
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Failed gathering AttestionApplicationId");
    }

    vector<Certificate> certificateChain;
    Status status = halBinder_->getAttestationCertificate(asn1AttestationId.value(), challenge,
                                                          &certificateChain);
    if (!status.isOk()) {
        LOG(ERROR) << "Error calling getAttestationCertificate()";
        return halStatusToGenericError(status);
    }

    vector<vector<uint8_t>> splitCerts;
    for (const auto& cert : certificateChain) {
        splitCerts.push_back(cert.encodedCertificate);
    }
    attestationCertificate_ =
        ::android::hardware::identity::support::certificateChainJoin(splitCerts);

    return Status::ok();
}

Status WritableCredential::getCredentialKeyCertificateChain(const vector<uint8_t>& challenge,
                                                            vector<uint8_t>* _aidl_return) {

    Status ensureStatus = ensureAttestationCertificateExists(challenge);
    if (!ensureStatus.isOk()) {
        return ensureStatus;
    }

    *_aidl_return = attestationCertificate_;
    return Status::ok();
}

ssize_t WritableCredential::calcExpectedProofOfProvisioningSize(
    const vector<AccessControlProfileParcel>& accessControlProfiles,
    const vector<EntryNamespaceParcel>& entryNamespaces) {

    // Right now, we calculate the size by simply just calculating the
    // CBOR. There's a little bit of overhead associated with this (as compared
    // to just adding up sizes) but it's a lot simpler and robust. In the future
    // if this turns out to be a problem, we can optimize it.
    //

    cppbor::Array acpArray;
    for (const AccessControlProfileParcel& profile : accessControlProfiles) {
        cppbor::Map map;
        map.add("id", profile.id);
        if (profile.readerCertificate.size() > 0) {
            map.add("readerCertificate", cppbor::Bstr(profile.readerCertificate));
        }
        if (profile.userAuthenticationRequired) {
            map.add("userAuthenticationRequired", profile.userAuthenticationRequired);
            map.add("timeoutMillis", profile.userAuthenticationTimeoutMillis);
        }
        acpArray.add(std::move(map));
    }

    cppbor::Map dataMap;
    for (const EntryNamespaceParcel& ensParcel : entryNamespaces) {
        cppbor::Array entriesArray;
        for (const EntryParcel& eParcel : ensParcel.entries) {
            // TODO: ideally do do this without parsing the data (but still validate data is valid
            // CBOR).
            auto [itemForValue, _, _2] = cppbor::parse(eParcel.value);
            if (itemForValue == nullptr) {
                return -1;
            }
            cppbor::Map entryMap;
            entryMap.add("name", eParcel.name);
            entryMap.add("value", std::move(itemForValue));
            cppbor::Array acpIdsArray;
            for (int32_t id : eParcel.accessControlProfileIds) {
                acpIdsArray.add(id);
            }
            entryMap.add("accessControlProfiles", std::move(acpIdsArray));
            entriesArray.add(std::move(entryMap));
        }
        dataMap.add(ensParcel.namespaceName, std::move(entriesArray));
    }

    cppbor::Array array;
    array.add("ProofOfProvisioning");
    array.add(docType_);
    array.add(std::move(acpArray));
    array.add(std::move(dataMap));
    array.add(false);  // testCredential
    return array.encode().size();
}

Status
WritableCredential::personalize(const vector<AccessControlProfileParcel>& accessControlProfiles,
                                const vector<EntryNamespaceParcel>& entryNamespaces,
                                int64_t secureUserId, vector<uint8_t>* _aidl_return) {
    Status ensureStatus = ensureAttestationCertificateExists({0x00});  // Challenge cannot be empty.
    if (!ensureStatus.isOk()) {
        return ensureStatus;
    }

    uid_t callingUid = android::IPCThreadState::self()->getCallingUid();
    CredentialData data = CredentialData(dataPath_, callingUid, credentialName_);

    // Note: The value 0 is used to convey that no user-authentication is needed for this
    // credential. This is to allow creating credentials w/o user authentication on devices
    // where Secure lock screen is not enabled.
    data.setSecureUserId(secureUserId);

    data.setAttestationCertificate(attestationCertificate_);

    vector<int32_t> entryCounts;
    for (const EntryNamespaceParcel& ensParcel : entryNamespaces) {
        entryCounts.push_back(ensParcel.entries.size());
    }

    ssize_t expectedPoPSize =
        calcExpectedProofOfProvisioningSize(accessControlProfiles, entryNamespaces);
    if (expectedPoPSize < 0) {
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Data is not valid CBOR");
    }
    // This is not catastrophic, we might be dealing with a version 1 implementation which
    // doesn't have this method.
    Status status = halBinder_->setExpectedProofOfProvisioningSize(expectedPoPSize);
    if (!status.isOk()) {
        LOG(INFO) << "Failed setting expected ProofOfProvisioning size, assuming V1 HAL "
                  << "and continuing";
    }

    status = halBinder_->startPersonalization(accessControlProfiles.size(), entryCounts);
    if (!status.isOk()) {
        return halStatusToGenericError(status);
    }

    for (const AccessControlProfileParcel& acpParcel : accessControlProfiles) {
        Certificate certificate;
        certificate.encodedCertificate = acpParcel.readerCertificate;
        SecureAccessControlProfile profile;
        status = halBinder_->addAccessControlProfile(
            acpParcel.id, certificate, acpParcel.userAuthenticationRequired,
            acpParcel.userAuthenticationTimeoutMillis, secureUserId, &profile);
        if (!status.isOk()) {
            return halStatusToGenericError(status);
        }
        data.addSecureAccessControlProfile(profile);
    }

    for (const EntryNamespaceParcel& ensParcel : entryNamespaces) {
        for (const EntryParcel& eParcel : ensParcel.entries) {
            vector<vector<uint8_t>> chunks = chunkVector(eParcel.value, dataChunkSize_);

            vector<int32_t> ids;
            std::copy(eParcel.accessControlProfileIds.begin(),
                      eParcel.accessControlProfileIds.end(), std::back_inserter(ids));

            status = halBinder_->beginAddEntry(ids, ensParcel.namespaceName, eParcel.name,
                                               eParcel.value.size());
            if (!status.isOk()) {
                return halStatusToGenericError(status);
            }

            vector<vector<uint8_t>> encryptedChunks;
            for (const auto& chunk : chunks) {
                vector<uint8_t> encryptedChunk;
                status = halBinder_->addEntryValue(chunk, &encryptedChunk);
                if (!status.isOk()) {
                    return halStatusToGenericError(status);
                }
                encryptedChunks.push_back(encryptedChunk);
            }
            EntryData eData;
            eData.size = eParcel.value.size();
            eData.accessControlProfileIds = std::move(ids);
            eData.encryptedChunks = std::move(encryptedChunks);
            data.addEntryData(ensParcel.namespaceName, eParcel.name, eData);
        }
    }

    vector<uint8_t> credentialData;
    vector<uint8_t> proofOfProvisioningSignature;
    status = halBinder_->finishAddingEntries(&credentialData, &proofOfProvisioningSignature);
    if (!status.isOk()) {
        return halStatusToGenericError(status);
    }
    data.setCredentialData(credentialData);

    if (!data.saveToDisk()) {
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error saving credential data to disk");
    }

    *_aidl_return = proofOfProvisioningSignature;
    return Status::ok();
}

}  // namespace identity
}  // namespace security
}  // namespace android
