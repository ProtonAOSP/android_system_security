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

#define LOG_TAG "Credential"

#include <android-base/logging.h>

#include <android/hardware/identity/support/IdentityCredentialSupport.h>

#include <android/security/identity/ICredentialStore.h>

#include <android/security/keystore/BnCredstoreTokenCallback.h>
#include <android/security/keystore/IKeystoreService.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <keymasterV4_0/keymaster_utils.h>

#include <cppbor.h>
#include <cppbor_parse.h>
#include <future>
#include <tuple>

#include "Credential.h"
#include "CredentialData.h"
#include "Util.h"

namespace android {
namespace security {
namespace identity {

using std::optional;
using std::promise;
using std::tuple;

using android::security::keystore::IKeystoreService;

using ::android::hardware::identity::support::ecKeyPairGetPkcs12;
using ::android::hardware::identity::support::ecKeyPairGetPrivateKey;
using ::android::hardware::identity::support::ecKeyPairGetPublicKey;
using ::android::hardware::identity::support::sha256;

using android::hardware::keymaster::V4_0::HardwareAuthToken;
using android::hardware::keymaster::V4_0::VerificationToken;
using AidlHardwareAuthToken = android::hardware::keymaster::HardwareAuthToken;
using AidlVerificationToken = android::hardware::keymaster::VerificationToken;

Credential::Credential(CipherSuite cipherSuite, const std::string& dataPath,
                       const std::string& credentialName)
    : cipherSuite_(cipherSuite), dataPath_(dataPath), credentialName_(credentialName) {}

Credential::~Credential() {}

Status Credential::loadCredential(sp<IIdentityCredentialStore> halStoreBinder) {
    uid_t callingUid = android::IPCThreadState::self()->getCallingUid();
    sp<CredentialData> data = new CredentialData(dataPath_, callingUid, credentialName_);
    if (!data->loadFromDisk()) {
        LOG(ERROR) << "Error loading data for credential";
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error loading data for credential");
    }

    data_ = data;

    sp<IIdentityCredential> halBinder;
    Status status =
        halStoreBinder->getCredential(cipherSuite_, data_->getCredentialData(), &halBinder);
    if (!status.isOk() && status.exceptionCode() == binder::Status::EX_SERVICE_SPECIFIC) {
        int code = status.serviceSpecificErrorCode();
        if (code == IIdentityCredentialStore::STATUS_CIPHER_SUITE_NOT_SUPPORTED) {
            return halStatusToError(status, ICredentialStore::ERROR_CIPHER_SUITE_NOT_SUPPORTED);
        }
    }
    if (!status.isOk()) {
        LOG(ERROR) << "Error getting HAL binder";
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC);
    }

    halBinder_ = halBinder;

    return Status::ok();
}

Status Credential::getCredentialKeyCertificateChain(std::vector<uint8_t>* _aidl_return) {
    *_aidl_return = data_->getAttestationCertificate();
    return Status::ok();
}

// Returns operation handle
Status Credential::selectAuthKey(bool allowUsingExhaustedKeys, int64_t* _aidl_return) {

    selectedAuthKey_ = data_->selectAuthKey(allowUsingExhaustedKeys);
    if (selectedAuthKey_ == nullptr) {
        return Status::fromServiceSpecificError(
            ICredentialStore::ERROR_NO_AUTHENTICATION_KEY_AVAILABLE,
            "No suitable authentication key available");
    }

    int64_t challenge;
    Status status = halBinder_->createAuthChallenge(&challenge);
    if (!status.isOk()) {
        return halStatusToGenericError(status);
    }
    if (challenge == 0) {
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Returned challenge is 0 (bug in HAL or TA)");
    }

    selectedChallenge_ = challenge;
    *_aidl_return = challenge;
    return Status::ok();
}

class CredstoreTokenCallback : public android::security::keystore::BnCredstoreTokenCallback,
                               public promise<tuple<bool, vector<uint8_t>, vector<uint8_t>>> {
  public:
    CredstoreTokenCallback() {}
    virtual Status onFinished(bool success, const vector<uint8_t>& authToken,
                              const vector<uint8_t>& verificationToken) override {
        this->set_value({success, authToken, verificationToken});
        return Status::ok();
    }
};

// Returns false if an error occurred communicating with keystore.
//
bool getTokensFromKeystore(uint64_t challenge, uint64_t secureUserId,
                           unsigned int authTokenMaxAgeMillis, vector<uint8_t>& authToken,
                           vector<uint8_t>& verificationToken) {
    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16("android.security.keystore"));
    sp<IKeystoreService> keystore = interface_cast<IKeystoreService>(binder);
    if (keystore == nullptr) {
        return false;
    }

    sp<CredstoreTokenCallback> callback = new CredstoreTokenCallback();
    auto future = callback->get_future();

    Status status =
        keystore->getTokensForCredstore(challenge, secureUserId, authTokenMaxAgeMillis, callback);
    if (!status.isOk()) {
        return false;
    }

    auto fstatus = future.wait_for(std::chrono::milliseconds(5000));
    if (fstatus != std::future_status::ready) {
        LOG(ERROR) << "Waited 5 seconds from tokens for credstore, aborting";
        return false;
    }
    auto [success, returnedAuthToken, returnedVerificationToken] = future.get();
    if (!success) {
        LOG(ERROR) << "Error getting tokens from credstore";
        return false;
    }
    authToken = returnedAuthToken;
    verificationToken = returnedVerificationToken;
    return true;
}

Status Credential::getEntries(const vector<uint8_t>& requestMessage,
                              const vector<RequestNamespaceParcel>& requestNamespaces,
                              const vector<uint8_t>& sessionTranscript,
                              const vector<uint8_t>& readerSignature, bool allowUsingExhaustedKeys,
                              GetEntriesResultParcel* _aidl_return) {
    GetEntriesResultParcel ret;

    // Calculate requestCounts ahead of time and be careful not to include
    // elements that don't exist.
    //
    // Also go through and figure out which access control profiles to include
    // in the startRetrieval() call.
    vector<int32_t> requestCounts;
    const vector<SecureAccessControlProfile>& allProfiles = data_->getSecureAccessControlProfiles();

    // We don't support ACP identifiers which isn't in the range 0 to 31. This
    // guarantee exists so it's feasible to implement the TA part of an Identity
    // Credential HAL implementation where the TA uses a 32-bit word to indicate
    // which profiles are authorized.
    for (const SecureAccessControlProfile& profile : allProfiles) {
        if (profile.id < 0 || profile.id >= 32) {
            return Status::fromServiceSpecificError(
                ICredentialStore::ERROR_GENERIC,
                "Invalid accessProfileId in profile (must be between 0 and 31)");
        }
    }

    vector<bool> includeProfile(32);

    for (const RequestNamespaceParcel& rns : requestNamespaces) {
        size_t numEntriesInNsToRequest = 0;
        for (const RequestEntryParcel& rep : rns.entries) {
            if (data_->hasEntryData(rns.namespaceName, rep.name)) {
                numEntriesInNsToRequest++;
            }

            optional<EntryData> data = data_->getEntryData(rns.namespaceName, rep.name);
            if (data) {
                for (int32_t id : data.value().accessControlProfileIds) {
                    if (id < 0 || id >= 32) {
                        LOG(ERROR) << "Invalid accessControlProfileId " << id << " for "
                                   << rns.namespaceName << ": " << rep.name;
                        return Status::fromServiceSpecificError(
                            ICredentialStore::ERROR_GENERIC,
                            "Invalid accessProfileId in entry (must be between 0 and 31)");
                    }
                    includeProfile[id] = true;
                }
            }
        }
        requestCounts.push_back(numEntriesInNsToRequest);
    }

    // Now that we know which profiles are needed, send only those to the
    // HAL.
    vector<SecureAccessControlProfile> selectedProfiles;
    for (size_t n = 0; n < allProfiles.size(); n++) {
        if (includeProfile[allProfiles[n].id]) {
            selectedProfiles.push_back(allProfiles[n]);
        }
    }

    // Calculate the highest [1] non-zero timeout and if user-auth is needed
    // ... we need this to select an appropriate authToken.
    //
    // [1] : Why do we request the highest timeout and not the lowest? Well, we
    //       return partial results in getEntries e.g. if some data elements
    //       fail to authorize we'll still return the ones that did not fail. So
    //       e.g. consider data elements A and B where A has an ACP with 60
    //       seconds and B has an ACP with 3600 seconds. In this case we'll be
    //       fine with getting an authToken for e.g. 2400 seconds which would
    //       mean returning only B.
    //
    bool userAuthNeeded = false;
    unsigned int authTokenMaxAgeMillis = 0;
    for (auto& profile : selectedProfiles) {
        if (profile.userAuthenticationRequired) {
            userAuthNeeded = true;
            if (profile.timeoutMillis > 0) {
                if (profile.timeoutMillis > authTokenMaxAgeMillis) {
                    authTokenMaxAgeMillis = profile.timeoutMillis;
                }
            }
        }
    }

    // If requesting a challenge-based authToken the idea is that authentication
    // happens as part of the transaction. As such, authTokenMaxAgeMillis should
    // be nearly zero. We'll use 10 seconds for this.
    if (userAuthNeeded && selectedChallenge_ != 0) {
        authTokenMaxAgeMillis = 10 * 1000;
    }

    // Reset tokens and only get them if they're actually needed, e.g. if user authentication
    // is needed in any of the access control profiles for data items being requested.
    //
    AidlHardwareAuthToken aidlAuthToken;
    AidlVerificationToken aidlVerificationToken;
    aidlAuthToken.challenge = 0;
    aidlAuthToken.userId = 0;
    aidlAuthToken.authenticatorId = 0;
    aidlAuthToken.authenticatorType =
        ::android::hardware::keymaster::HardwareAuthenticatorType::NONE;
    aidlAuthToken.timestamp.milliSeconds = 0;
    aidlAuthToken.mac.clear();
    aidlVerificationToken.challenge = 0;
    aidlVerificationToken.timestamp.milliSeconds = 0;
    aidlVerificationToken.securityLevel = ::android::hardware::keymaster::SecurityLevel::SOFTWARE;
    aidlVerificationToken.mac.clear();
    if (userAuthNeeded) {
        vector<uint8_t> authTokenBytes;
        vector<uint8_t> verificationTokenBytes;
        if (!getTokensFromKeystore(selectedChallenge_, data_->getSecureUserId(),
                                   authTokenMaxAgeMillis, authTokenBytes, verificationTokenBytes)) {
            LOG(ERROR) << "Error getting tokens from keystore";
            return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                    "Error getting tokens from keystore");
        }

        // It's entirely possible getTokensFromKeystore() succeeded but didn't
        // return any tokens (in which case the returned byte-vectors are
        // empty). For example, this can happen if no auth token is available
        // which satifies e.g. |authTokenMaxAgeMillis|.
        //
        if (authTokenBytes.size() > 0) {
            HardwareAuthToken authToken =
                android::hardware::keymaster::V4_0::support::hidlVec2AuthToken(authTokenBytes);
            // Convert from HIDL to AIDL...
            aidlAuthToken.challenge = int64_t(authToken.challenge);
            aidlAuthToken.userId = int64_t(authToken.userId);
            aidlAuthToken.authenticatorId = int64_t(authToken.authenticatorId);
            aidlAuthToken.authenticatorType =
                ::android::hardware::keymaster::HardwareAuthenticatorType(
                    int32_t(authToken.authenticatorType));
            aidlAuthToken.timestamp.milliSeconds = int64_t(authToken.timestamp);
            aidlAuthToken.mac = authToken.mac;
        }

        if (verificationTokenBytes.size() > 0) {
            optional<VerificationToken> token =
                android::hardware::keymaster::V4_0::support::deserializeVerificationToken(
                    verificationTokenBytes);
            if (!token) {
                LOG(ERROR) << "Error deserializing verification token";
                return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                        "Error deserializing verification token");
            }
            aidlVerificationToken.challenge = token->challenge;
            aidlVerificationToken.timestamp.milliSeconds = token->timestamp;
            aidlVerificationToken.securityLevel =
                ::android::hardware::keymaster::SecurityLevel(token->securityLevel);
            aidlVerificationToken.mac = token->mac;
        }
    }

    // Note that the selectAuthKey() method is only called if a CryptoObject is involved at
    // the Java layer. So we could end up with no previously selected auth key and we may
    // need one.
    const AuthKeyData* authKey = selectedAuthKey_;
    if (sessionTranscript.size() > 0) {
        if (authKey == nullptr) {
            authKey = data_->selectAuthKey(allowUsingExhaustedKeys);
            if (authKey == nullptr) {
                return Status::fromServiceSpecificError(
                    ICredentialStore::ERROR_NO_AUTHENTICATION_KEY_AVAILABLE,
                    "No suitable authentication key available");
            }
        }
    }
    vector<uint8_t> signingKeyBlob;
    if (authKey != nullptr) {
        signingKeyBlob = authKey->keyBlob;
    }

    // Pass the HAL enough information to allow calculating the size of
    // DeviceNameSpaces ahead of time.
    vector<RequestNamespace> halRequestNamespaces;
    for (const RequestNamespaceParcel& rns : requestNamespaces) {
        RequestNamespace ns;
        ns.namespaceName = rns.namespaceName;
        for (const RequestEntryParcel& rep : rns.entries) {
            optional<EntryData> entryData = data_->getEntryData(rns.namespaceName, rep.name);
            if (entryData) {
                RequestDataItem di;
                di.name = rep.name;
                di.size = entryData.value().size;
                di.accessControlProfileIds = entryData.value().accessControlProfileIds;
                ns.items.push_back(di);
            }
        }
        if (ns.items.size() > 0) {
            halRequestNamespaces.push_back(ns);
        }
    }
    // This is not catastrophic, we might be dealing with a version 1 implementation which
    // doesn't have this method.
    Status status = halBinder_->setRequestedNamespaces(halRequestNamespaces);
    if (!status.isOk()) {
        LOG(INFO) << "Failed setting expected requested namespaces, assuming V1 HAL "
                  << "and continuing";
    }

    // Pass the verification token. Failure is OK, this method isn't in the V1 HAL.
    status = halBinder_->setVerificationToken(aidlVerificationToken);
    if (!status.isOk()) {
        LOG(INFO) << "Failed setting verification token, assuming V1 HAL "
                  << "and continuing";
    }

    status =
        halBinder_->startRetrieval(selectedProfiles, aidlAuthToken, requestMessage, signingKeyBlob,
                                   sessionTranscript, readerSignature, requestCounts);
    if (!status.isOk() && status.exceptionCode() == binder::Status::EX_SERVICE_SPECIFIC) {
        int code = status.serviceSpecificErrorCode();
        if (code == IIdentityCredentialStore::STATUS_EPHEMERAL_PUBLIC_KEY_NOT_FOUND) {
            return halStatusToError(status, ICredentialStore::ERROR_EPHEMERAL_PUBLIC_KEY_NOT_FOUND);
        } else if (code == IIdentityCredentialStore::STATUS_READER_SIGNATURE_CHECK_FAILED) {
            return halStatusToError(status, ICredentialStore::ERROR_INVALID_READER_SIGNATURE);
        } else if (code == IIdentityCredentialStore::STATUS_INVALID_ITEMS_REQUEST_MESSAGE) {
            return halStatusToError(status, ICredentialStore::ERROR_INVALID_ITEMS_REQUEST_MESSAGE);
        } else if (code == IIdentityCredentialStore::STATUS_SESSION_TRANSCRIPT_MISMATCH) {
            return halStatusToError(status, ICredentialStore::ERROR_SESSION_TRANSCRIPT_MISMATCH);
        }
    }
    if (!status.isOk()) {
        return halStatusToGenericError(status);
    }

    for (const RequestNamespaceParcel& rns : requestNamespaces) {
        ResultNamespaceParcel resultNamespaceParcel;
        resultNamespaceParcel.namespaceName = rns.namespaceName;

        for (const RequestEntryParcel& rep : rns.entries) {
            ResultEntryParcel resultEntryParcel;
            resultEntryParcel.name = rep.name;

            optional<EntryData> data = data_->getEntryData(rns.namespaceName, rep.name);
            if (!data) {
                resultEntryParcel.status = STATUS_NO_SUCH_ENTRY;
                resultNamespaceParcel.entries.push_back(resultEntryParcel);
                continue;
            }

            status =
                halBinder_->startRetrieveEntryValue(rns.namespaceName, rep.name, data.value().size,
                                                    data.value().accessControlProfileIds);
            if (!status.isOk() && status.exceptionCode() == binder::Status::EX_SERVICE_SPECIFIC) {
                int code = status.serviceSpecificErrorCode();
                if (code == IIdentityCredentialStore::STATUS_USER_AUTHENTICATION_FAILED) {
                    resultEntryParcel.status = STATUS_USER_AUTHENTICATION_FAILED;
                    resultNamespaceParcel.entries.push_back(resultEntryParcel);
                    continue;
                } else if (code == IIdentityCredentialStore::STATUS_READER_AUTHENTICATION_FAILED) {
                    resultEntryParcel.status = STATUS_READER_AUTHENTICATION_FAILED;
                    resultNamespaceParcel.entries.push_back(resultEntryParcel);
                    continue;
                } else if (code == IIdentityCredentialStore::STATUS_NOT_IN_REQUEST_MESSAGE) {
                    resultEntryParcel.status = STATUS_NOT_IN_REQUEST_MESSAGE;
                    resultNamespaceParcel.entries.push_back(resultEntryParcel);
                    continue;
                } else if (code == IIdentityCredentialStore::STATUS_NO_ACCESS_CONTROL_PROFILES) {
                    resultEntryParcel.status = STATUS_NO_ACCESS_CONTROL_PROFILES;
                    resultNamespaceParcel.entries.push_back(resultEntryParcel);
                    continue;
                }
            }
            if (!status.isOk()) {
                return halStatusToGenericError(status);
            }

            vector<uint8_t> value;
            for (const auto& encryptedChunk : data.value().encryptedChunks) {
                vector<uint8_t> chunk;
                status = halBinder_->retrieveEntryValue(encryptedChunk, &chunk);
                if (!status.isOk()) {
                    return halStatusToGenericError(status);
                }
                value.insert(value.end(), chunk.begin(), chunk.end());
            }

            resultEntryParcel.status = STATUS_OK;
            resultEntryParcel.value = value;
            resultNamespaceParcel.entries.push_back(resultEntryParcel);
        }
        ret.resultNamespaces.push_back(resultNamespaceParcel);
    }

    status = halBinder_->finishRetrieval(&ret.mac, &ret.deviceNameSpaces);
    if (!status.isOk()) {
        return halStatusToGenericError(status);
    }
    if (authKey != nullptr) {
        ret.staticAuthenticationData = authKey->staticAuthenticationData;
    }

    // Ensure useCount is updated on disk.
    if (authKey != nullptr) {
        if (!data_->saveToDisk()) {
            return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                    "Error saving data");
        }
    }

    *_aidl_return = ret;
    return Status::ok();
}

Status Credential::deleteCredential(vector<uint8_t>* _aidl_return) {
    vector<uint8_t> proofOfDeletionSignature;
    Status status = halBinder_->deleteCredential(&proofOfDeletionSignature);
    if (!status.isOk()) {
        return halStatusToGenericError(status);
    }
    if (!data_->deleteCredential()) {
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error deleting credential data on disk");
    }
    *_aidl_return = proofOfDeletionSignature;
    return Status::ok();
}

Status Credential::createEphemeralKeyPair(vector<uint8_t>* _aidl_return) {
    vector<uint8_t> keyPair;
    Status status = halBinder_->createEphemeralKeyPair(&keyPair);
    if (!status.isOk()) {
        return halStatusToGenericError(status);
    }

    optional<vector<uint8_t>> pkcs12Bytes = ecKeyPairGetPkcs12(keyPair,
                                                               "ephemeralKey",  // Alias for key
                                                               "0",  // Serial, as a decimal number
                                                               "Credstore",      // Issuer
                                                               "Ephemeral Key",  // Subject
                                                               0,  // Validity Not Before
                                                               24 * 60 * 60);  // Validity Not After
    if (!pkcs12Bytes) {
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error creating PKCS#12 structure for key pair");
    }
    *_aidl_return = pkcs12Bytes.value();
    return Status::ok();
}

Status Credential::setReaderEphemeralPublicKey(const vector<uint8_t>& publicKey) {
    Status status = halBinder_->setReaderEphemeralPublicKey(publicKey);
    if (!status.isOk()) {
        return halStatusToGenericError(status);
    }
    return Status::ok();
}

Status Credential::setAvailableAuthenticationKeys(int32_t keyCount, int32_t maxUsesPerKey) {
    data_->setAvailableAuthenticationKeys(keyCount, maxUsesPerKey);
    if (!data_->saveToDisk()) {
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error saving data");
    }
    return Status::ok();
}

Status Credential::getAuthKeysNeedingCertification(vector<AuthKeyParcel>* _aidl_return) {
    optional<vector<vector<uint8_t>>> keysNeedingCert =
        data_->getAuthKeysNeedingCertification(halBinder_);
    if (!keysNeedingCert) {
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error getting auth keys neededing certification");
    }
    vector<AuthKeyParcel> authKeyParcels;
    for (const vector<uint8_t>& key : keysNeedingCert.value()) {
        AuthKeyParcel authKeyParcel;
        authKeyParcel.x509cert = key;
        authKeyParcels.push_back(authKeyParcel);
    }
    if (!data_->saveToDisk()) {
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error saving data");
    }
    *_aidl_return = authKeyParcels;
    return Status::ok();
}

Status Credential::storeStaticAuthenticationData(const AuthKeyParcel& authenticationKey,
                                                 const vector<uint8_t>& staticAuthData) {
    if (!data_->storeStaticAuthenticationData(authenticationKey.x509cert, staticAuthData)) {
        return Status::fromServiceSpecificError(
            ICredentialStore::ERROR_AUTHENTICATION_KEY_NOT_FOUND,
            "Error finding authentication key to store static "
            "authentication data for");
    }
    if (!data_->saveToDisk()) {
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error saving data");
    }
    return Status::ok();
}

Status Credential::getAuthenticationDataUsageCount(vector<int32_t>* _aidl_return) {
    const vector<AuthKeyData>& authKeyDatas = data_->getAuthKeyDatas();
    vector<int32_t> ret;
    for (const AuthKeyData& authKeyData : authKeyDatas) {
        ret.push_back(authKeyData.useCount);
    }
    *_aidl_return = ret;
    return Status::ok();
}

}  // namespace identity
}  // namespace security
}  // namespace android
