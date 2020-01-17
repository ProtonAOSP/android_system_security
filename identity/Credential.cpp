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

#include <android/security/keystore/IKeystoreService.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <keymasterV4_0/keymaster_utils.h>

#include <cppbor.h>
#include <cppbor_parse.h>

#include "Credential.h"
#include "CredentialData.h"
#include "Util.h"

namespace android {
namespace security {
namespace identity {

using std::optional;

using android::security::keystore::IKeystoreService;

using ::android::hardware::hidl_vec;

using ::android::hardware::identity::V1_0::Result;
using ::android::hardware::identity::V1_0::ResultCode;
using ::android::hardware::identity::V1_0::SecureAccessControlProfile;

using ::android::hardware::identity::support::ecKeyPairGetPkcs12;
using ::android::hardware::identity::support::ecKeyPairGetPrivateKey;
using ::android::hardware::identity::support::ecKeyPairGetPublicKey;
using ::android::hardware::identity::support::sha256;

using android::hardware::keymaster::V4_0::HardwareAuthToken;

Credential::Credential(const std::string& dataPath, const std::string& credentialName)
    : dataPath_(dataPath), credentialName_(credentialName) {}

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

    Result result;
    sp<IIdentityCredential> halBinder;
    halStoreBinder->getCredential(
        data_->getCredentialData(),
        [&](const Result& _result, const sp<IIdentityCredential>& _halBinder) {
            result = _result;
            halBinder = _halBinder;
        });
    if (result.code != ResultCode::OK) {
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

    Result result;
    uint64_t challenge;
    halBinder_->createAuthChallenge([&](const Result& _result, uint64_t _challenge) {
        result = _result;
        challenge = _challenge;
    });
    if (result.code != ResultCode::OK) {
        LOG(ERROR) << "createAuthChallenge() failed " << ((int)result.code) << ": "
                   << result.message;
        return halResultToGenericError(result);
    }
    if (challenge == 0) {
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Returned challenge is 0 (bug in HAL or TA)");
    }

    selectedChallenge_ = challenge;
    *_aidl_return = challenge;
    return Status::ok();
}

// Returns false if an error occurred communicating with keystore.
//
// Sets |authToken| to the empty vector if an auth token couldn't be obtained.
//
bool getAuthTokenFromKeystore(uint64_t challenge, uint64_t secureUserId,
                              unsigned int authTokenMaxAgeMillis, vector<uint8_t>& authToken) {
    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16("android.security.keystore"));
    sp<IKeystoreService> keystore = interface_cast<IKeystoreService>(binder);
    if (keystore == nullptr) {
        return false;
    }

    vector<uint8_t> returnedAuthToken;
    Status ret = keystore->getAuthTokenForCredstore(challenge, secureUserId, authTokenMaxAgeMillis,
                                                    &returnedAuthToken);
    if (!ret.isOk()) {
        return false;
    }
    authToken = returnedAuthToken;
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
    vector<uint16_t> requestCounts;
    const vector<SecureAccessControlProfile>& allProfiles = data_->getSecureAccessControlProfiles();
    vector<bool> includeProfile(allProfiles.size());
    for (const RequestNamespaceParcel& rns : requestNamespaces) {
        size_t numEntriesInNsToRequest = 0;
        for (const RequestEntryParcel& rep : rns.entries) {
            if (data_->hasEntryData(rns.namespaceName, rep.name)) {
                numEntriesInNsToRequest++;
            }

            optional<EntryData> data = data_->getEntryData(rns.namespaceName, rep.name);
            if (data) {
                for (uint16_t id : data.value().accessControlProfileIds) {
                    if (id >= includeProfile.size()) {
                        LOG(ERROR) << "Invalid accessControlProfileId " << id << " for "
                                   << rns.namespaceName << ": " << rep.name;
                        return Status::fromServiceSpecificError(
                            ICredentialStore::ERROR_GENERIC, "Invalid accessProfileId for entry");
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
        if (includeProfile[n]) {
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

    // Only get an authToken if it's actually needed.
    HardwareAuthToken authToken;
    if (userAuthNeeded) {
        vector<uint8_t> authTokenBytes;
        if (!getAuthTokenFromKeystore(selectedChallenge_, data_->getSecureUserId(),
                                      authTokenMaxAgeMillis, authTokenBytes)) {
            LOG(ERROR) << "Error getting auth token from keystore";
            return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                    "Error getting auth token from keystore");
        }
        if (authTokenBytes.size() > 0) {
            authToken =
                android::hardware::keymaster::V4_0::support::hidlVec2AuthToken(authTokenBytes);
        }
    }

    Result result;
    halBinder_->startRetrieval(selectedProfiles, authToken, requestMessage, sessionTranscript,
                               readerSignature, requestCounts,
                               [&](const Result& _result) { result = _result; });
    if (result.code == ResultCode::EPHEMERAL_PUBLIC_KEY_NOT_FOUND) {
        LOG(ERROR) << "startRetrieval() failed " << ((int)result.code) << ": " << result.message;
        return Status::fromServiceSpecificError(
            ICredentialStore::ERROR_EPHEMERAL_PUBLIC_KEY_NOT_FOUND, result.message.c_str());
    } else if (result.code == ResultCode::READER_SIGNATURE_CHECK_FAILED) {
        LOG(ERROR) << "startRetrieval() failed " << ((int)result.code) << ": " << result.message;
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_INVALID_READER_SIGNATURE,
                                                result.message.c_str());
    } else if (result.code == ResultCode::INVALID_ITEMS_REQUEST_MESSAGE) {
        LOG(ERROR) << "startRetrieval() failed " << ((int)result.code) << ": " << result.message;
        return Status::fromServiceSpecificError(
            ICredentialStore::ERROR_INVALID_ITEMS_REQUEST_MESSAGE, result.message.c_str());
    } else if (result.code == ResultCode::SESSION_TRANSCRIPT_MISMATCH) {
        LOG(ERROR) << "startRetrieval() failed " << ((int)result.code) << ": " << result.message;
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_SESSION_TRANSCRIPT_MISMATCH,
                                                result.message.c_str());
    } else if (result.code != ResultCode::OK) {
        LOG(ERROR) << "startRetrieval() failed " << ((int)result.code) << ": " << result.message;
        return halResultToGenericError(result);
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

            halBinder_->startRetrieveEntryValue(rns.namespaceName, rep.name, data.value().size,
                                                data.value().accessControlProfileIds,
                                                [&](const Result& _result) { result = _result; });
            if (result.code == ResultCode::USER_AUTHENTICATION_FAILED) {
                resultEntryParcel.status = STATUS_USER_AUTHENTICATION_FAILED;
                resultNamespaceParcel.entries.push_back(resultEntryParcel);
                continue;
            } else if (result.code == ResultCode::READER_AUTHENTICATION_FAILED) {
                resultEntryParcel.status = STATUS_READER_AUTHENTICATION_FAILED;
                resultNamespaceParcel.entries.push_back(resultEntryParcel);
                continue;
            } else if (result.code == ResultCode::NOT_IN_REQUEST_MESSAGE) {
                resultEntryParcel.status = STATUS_NOT_IN_REQUEST_MESSAGE;
                resultNamespaceParcel.entries.push_back(resultEntryParcel);
                continue;
            } else if (result.code == ResultCode::NO_ACCESS_CONTROL_PROFILES) {
                resultEntryParcel.status = STATUS_NO_ACCESS_CONTROL_PROFILES;
                resultNamespaceParcel.entries.push_back(resultEntryParcel);
                continue;
            } else if (result.code != ResultCode::OK) {
                LOG(ERROR) << "startRetrieveEntryValue() failed " << ((int)result.code) << ": "
                           << result.message;
                return halResultToGenericError(result);
            }

            vector<uint8_t> value;
            for (const auto& encryptedChunk : data.value().encryptedChunks) {
                halBinder_->retrieveEntryValue(
                    encryptedChunk, [&](const Result& _result, const hidl_vec<uint8_t>& chunk) {
                        result = _result;
                        value.insert(value.end(), chunk.begin(), chunk.end());
                    });
                if (result.code != ResultCode::OK) {
                    LOG(ERROR) << "retrieveEntryValue failed() " << ((int)result.code) << ": "
                               << result.message;
                    return halResultToGenericError(result);
                }
            }

            resultEntryParcel.status = STATUS_OK;
            resultEntryParcel.value = value;
            resultNamespaceParcel.entries.push_back(resultEntryParcel);
        }
        ret.resultNamespaces.push_back(resultNamespaceParcel);
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
    halBinder_->finishRetrieval(signingKeyBlob, [&](const Result& _result,
                                                    const hidl_vec<uint8_t>& _mac,
                                                    const hidl_vec<uint8_t>& _deviceNameSpaces) {
        result = _result;
        ret.mac = _mac;
        ret.deviceNameSpaces = _deviceNameSpaces;
        if (authKey != nullptr) {
            ret.staticAuthenticationData = authKey->staticAuthenticationData;
        }
    });
    if (result.code != ResultCode::OK) {
        LOG(ERROR) << "finishRetrieval failed() " << ((int)result.code) << ": " << result.message;
        return halResultToGenericError(result);
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
    Result result;
    halBinder_->deleteCredential(
        [&](const Result& _result, const hidl_vec<uint8_t>& _proofOfDeletionSignature) {
            result = _result;
            *_aidl_return = _proofOfDeletionSignature;
        });
    if (result.code != ResultCode::OK) {
        LOG(ERROR) << "deleteCredential failed() " << ((int)result.code) << ": " << result.message;
        return halResultToGenericError(result);
    }
    if (!data_->deleteCredential()) {
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error deleting credential data on disk");
    }
    return Status::ok();
}

Status Credential::createEphemeralKeyPair(vector<uint8_t>* _aidl_return) {
    Result result;

    vector<uint8_t> keyPair;
    halBinder_->createEphemeralKeyPair(
        [&](const Result& _result, const hidl_vec<uint8_t>& _keyPair) {
            result = _result;
            keyPair = _keyPair;
        });
    if (result.code != ResultCode::OK) {
        LOG(ERROR) << "createEphemeralKeyPair failed() " << ((int)result.code) << ": "
                   << result.message;
        return halResultToGenericError(result);
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
    Result result;
    halBinder_->setReaderEphemeralPublicKey(publicKey,
                                            [&](const Result& _result) { result = _result; });
    if (result.code != ResultCode::OK) {
        LOG(ERROR) << "setReaderEphemeralPublicKey failed() " << ((int)result.code) << ": "
                   << result.message;
        return halResultToGenericError(result);
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
