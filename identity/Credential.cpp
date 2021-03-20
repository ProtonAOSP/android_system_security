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
#include <android/binder_manager.h>
#include <android/hardware/identity/support/IdentityCredentialSupport.h>

#include <android/security/identity/ICredentialStore.h>

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <keymasterV4_0/keymaster_utils.h>

#include <cppbor.h>
#include <cppbor_parse.h>
#include <future>
#include <tuple>

#include <aidl/android/hardware/security/keymint/HardwareAuthToken.h>
#include <aidl/android/hardware/security/secureclock/TimeStampToken.h>
#include <aidl/android/security/authorization/AuthorizationTokens.h>
#include <aidl/android/security/authorization/IKeystoreAuthorization.h>

#include "Credential.h"
#include "CredentialData.h"
#include "Util.h"
#include "WritableCredential.h"

namespace android {
namespace security {
namespace identity {

using std::optional;
using std::promise;
using std::tuple;

using ::android::hardware::identity::IWritableIdentityCredential;

using ::android::hardware::identity::support::ecKeyPairGetPkcs12;
using ::android::hardware::identity::support::ecKeyPairGetPrivateKey;
using ::android::hardware::identity::support::ecKeyPairGetPublicKey;
using ::android::hardware::identity::support::sha256;

using android::hardware::keymaster::SecurityLevel;
using android::hardware::keymaster::V4_0::HardwareAuthToken;
using android::hardware::keymaster::V4_0::VerificationToken;
using AidlHardwareAuthToken = android::hardware::keymaster::HardwareAuthToken;
using AidlVerificationToken = android::hardware::keymaster::VerificationToken;

using KeyMintAuthToken = ::aidl::android::hardware::security::keymint::HardwareAuthToken;
using ::aidl::android::hardware::security::secureclock::TimeStampToken;
using ::aidl::android::security::authorization::AuthorizationTokens;
using ::aidl::android::security::authorization::IKeystoreAuthorization;

Credential::Credential(CipherSuite cipherSuite, const std::string& dataPath,
                       const std::string& credentialName, uid_t callingUid,
                       HardwareInformation hwInfo, sp<IIdentityCredentialStore> halStoreBinder,
                       int halApiVersion)
    : cipherSuite_(cipherSuite), dataPath_(dataPath), credentialName_(credentialName),
      callingUid_(callingUid), hwInfo_(std::move(hwInfo)), halStoreBinder_(halStoreBinder),
      halApiVersion_(halApiVersion) {}

Credential::~Credential() {}

Status Credential::ensureOrReplaceHalBinder() {
    sp<CredentialData> data = new CredentialData(dataPath_, callingUid_, credentialName_);
    if (!data->loadFromDisk()) {
        LOG(ERROR) << "Error loading data for credential";
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error loading data for credential");
    }

    sp<IIdentityCredential> halBinder;
    Status status =
        halStoreBinder_->getCredential(cipherSuite_, data->getCredentialData(), &halBinder);
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
    sp<CredentialData> data = new CredentialData(dataPath_, callingUid_, credentialName_);
    if (!data->loadFromDisk()) {
        LOG(ERROR) << "Error loading data for credential";
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error loading data for credential");
    }
    *_aidl_return = data->getAttestationCertificate();
    return Status::ok();
}

// Returns operation handle
Status Credential::selectAuthKey(bool allowUsingExhaustedKeys, bool allowUsingExpiredKeys,
                                 int64_t* _aidl_return) {
    sp<CredentialData> data = new CredentialData(dataPath_, callingUid_, credentialName_);
    if (!data->loadFromDisk()) {
        LOG(ERROR) << "Error loading data for credential";
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error loading data for credential");
    }

    // We just check if a key is available, we actually don't store it since we
    // don't keep CredentialData around between binder calls.
    const AuthKeyData* authKey =
        data->selectAuthKey(allowUsingExhaustedKeys, allowUsingExpiredKeys);
    if (authKey == nullptr) {
        return Status::fromServiceSpecificError(
            ICredentialStore::ERROR_NO_AUTHENTICATION_KEY_AVAILABLE,
            "No suitable authentication key available");
    }

    if (!ensureChallenge()) {
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error getting challenge (bug in HAL or TA)");
    }
    *_aidl_return = selectedChallenge_;
    return Status::ok();
}

bool Credential::ensureChallenge() {
    if (selectedChallenge_ != 0) {
        return true;
    }

    int64_t challenge;
    Status status = halBinder_->createAuthChallenge(&challenge);
    if (!status.isOk()) {
        LOG(ERROR) << "Error getting challenge: " << status.exceptionMessage();
        return false;
    }
    if (challenge == 0) {
        LOG(ERROR) << "Returned challenge is 0 (bug in HAL or TA)";
        return false;
    }

    selectedChallenge_ = challenge;
    return true;
}

// Returns false if an error occurred communicating with keystore.
//
bool getTokensFromKeystore2(uint64_t challenge, uint64_t secureUserId,
                            unsigned int authTokenMaxAgeMillis,
                            AidlHardwareAuthToken& aidlAuthToken,
                            AidlVerificationToken& aidlVerificationToken) {
    // try to connect to IKeystoreAuthorization AIDL service first.
    AIBinder* authzAIBinder = AServiceManager_checkService("android.security.authorization");
    ::ndk::SpAIBinder authzBinder(authzAIBinder);
    auto authzService = IKeystoreAuthorization::fromBinder(authzBinder);
    if (authzService) {
        AuthorizationTokens authzTokens;
        auto result = authzService->getAuthTokensForCredStore(challenge, secureUserId,
                                                              authTokenMaxAgeMillis, &authzTokens);
        // Convert KeyMint auth token to KeyMaster authtoken, only if tokens are
        // returned
        if (result.isOk()) {
            KeyMintAuthToken keymintAuthToken = authzTokens.authToken;
            aidlAuthToken.challenge = keymintAuthToken.challenge;
            aidlAuthToken.userId = keymintAuthToken.userId;
            aidlAuthToken.authenticatorId = keymintAuthToken.authenticatorId;
            aidlAuthToken.authenticatorType =
                ::android::hardware::keymaster::HardwareAuthenticatorType(
                    int32_t(keymintAuthToken.authenticatorType));
            aidlAuthToken.timestamp.milliSeconds = keymintAuthToken.timestamp.milliSeconds;
            aidlAuthToken.mac = keymintAuthToken.mac;

            // Convert timestamp token to KeyMaster verification token
            TimeStampToken timestampToken = authzTokens.timestampToken;
            aidlVerificationToken.challenge = timestampToken.challenge;
            aidlVerificationToken.timestamp.milliSeconds = timestampToken.timestamp.milliSeconds;
            // Legacy verification tokens were always minted by TEE.
            aidlVerificationToken.securityLevel = SecurityLevel::TRUSTED_ENVIRONMENT;
            aidlVerificationToken.mac = timestampToken.mac;
        } else {
            if (result.getServiceSpecificError() == 0) {
                // Here we differentiate the errors occurred during communication
                // from the service specific errors.
                LOG(ERROR) << "Error getting tokens from keystore2: " << result.getDescription();
                return false;
            } else {
                // Log the reason for not receiving auth tokens from keystore2.
                LOG(INFO) << "Auth tokens were not received due to: " << result.getDescription();
            }
        }
        return true;
    } else {
        LOG(ERROR) << "Error connecting to IKeystoreAuthorization service";
        return false;
    }
}

Status Credential::getEntries(const vector<uint8_t>& requestMessage,
                              const vector<RequestNamespaceParcel>& requestNamespaces,
                              const vector<uint8_t>& sessionTranscript,
                              const vector<uint8_t>& readerSignature, bool allowUsingExhaustedKeys,
                              bool allowUsingExpiredKeys, GetEntriesResultParcel* _aidl_return) {
    GetEntriesResultParcel ret;

    sp<CredentialData> data = new CredentialData(dataPath_, callingUid_, credentialName_);
    if (!data->loadFromDisk()) {
        LOG(ERROR) << "Error loading data for credential";
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error loading data for credential");
    }

    // Calculate requestCounts ahead of time and be careful not to include
    // elements that don't exist.
    //
    // Also go through and figure out which access control profiles to include
    // in the startRetrieval() call.
    vector<int32_t> requestCounts;
    const vector<SecureAccessControlProfile>& allProfiles = data->getSecureAccessControlProfiles();

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
            if (data->hasEntryData(rns.namespaceName, rep.name)) {
                numEntriesInNsToRequest++;
            }

            optional<EntryData> eData = data->getEntryData(rns.namespaceName, rep.name);
            if (eData) {
                for (int32_t id : eData.value().accessControlProfileIds) {
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
        // If user authentication is needed, always get a challenge from the
        // HAL/TA since it'll need it to check the returned VerificationToken
        // for freshness.
        if (!ensureChallenge()) {
            return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                    "Error getting challenge (bug in HAL or TA)");
        }

        // Note: if all selected profiles require auth-on-every-presentation
        // then authTokenMaxAgeMillis will be 0 (because timeoutMillis for each
        // profile is 0). Which means that keystore will only return an
        // AuthToken if its challenge matches what we pass, regardless of its
        // age. This is intended b/c the HAL/TA will check not care about
        // the age in this case, it only cares that the challenge matches.
        //
        // Otherwise, if one or more of the profiles is auth-with-a-timeout then
        // authTokenMaxAgeMillis will be set to the largest of those
        // timeouts. We'll get an AuthToken which satisfies this deadline if it
        // exists. This authToken _may_ have the requested challenge but it's
        // not a guarantee and it's also not required.
        //

        if (!getTokensFromKeystore2(selectedChallenge_, data->getSecureUserId(),
                                    authTokenMaxAgeMillis, aidlAuthToken, aidlVerificationToken)) {
            LOG(ERROR) << "Error getting tokens from keystore2";
            return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                    "Error getting tokens from keystore2");
        }
    }

    // Note that the selectAuthKey() method is only called if a CryptoObject is involved at
    // the Java layer. So we could end up with no previously selected auth key and we may
    // need one.
    //
    const AuthKeyData* authKey =
        data->selectAuthKey(allowUsingExhaustedKeys, allowUsingExpiredKeys);
    if (authKey == nullptr) {
        // If no authKey is available, consider it an error only when a
        // SessionTranscript was provided.
        //
        // We allow no SessionTranscript to be provided because it makes
        // the API simpler to deal with insofar it can be used without having
        // to generate any authentication keys.
        //
        // In this "no SessionTranscript is provided" mode we don't return
        // DeviceNameSpaces nor a MAC over DeviceAuthentication so we don't
        // need a device key.
        //
        if (sessionTranscript.size() > 0) {
            return Status::fromServiceSpecificError(
                ICredentialStore::ERROR_NO_AUTHENTICATION_KEY_AVAILABLE,
                "No suitable authentication key available and one is needed");
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
            optional<EntryData> entryData = data->getEntryData(rns.namespaceName, rep.name);
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

            optional<EntryData> eData = data->getEntryData(rns.namespaceName, rep.name);
            if (!eData) {
                resultEntryParcel.status = STATUS_NO_SUCH_ENTRY;
                resultNamespaceParcel.entries.push_back(resultEntryParcel);
                continue;
            }

            status =
                halBinder_->startRetrieveEntryValue(rns.namespaceName, rep.name, eData.value().size,
                                                    eData.value().accessControlProfileIds);
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
            for (const auto& encryptedChunk : eData.value().encryptedChunks) {
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
        if (!data->saveToDisk()) {
            return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                    "Error saving data");
        }
    }

    *_aidl_return = ret;
    return Status::ok();
}

Status Credential::deleteCredential(vector<uint8_t>* _aidl_return) {
    vector<uint8_t> proofOfDeletionSignature;

    sp<CredentialData> data = new CredentialData(dataPath_, callingUid_, credentialName_);
    if (!data->loadFromDisk()) {
        LOG(ERROR) << "Error loading data for credential";
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error loading data for credential");
    }

    Status status = halBinder_->deleteCredential(&proofOfDeletionSignature);
    if (!status.isOk()) {
        return halStatusToGenericError(status);
    }
    if (!data->deleteCredential()) {
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error deleting credential data on disk");
    }
    *_aidl_return = proofOfDeletionSignature;
    return Status::ok();
}

Status Credential::deleteWithChallenge(const vector<uint8_t>& challenge,
                                       vector<uint8_t>* _aidl_return) {
    if (halApiVersion_ < 3) {
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_NOT_SUPPORTED,
                                                "Not implemented by HAL");
    }
    vector<uint8_t> proofOfDeletionSignature;

    sp<CredentialData> data = new CredentialData(dataPath_, callingUid_, credentialName_);
    if (!data->loadFromDisk()) {
        LOG(ERROR) << "Error loading data for credential";
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error loading data for credential");
    }

    Status status = halBinder_->deleteCredentialWithChallenge(challenge, &proofOfDeletionSignature);
    if (!status.isOk()) {
        return halStatusToGenericError(status);
    }
    if (!data->deleteCredential()) {
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error deleting credential data on disk");
    }
    *_aidl_return = proofOfDeletionSignature;
    return Status::ok();
}

Status Credential::proveOwnership(const vector<uint8_t>& challenge, vector<uint8_t>* _aidl_return) {
    if (halApiVersion_ < 3) {
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_NOT_SUPPORTED,
                                                "Not implemented by HAL");
    }
    vector<uint8_t> proofOfOwnershipSignature;
    Status status = halBinder_->proveOwnership(challenge, &proofOfOwnershipSignature);
    if (!status.isOk()) {
        return halStatusToGenericError(status);
    }
    *_aidl_return = proofOfOwnershipSignature;
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
    sp<CredentialData> data = new CredentialData(dataPath_, callingUid_, credentialName_);
    if (!data->loadFromDisk()) {
        LOG(ERROR) << "Error loading data for credential";
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error loading data for credential");
    }
    data->setAvailableAuthenticationKeys(keyCount, maxUsesPerKey);
    if (!data->saveToDisk()) {
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error saving data");
    }
    return Status::ok();
}

Status Credential::getAuthKeysNeedingCertification(vector<AuthKeyParcel>* _aidl_return) {
    sp<CredentialData> data = new CredentialData(dataPath_, callingUid_, credentialName_);
    if (!data->loadFromDisk()) {
        LOG(ERROR) << "Error loading data for credential";
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error loading data for credential");
    }
    optional<vector<vector<uint8_t>>> keysNeedingCert =
        data->getAuthKeysNeedingCertification(halBinder_);
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
    if (!data->saveToDisk()) {
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error saving data");
    }
    *_aidl_return = authKeyParcels;
    return Status::ok();
}

Status Credential::storeStaticAuthenticationData(const AuthKeyParcel& authenticationKey,
                                                 const vector<uint8_t>& staticAuthData) {
    sp<CredentialData> data = new CredentialData(dataPath_, callingUid_, credentialName_);
    if (!data->loadFromDisk()) {
        LOG(ERROR) << "Error loading data for credential";
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error loading data for credential");
    }
    if (!data->storeStaticAuthenticationData(authenticationKey.x509cert,
                                             std::numeric_limits<int64_t>::max(), staticAuthData)) {
        return Status::fromServiceSpecificError(
            ICredentialStore::ERROR_AUTHENTICATION_KEY_NOT_FOUND,
            "Error finding authentication key to store static "
            "authentication data for");
    }
    if (!data->saveToDisk()) {
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error saving data");
    }
    return Status::ok();
}

Status
Credential::storeStaticAuthenticationDataWithExpiration(const AuthKeyParcel& authenticationKey,
                                                        int64_t expirationDateMillisSinceEpoch,
                                                        const vector<uint8_t>& staticAuthData) {
    if (halApiVersion_ < 3) {
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_NOT_SUPPORTED,
                                                "Not implemented by HAL");
    }
    sp<CredentialData> data = new CredentialData(dataPath_, callingUid_, credentialName_);
    if (!data->loadFromDisk()) {
        LOG(ERROR) << "Error loading data for credential";
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error loading data for credential");
    }
    if (!data->storeStaticAuthenticationData(authenticationKey.x509cert,
                                             expirationDateMillisSinceEpoch, staticAuthData)) {
        return Status::fromServiceSpecificError(
            ICredentialStore::ERROR_AUTHENTICATION_KEY_NOT_FOUND,
            "Error finding authentication key to store static "
            "authentication data for");
    }
    if (!data->saveToDisk()) {
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error saving data");
    }
    return Status::ok();
}

Status Credential::getAuthenticationDataUsageCount(vector<int32_t>* _aidl_return) {
    sp<CredentialData> data = new CredentialData(dataPath_, callingUid_, credentialName_);
    if (!data->loadFromDisk()) {
        LOG(ERROR) << "Error loading data for credential";
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error loading data for credential");
    }
    const vector<AuthKeyData>& authKeyDatas = data->getAuthKeyDatas();
    vector<int32_t> ret;
    for (const AuthKeyData& authKeyData : authKeyDatas) {
        ret.push_back(authKeyData.useCount);
    }
    *_aidl_return = ret;
    return Status::ok();
}

optional<string> extractDocType(const vector<uint8_t>& credentialData) {
    auto [item, _ /* newPos */, message] = cppbor::parse(credentialData);
    if (item == nullptr) {
        LOG(ERROR) << "CredentialData is not valid CBOR: " << message;
        return {};
    }
    const cppbor::Array* array = item->asArray();
    if (array == nullptr || array->size() < 1) {
        LOG(ERROR) << "CredentialData array with at least one element";
        return {};
    }
    const cppbor::Tstr* tstr = ((*array)[0])->asTstr();
    if (tstr == nullptr) {
        LOG(ERROR) << "First item in CredentialData is not a string";
        return {};
    }
    return tstr->value();
}

Status Credential::update(sp<IWritableCredential>* _aidl_return) {
    if (halApiVersion_ < 3) {
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_NOT_SUPPORTED,
                                                "Not implemented by HAL");
    }
    sp<CredentialData> data = new CredentialData(dataPath_, callingUid_, credentialName_);
    if (!data->loadFromDisk()) {
        LOG(ERROR) << "Error loading data for credential";
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Error loading data for credential");
    }

    sp<IWritableIdentityCredential> halWritableCredential;
    Status status = halBinder_->updateCredential(&halWritableCredential);
    if (!status.isOk()) {
        return halStatusToGenericError(status);
    }

    optional<string> docType = extractDocType(data->getCredentialData());
    if (!docType) {
        return Status::fromServiceSpecificError(ICredentialStore::ERROR_GENERIC,
                                                "Unable to extract DocType from CredentialData");
    }

    // NOTE: The caller is expected to call WritableCredential::personalize() which will
    // write brand new data to disk, specifically it will overwrite any data already
    // have _including_ authentication keys.
    //
    // It is because of this we need to set the CredentialKey certificate chain,
    // keyCount, and maxUsesPerKey below.
    sp<WritableCredential> writableCredential = new WritableCredential(
        dataPath_, credentialName_, docType.value(), true, hwInfo_, halWritableCredential);

    writableCredential->setAttestationCertificate(data->getAttestationCertificate());
    auto [keyCount, maxUsesPerKey] = data->getAvailableAuthenticationKeys();
    writableCredential->setAvailableAuthenticationKeys(keyCount, maxUsesPerKey);

    // Because its data has changed, we need to replace the binder for the
    // IIdentityCredential when the credential has been updated... otherwise the
    // remote object will have stale data for future calls, for example
    // getAuthKeysNeedingCertification().
    //
    // The way this is implemented is that setCredentialToReloadWhenUpdated()
    // instructs the WritableCredential to call writableCredentialPersonalized()
    // on |this|.
    //
    //
    writableCredential->setCredentialToReloadWhenUpdated(this);

    *_aidl_return = writableCredential;
    return Status::ok();
}

void Credential::writableCredentialPersonalized() {
    Status status = ensureOrReplaceHalBinder();
    if (!status.isOk()) {
        LOG(ERROR) << "Error reloading credential";
    }
}

}  // namespace identity
}  // namespace security
}  // namespace android
