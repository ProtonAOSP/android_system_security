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

#define LOG_TAG "CredentialStore"

#include <algorithm>

#include <android-base/logging.h>

#include <binder/IPCThreadState.h>

#include "Credential.h"
#include "CredentialStore.h"
#include "Util.h"
#include "WritableCredential.h"

namespace android {
namespace security {
namespace identity {

using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::identity::V1_0::Result;
using ::android::hardware::identity::V1_0::ResultCode;

using ::android::hardware::identity::V1_0::IWritableIdentityCredential;

CredentialStore::CredentialStore(const std::string& dataPath, sp<IIdentityCredentialStore> hal)
    : dataPath_(dataPath), hal_(hal) {}

bool CredentialStore::init() {
    Result result;
    hal_->getHardwareInformation([&](const Result& _result, const hidl_string& credentialStoreName,
                                     const hidl_string& credentialStoreAuthorName,
                                     uint32_t _dataChunkSize, bool _isDirectAccess,
                                     const hidl_vec<hidl_string>& _supportedDocTypes) {
        result = _result;
        dataChunkSize_ = _dataChunkSize;
        isDirectAccess_ = _isDirectAccess;
        supportedDocTypes_.clear();
        for (auto& docType : _supportedDocTypes) {
            supportedDocTypes_.push_back(docType);
        }
        LOG(INFO) << "Connected to Identity Credential HAL with name '" << credentialStoreName
                  << "' authored by '" << credentialStoreAuthorName << "' with chunk size "
                  << _dataChunkSize << " and directoAccess set to "
                  << (_isDirectAccess ? "true" : "false");
    });
    if (result.code != ResultCode::OK) {
        LOG(ERROR) << "Error getting hardware information: " << (int)result.code << ": "
                   << result.message;
        return false;
    }
    return true;
}

CredentialStore::~CredentialStore() {}

Status CredentialStore::getSecurityHardwareInfo(SecurityHardwareInfoParcel* _aidl_return) {
    SecurityHardwareInfoParcel info;
    info.directAccess = isDirectAccess_;
    info.supportedDocTypes = supportedDocTypes_;
    *_aidl_return = info;
    return Status::ok();
};

Status CredentialStore::createCredential(const std::string& credentialName,
                                         const std::string& docType,
                                         sp<IWritableCredential>* _aidl_return) {
    uid_t callingUid = android::IPCThreadState::self()->getCallingUid();
    optional<bool> credentialExists =
        CredentialData::credentialExists(dataPath_, callingUid, credentialName);
    if (!credentialExists.has_value()) {
        return Status::fromServiceSpecificError(
            ERROR_GENERIC, "Error determining if credential with given name exists");
    }
    if (credentialExists.value()) {
        return Status::fromServiceSpecificError(ERROR_ALREADY_PERSONALIZED,
                                                "Credential with given name already exists");
    }

    if (supportedDocTypes_.size() > 0) {
        if (std::find(supportedDocTypes_.begin(), supportedDocTypes_.end(), docType) ==
            supportedDocTypes_.end()) {
            return Status::fromServiceSpecificError(ERROR_DOCUMENT_TYPE_NOT_SUPPORTED,
                                                    "No support for given document type");
        }
    }

    Result result;
    sp<IWritableIdentityCredential> halWritableCredential;
    hal_->createCredential(
        docType, false,
        [&](const Result& _result, const sp<IWritableIdentityCredential>& _halWritableCredential) {
            result = _result;
            halWritableCredential = _halWritableCredential;
        });
    if (result.code != ResultCode::OK) {
        return halResultToGenericError(result);
    }

    sp<IWritableCredential> writableCredential = new WritableCredential(
        dataPath_, credentialName, docType, dataChunkSize_, halWritableCredential);
    *_aidl_return = writableCredential;
    return Status::ok();
}

// Keep in sync with IdentityCredentialStore.java
//

const int CIPHERSUITE_ECDHE_HKDF_ECDSA_WITH_AES_256_GCM_SHA256 = 1;

Status CredentialStore::getCredentialByName(const std::string& credentialName, int32_t cipherSuite,
                                            sp<ICredential>* _aidl_return) {
    *_aidl_return = nullptr;

    uid_t callingUid = android::IPCThreadState::self()->getCallingUid();
    optional<bool> credentialExists =
        CredentialData::credentialExists(dataPath_, callingUid, credentialName);
    if (!credentialExists.has_value()) {
        return Status::fromServiceSpecificError(
            ERROR_GENERIC, "Error determining if credential with given name exists");
    }
    if (!credentialExists.value()) {
        return Status::fromServiceSpecificError(ERROR_NO_SUCH_CREDENTIAL,
                                                "Credential with given name doesn't exist");
    }

    // We only support a single cipher-suite right now.
    if (cipherSuite != CIPHERSUITE_ECDHE_HKDF_ECDSA_WITH_AES_256_GCM_SHA256) {
        return Status::fromServiceSpecificError(ERROR_CIPHER_SUITE_NOT_SUPPORTED,
                                                "Cipher suite not supported");
    }

    sp<Credential> credential = new Credential(dataPath_, credentialName);

    Status loadStatus = credential->loadCredential(hal_);
    if (!loadStatus.isOk()) {
        LOG(ERROR) << "Error loading credential";
    } else {
        *_aidl_return = credential;
    }
    return loadStatus;
}

}  // namespace identity
}  // namespace security
}  // namespace android
