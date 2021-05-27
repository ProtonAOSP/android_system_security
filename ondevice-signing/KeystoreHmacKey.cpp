/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <binder/IServiceManager.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "CertUtils.h"
#include "KeyConstants.h"
#include "KeystoreHmacKey.h"

using android::sp;
using android::String16;

using android::hardware::security::keymint::Algorithm;
using android::hardware::security::keymint::Digest;
using android::hardware::security::keymint::KeyParameter;
using android::hardware::security::keymint::KeyParameterValue;
using android::hardware::security::keymint::KeyPurpose;
using android::hardware::security::keymint::Tag;

using android::system::keystore2::CreateOperationResponse;
using android::system::keystore2::Domain;
using android::system::keystore2::KeyDescriptor;
using android::system::keystore2::KeyEntryResponse;
using android::system::keystore2::KeyMetadata;

using android::base::Error;
using android::base::Result;

using android::base::unique_fd;

// Keystore boot level that the odsign key uses
static const int kOdsignBootLevel = 30;

static KeyDescriptor getHmacKeyDescriptor() {
    // AIDL parcelable objects don't have constructor
    static KeyDescriptor descriptor;
    static std::once_flag flag;
    std::call_once(flag, [&]() {
        descriptor.domain = Domain::SELINUX;
        descriptor.alias = String16("ondevice-signing-hmac");
        descriptor.nspace = 101;  // odsign_key
    });

    return descriptor;
}

Result<void> KeystoreHmacKey::createKey() {
    std::vector<KeyParameter> params;

    KeyParameter algo;
    algo.tag = Tag::ALGORITHM;
    algo.value = KeyParameterValue::make<KeyParameterValue::algorithm>(Algorithm::HMAC);
    params.push_back(algo);

    KeyParameter key_size;
    key_size.tag = Tag::KEY_SIZE;
    key_size.value = KeyParameterValue::make<KeyParameterValue::integer>(kHmacKeySize);
    params.push_back(key_size);

    KeyParameter min_mac_length;
    min_mac_length.tag = Tag::MIN_MAC_LENGTH;
    min_mac_length.value = KeyParameterValue::make<KeyParameterValue::integer>(256);
    params.push_back(min_mac_length);

    KeyParameter digest;
    digest.tag = Tag::DIGEST;
    digest.value = KeyParameterValue::make<KeyParameterValue::digest>(Digest::SHA_2_256);
    params.push_back(digest);

    KeyParameter purposeSign;
    purposeSign.tag = Tag::PURPOSE;
    purposeSign.value = KeyParameterValue::make<KeyParameterValue::keyPurpose>(KeyPurpose::SIGN);
    params.push_back(purposeSign);

    KeyParameter purposeVerify;
    purposeVerify.tag = Tag::PURPOSE;
    purposeVerify.value =
        KeyParameterValue::make<KeyParameterValue::keyPurpose>(KeyPurpose::VERIFY);
    params.push_back(purposeVerify);

    KeyParameter auth;
    auth.tag = Tag::NO_AUTH_REQUIRED;
    auth.value = KeyParameterValue::make<KeyParameterValue::boolValue>(true);
    params.push_back(auth);

    KeyParameter boot_level;
    boot_level.tag = Tag::MAX_BOOT_LEVEL;
    boot_level.value = KeyParameterValue::make<KeyParameterValue::integer>(kOdsignBootLevel);
    params.push_back(boot_level);

    KeyMetadata metadata;
    auto status = mSecurityLevel->generateKey(mDescriptor, {}, params, 0, {}, &metadata);
    if (!status.isOk()) {
        return Error() << "Failed to create new HMAC key";
    }

    return {};
}

Result<void> KeystoreHmacKey::initialize(sp<IKeystoreService> service,
                                         sp<IKeystoreSecurityLevel> securityLevel) {
    mService = std::move(service);
    mSecurityLevel = std::move(securityLevel);

    // See if we can fetch an existing key
    KeyEntryResponse keyEntryResponse;
    LOG(INFO) << "Trying to retrieve existing HMAC key...";
    auto status = mService->getKeyEntry(mDescriptor, &keyEntryResponse);
    bool keyValid = false;

    if (status.isOk()) {
        // Make sure this is an early boot key
        for (const auto& auth : keyEntryResponse.metadata.authorizations) {
            if (auth.keyParameter.tag == Tag::MAX_BOOT_LEVEL) {
                if (auth.keyParameter.value.get<KeyParameterValue::integer>() == kOdsignBootLevel) {
                    keyValid = true;
                    break;
                }
            }
        }
        if (!keyValid) {
            LOG(WARNING) << "Found invalid HMAC key without MAX_BOOT_LEVEL tag";
        }
    }

    if (!keyValid) {
        LOG(INFO) << "Existing HMAC key not found or invalid, creating new key";
        return createKey();
    } else {
        return {};
    }
}

KeystoreHmacKey::KeystoreHmacKey() {
    mDescriptor = getHmacKeyDescriptor();
}

static std::vector<KeyParameter> getVerifyOpParameters() {
    std::vector<KeyParameter> opParameters;

    KeyParameter algo;
    algo.tag = Tag::ALGORITHM;
    algo.value = KeyParameterValue::make<KeyParameterValue::algorithm>(Algorithm::HMAC);
    opParameters.push_back(algo);

    KeyParameter digest;
    digest.tag = Tag::DIGEST;
    digest.value = KeyParameterValue::make<KeyParameterValue::digest>(Digest::SHA_2_256);
    opParameters.push_back(digest);

    KeyParameter mac_length;
    mac_length.tag = Tag::MAC_LENGTH;
    mac_length.value = KeyParameterValue::make<KeyParameterValue::integer>(256);
    opParameters.push_back(mac_length);

    KeyParameter purpose;
    purpose.tag = Tag::PURPOSE;
    purpose.value = KeyParameterValue::make<KeyParameterValue::keyPurpose>(KeyPurpose::VERIFY);
    opParameters.push_back(purpose);

    return opParameters;
}

static std::vector<KeyParameter> getSignOpParameters() {
    std::vector<KeyParameter> opParameters;

    KeyParameter algo;
    algo.tag = Tag::ALGORITHM;
    algo.value = KeyParameterValue::make<KeyParameterValue::algorithm>(Algorithm::HMAC);
    opParameters.push_back(algo);

    KeyParameter mac_length;
    mac_length.tag = Tag::MAC_LENGTH;
    mac_length.value = KeyParameterValue::make<KeyParameterValue::integer>(256);
    opParameters.push_back(mac_length);

    KeyParameter digest;
    digest.tag = Tag::DIGEST;
    digest.value = KeyParameterValue::make<KeyParameterValue::digest>(Digest::SHA_2_256);
    opParameters.push_back(digest);

    KeyParameter purpose;
    purpose.tag = Tag::PURPOSE;
    purpose.value = KeyParameterValue::make<KeyParameterValue::keyPurpose>(KeyPurpose::SIGN);
    opParameters.push_back(purpose);

    return opParameters;
}

Result<std::string> KeystoreHmacKey::sign(const std::string& message) const {
    CreateOperationResponse opResponse;
    static auto params = getSignOpParameters();

    auto status = mSecurityLevel->createOperation(mDescriptor, params, false, &opResponse);
    if (!status.isOk()) {
        return Error() << "Failed to create keystore signing operation: "
                       << status.serviceSpecificErrorCode();
    }
    auto operation = opResponse.iOperation;

    std::optional<std::vector<uint8_t>> out;
    status = operation->update({message.begin(), message.end()}, &out);
    if (!status.isOk()) {
        return Error() << "Failed to call keystore update operation.";
    }

    std::optional<std::vector<uint8_t>> signature;
    status = operation->finish({}, {}, &signature);
    if (!status.isOk()) {
        return Error() << "Failed to call keystore finish operation.";
    }

    if (!signature.has_value()) {
        return Error() << "Didn't receive a signature from keystore finish operation.";
    }

    return std::string{signature.value().begin(), signature.value().end()};
}

Result<void> KeystoreHmacKey::verify(const std::string& message,
                                     const std::string& signature) const {
    CreateOperationResponse opResponse;
    static auto params = getVerifyOpParameters();

    auto status = mSecurityLevel->createOperation(mDescriptor, params, false, &opResponse);
    if (!status.isOk()) {
        return Error() << "Failed to create keystore verification operation: "
                       << status.serviceSpecificErrorCode();
    }
    auto operation = opResponse.iOperation;

    std::optional<std::vector<uint8_t>> out;
    status = operation->update({message.begin(), message.end()}, &out);
    if (!status.isOk()) {
        return Error() << "Failed to call keystore update operation.";
    }

    std::optional<std::vector<uint8_t>> out_signature;
    std::vector<uint8_t> in_signature{signature.begin(), signature.end()};
    status = operation->finish({}, in_signature, &out_signature);
    if (!status.isOk()) {
        return Error() << "Failed to call keystore finish operation.";
    }

    return {};
}
