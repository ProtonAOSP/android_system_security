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
#include "KeystoreKey.h"

using android::defaultServiceManager;
using android::IServiceManager;
using android::sp;
using android::String16;

using android::hardware::security::keymint::Algorithm;
using android::hardware::security::keymint::Digest;
using android::hardware::security::keymint::KeyParameter;
using android::hardware::security::keymint::KeyParameterValue;
using android::hardware::security::keymint::KeyPurpose;
using android::hardware::security::keymint::PaddingMode;
using android::hardware::security::keymint::SecurityLevel;
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

static KeyDescriptor getKeyDescriptor() {
    // AIDL parcelable objects don't have constructor
    static KeyDescriptor descriptor;
    static std::once_flag flag;
    std::call_once(flag, [&]() {
        descriptor.domain = Domain::SELINUX;
        descriptor.alias = String16("ondevice-signing");
        descriptor.nspace = 101;  // odsign_key
    });

    return descriptor;
}

KeystoreKey::KeystoreKey() {}

Result<KeyMetadata> KeystoreKey::createNewKey(const KeyDescriptor& descriptor) {
    std::vector<KeyParameter> params;

    KeyParameter algo;
    algo.tag = Tag::ALGORITHM;
    algo.value = KeyParameterValue::make<KeyParameterValue::algorithm>(Algorithm::RSA);
    params.push_back(algo);

    KeyParameter key_size;
    key_size.tag = Tag::KEY_SIZE;
    key_size.value = KeyParameterValue::make<KeyParameterValue::integer>(kRsaKeySize);
    params.push_back(key_size);

    KeyParameter digest;
    digest.tag = Tag::DIGEST;
    digest.value = KeyParameterValue::make<KeyParameterValue::digest>(Digest::SHA_2_256);
    params.push_back(digest);

    KeyParameter padding;
    padding.tag = Tag::PADDING;
    padding.value =
        KeyParameterValue::make<KeyParameterValue::paddingMode>(PaddingMode::RSA_PKCS1_1_5_SIGN);
    params.push_back(padding);

    KeyParameter exponent;
    exponent.tag = Tag::RSA_PUBLIC_EXPONENT;
    exponent.value = KeyParameterValue::make<KeyParameterValue::longInteger>(kRsaKeyExponent);
    params.push_back(exponent);

    KeyParameter purpose;
    purpose.tag = Tag::PURPOSE;
    purpose.value = KeyParameterValue::make<KeyParameterValue::keyPurpose>(KeyPurpose::SIGN);
    params.push_back(purpose);

    KeyParameter auth;
    auth.tag = Tag::NO_AUTH_REQUIRED;
    auth.value = KeyParameterValue::make<KeyParameterValue::boolValue>(true);
    params.push_back(auth);

    KeyParameter boot_level;
    boot_level.tag = Tag::MAX_BOOT_LEVEL;
    boot_level.value = KeyParameterValue::make<KeyParameterValue::integer>(kOdsignBootLevel);
    params.push_back(boot_level);

    KeyMetadata metadata;
    auto status = mSecurityLevel->generateKey(descriptor, {}, params, 0, {}, &metadata);
    if (!status.isOk()) {
        return Error() << "Failed to create new key";
    }

    return metadata;
}

bool KeystoreKey::initialize() {
    sp<IServiceManager> sm = defaultServiceManager();
    if (sm == nullptr) {
        return false;
    }
    auto service = sm->getService(String16("android.system.keystore2.IKeystoreService/default"));
    if (service == nullptr) {
        return false;
    }
    mService = interface_cast<android::system::keystore2::IKeystoreService>(service);
    if (mService == nullptr) {
        return false;
    }

    auto status = mService->getSecurityLevel(SecurityLevel::STRONGBOX, &mSecurityLevel);
    if (!status.isOk()) {
        status = mService->getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT, &mSecurityLevel);
        if (!status.isOk()) {
            return false;
        }
    }

    auto descriptor = getKeyDescriptor();
    // See if we can fetch an existing key
    KeyEntryResponse keyEntryResponse;
    LOG(INFO) << "Trying to retrieve existing keystore key...";
    status = mService->getKeyEntry(descriptor, &keyEntryResponse);
    if (!status.isOk()) {
        LOG(INFO) << "Existing keystore key not found, creating new key";
        auto newKeyStatus = createNewKey(descriptor);
        if (!newKeyStatus.ok()) {
            LOG(ERROR) << "Failed to create new key";
            return false;
        }
        mKeyMetadata = *newKeyStatus;
    } else {
        mKeyMetadata = keyEntryResponse.metadata;
    }

    LOG(ERROR) << "Initialized Keystore key.";
    return true;
}

Result<SigningKey*> KeystoreKey::getInstance() {
    static KeystoreKey keystoreKey;

    if (!keystoreKey.initialize()) {
        return Error() << "Failed to initialize keystore key.";
    } else {
        return &keystoreKey;
    }
}

static std::vector<KeyParameter> getSignOpParameters() {
    std::vector<KeyParameter> opParameters;

    KeyParameter algo;
    algo.tag = Tag::ALGORITHM;
    algo.value = KeyParameterValue::make<KeyParameterValue::algorithm>(Algorithm::RSA);
    opParameters.push_back(algo);

    KeyParameter digest;
    digest.tag = Tag::DIGEST;
    digest.value = KeyParameterValue::make<KeyParameterValue::digest>(Digest::SHA_2_256);
    opParameters.push_back(digest);

    KeyParameter padding;
    padding.tag = Tag::PADDING;
    padding.value =
        KeyParameterValue::make<KeyParameterValue::paddingMode>(PaddingMode::RSA_PKCS1_1_5_SIGN);
    opParameters.push_back(padding);

    KeyParameter purpose;
    purpose.tag = Tag::PURPOSE;
    purpose.value = KeyParameterValue::make<KeyParameterValue::keyPurpose>(KeyPurpose::SIGN);
    opParameters.push_back(purpose);

    return opParameters;
}

Result<std::string> KeystoreKey::sign(const std::string& message) const {
    static auto opParameters = getSignOpParameters();

    CreateOperationResponse opResponse;

    auto status =
        mSecurityLevel->createOperation(getKeyDescriptor(), opParameters, false, &opResponse);
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

    std::string result{signature.value().begin(), signature.value().end()};

    return result;
}

Result<std::vector<uint8_t>> KeystoreKey::getPublicKey() const {
    return extractPublicKeyFromX509(mKeyMetadata.certificate.value());
}
