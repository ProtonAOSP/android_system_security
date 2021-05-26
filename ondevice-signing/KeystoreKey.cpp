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

using android::base::Error;
using android::base::Result;

// Keystore boot level that the odsign key uses
static const int kOdsignBootLevel = 30;

const std::string kPublicKeySignature = "/data/misc/odsign/publickey.signature";

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

KeystoreKey::KeystoreKey() {
    mDescriptor = getKeyDescriptor();
}

Result<std::vector<uint8_t>> KeystoreKey::createKey() {
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
    auto status = mSecurityLevel->generateKey(mDescriptor, {}, params, 0, {}, &metadata);
    if (!status.isOk()) {
        return Error() << "Failed to create new key";
    }

    // Extract the public key from the certificate, HMAC it and store the signature
    auto cert = metadata.certificate;
    if (!cert) {
        return Error() << "Key did not have a certificate.";
    }
    auto publicKey = extractPublicKeyFromX509(cert.value());
    if (!publicKey.ok()) {
        return publicKey.error();
    }
    std::string publicKeyString = {publicKey->begin(), publicKey->end()};
    auto signature = mHmacKey.sign(publicKeyString);
    if (!signature.ok()) {
        return Error() << "Failed to sign public key.";
    }

    if (!android::base::WriteStringToFile(*signature, kPublicKeySignature)) {
        return Error() << "Can't write public key signature.";
    }

    return *publicKey;
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

    auto status = mService->getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT, &mSecurityLevel);
    if (!status.isOk()) {
        return false;
    }

    // Initialize the HMAC key we use to sign/verify information about this key
    auto hmacStatus = mHmacKey.initialize(mService, mSecurityLevel);
    if (!hmacStatus.ok()) {
        LOG(ERROR) << hmacStatus.error().message();
        return false;
    }

    auto key = getOrCreateKey();
    if (!key.ok()) {
        LOG(ERROR) << key.error().message();
        return false;
    }
    mPublicKey = *key;
    LOG(ERROR) << "Initialized Keystore key.";
    return true;
}

Result<std::vector<uint8_t>> KeystoreKey::verifyExistingKey() {
    // See if we can fetch an existing key
    KeyEntryResponse keyEntryResponse;
    LOG(INFO) << "Trying to retrieve existing keystore key...";
    auto status = mService->getKeyEntry(mDescriptor, &keyEntryResponse);

    if (!status.isOk()) {
        return Error() << "Failed to find keystore key...";
    }

    // On some earlier builds, we created this key on the Strongbox security level;
    // we now use TEE keys instead (mostly for speed). It shouldn't matter since
    // verified boot is protected by the TEE anyway. If the key happens to be on
    // the wrong security level, delete it (this should happen just once).
    if (keyEntryResponse.metadata.keySecurityLevel != SecurityLevel::TRUSTED_ENVIRONMENT) {
        return Error() << "Found invalid keystore key with security level: "
                       << android::hardware::security::keymint::toString(
                              keyEntryResponse.metadata.keySecurityLevel);
    }

    // Make sure this is an early boot key
    bool foundBootLevel = false;
    for (const auto& auth : keyEntryResponse.metadata.authorizations) {
        if (auth.keyParameter.tag == Tag::MAX_BOOT_LEVEL) {
            if (auth.keyParameter.value.get<KeyParameterValue::integer>() == kOdsignBootLevel) {
                foundBootLevel = true;
                break;
            }
        }
    }
    if (!foundBootLevel) {
        return Error() << "Found invalid keystore key without MAX_BOOT_LEVEL tag";
    }

    // If the key is still considered valid at this point, extract the public
    // key from the certificate. Note that we cannot trust this public key,
    // because it is a part of the keystore2 database, which can be modified by
    // an attacker.  So instead, when creating the key we HMAC the public key
    // with a key of the same boot level, and verify the signature here.
    auto cert = keyEntryResponse.metadata.certificate;
    if (!cert) {
        return Error() << "Key did not have a certificate.";
    }
    auto publicKey = extractPublicKeyFromX509(cert.value());
    if (!publicKey.ok()) {
        return publicKey.error();
    }
    std::string publicKeyString = {publicKey->begin(), publicKey->end()};

    std::string signature;
    if (!android::base::ReadFileToString(kPublicKeySignature, &signature)) {
        return Error() << "Can't find signature for public key.";
    }

    auto signatureValid = mHmacKey.verify(publicKeyString, signature);
    if (!signatureValid.ok()) {
        return Error() << "Signature of public key did not match.";
    }
    LOG(INFO) << "Verified public key signature.";

    return *publicKey;
}

Result<std::vector<uint8_t>> KeystoreKey::getOrCreateKey() {
    auto existingKey = verifyExistingKey();
    if (!existingKey.ok()) {
        LOG(INFO) << existingKey.error().message();
        LOG(INFO) << "Existing keystore key not found or invalid, creating new key";
        return createKey();
    }

    return *existingKey;
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

    auto status = mSecurityLevel->createOperation(mDescriptor, opParameters, false, &opResponse);
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

Result<std::vector<uint8_t>> KeystoreKey::getPublicKey() const {
    return mPublicKey;
}
