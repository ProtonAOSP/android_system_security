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

#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "CertUtils.h"
#include "Keymaster.h"
#include "KeymasterSigningKey.h"

using android::base::ErrnoError;
using android::base::Error;
using android::base::ReadFileToString;
using android::base::Result;
using android::base::unique_fd;

KeymasterSigningKey::KeymasterSigningKey() {}

Result<KeymasterSigningKey> KeymasterSigningKey::loadFromBlobAndVerify(const std::string& path) {
    KeymasterSigningKey signingKey;

    auto status = signingKey.initializeFromKeyblob(path);

    if (!status.ok()) {
        return status.error();
    }

    return std::move(signingKey);
}

Result<KeymasterSigningKey> KeymasterSigningKey::createNewKey() {
    KeymasterSigningKey signingKey;

    auto status = signingKey.createSigningKey();

    if (!status.ok()) {
        return status.error();
    }

    return std::move(signingKey);
}

Result<void> KeymasterSigningKey::createSigningKey() {
    KeymasterSigningKey signingKey;
    auto keymaster = Keymaster::getInstance();
    if (!keymaster.has_value()) {
        return Error() << "Failed to initialize keymaster.";
    }
    mKeymaster = keymaster;

    auto keyBlob = mKeymaster->createKey();

    if (!keyBlob.ok()) {
        return keyBlob.error();
    }

    mVerifiedKeyBlob.assign(keyBlob->begin(), keyBlob->end());

    return {};
}

Result<void> KeymasterSigningKey::saveKeyblob(const std::string& path) const {
    int flags = O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC;

    unique_fd fd(TEMP_FAILURE_RETRY(open(path.c_str(), flags, 0600)));
    if (fd == -1) {
        return ErrnoError() << "Error creating key blob file " << path;
    }

    if (!android::base::WriteFully(fd, mVerifiedKeyBlob.data(), mVerifiedKeyBlob.size())) {
        return ErrnoError() << "Error writing key blob file " << path;
    } else {
        return {};
    }
}

Result<std::vector<uint8_t>> KeymasterSigningKey::getPublicKey() const {
    auto publicKeyX509 = mKeymaster->extractPublicKey(mVerifiedKeyBlob);
    if (!publicKeyX509.ok()) {
        return publicKeyX509.error();
    }
    return extractPublicKeyFromX509(publicKeyX509.value());
}

Result<void> KeymasterSigningKey::createX509Cert(const std::string& outPath) const {
    auto publicKey = mKeymaster->extractPublicKey(mVerifiedKeyBlob);

    if (!publicKey.ok()) {
        return publicKey.error();
    }

    auto keymasterSignFunction = [&](const std::string& to_be_signed) {
        return this->sign(to_be_signed);
    };
    createSelfSignedCertificate(*publicKey, keymasterSignFunction, outPath);
    return {};
}

Result<void> KeymasterSigningKey::initializeFromKeyblob(const std::string& path) {
    std::string keyBlobData;
    auto keymaster = Keymaster::getInstance();
    if (!keymaster.has_value()) {
        return Error() << "Failed to initialize keymaster.";
    }
    mKeymaster = keymaster;

    bool result = ReadFileToString(path, &keyBlobData);
    if (!result) {
        return ErrnoError() << "Failed to read " << path;
    }

    std::vector<uint8_t> keyBlob = {keyBlobData.begin(), keyBlobData.end()};

    auto verifyResult = mKeymaster->verifyKey(keyBlob);
    if (!verifyResult.ok()) {
        return Error() << "Failed to verify key: " << verifyResult.error().message();
    }

    if (*verifyResult == KeymasterVerifyResult::UPGRADE) {
        auto upgradeResult = mKeymaster->upgradeKey(keyBlob);
        if (!upgradeResult.ok()) {
            return Error() << "Failed to upgrade key: " << upgradeResult.error().message();
        }
        mVerifiedKeyBlob = *upgradeResult;
        // Make sure we persist the new blob
        auto saveResult = saveKeyblob(path);
        if (!saveResult.ok()) {
            return Error() << "Failed to store upgraded key";
        }
    } else {
        mVerifiedKeyBlob = keyBlob;
    }

    return {};
}

Result<std::string> KeymasterSigningKey::sign(const std::string& message) const {
    return mKeymaster->sign(mVerifiedKeyBlob, message);
}
