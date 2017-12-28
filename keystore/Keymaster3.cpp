/*
 **
 ** Copyright 2017, The Android Open Source Project
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

#include "Keymaster3.h"

#include <android-base/logging.h>

#include <keystore/keystore_hidl_support.h>

namespace keystore {

namespace oldkeymaster = ::android::hardware::keymaster::V3_0;
using android::hardware::details::StatusOf;

namespace {

ErrorCode convert(oldkeymaster::ErrorCode error) {
    return static_cast<ErrorCode>(error);
}

oldkeymaster::KeyPurpose convert(KeyPurpose purpose) {
    return static_cast<oldkeymaster::KeyPurpose>(purpose);
}

oldkeymaster::KeyParameter convert(const KeyParameter& param) {
    oldkeymaster::KeyParameter converted;
    converted.tag = static_cast<oldkeymaster::Tag>(param.tag);
    static_assert(sizeof(converted.f) == sizeof(param.f), "This function assumes sizes match");
    memcpy(&converted.f, &param.f, sizeof(param.f));
    converted.blob = param.blob;
    return converted;
}

KeyParameter convert(const oldkeymaster::KeyParameter& param) {
    KeyParameter converted;
    converted.tag = static_cast<Tag>(param.tag);
    static_assert(sizeof(converted.f) == sizeof(param.f), "This function assumes sizes match");
    memcpy(&converted.f, &param.f, sizeof(param.f));
    converted.blob = param.blob;
    return converted;
}

hidl_vec<oldkeymaster::KeyParameter> convert(const hidl_vec<KeyParameter>& params) {
    hidl_vec<oldkeymaster::KeyParameter> converted(params.size());
    for (size_t i = 0; i < params.size(); ++i) {
        converted[i] = convert(params[i]);
    }
    return converted;
}

hidl_vec<KeyParameter> convert(const hidl_vec<oldkeymaster::KeyParameter>& params) {
    hidl_vec<KeyParameter> converted(params.size());
    for (size_t i = 0; i < params.size(); ++i) {
        converted[i] = convert(params[i]);
    }
    return converted;
}

hidl_vec<oldkeymaster::KeyParameter> convertAndAddAuthToken(const hidl_vec<KeyParameter>& params,
                                                            const HardwareAuthToken& authToken) {
    hidl_vec<oldkeymaster::KeyParameter> converted(params.size() + 1);
    for (size_t i = 0; i < params.size(); ++i) {
        converted[i] = convert(params[i]);
    }
    converted[params.size()].tag = oldkeymaster::Tag::AUTH_TOKEN;
    converted[params.size()].blob = authToken2HidlVec(authToken);

    return converted;
}

KeyCharacteristics convert(const oldkeymaster::KeyCharacteristics& chars) {
    KeyCharacteristics converted;
    converted.hardwareEnforced = convert(chars.teeEnforced);
    converted.softwareEnforced = convert(chars.softwareEnforced);
    return converted;
}

}  // namespace

void Keymaster3::getVersionIfNeeded() {
    if (haveVersion_) return;

    auto rc = km3_dev_->getHardwareFeatures(
        [&](bool isSecure, bool supportsEllipticCurve, bool supportsSymmetricCryptography,
            bool supportsAttestation, bool supportsAllDigests, const hidl_string& keymasterName,
            const hidl_string& keymasterAuthorName) {
            securityLevel_ =
                isSecure ? SecurityLevel::TRUSTED_ENVIRONMENT : SecurityLevel::SOFTWARE;
            supportsEllipticCurve_ = supportsEllipticCurve;
            supportsSymmetricCryptography_ = supportsSymmetricCryptography;
            supportsAttestation_ = supportsAttestation;
            supportsAllDigests_ = supportsAllDigests;
            keymasterName_ = keymasterName;
            authorName_ = keymasterAuthorName;
        });

    CHECK(rc.isOk()) << "Got error " << rc.description() << " trying to get hardware features";

    if (securityLevel_ == SecurityLevel::SOFTWARE) {
        majorVersion_ = 3;
    } else if (supportsAttestation_) {
        majorVersion_ = 3;  // Could be 2, doesn't matter.
    } else if (supportsSymmetricCryptography_) {
        majorVersion_ = 1;
    } else {
        majorVersion_ = 0;
    }
}

Keymaster::VersionResult Keymaster3::halVersion() {
    getVersionIfNeeded();
    return {ErrorCode::OK, majorVersion_, securityLevel_, supportsEllipticCurve_};
}

Return<void> Keymaster3::getHardwareInfo(Keymaster3::getHardwareInfo_cb _hidl_cb) {
    getVersionIfNeeded();
    _hidl_cb(securityLevel_, keymasterName_ + " (wrapped by keystore::Keymaster3)", authorName_);
    return Void();
}

Return<ErrorCode> Keymaster3::addRngEntropy(const hidl_vec<uint8_t>& data) {
    auto rc = km3_dev_->addRngEntropy(data);
    if (!rc.isOk()) {
        return StatusOf<oldkeymaster::ErrorCode, ErrorCode>(rc);
    }
    return convert(rc);
}

Return<void> Keymaster3::generateKey(const hidl_vec<KeyParameter>& keyParams,
                                     generateKey_cb _hidl_cb) {
    auto cb = [&](oldkeymaster::ErrorCode error, const hidl_vec<uint8_t>& keyBlob,
                  const oldkeymaster::KeyCharacteristics& characteristics) {
        _hidl_cb(convert(error), keyBlob, convert(characteristics));
    };
    auto rc = km3_dev_->generateKey(convert(keyParams), cb);
    rc.isOk();  // move ctor prereq
    return rc;
}

Return<void> Keymaster3::getKeyCharacteristics(const hidl_vec<uint8_t>& keyBlob,
                                               const hidl_vec<uint8_t>& clientId,
                                               const hidl_vec<uint8_t>& appData,
                                               getKeyCharacteristics_cb _hidl_cb) {
    auto cb = [&](oldkeymaster::ErrorCode error, const oldkeymaster::KeyCharacteristics& chars) {
        _hidl_cb(convert(error), convert(chars));
    };

    auto rc = km3_dev_->getKeyCharacteristics(keyBlob, clientId, appData, cb);
    rc.isOk();  // move ctor prereq
    return rc;
}

Return<void> Keymaster3::importKey(const hidl_vec<KeyParameter>& params, KeyFormat keyFormat,
                                   const hidl_vec<uint8_t>& keyData, importKey_cb _hidl_cb) {
    auto cb = [&](oldkeymaster::ErrorCode error, const hidl_vec<uint8_t>& keyBlob,
                  const oldkeymaster::KeyCharacteristics& chars) {
        _hidl_cb(convert(error), keyBlob, convert(chars));
    };
    auto rc = km3_dev_->importKey(convert(params), keyFormat, keyData, cb);
    rc.isOk();  // move ctor prereq
    return rc;
}

Return<void> Keymaster3::exportKey(KeyFormat exportFormat, const hidl_vec<uint8_t>& keyBlob,
                                   const hidl_vec<uint8_t>& clientId,
                                   const hidl_vec<uint8_t>& appData, exportKey_cb _hidl_cb) {
    auto cb = [&](oldkeymaster::ErrorCode error, const hidl_vec<uint8_t>& keyMaterial) {
        _hidl_cb(convert(error), keyMaterial);
    };
    auto rc = km3_dev_->exportKey(exportFormat, keyBlob, clientId, appData, cb);
    rc.isOk();  // move ctor prereq
    return rc;
}

Return<void> Keymaster3::attestKey(const hidl_vec<uint8_t>& keyToAttest,
                                   const hidl_vec<KeyParameter>& attestParams,
                                   attestKey_cb _hidl_cb) {
    auto cb = [&](oldkeymaster::ErrorCode error, const hidl_vec<hidl_vec<uint8_t>>& certChain) {
        _hidl_cb(convert(error), certChain);
    };
    auto rc = km3_dev_->attestKey(keyToAttest, convert(attestParams), cb);
    rc.isOk();  // move ctor prereq
    return rc;
}

Return<void> Keymaster3::upgradeKey(const hidl_vec<uint8_t>& keyBlobToUpgrade,
                                    const hidl_vec<KeyParameter>& upgradeParams,
                                    upgradeKey_cb _hidl_cb) {
    auto cb = [&](oldkeymaster::ErrorCode error, const hidl_vec<uint8_t>& upgradedKeyBlob) {
        _hidl_cb(convert(error), upgradedKeyBlob);
    };
    auto rc = km3_dev_->upgradeKey(keyBlobToUpgrade, convert(upgradeParams), cb);
    rc.isOk();  // move ctor prereq
    return rc;
}

Return<ErrorCode> Keymaster3::deleteKey(const hidl_vec<uint8_t>& keyBlob) {
    auto rc = km3_dev_->deleteKey(keyBlob);
    if (!rc.isOk()) return StatusOf<oldkeymaster::ErrorCode, ErrorCode>(rc);
    return convert(rc);
}

Return<ErrorCode> Keymaster3::deleteAllKeys() {
    auto rc = km3_dev_->deleteAllKeys();
    if (!rc.isOk()) return StatusOf<oldkeymaster::ErrorCode, ErrorCode>(rc);
    return convert(rc);
}

Return<ErrorCode> Keymaster3::destroyAttestationIds() {
    auto rc = km3_dev_->destroyAttestationIds();
    if (!rc.isOk()) return StatusOf<oldkeymaster::ErrorCode, ErrorCode>(rc);
    return convert(rc);
}

Return<void> Keymaster3::begin(KeyPurpose purpose, const hidl_vec<uint8_t>& key,
                               const hidl_vec<KeyParameter>& inParams,
                               const HardwareAuthToken& authToken, begin_cb _hidl_cb) {
    auto cb = [&](oldkeymaster::ErrorCode error,
                  const hidl_vec<oldkeymaster::KeyParameter>& outParams,
                  OperationHandle operationHandle) {
        _hidl_cb(convert(error), convert(outParams), operationHandle);
    };

    auto rc =
        km3_dev_->begin(convert(purpose), key, convertAndAddAuthToken(inParams, authToken), cb);
    rc.isOk();  // move ctor prereq
    return rc;
}

Return<void> Keymaster3::update(uint64_t operationHandle, const hidl_vec<KeyParameter>& inParams,
                                const hidl_vec<uint8_t>& input, const HardwareAuthToken& authToken,
                                const VerificationToken& /* verificationToken */,
                                update_cb _hidl_cb) {
    auto cb = [&](oldkeymaster::ErrorCode error, uint32_t inputConsumed,
                  const hidl_vec<oldkeymaster::KeyParameter>& outParams,
                  const hidl_vec<uint8_t>& output) {
        _hidl_cb(convert(error), inputConsumed, convert(outParams), output);
    };

    auto rc =
        km3_dev_->update(operationHandle, convertAndAddAuthToken(inParams, authToken), input, cb);
    rc.isOk();  // move ctor prereq
    return rc;
}

Return<void> Keymaster3::finish(uint64_t operationHandle, const hidl_vec<KeyParameter>& inParams,
                                const hidl_vec<uint8_t>& input, const hidl_vec<uint8_t>& signature,
                                const HardwareAuthToken& authToken,
                                const VerificationToken& /* verificationToken */,
                                finish_cb _hidl_cb) {
    auto cb = [&](oldkeymaster::ErrorCode error,
                  const hidl_vec<oldkeymaster::KeyParameter>& outParams,
                  const hidl_vec<uint8_t>& output) {
        _hidl_cb(convert(error), convert(outParams), output);
    };

    auto rc = km3_dev_->finish(operationHandle, convertAndAddAuthToken(inParams, authToken), input,
                               signature, cb);
    rc.isOk();  // move ctor prereq
    return rc;
}

Return<ErrorCode> Keymaster3::abort(uint64_t operationHandle) {
    auto rc = km3_dev_->abort(operationHandle);
    if (!rc.isOk()) return StatusOf<oldkeymaster::ErrorCode, ErrorCode>(rc);
    return convert(rc);
}

}  // namespace keystore
