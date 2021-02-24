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

#include <android-base/logging.h>
#include <keymasterV4_1/Keymaster.h>
#include <keymasterV4_1/authorization_set.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "Keymaster.h"

using AuthorizationSet = ::android::hardware::keymaster::V4_0::AuthorizationSet;
using AuthorizationSetBuilder = ::android::hardware::keymaster::V4_0::AuthorizationSetBuilder;
using Digest = ::android::hardware::keymaster::V4_0::Digest;
using ErrorCode = ::android::hardware::keymaster::V4_0::ErrorCode;
using HardwareAuthToken = ::android::hardware::keymaster::V4_0::HardwareAuthToken;
using HidlBuf = ::android::hardware::hidl_vec<uint8_t>;
using KeyCharacteristics = ::android::hardware::keymaster::V4_0::KeyCharacteristics;
using KeyFormat = ::android::hardware::keymaster::V4_0::KeyFormat;
using KeyParameter = ::android::hardware::keymaster::V4_0::KeyParameter;
using KeyPurpose = ::android::hardware::keymaster::V4_0::KeyPurpose;
using KmSupport = ::android::hardware::keymaster::V4_1::support::Keymaster;
using KmDevice = ::android::hardware::keymaster::V4_1::IKeymasterDevice;
using OperationHandle = ::android::hardware::keymaster::V4_0::OperationHandle;
using PaddingMode = ::android::hardware::keymaster::V4_0::PaddingMode;
using VerificationToken = ::android::hardware::keymaster::V4_0::VerificationToken;

using android::sp;
using android::base::Error;
using android::base::Result;
using android::base::unique_fd;
using android::hardware::hidl_vec;

Keymaster::Keymaster() {}

bool Keymaster::initialize() {
    // TODO(b/165630556): Stop using Keymaster directly and migrate to keystore2
    // (once available).
    auto devices = KmSupport::enumerateAvailableDevices();
    sp<KmDevice> devToUse = nullptr;
    for (const auto& dev : devices) {
        auto version = dev->halVersion();
        if (version.majorVersion > 4 || (version.majorVersion == 4 && version.minorVersion >= 1)) {
            // TODO we probably have a preference for the SE, hoping Keystore2 will provide this
            LOG(INFO) << "Using keymaster " << version.keymasterName << " "
                      << (int)version.majorVersion << "." << (int)version.minorVersion;
            devToUse = dev;
            break;
        }
    }

    mDevice = devToUse;

    return mDevice != nullptr;
}

std::optional<Keymaster> Keymaster::getInstance() {
    static Keymaster keymaster;

    if (!keymaster.initialize()) {
        return {};
    } else {
        return {keymaster};
    }
}

Result<std::vector<uint8_t>> Keymaster::createKey() const {
    ErrorCode error;
    HidlBuf keyBlob;

    auto params = AuthorizationSetBuilder()
                      .Authorization(::android::hardware::keymaster::V4_0::TAG_NO_AUTH_REQUIRED)
                      // TODO MAKE SURE WE ADD THE EARLY_BOOT_ONLY FLAG here
                      // currently doesn't work on cuttlefish (b/173618442)
                      //.Authorization(::android::hardware::keymaster::V4_1::TAG_EARLY_BOOT_ONLY)
                      .RsaSigningKey(2048, 65537)
                      .Digest(Digest::SHA_2_256)
                      .Padding(PaddingMode::RSA_PKCS1_1_5_SIGN);

    mDevice->generateKey(params.hidl_data(), [&](ErrorCode hidl_error, const HidlBuf& hidl_key_blob,
                                                 const KeyCharacteristics&
                                                 /* hidl_key_characteristics */) {
        error = hidl_error;
        keyBlob = hidl_key_blob;
    });

    if (error != ErrorCode::OK) {
        return Error() << "Error creating keymaster signing key: "
                       << static_cast<std::underlying_type<ErrorCode>::type>(error);
    }

    return keyBlob;
}

static ErrorCode Begin(const sp<KmDevice>& keymaster_, KeyPurpose purpose, const HidlBuf& key_blob,
                       const AuthorizationSet& in_params, AuthorizationSet* out_params,
                       OperationHandle* op_handle) {
    ErrorCode error;
    OperationHandle saved_handle = *op_handle;
    CHECK(keymaster_
              ->begin(purpose, key_blob, in_params.hidl_data(), HardwareAuthToken(),
                      [&](ErrorCode hidl_error, const hidl_vec<KeyParameter>& hidl_out_params,
                          uint64_t hidl_op_handle) {
                          error = hidl_error;
                          *out_params = hidl_out_params;
                          *op_handle = hidl_op_handle;
                      })
              .isOk());
    if (error != ErrorCode::OK) {
        // Some implementations may modify *op_handle on error.
        *op_handle = saved_handle;
    }
    return error;
}

static ErrorCode Update(const sp<KmDevice>& keymaster_, OperationHandle op_handle,
                        const AuthorizationSet& in_params, const std::string& input,
                        AuthorizationSet* out_params, std::string* output, size_t* input_consumed) {
    ErrorCode error;
    HidlBuf inputData(input.size());
    memcpy(inputData.data(), input.c_str(), input.size());
    CHECK(keymaster_
              ->update(op_handle, in_params.hidl_data(), inputData, HardwareAuthToken(),
                       VerificationToken(),
                       [&](ErrorCode hidl_error, uint32_t hidl_input_consumed,
                           const hidl_vec<KeyParameter>& hidl_out_params,
                           const HidlBuf& hidl_output) {
                           error = hidl_error;
                           out_params->push_back(AuthorizationSet(hidl_out_params));
                           std::string retdata(reinterpret_cast<const char*>(hidl_output.data()),
                                               hidl_output.size());
                           output->append(retdata);
                           *input_consumed = hidl_input_consumed;
                       })
              .isOk());
    return error;
}

static ErrorCode Finish(const sp<KmDevice>& keymaster_, OperationHandle op_handle,
                        const AuthorizationSet& in_params, const std::string& input,
                        const std::string& signature, AuthorizationSet* out_params,
                        std::string* output) {
    ErrorCode error;
    HidlBuf inputData(input.size());
    memcpy(inputData.data(), input.c_str(), input.size());
    HidlBuf signatureData(signature.size());
    memcpy(signatureData.data(), signature.c_str(), signature.size());
    // TODO still need to handle error -62 - key requires upgrade
    CHECK(keymaster_
              ->finish(op_handle, in_params.hidl_data(), inputData, signatureData,
                       HardwareAuthToken(), VerificationToken(),
                       [&](ErrorCode hidl_error, const hidl_vec<KeyParameter>& hidl_out_params,
                           const HidlBuf& hidl_output) {
                           error = hidl_error;
                           *out_params = hidl_out_params;
                           std::string retdata(reinterpret_cast<const char*>(hidl_output.data()),
                                               hidl_output.size());
                           output->append(retdata);
                       })
              .isOk());
    return error;
}

static std::string ProcessMessage(const sp<KmDevice>& keymaster_, const HidlBuf& key_blob,
                                  KeyPurpose operation, const std::string& message,
                                  const AuthorizationSet& in_params, AuthorizationSet* out_params) {
    AuthorizationSet begin_out_params;
    OperationHandle op_handle_;
    ErrorCode ec =
        Begin(keymaster_, operation, key_blob, in_params, &begin_out_params, &op_handle_);

    std::string output;
    size_t consumed = 0;
    AuthorizationSet update_params;
    AuthorizationSet update_out_params;
    ec = Update(keymaster_, op_handle_, update_params, message, &update_out_params, &output,
                &consumed);

    std::string unused;
    AuthorizationSet finish_params;
    AuthorizationSet finish_out_params;
    ec = Finish(keymaster_, op_handle_, finish_params, message.substr(consumed), unused,
                &finish_out_params, &output);

    out_params->push_back(begin_out_params);
    out_params->push_back(finish_out_params);
    return output;
}

Result<std::vector<uint8_t>>
Keymaster::extractPublicKey(const std::vector<uint8_t>& keyBlob) const {
    std::vector<uint8_t> publicKey;
    ErrorCode error;

    mDevice->exportKey(KeyFormat::X509, keyBlob, {} /* clientId */, {} /* appData */,
                       [&](ErrorCode hidl_error, const HidlBuf& keyData) {
                           error = hidl_error;
                           publicKey = keyData;
                       });

    if (error != ErrorCode::OK) {
        return Error() << "Error extracting public key: "
                       << static_cast<std::underlying_type<ErrorCode>::type>(error);
    }

    return publicKey;
}

Result<KeymasterVerifyResult> Keymaster::verifyKey(const std::vector<uint8_t>& keyBlob) const {
    ErrorCode error;
    KeyCharacteristics characteristics;

    mDevice->getKeyCharacteristics(
        keyBlob, {} /* clientId */, {} /* appData */,
        [&](ErrorCode hidl_error, const KeyCharacteristics& hidl_characteristics) {
            error = hidl_error;
            characteristics = hidl_characteristics;
        });

    if (error == ErrorCode::KEY_REQUIRES_UPGRADE) {
        return KeymasterVerifyResult::UPGRADE;
    }

    if (error != ErrorCode::OK) {
        return Error() << "Error getting key characteristics: "
                       << static_cast<std::underlying_type<ErrorCode>::type>(error);
    }

    // TODO(b/165630556)
    // Verify this is an early boot key and the other key parameters
    return KeymasterVerifyResult::OK;
}

Result<std::vector<uint8_t>> Keymaster::upgradeKey(const std::vector<uint8_t>& keyBlob) const {
    ErrorCode error;
    HidlBuf newKeyBlob;

    // TODO deduplicate
    auto params = AuthorizationSetBuilder()
                      .Authorization(::android::hardware::keymaster::V4_0::TAG_NO_AUTH_REQUIRED)
                      // TODO MAKE SURE WE ADD THE EARLY_BOOT_ONLY FLAG here
                      // currently doesn't work on cuttlefish (b/173618442)
                      //.Authorization(::android::hardware::keymaster::V4_1::TAG_EARLY_BOOT_ONLY)
                      .RsaSigningKey(2048, 65537)
                      .Digest(Digest::SHA_2_256)
                      .Padding(PaddingMode::RSA_PKCS1_1_5_SIGN);

    mDevice->upgradeKey(keyBlob, params.hidl_data(),
                        [&](ErrorCode hidl_error, const HidlBuf& hidl_key_blob) {
                            error = hidl_error;
                            newKeyBlob = hidl_key_blob;
                        });

    if (error != ErrorCode::OK) {
        return Error() << "Error upgrading keymaster signing key: "
                       << static_cast<std::underlying_type<ErrorCode>::type>(error);
    }

    return newKeyBlob;
}

Result<std::string> Keymaster::sign(const std::vector<uint8_t>& keyBlob,
                                    const std::string& message) const {
    AuthorizationSet out_params;
    auto params = AuthorizationSetBuilder()
                      .Digest(Digest::SHA_2_256)
                      .Padding(PaddingMode::RSA_PKCS1_1_5_SIGN);
    std::string signature =
        ProcessMessage(mDevice, keyBlob, KeyPurpose::SIGN, message, params, &out_params);
    if (!out_params.empty()) {
        return Error() << "Error signing key: expected empty out params.";
    }
    return signature;
}
