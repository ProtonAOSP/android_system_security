// Copyright 2015 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#define LOG_TAG "keystore_client"

#include "keystore/keystore_client_impl.h"

#include <string>
#include <vector>

#include <binder/IBinder.h>
#include <binder/IInterface.h>
#include <binder/IServiceManager.h>
#include <keystore/IKeystoreService.h>
#include <keystore/keystore.h>
#include <log/log.h>
#include <utils/String16.h>
#include <utils/String8.h>

#include "keystore_client.pb.h"
#include <keystore/authorization_set.h>
#include <keystore/keystore_hidl_support.h>

using android::ExportResult;
using keystore::KeyCharacteristics;
using android::OperationResult;
using android::String16;
using keystore::AuthorizationSet;
using keystore::AuthorizationSetBuilder;

namespace {

// Use the UID of the current process.
const int kDefaultUID = -1;
const char kEncryptSuffix[] = "_ENC";
const char kAuthenticateSuffix[] = "_AUTH";
constexpr uint32_t kAESKeySize = 256;      // bits
constexpr uint32_t kHMACKeySize = 256;     // bits
constexpr uint32_t kHMACOutputSize = 256;  // bits

}  // namespace

namespace keystore {

KeystoreClientImpl::KeystoreClientImpl() {
    service_manager_ = android::defaultServiceManager();
    keystore_binder_ = service_manager_->getService(String16("android.security.keystore"));
    keystore_ = android::interface_cast<android::IKeystoreService>(keystore_binder_);
}

bool KeystoreClientImpl::encryptWithAuthentication(const std::string& key_name,
                                                   const std::string& data,
                                                   std::string* encrypted_data) {
    // The encryption algorithm is AES-256-CBC with PKCS #7 padding and a random
    // IV. The authentication algorithm is HMAC-SHA256 and is computed over the
    // cipher-text (i.e. Encrypt-then-MAC approach). This was chosen over AES-GCM
    // because hardware support for GCM is not mandatory for all Brillo devices.
    std::string encryption_key_name = key_name + kEncryptSuffix;
    if (!createOrVerifyEncryptionKey(encryption_key_name)) {
        return false;
    }
    std::string authentication_key_name = key_name + kAuthenticateSuffix;
    if (!createOrVerifyAuthenticationKey(authentication_key_name)) {
        return false;
    }
    AuthorizationSetBuilder encrypt_params;
    encrypt_params.Padding(PaddingMode::PKCS7);
    encrypt_params.Authorization(TAG_BLOCK_MODE, BlockMode::CBC);
    AuthorizationSet output_params;
    std::string raw_encrypted_data;
    if (!oneShotOperation(KeyPurpose::ENCRYPT, encryption_key_name, encrypt_params, data,
                          std::string(), /* signature_to_verify */
                          &output_params, &raw_encrypted_data)) {
        ALOGE("Encrypt: AES operation failed.");
        return false;
    }
    auto init_vector_blob = output_params.GetTagValue(TAG_NONCE);
    if (!init_vector_blob.isOk()){
        ALOGE("Encrypt: Missing initialization vector.");
        return false;
    }
    std::string init_vector = hidlVec2String(init_vector_blob.value());

    AuthorizationSetBuilder authenticate_params;
    authenticate_params.Digest(Digest::SHA_2_256);
    authenticate_params.Authorization(TAG_MAC_LENGTH, kHMACOutputSize);
    std::string raw_authentication_data;
    if (!oneShotOperation(KeyPurpose::SIGN, authentication_key_name, authenticate_params,
                          init_vector + raw_encrypted_data, std::string(), /* signature_to_verify */
                          &output_params, &raw_authentication_data)) {
        ALOGE("Encrypt: HMAC operation failed.");
        return false;
    }
    EncryptedData protobuf;
    protobuf.set_init_vector(init_vector);
    protobuf.set_authentication_data(raw_authentication_data);
    protobuf.set_encrypted_data(raw_encrypted_data);
    if (!protobuf.SerializeToString(encrypted_data)) {
        ALOGE("Encrypt: Failed to serialize EncryptedData protobuf.");
        return false;
    }
    return true;
}

bool KeystoreClientImpl::decryptWithAuthentication(const std::string& key_name,
                                                   const std::string& encrypted_data,
                                                   std::string* data) {
    EncryptedData protobuf;
    if (!protobuf.ParseFromString(encrypted_data)) {
        ALOGE("Decrypt: Failed to parse EncryptedData protobuf.");
    }
    // Verify authentication before attempting decryption.
    std::string authentication_key_name = key_name + kAuthenticateSuffix;
    AuthorizationSetBuilder authenticate_params;
    authenticate_params.Digest(Digest::SHA_2_256);
    AuthorizationSet output_params;
    std::string output_data;
    if (!oneShotOperation(KeyPurpose::VERIFY, authentication_key_name, authenticate_params,
                          protobuf.init_vector() + protobuf.encrypted_data(),
                          protobuf.authentication_data(), &output_params, &output_data)) {
        ALOGE("Decrypt: HMAC operation failed.");
        return false;
    }
    std::string encryption_key_name = key_name + kEncryptSuffix;
    AuthorizationSetBuilder encrypt_params;
    encrypt_params.Padding(PaddingMode::PKCS7);
    encrypt_params.Authorization(TAG_BLOCK_MODE, BlockMode::CBC);
    encrypt_params.Authorization(TAG_NONCE, protobuf.init_vector().data(),
                                 protobuf.init_vector().size());
    if (!oneShotOperation(KeyPurpose::DECRYPT, encryption_key_name, encrypt_params,
                          protobuf.encrypted_data(), std::string(), /* signature_to_verify */
                          &output_params, data)) {
        ALOGE("Decrypt: AES operation failed.");
        return false;
    }
    return true;
}

bool KeystoreClientImpl::oneShotOperation(KeyPurpose purpose, const std::string& key_name,
                                          const AuthorizationSet& input_parameters,
                                          const std::string& input_data,
                                          const std::string& signature_to_verify,
                                          AuthorizationSet* output_parameters,
                                          std::string* output_data) {
    uint64_t handle;
    auto result =
        beginOperation(purpose, key_name, input_parameters, output_parameters, &handle);
    if (!result.isOk()) {
        ALOGE("BeginOperation failed: %d", int32_t(result));
        return false;
    }
    AuthorizationSet empty_params;
    size_t num_input_bytes_consumed;
    AuthorizationSet ignored_params;
    result = updateOperation(handle, empty_params, input_data, &num_input_bytes_consumed,
                             &ignored_params, output_data);
    if (!result.isOk()) {
        ALOGE("UpdateOperation failed: %d", int32_t(result));
        return false;
    }
    result =
        finishOperation(handle, empty_params, signature_to_verify, &ignored_params, output_data);
    if (!result.isOk()) {
        ALOGE("FinishOperation failed: %d", int32_t(result));
        return false;
    }
    return true;
}

KeyStoreNativeReturnCode KeystoreClientImpl::addRandomNumberGeneratorEntropy(const std::string& entropy) {
    return keystore_->addRngEntropy(blob2hidlVec(entropy));
}

KeyStoreNativeReturnCode KeystoreClientImpl::generateKey(const std::string& key_name,
                                        const AuthorizationSet& key_parameters,
                                        AuthorizationSet* hardware_enforced_characteristics,
                                        AuthorizationSet* software_enforced_characteristics) {
    String16 key_name16(key_name.data(), key_name.size());
    KeyCharacteristics characteristics;
    auto result =
        keystore_->generateKey(key_name16, key_parameters.hidl_data(), hidl_vec<uint8_t>(),
                               kDefaultUID, KEYSTORE_FLAG_NONE, &characteristics);

    /* assignment (hidl_vec<KeyParameter> -> AuthorizationSet) makes a deep copy.
     * There are no references to Parcel memory after that, and ownership of the newly acquired
     * memory is with the AuthorizationSet objects. */
    *hardware_enforced_characteristics = characteristics.teeEnforced;
    *software_enforced_characteristics = characteristics.softwareEnforced;
    return result;
}

KeyStoreNativeReturnCode
KeystoreClientImpl::getKeyCharacteristics(const std::string& key_name,
                                          AuthorizationSet* hardware_enforced_characteristics,
                                          AuthorizationSet* software_enforced_characteristics) {
    String16 key_name16(key_name.data(), key_name.size());
    KeyCharacteristics characteristics;
    auto result = keystore_->getKeyCharacteristics(key_name16, hidl_vec<uint8_t>(), hidl_vec<uint8_t>(),
                                                      kDefaultUID, &characteristics);

    /* assignment (hidl_vec<KeyParameter> -> AuthorizationSet) makes a deep copy.
     * There are no references to Parcel memory after that, and ownership of the newly acquired
     * memory is with the AuthorizationSet objects. */
    *hardware_enforced_characteristics = characteristics.teeEnforced;
    *software_enforced_characteristics = characteristics.softwareEnforced;
    return result;
}

KeyStoreNativeReturnCode KeystoreClientImpl::importKey(const std::string& key_name,
                                      const AuthorizationSet& key_parameters,
                                      KeyFormat key_format,
                                      const std::string& key_data,
                                      AuthorizationSet* hardware_enforced_characteristics,
                                      AuthorizationSet* software_enforced_characteristics) {
    String16 key_name16(key_name.data(), key_name.size());
    auto hidlKeyData = blob2hidlVec(key_data);
    KeyCharacteristics characteristics;
    auto result = keystore_->importKey(key_name16, key_parameters.hidl_data(), key_format,
            hidlKeyData, kDefaultUID, KEYSTORE_FLAG_NONE, &characteristics);

    /* assignment (hidl_vec<KeyParameter> -> AuthorizationSet) makes a deep copy.
     * There are no references to Parcel memory after that, and ownership of the newly acquired
     * memory is with the AuthorizationSet objects. */
    *hardware_enforced_characteristics = characteristics.teeEnforced;
    *software_enforced_characteristics = characteristics.softwareEnforced;
    return result;
}

KeyStoreNativeReturnCode KeystoreClientImpl::exportKey(KeyFormat export_format,
                                      const std::string& key_name, std::string* export_data) {
    String16 key_name16(key_name.data(), key_name.size());
    ExportResult export_result;
    keystore_->exportKey(key_name16, export_format, hidl_vec<uint8_t>(), hidl_vec<uint8_t>(),
                         kDefaultUID, &export_result);
    *export_data = hidlVec2String(export_result.exportData);
    return export_result.resultCode;
}

KeyStoreNativeReturnCode KeystoreClientImpl::deleteKey(const std::string& key_name) {
    String16 key_name16(key_name.data(), key_name.size());
    return keystore_->del(key_name16, kDefaultUID);
}

KeyStoreNativeReturnCode KeystoreClientImpl::deleteAllKeys() {
    return keystore_->clear_uid(kDefaultUID);
}

KeyStoreNativeReturnCode KeystoreClientImpl::beginOperation(KeyPurpose purpose, const std::string& key_name,
                                           const AuthorizationSet& input_parameters,
                                           AuthorizationSet* output_parameters,
                                           uint64_t* handle) {
    android::sp<android::IBinder> token(new android::BBinder);
    String16 key_name16(key_name.data(), key_name.size());
    OperationResult result;
    keystore_->begin(token, key_name16, purpose, true /*pruneable*/, input_parameters.hidl_data(),
                     hidl_vec<uint8_t>(), kDefaultUID, &result);
    if (result.resultCode.isOk()) {
        *handle = getNextVirtualHandle();
        active_operations_[*handle] = result.token;
        if (result.outParams.size()) {
            *output_parameters = result.outParams;
        }
    }
    return result.resultCode;
}

KeyStoreNativeReturnCode KeystoreClientImpl::updateOperation(uint64_t handle,
                                            const AuthorizationSet& input_parameters,
                                            const std::string& input_data,
                                            size_t* num_input_bytes_consumed,
                                            AuthorizationSet* output_parameters,
                                            std::string* output_data) {
    if (active_operations_.count(handle) == 0) {
        return ErrorCode::INVALID_OPERATION_HANDLE;
    }
    OperationResult result;
    auto hidlInputData = blob2hidlVec(input_data);
    keystore_->update(active_operations_[handle], input_parameters.hidl_data(), hidlInputData,
            &result);

    if (result.resultCode.isOk()) {
        *num_input_bytes_consumed = result.inputConsumed;
        if (result.outParams.size()) {
            *output_parameters = result.outParams;
        }
        // TODO verify that append should not be assign
        output_data->append(hidlVec2String(result.data));
    }
    return result.resultCode;
}

KeyStoreNativeReturnCode KeystoreClientImpl::finishOperation(uint64_t handle,
                                            const AuthorizationSet& input_parameters,
                                            const std::string& signature_to_verify,
                                            AuthorizationSet* output_parameters,
                                            std::string* output_data) {
    if (active_operations_.count(handle) == 0) {
        return ErrorCode::INVALID_OPERATION_HANDLE;
    }
    OperationResult result;
    auto hidlSignature = blob2hidlVec(signature_to_verify);
    keystore_->finish(active_operations_[handle], input_parameters.hidl_data(),
                      hidlSignature,
                      hidl_vec<uint8_t>(), &result);

    if (result.resultCode.isOk()) {
        if (result.outParams.size()) {
            *output_parameters = result.outParams;
        }
        // TODO verify that append should not be assign
        output_data->append(hidlVec2String(result.data));
        active_operations_.erase(handle);
    }
    return result.resultCode;
}

KeyStoreNativeReturnCode KeystoreClientImpl::abortOperation(uint64_t handle) {
    if (active_operations_.count(handle) == 0) {
        return ErrorCode::INVALID_OPERATION_HANDLE;
    }
    auto error_code = keystore_->abort(active_operations_[handle]);
    if (error_code.isOk()) {
        active_operations_.erase(handle);
    }
    return error_code;
}

bool KeystoreClientImpl::doesKeyExist(const std::string& key_name) {
    String16 key_name16(key_name.data(), key_name.size());
    auto error_code = keystore_->exist(key_name16, kDefaultUID);
    return error_code.isOk();
}

bool KeystoreClientImpl::listKeys(const std::string& prefix,
                                  std::vector<std::string>* key_name_list) {
    String16 prefix16(prefix.data(), prefix.size());
    android::Vector<String16> matches;
    auto error_code = keystore_->list(prefix16, kDefaultUID, &matches);
    if (error_code.isOk()) {
        for (const auto& match : matches) {
            android::String8 key_name(match);
            key_name_list->push_back(prefix + std::string(key_name.string(), key_name.size()));
        }
        return true;
    }
    return false;
}

uint64_t KeystoreClientImpl::getNextVirtualHandle() {
    return next_virtual_handle_++;
}

bool KeystoreClientImpl::createOrVerifyEncryptionKey(const std::string& key_name) {
    bool key_exists = doesKeyExist(key_name);
    if (key_exists) {
        bool verified = false;
        if (!verifyEncryptionKeyAttributes(key_name, &verified)) {
            return false;
        }
        if (!verified) {
            auto result = deleteKey(key_name);
            if (!result.isOk()) {
                ALOGE("Failed to delete invalid encryption key: %d", int32_t(result));
                return false;
            }
            key_exists = false;
        }
    }
    if (!key_exists) {
        AuthorizationSetBuilder key_parameters;
        key_parameters.AesEncryptionKey(kAESKeySize)
            .Padding(PaddingMode::PKCS7)
            .Authorization(TAG_BLOCK_MODE, BlockMode::CBC)
            .Authorization(TAG_NO_AUTH_REQUIRED);
        AuthorizationSet hardware_enforced_characteristics;
        AuthorizationSet software_enforced_characteristics;
        auto result =
            generateKey(key_name, key_parameters, &hardware_enforced_characteristics,
                        &software_enforced_characteristics);
        if (!result.isOk()) {
            ALOGE("Failed to generate encryption key: %d", int32_t(result));
            return false;
        }
        if (hardware_enforced_characteristics.size() == 0) {
            ALOGW("WARNING: Encryption key is not hardware-backed.");
        }
    }
    return true;
}

bool KeystoreClientImpl::createOrVerifyAuthenticationKey(const std::string& key_name) {
    bool key_exists = doesKeyExist(key_name);
    if (key_exists) {
        bool verified = false;
        if (!verifyAuthenticationKeyAttributes(key_name, &verified)) {
            return false;
        }
        if (!verified) {
            auto result = deleteKey(key_name);
            if (!result.isOk()) {
                ALOGE("Failed to delete invalid authentication key: %d", int32_t(result));
                return false;
            }
            key_exists = false;
        }
    }
    if (!key_exists) {
        AuthorizationSetBuilder key_parameters;
        key_parameters.HmacKey(kHMACKeySize)
            .Digest(Digest::SHA_2_256)
            .Authorization(TAG_MIN_MAC_LENGTH, kHMACOutputSize)
            .Authorization(TAG_NO_AUTH_REQUIRED);
        AuthorizationSet hardware_enforced_characteristics;
        AuthorizationSet software_enforced_characteristics;
        auto result =
            generateKey(key_name, key_parameters, &hardware_enforced_characteristics,
                        &software_enforced_characteristics);
        if (!result.isOk()) {
            ALOGE("Failed to generate authentication key: %d", int32_t(result));
            return false;
        }
        if (hardware_enforced_characteristics.size() == 0) {
            ALOGW("WARNING: Authentication key is not hardware-backed.");
        }
    }
    return true;
}

bool KeystoreClientImpl::verifyEncryptionKeyAttributes(const std::string& key_name,
                                                       bool* verified) {
    AuthorizationSet hardware_enforced_characteristics;
    AuthorizationSet software_enforced_characteristics;
    auto result = getKeyCharacteristics(key_name, &hardware_enforced_characteristics,
                                           &software_enforced_characteristics);
    if (!result.isOk()) {
        ALOGE("Failed to query encryption key: %d", int32_t(result));
        return false;
    }
    *verified = true;
    auto algorithm = NullOrOr(hardware_enforced_characteristics.GetTagValue(TAG_ALGORITHM),
            software_enforced_characteristics.GetTagValue(TAG_ALGORITHM));
    if (!algorithm.isOk() || algorithm.value() != Algorithm::AES) {
        ALOGW("Found encryption key with invalid algorithm.");
        *verified = false;
    }
    auto key_size = NullOrOr(hardware_enforced_characteristics.GetTagValue(TAG_KEY_SIZE),
            software_enforced_characteristics.GetTagValue(TAG_KEY_SIZE));
    if (!key_size.isOk() || key_size.value() != kAESKeySize) {
        ALOGW("Found encryption key with invalid size.");
        *verified = false;
    }
    auto block_mode = NullOrOr(hardware_enforced_characteristics.GetTagValue(TAG_BLOCK_MODE),
            software_enforced_characteristics.GetTagValue(TAG_BLOCK_MODE));
    if (!block_mode.isOk() || block_mode.value() != BlockMode::CBC) {
        ALOGW("Found encryption key with invalid block mode.");
        *verified = false;
    }
    auto padding_mode = NullOrOr(hardware_enforced_characteristics.GetTagValue(TAG_PADDING),
            software_enforced_characteristics.GetTagValue(TAG_PADDING));
    if (!padding_mode.isOk() || padding_mode.value() != PaddingMode::PKCS7) {
        ALOGW("Found encryption key with invalid padding mode.");
        *verified = false;
    }
    if (hardware_enforced_characteristics.size() == 0) {
        ALOGW("WARNING: Encryption key is not hardware-backed.");
    }
    return true;
}

bool KeystoreClientImpl::verifyAuthenticationKeyAttributes(const std::string& key_name,
                                                           bool* verified) {
    AuthorizationSet hardware_enforced_characteristics;
    AuthorizationSet software_enforced_characteristics;
    auto result = getKeyCharacteristics(key_name, &hardware_enforced_characteristics,
                                           &software_enforced_characteristics);
    if (!result.isOk()) {
        ALOGE("Failed to query authentication key: %d", int32_t(result));
        return false;
    }
    *verified = true;
    auto algorithm = NullOrOr(hardware_enforced_characteristics.GetTagValue(TAG_ALGORITHM),
            software_enforced_characteristics.GetTagValue(TAG_ALGORITHM));
    if (!algorithm.isOk() || algorithm.value() != Algorithm::HMAC){
        ALOGW("Found authentication key with invalid algorithm.");
        *verified = false;
    }
    auto key_size = NullOrOr(hardware_enforced_characteristics.GetTagValue(TAG_KEY_SIZE),
            software_enforced_characteristics.GetTagValue(TAG_KEY_SIZE));
    if (!key_size.isOk() || key_size.value() != kHMACKeySize) {
        ALOGW("Found authentication key with invalid size.");
        *verified = false;
    }
    auto mac_size = NullOrOr(hardware_enforced_characteristics.GetTagValue(TAG_MIN_MAC_LENGTH),
            software_enforced_characteristics.GetTagValue(TAG_MIN_MAC_LENGTH));
    if (!mac_size.isOk() || mac_size.value() != kHMACOutputSize) {
        ALOGW("Found authentication key with invalid minimum mac size.");
        *verified = false;
    }
    auto digest = NullOrOr(hardware_enforced_characteristics.GetTagValue(TAG_DIGEST),
            software_enforced_characteristics.GetTagValue(TAG_DIGEST));
    if (!digest.isOk() || digest.value() != Digest::SHA_2_256) {
        ALOGW("Found authentication key with invalid digest list.");
        *verified = false;
    }
    if (hardware_enforced_characteristics.size() == 0) {
        ALOGW("WARNING: Authentication key is not hardware-backed.");
    }
    return true;
}

}  // namespace keystore
