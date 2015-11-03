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

#include "binder/IBinder.h"
#include "binder/IInterface.h"
#include "binder/IServiceManager.h"
#include "keystore/IKeystoreService.h"
#include "keystore/keystore.h"
#include "log/log.h"
#include "utils/String16.h"
#include "utils/String8.h"

#include "keystore_client.pb.h"

using android::ExportResult;
using android::KeyCharacteristics;
using android::KeymasterArguments;
using android::OperationResult;
using android::String16;
using keymaster::AuthorizationSet;
using keymaster::AuthorizationSetBuilder;

namespace {

// Use the UID of the current process.
const int kDefaultUID = -1;
const char kEncryptSuffix[] = "_ENC";
const char kAuthenticateSuffix[] = "_AUTH";
const uint32_t kAESKeySize = 256;      // bits
const uint32_t kHMACKeySize = 256;     // bits
const uint32_t kHMACOutputSize = 256;  // bits

const uint8_t* StringAsByteArray(const std::string& s) {
    return reinterpret_cast<const uint8_t*>(s.data());
}

std::string ByteArrayAsString(const uint8_t* data, size_t data_size) {
    return std::string(reinterpret_cast<const char*>(data), data_size);
}

void CopyParameters(const AuthorizationSet& in, std::vector<keymaster_key_param_t>* out) {
  keymaster_key_param_set_t tmp;
  in.CopyToParamSet(&tmp);
  out->assign(&tmp.params[0], &tmp.params[tmp.length]);
  free(tmp.params);
}

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
    encrypt_params.Padding(KM_PAD_PKCS7);
    encrypt_params.Authorization(keymaster::TAG_BLOCK_MODE, KM_MODE_CBC);
    AuthorizationSet output_params;
    std::string raw_encrypted_data;
    if (!oneShotOperation(KM_PURPOSE_ENCRYPT, encryption_key_name, encrypt_params.build(), data,
                          std::string(), /* signature_to_verify */
                          &output_params, &raw_encrypted_data)) {
        ALOGE("Encrypt: AES operation failed.");
        return false;
    }
    keymaster_blob_t init_vector_blob;
    if (!output_params.GetTagValue(keymaster::TAG_NONCE, &init_vector_blob)) {
        ALOGE("Encrypt: Missing initialization vector.");
        return false;
    }
    std::string init_vector =
        ByteArrayAsString(init_vector_blob.data, init_vector_blob.data_length);

    AuthorizationSetBuilder authenticate_params;
    authenticate_params.Digest(KM_DIGEST_SHA_2_256);
    authenticate_params.Authorization(keymaster::TAG_MAC_LENGTH, kHMACOutputSize);
    std::string raw_authentication_data;
    if (!oneShotOperation(KM_PURPOSE_SIGN, authentication_key_name, authenticate_params.build(),
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
    authenticate_params.Digest(KM_DIGEST_SHA_2_256);
    AuthorizationSet output_params;
    std::string output_data;
    if (!oneShotOperation(KM_PURPOSE_VERIFY, authentication_key_name, authenticate_params.build(),
                          protobuf.init_vector() + protobuf.encrypted_data(),
                          protobuf.authentication_data(), &output_params, &output_data)) {
        ALOGE("Decrypt: HMAC operation failed.");
        return false;
    }
    std::string encryption_key_name = key_name + kEncryptSuffix;
    AuthorizationSetBuilder encrypt_params;
    encrypt_params.Padding(KM_PAD_PKCS7);
    encrypt_params.Authorization(keymaster::TAG_BLOCK_MODE, KM_MODE_CBC);
    encrypt_params.Authorization(keymaster::TAG_NONCE, protobuf.init_vector().data(),
                                 protobuf.init_vector().size());
    if (!oneShotOperation(KM_PURPOSE_DECRYPT, encryption_key_name, encrypt_params.build(),
                          protobuf.encrypted_data(), std::string(), /* signature_to_verify */
                          &output_params, data)) {
        ALOGE("Decrypt: AES operation failed.");
        return false;
    }
    return true;
}

bool KeystoreClientImpl::oneShotOperation(keymaster_purpose_t purpose, const std::string& key_name,
                                          const keymaster::AuthorizationSet& input_parameters,
                                          const std::string& input_data,
                                          const std::string& signature_to_verify,
                                          keymaster::AuthorizationSet* output_parameters,
                                          std::string* output_data) {
    keymaster_operation_handle_t handle;
    int32_t result =
        beginOperation(purpose, key_name, input_parameters, output_parameters, &handle);
    if (result != KM_ERROR_OK) {
        ALOGE("BeginOperation failed: %d", result);
        return false;
    }
    AuthorizationSet empty_params;
    size_t num_input_bytes_consumed;
    AuthorizationSet ignored_params;
    result = updateOperation(handle, empty_params, input_data, &num_input_bytes_consumed,
                             &ignored_params, output_data);
    if (result != KM_ERROR_OK) {
        ALOGE("UpdateOperation failed: %d", result);
        return false;
    }
    result =
        finishOperation(handle, empty_params, signature_to_verify, &ignored_params, output_data);
    if (result != KM_ERROR_OK) {
        ALOGE("FinishOperation failed: %d", result);
        return false;
    }
    return true;
}

int32_t KeystoreClientImpl::addRandomNumberGeneratorEntropy(const std::string& entropy) {
    return mapKeystoreError(keystore_->addRngEntropy(StringAsByteArray(entropy), entropy.size()));
}

int32_t KeystoreClientImpl::generateKey(const std::string& key_name,
                                        const AuthorizationSet& key_parameters,
                                        AuthorizationSet* hardware_enforced_characteristics,
                                        AuthorizationSet* software_enforced_characteristics) {
    String16 key_name16(key_name.data(), key_name.size());
    KeymasterArguments key_arguments;
    CopyParameters(key_parameters, &key_arguments.params);
    KeyCharacteristics characteristics;
    int32_t result =
        keystore_->generateKey(key_name16, key_arguments, NULL /*entropy*/, 0 /*entropyLength*/,
                               kDefaultUID, KEYSTORE_FLAG_NONE, &characteristics);
    hardware_enforced_characteristics->Reinitialize(characteristics.characteristics.hw_enforced);
    software_enforced_characteristics->Reinitialize(characteristics.characteristics.sw_enforced);
    return mapKeystoreError(result);
}

int32_t
KeystoreClientImpl::getKeyCharacteristics(const std::string& key_name,
                                          AuthorizationSet* hardware_enforced_characteristics,
                                          AuthorizationSet* software_enforced_characteristics) {
    String16 key_name16(key_name.data(), key_name.size());
    keymaster_blob_t client_id_blob = {nullptr, 0};
    keymaster_blob_t app_data_blob = {nullptr, 0};
    KeyCharacteristics characteristics;
    int32_t result = keystore_->getKeyCharacteristics(key_name16, &client_id_blob, &app_data_blob,
                                                      kDefaultUID, &characteristics);
    hardware_enforced_characteristics->Reinitialize(characteristics.characteristics.hw_enforced);
    software_enforced_characteristics->Reinitialize(characteristics.characteristics.sw_enforced);
    return mapKeystoreError(result);
}

int32_t KeystoreClientImpl::importKey(const std::string& key_name,
                                      const AuthorizationSet& key_parameters,
                                      keymaster_key_format_t key_format,
                                      const std::string& key_data,
                                      AuthorizationSet* hardware_enforced_characteristics,
                                      AuthorizationSet* software_enforced_characteristics) {
    String16 key_name16(key_name.data(), key_name.size());
    KeymasterArguments key_arguments;
    CopyParameters(key_parameters, &key_arguments.params);
    KeyCharacteristics characteristics;
    int32_t result =
        keystore_->importKey(key_name16, key_arguments, key_format, StringAsByteArray(key_data),
                             key_data.size(), kDefaultUID, KEYSTORE_FLAG_NONE, &characteristics);
    hardware_enforced_characteristics->Reinitialize(characteristics.characteristics.hw_enforced);
    software_enforced_characteristics->Reinitialize(characteristics.characteristics.sw_enforced);
    return mapKeystoreError(result);
}

int32_t KeystoreClientImpl::exportKey(keymaster_key_format_t export_format,
                                      const std::string& key_name, std::string* export_data) {
    String16 key_name16(key_name.data(), key_name.size());
    keymaster_blob_t client_id_blob = {nullptr, 0};
    keymaster_blob_t app_data_blob = {nullptr, 0};
    ExportResult export_result;
    keystore_->exportKey(key_name16, export_format, &client_id_blob, &app_data_blob,
                         kDefaultUID, &export_result);
    *export_data = ByteArrayAsString(export_result.exportData.get(), export_result.dataLength);
    return mapKeystoreError(export_result.resultCode);
}

int32_t KeystoreClientImpl::deleteKey(const std::string& key_name) {
    String16 key_name16(key_name.data(), key_name.size());
    return mapKeystoreError(keystore_->del(key_name16, kDefaultUID));
}

int32_t KeystoreClientImpl::deleteAllKeys() {
    return mapKeystoreError(keystore_->clear_uid(kDefaultUID));
}

int32_t KeystoreClientImpl::beginOperation(keymaster_purpose_t purpose, const std::string& key_name,
                                           const AuthorizationSet& input_parameters,
                                           AuthorizationSet* output_parameters,
                                           keymaster_operation_handle_t* handle) {
    android::sp<android::IBinder> token(new android::BBinder);
    String16 key_name16(key_name.data(), key_name.size());
    KeymasterArguments input_arguments;
    CopyParameters(input_parameters, &input_arguments.params);
    OperationResult result;
    keystore_->begin(token, key_name16, purpose, true /*pruneable*/, input_arguments,
                     NULL /*entropy*/, 0 /*entropyLength*/, kDefaultUID, &result);
    int32_t error_code = mapKeystoreError(result.resultCode);
    if (error_code == KM_ERROR_OK) {
        *handle = getNextVirtualHandle();
        active_operations_[*handle] = result.token;
        if (!result.outParams.params.empty()) {
            output_parameters->Reinitialize(&*result.outParams.params.begin(),
                                            result.outParams.params.size());
        }
    }
    return error_code;
}

int32_t KeystoreClientImpl::updateOperation(keymaster_operation_handle_t handle,
                                            const AuthorizationSet& input_parameters,
                                            const std::string& input_data,
                                            size_t* num_input_bytes_consumed,
                                            AuthorizationSet* output_parameters,
                                            std::string* output_data) {
    if (active_operations_.count(handle) == 0) {
        return KM_ERROR_INVALID_OPERATION_HANDLE;
    }
    KeymasterArguments input_arguments;
    CopyParameters(input_parameters, &input_arguments.params);
    OperationResult result;
    keystore_->update(active_operations_[handle], input_arguments, StringAsByteArray(input_data),
                      input_data.size(), &result);
    int32_t error_code = mapKeystoreError(result.resultCode);
    if (error_code == KM_ERROR_OK) {
        *num_input_bytes_consumed = result.inputConsumed;
        if (!result.outParams.params.empty()) {
            output_parameters->Reinitialize(&*result.outParams.params.begin(),
                                            result.outParams.params.size());
        }
        output_data->append(ByteArrayAsString(result.data.get(), result.dataLength));
    }
    return error_code;
}

int32_t KeystoreClientImpl::finishOperation(keymaster_operation_handle_t handle,
                                            const AuthorizationSet& input_parameters,
                                            const std::string& signature_to_verify,
                                            AuthorizationSet* output_parameters,
                                            std::string* output_data) {
    if (active_operations_.count(handle) == 0) {
        return KM_ERROR_INVALID_OPERATION_HANDLE;
    }
    KeymasterArguments input_arguments;
    CopyParameters(input_parameters, &input_arguments.params);
    OperationResult result;
    keystore_->finish(active_operations_[handle], input_arguments,
                      StringAsByteArray(signature_to_verify), signature_to_verify.size(),
                      NULL /*entropy*/, 0 /*entropyLength*/, &result);
    int32_t error_code = mapKeystoreError(result.resultCode);
    if (error_code == KM_ERROR_OK) {
        if (!result.outParams.params.empty()) {
            output_parameters->Reinitialize(&*result.outParams.params.begin(),
                                            result.outParams.params.size());
        }
        output_data->append(ByteArrayAsString(result.data.get(), result.dataLength));
        active_operations_.erase(handle);
    }
    return error_code;
}

int32_t KeystoreClientImpl::abortOperation(keymaster_operation_handle_t handle) {
    if (active_operations_.count(handle) == 0) {
        return KM_ERROR_INVALID_OPERATION_HANDLE;
    }
    int32_t error_code = mapKeystoreError(keystore_->abort(active_operations_[handle]));
    if (error_code == KM_ERROR_OK) {
        active_operations_.erase(handle);
    }
    return error_code;
}

bool KeystoreClientImpl::doesKeyExist(const std::string& key_name) {
    String16 key_name16(key_name.data(), key_name.size());
    int32_t error_code = mapKeystoreError(keystore_->exist(key_name16, kDefaultUID));
    return (error_code == KM_ERROR_OK);
}

bool KeystoreClientImpl::listKeys(const std::string& prefix,
                                  std::vector<std::string>* key_name_list) {
    String16 prefix16(prefix.data(), prefix.size());
    android::Vector<String16> matches;
    int32_t error_code = mapKeystoreError(keystore_->list(prefix16, kDefaultUID, &matches));
    if (error_code == KM_ERROR_OK) {
        for (const auto& match : matches) {
            android::String8 key_name(match);
            key_name_list->push_back(prefix + std::string(key_name.string(), key_name.size()));
        }
        return true;
    }
    return false;
}

keymaster_operation_handle_t KeystoreClientImpl::getNextVirtualHandle() {
    return next_virtual_handle_++;
}

int32_t KeystoreClientImpl::mapKeystoreError(int32_t keystore_error) {
    // See notes in keystore_client.h for rationale.
    if (keystore_error == ::NO_ERROR) {
        return KM_ERROR_OK;
    }
    return keystore_error;
}

bool KeystoreClientImpl::createOrVerifyEncryptionKey(const std::string& key_name) {
    bool key_exists = doesKeyExist(key_name);
    if (key_exists) {
        bool verified = false;
        if (!verifyEncryptionKeyAttributes(key_name, &verified)) {
            return false;
        }
        if (!verified) {
            int32_t result = deleteKey(key_name);
            if (result != KM_ERROR_OK) {
                ALOGE("Failed to delete invalid encryption key: %d", result);
                return false;
            }
            key_exists = false;
        }
    }
    if (!key_exists) {
        AuthorizationSetBuilder key_parameters;
        key_parameters.AesEncryptionKey(kAESKeySize)
            .Padding(KM_PAD_PKCS7)
            .Authorization(keymaster::TAG_BLOCK_MODE, KM_MODE_CBC)
            .Authorization(keymaster::TAG_NO_AUTH_REQUIRED);
        AuthorizationSet hardware_enforced_characteristics;
        AuthorizationSet software_enforced_characteristics;
        int32_t result =
            generateKey(key_name, key_parameters.build(), &hardware_enforced_characteristics,
                        &software_enforced_characteristics);
        if (result != KM_ERROR_OK) {
            ALOGE("Failed to generate encryption key: %d", result);
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
            int32_t result = deleteKey(key_name);
            if (result != KM_ERROR_OK) {
                ALOGE("Failed to delete invalid authentication key: %d", result);
                return false;
            }
            key_exists = false;
        }
    }
    if (!key_exists) {
        AuthorizationSetBuilder key_parameters;
        key_parameters.HmacKey(kHMACKeySize)
            .Digest(KM_DIGEST_SHA_2_256)
            .Authorization(keymaster::TAG_MIN_MAC_LENGTH, kHMACOutputSize)
            .Authorization(keymaster::TAG_NO_AUTH_REQUIRED);
        AuthorizationSet hardware_enforced_characteristics;
        AuthorizationSet software_enforced_characteristics;
        int32_t result =
            generateKey(key_name, key_parameters.build(), &hardware_enforced_characteristics,
                        &software_enforced_characteristics);
        if (result != KM_ERROR_OK) {
            ALOGE("Failed to generate authentication key: %d", result);
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
    int32_t result = getKeyCharacteristics(key_name, &hardware_enforced_characteristics,
                                           &software_enforced_characteristics);
    if (result != KM_ERROR_OK) {
        ALOGE("Failed to query encryption key: %d", result);
        return false;
    }
    *verified = true;
    keymaster_algorithm_t algorithm = KM_ALGORITHM_RSA;
    if ((!hardware_enforced_characteristics.GetTagValue(keymaster::TAG_ALGORITHM, &algorithm) &&
         !software_enforced_characteristics.GetTagValue(keymaster::TAG_ALGORITHM, &algorithm)) ||
        algorithm != KM_ALGORITHM_AES) {
        ALOGW("Found encryption key with invalid algorithm.");
        *verified = false;
    }
    uint32_t key_size = 0;
    if ((!hardware_enforced_characteristics.GetTagValue(keymaster::TAG_KEY_SIZE, &key_size) &&
         !software_enforced_characteristics.GetTagValue(keymaster::TAG_KEY_SIZE, &key_size)) ||
        key_size != kAESKeySize) {
        ALOGW("Found encryption key with invalid size.");
        *verified = false;
    }
    keymaster_block_mode_t block_mode = KM_MODE_ECB;
    if ((!hardware_enforced_characteristics.GetTagValue(keymaster::TAG_BLOCK_MODE, &block_mode) &&
         !software_enforced_characteristics.GetTagValue(keymaster::TAG_BLOCK_MODE, &block_mode)) ||
        block_mode != KM_MODE_CBC) {
        ALOGW("Found encryption key with invalid block mode.");
        *verified = false;
    }
    keymaster_padding_t padding_mode = KM_PAD_NONE;
    if ((!hardware_enforced_characteristics.GetTagValue(keymaster::TAG_PADDING, &padding_mode) &&
         !software_enforced_characteristics.GetTagValue(keymaster::TAG_PADDING, &padding_mode)) ||
        padding_mode != KM_PAD_PKCS7) {
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
    int32_t result = getKeyCharacteristics(key_name, &hardware_enforced_characteristics,
                                           &software_enforced_characteristics);
    if (result != KM_ERROR_OK) {
        ALOGE("Failed to query authentication key: %d", result);
        return false;
    }
    *verified = true;
    keymaster_algorithm_t algorithm = KM_ALGORITHM_RSA;
    if ((!hardware_enforced_characteristics.GetTagValue(keymaster::TAG_ALGORITHM, &algorithm) &&
         !software_enforced_characteristics.GetTagValue(keymaster::TAG_ALGORITHM, &algorithm)) ||
        algorithm != KM_ALGORITHM_HMAC) {
        ALOGW("Found authentication key with invalid algorithm.");
        *verified = false;
    }
    uint32_t key_size = 0;
    if ((!hardware_enforced_characteristics.GetTagValue(keymaster::TAG_KEY_SIZE, &key_size) &&
         !software_enforced_characteristics.GetTagValue(keymaster::TAG_KEY_SIZE, &key_size)) ||
        key_size != kHMACKeySize) {
        ALOGW("Found authentication key with invalid size.");
        *verified = false;
    }
    uint32_t mac_size = 0;
    if ((!hardware_enforced_characteristics.GetTagValue(keymaster::TAG_MIN_MAC_LENGTH, &mac_size) &&
         !software_enforced_characteristics.GetTagValue(keymaster::TAG_MIN_MAC_LENGTH,
                                                        &mac_size)) ||
        mac_size != kHMACOutputSize) {
        ALOGW("Found authentication key with invalid minimum mac size.");
        *verified = false;
    }
    keymaster_digest_t digest = KM_DIGEST_NONE;
    if ((!hardware_enforced_characteristics.GetTagValue(keymaster::TAG_DIGEST, &digest) &&
         !software_enforced_characteristics.GetTagValue(keymaster::TAG_DIGEST, &digest)) ||
        digest != KM_DIGEST_SHA_2_256) {
        ALOGW("Found authentication key with invalid digest list.");
        *verified = false;
    }
    if (hardware_enforced_characteristics.size() == 0) {
        ALOGW("WARNING: Authentication key is not hardware-backed.");
    }
    return true;
}

}  // namespace keystore
