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

#include "keystore/keystore_client_impl.h"

#include <string>
#include <vector>

#include "binder/IBinder.h"
#include "binder/IInterface.h"
#include "binder/IServiceManager.h"
#include "keystore/IKeystoreService.h"
#include "keystore/keystore.h"
#include "utils/String16.h"
#include "utils/String8.h"

using android::ExportResult;
using android::KeyCharacteristics;
using android::KeymasterArguments;
using android::OperationResult;
using android::String16;
using keymaster::AuthorizationSet;

namespace {

// Use the UID of the current process.
const int kDefaultUID = -1;

const uint8_t* StringAsByteArray(const std::string& s) {
    return reinterpret_cast<const uint8_t*>(s.data());
}

std::string ByteArrayAsString(const uint8_t* data, size_t data_size) {
    return std::string(reinterpret_cast<const char*>(data), data_size);
}

}  // namespace

namespace keystore {

KeystoreClientImpl::KeystoreClientImpl() {
    service_manager_ = android::defaultServiceManager();
    keystore_binder_ = service_manager_->getService(String16("android.security.keystore"));
    keystore_ = android::interface_cast<android::IKeystoreService>(keystore_binder_);
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
    key_arguments.params.assign(key_parameters.begin(), key_parameters.end());
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
                                                      &characteristics);
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
    key_arguments.params.assign(key_parameters.begin(), key_parameters.end());
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
                         &export_result);
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
    input_arguments.params.assign(input_parameters.begin(), input_parameters.end());
    OperationResult result;
    keystore_->begin(token, key_name16, purpose, true /*pruneable*/, input_arguments,
                     NULL /*entropy*/, 0 /*entropyLength*/, &result);
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
    input_arguments.params.assign(input_parameters.begin(), input_parameters.end());
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
        *output_data = ByteArrayAsString(result.data.get(), result.dataLength);
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
    input_arguments.params.assign(input_parameters.begin(), input_parameters.end());
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
        *output_data = ByteArrayAsString(result.data.get(), result.dataLength);
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

}  // namespace keystore
