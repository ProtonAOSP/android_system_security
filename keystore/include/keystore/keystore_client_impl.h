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

#ifndef KEYSTORE_KEYSTORE_CLIENT_IMPL_H_
#define KEYSTORE_KEYSTORE_CLIENT_IMPL_H_

#include "keystore/keystore_client.h"

#include <string>
#include <map>
#include <vector>

#include "binder/IBinder.h"
#include "binder/IServiceManager.h"
#include "keystore/IKeystoreService.h"
#include "utils/StrongPointer.h"

namespace keystore {

class KeystoreClientImpl : public KeystoreClient {
  public:
    KeystoreClientImpl();
    ~KeystoreClientImpl() override = default;

    // KeystoreClient methods.
    bool encryptWithAuthentication(const std::string& key_name, const std::string& data,
                                   std::string* encrypted_data) override;
    bool decryptWithAuthentication(const std::string& key_name, const std::string& encrypted_data,
                                   std::string* data) override;
    bool oneShotOperation(keymaster_purpose_t purpose, const std::string& key_name,
                          const keymaster::AuthorizationSet& input_parameters,
                          const std::string& input_data, const std::string& signature_to_verify,
                          keymaster::AuthorizationSet* output_parameters,
                          std::string* output_data) override;
    int32_t addRandomNumberGeneratorEntropy(const std::string& entropy) override;
    int32_t generateKey(const std::string& key_name,
                        const keymaster::AuthorizationSet& key_parameters,
                        keymaster::AuthorizationSet* hardware_enforced_characteristics,
                        keymaster::AuthorizationSet* software_enforced_characteristics) override;
    int32_t
    getKeyCharacteristics(const std::string& key_name,
                          keymaster::AuthorizationSet* hardware_enforced_characteristics,
                          keymaster::AuthorizationSet* software_enforced_characteristics) override;
    int32_t importKey(const std::string& key_name,
                      const keymaster::AuthorizationSet& key_parameters,
                      keymaster_key_format_t key_format, const std::string& key_data,
                      keymaster::AuthorizationSet* hardware_enforced_characteristics,
                      keymaster::AuthorizationSet* software_enforced_characteristics) override;
    int32_t exportKey(keymaster_key_format_t export_format, const std::string& key_name,
                      std::string* export_data) override;
    int32_t deleteKey(const std::string& key_name) override;
    int32_t deleteAllKeys() override;
    int32_t beginOperation(keymaster_purpose_t purpose, const std::string& key_name,
                           const keymaster::AuthorizationSet& input_parameters,
                           keymaster::AuthorizationSet* output_parameters,
                           keymaster_operation_handle_t* handle) override;
    int32_t updateOperation(keymaster_operation_handle_t handle,
                            const keymaster::AuthorizationSet& input_parameters,
                            const std::string& input_data, size_t* num_input_bytes_consumed,
                            keymaster::AuthorizationSet* output_parameters,
                            std::string* output_data) override;
    int32_t finishOperation(keymaster_operation_handle_t handle,
                            const keymaster::AuthorizationSet& input_parameters,
                            const std::string& signature_to_verify,
                            keymaster::AuthorizationSet* output_parameters,
                            std::string* output_data) override;
    int32_t abortOperation(keymaster_operation_handle_t handle) override;
    bool doesKeyExist(const std::string& key_name) override;
    bool listKeys(const std::string& prefix, std::vector<std::string>* key_name_list) override;

  private:
    // Returns an available virtual operation handle.
    keymaster_operation_handle_t getNextVirtualHandle();

    // Maps a keystore error code to a code where all success cases use
    // KM_ERROR_OK (not keystore's NO_ERROR).
    int32_t mapKeystoreError(int32_t keystore_error);

    // Creates an encryption key suitable for EncryptWithAuthentication or
    // verifies attributes if the key already exists. Returns true on success.
    bool createOrVerifyEncryptionKey(const std::string& key_name);

    // Creates an authentication key suitable for EncryptWithAuthentication or
    // verifies attributes if the key already exists. Returns true on success.
    bool createOrVerifyAuthenticationKey(const std::string& key_name);

    // Verifies attributes of an encryption key suitable for
    // EncryptWithAuthentication. Returns true on success and populates |verified|
    // with the result of the verification.
    bool verifyEncryptionKeyAttributes(const std::string& key_name, bool* verified);

    // Verifies attributes of an authentication key suitable for
    // EncryptWithAuthentication. Returns true on success and populates |verified|
    // with the result of the verification.
    bool verifyAuthenticationKeyAttributes(const std::string& key_name, bool* verified);

    android::sp<android::IServiceManager> service_manager_;
    android::sp<android::IBinder> keystore_binder_;
    android::sp<android::IKeystoreService> keystore_;
    keymaster_operation_handle_t next_virtual_handle_ = 1;
    std::map<keymaster_operation_handle_t, android::sp<android::IBinder>> active_operations_;

    DISALLOW_COPY_AND_ASSIGN(KeystoreClientImpl);
};

}  // namespace keystore

#endif  // KEYSTORE_KEYSTORE_CLIENT_IMPL_H_
