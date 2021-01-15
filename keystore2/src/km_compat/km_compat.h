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

#pragma once

#include <aidl/android/hardware/security/keymint/BnKeyMintDevice.h>
#include <aidl/android/hardware/security/keymint/BnKeyMintOperation.h>
#include <aidl/android/security/compat/BnKeystoreCompatService.h>
#include <keymasterV4_1/Keymaster4.h>
#include <unordered_map>
#include <variant>

#include "certificate_utils.h"

using ::aidl::android::hardware::security::keymint::BeginResult;
using ::aidl::android::hardware::security::keymint::ByteArray;
using ::aidl::android::hardware::security::keymint::Certificate;
using ::aidl::android::hardware::security::keymint::HardwareAuthToken;
using ::aidl::android::hardware::security::keymint::KeyCharacteristics;
using ::aidl::android::hardware::security::keymint::KeyCreationResult;
using ::aidl::android::hardware::security::keymint::KeyFormat;
using ::aidl::android::hardware::security::keymint::KeyMintHardwareInfo;
using ::aidl::android::hardware::security::keymint::KeyParameter;
using ::aidl::android::hardware::security::keymint::KeyParameterArray;
using ::aidl::android::hardware::security::keymint::KeyPurpose;
using ::aidl::android::hardware::security::keymint::VerificationToken;
using KeyMintSecurityLevel = ::aidl::android::hardware::security::keymint::SecurityLevel;
using V4_0_ErrorCode = ::android::hardware::keymaster::V4_0::ErrorCode;
using ::aidl::android::hardware::security::keymint::IKeyMintDevice;
using ::aidl::android::security::compat::BnKeystoreCompatService;
using ::android::hardware::keymaster::V4_1::support::Keymaster;
using ::ndk::ScopedAStatus;

class OperationSlots {
  private:
    uint8_t mNumFreeSlots;
    std::mutex mNumFreeSlotsMutex;

  public:
    void setNumFreeSlots(uint8_t numFreeSlots);
    bool claimSlot();
    void freeSlot();
};

// An abstraction for a single operation slot.
// This contains logic to ensure that we do not free the slot multiple times,
// e.g., if we call abort twice on the same operation.
class OperationSlot {
  private:
    OperationSlots* mOperationSlots;
    bool mIsActive;

  public:
    OperationSlot(OperationSlots* slots, bool isActive)
        : mOperationSlots(slots), mIsActive(isActive) {}

    void freeSlot();
    bool hasSlot() { return mIsActive; }
};

class KeyMintDevice : public aidl::android::hardware::security::keymint::BnKeyMintDevice {
  private:
    ::android::sp<Keymaster> mDevice;
    OperationSlots mOperationSlots;

  public:
    explicit KeyMintDevice(::android::sp<Keymaster>, KeyMintSecurityLevel);
    static std::shared_ptr<KeyMintDevice> createKeyMintDevice(KeyMintSecurityLevel securityLevel);

    ScopedAStatus getHardwareInfo(KeyMintHardwareInfo* _aidl_return) override;
    ScopedAStatus verifyAuthorization(int64_t in_challenge, const HardwareAuthToken& in_token,
                                      VerificationToken* _aidl_return) override;
    ScopedAStatus addRngEntropy(const std::vector<uint8_t>& in_data) override;
    ScopedAStatus generateKey(const std::vector<KeyParameter>& in_keyParams,
                              KeyCreationResult* out_creationResult) override;
    ScopedAStatus importKey(const std::vector<KeyParameter>& in_inKeyParams,
                            KeyFormat in_inKeyFormat, const std::vector<uint8_t>& in_inKeyData,
                            KeyCreationResult* out_creationResult) override;
    ScopedAStatus importWrappedKey(const std::vector<uint8_t>& in_inWrappedKeyData,
                                   const std::vector<uint8_t>& in_inWrappingKeyBlob,
                                   const std::vector<uint8_t>& in_inMaskingKey,
                                   const std::vector<KeyParameter>& in_inUnwrappingParams,
                                   int64_t in_inPasswordSid, int64_t in_inBiometricSid,
                                   KeyCreationResult* out_creationResult) override;
    ScopedAStatus upgradeKey(const std::vector<uint8_t>& in_inKeyBlobToUpgrade,
                             const std::vector<KeyParameter>& in_inUpgradeParams,
                             std::vector<uint8_t>* _aidl_return) override;
    ScopedAStatus deleteKey(const std::vector<uint8_t>& in_inKeyBlob) override;
    ScopedAStatus deleteAllKeys() override;
    ScopedAStatus destroyAttestationIds() override;
    ScopedAStatus begin(KeyPurpose in_inPurpose, const std::vector<uint8_t>& in_inKeyBlob,
                        const std::vector<KeyParameter>& in_inParams,
                        const HardwareAuthToken& in_inAuthToken,
                        BeginResult* _aidl_return) override;

    // These are public to allow testing code to use them directly.
    // This class should not be used publicly anyway.

    std::variant<std::vector<Certificate>, V4_0_ErrorCode>
    getCertificate(const std::vector<KeyParameter>& keyParams, const std::vector<uint8_t>& keyBlob);

    void setNumFreeSlots(uint8_t numFreeSlots);

  private:
    std::optional<V4_0_ErrorCode> signCertificate(const std::vector<KeyParameter>& keyParams,
                                                  const std::vector<uint8_t>& keyBlob, X509* cert);
    KeyMintSecurityLevel securityLevel_;
};

class KeyMintOperation : public aidl::android::hardware::security::keymint::BnKeyMintOperation {
  private:
    ::android::sp<Keymaster> mDevice;
    uint64_t mOperationHandle;
    OperationSlot mOperationSlot;

  public:
    KeyMintOperation(::android::sp<Keymaster> device, uint64_t operationHandle,
                     OperationSlots* slots, bool isActive)
        : mDevice(device), mOperationHandle(operationHandle), mOperationSlot(slots, isActive) {}
    ~KeyMintOperation();

    ScopedAStatus update(const std::optional<KeyParameterArray>& in_inParams,
                         const std::optional<std::vector<uint8_t>>& in_input,
                         const std::optional<HardwareAuthToken>& in_inAuthToken,
                         const std::optional<VerificationToken>& in_inVerificationToken,
                         std::optional<KeyParameterArray>* out_outParams,
                         std::optional<ByteArray>* out_output, int32_t* _aidl_return);
    ScopedAStatus finish(const std::optional<KeyParameterArray>& in_inParams,
                         const std::optional<std::vector<uint8_t>>& in_input,
                         const std::optional<std::vector<uint8_t>>& in_inSignature,
                         const std::optional<HardwareAuthToken>& in_authToken,
                         const std::optional<VerificationToken>& in_inVerificationToken,
                         std::optional<KeyParameterArray>* out_outParams,
                         std::vector<uint8_t>* _aidl_return);
    ScopedAStatus abort();
};

class KeystoreCompatService : public BnKeystoreCompatService {
  private:
    std::unordered_map<KeyMintSecurityLevel, std::shared_ptr<IKeyMintDevice>> mDeviceCache;

  public:
    KeystoreCompatService() {}
    ScopedAStatus getKeyMintDevice(KeyMintSecurityLevel in_securityLevel,
                                   std::shared_ptr<IKeyMintDevice>* _aidl_return) override;
};
