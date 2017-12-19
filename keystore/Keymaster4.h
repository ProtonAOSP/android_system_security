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

#ifndef KEYSTORE_KEYMASTER_4_H_
#define KEYSTORE_KEYMASTER_4_H_

#include <keystore/keymaster_types.h>
#include <utils/StrongPointer.h>

#include "Keymaster.h"

namespace keystore {

using android::sp;
using IKeymaster4Device = ::android::hardware::keymaster::V4_0::IKeymasterDevice;

class Keymaster4 : public Keymaster {
  public:
    using WrappedIKeymasterDevice = IKeymaster4Device;
    Keymaster4(sp<IKeymasterDevice> km4_dev) : haveVersion_(false), dev_(km4_dev) {}

    uint8_t halMajorVersion() { return 4; }

    VersionResult halVersion() override;

    Return<void> getHardwareInfo(getHardwareInfo_cb _hidl_cb) override {
        return dev_->getHardwareInfo(_hidl_cb);
    }

    Return<void> getHmacSharingParameters(getHmacSharingParameters_cb _hidl_cb) override {
        return dev_->getHmacSharingParameters(_hidl_cb);
    }

    Return<void> computeSharedHmac(const hidl_vec<HmacSharingParameters>& params,
                                   computeSharedHmac_cb _hidl_cb) override {
        return dev_->computeSharedHmac(params, _hidl_cb);
    }

    Return<void> verifyAuthorization(uint64_t operationHandle, const hidl_vec<KeyParameter>& params,
                                     const HardwareAuthToken& authToken,
                                     verifyAuthorization_cb _hidl_cb) override {
        return dev_->verifyAuthorization(operationHandle, params, authToken, _hidl_cb);
    }

    Return<ErrorCode> addRngEntropy(const hidl_vec<uint8_t>& data) override {
        return dev_->addRngEntropy(data);
    }

    Return<void> generateKey(const hidl_vec<KeyParameter>& keyParams,
                             generateKey_cb _hidl_cb) override {
        return dev_->generateKey(keyParams, _hidl_cb);
    }

    Return<void> getKeyCharacteristics(const hidl_vec<uint8_t>& keyBlob,
                                       const hidl_vec<uint8_t>& clientId,
                                       const hidl_vec<uint8_t>& appData,
                                       getKeyCharacteristics_cb _hidl_cb) override {
        return dev_->getKeyCharacteristics(keyBlob, clientId, appData, _hidl_cb);
    }

    Return<void> importKey(const hidl_vec<KeyParameter>& params, KeyFormat keyFormat,
                           const hidl_vec<uint8_t>& keyData, importKey_cb _hidl_cb) override {
        return dev_->importKey(params, keyFormat, keyData, _hidl_cb);
    }

    Return<void> importWrappedKey(const hidl_vec<uint8_t>& wrappedKeyData,
                                  const hidl_vec<uint8_t>& wrappingKeyBlob,
                                  const hidl_vec<uint8_t>& maskingKey,
                                  importWrappedKey_cb _hidl_cb) {
        return dev_->importWrappedKey(wrappedKeyData, wrappingKeyBlob, maskingKey, _hidl_cb);
    }

    Return<void> exportKey(KeyFormat exportFormat, const hidl_vec<uint8_t>& keyBlob,
                           const hidl_vec<uint8_t>& clientId, const hidl_vec<uint8_t>& appData,
                           exportKey_cb _hidl_cb) override {
        return dev_->exportKey(exportFormat, keyBlob, clientId, appData, _hidl_cb);
    }

    Return<void> attestKey(const hidl_vec<uint8_t>& keyToAttest,
                           const hidl_vec<KeyParameter>& attestParams,
                           attestKey_cb _hidl_cb) override {
        return dev_->attestKey(keyToAttest, attestParams, _hidl_cb);
    }

    Return<void> upgradeKey(const hidl_vec<uint8_t>& keyBlobToUpgrade,
                            const hidl_vec<KeyParameter>& upgradeParams,
                            upgradeKey_cb _hidl_cb) override {
        return dev_->upgradeKey(keyBlobToUpgrade, upgradeParams, _hidl_cb);
    }

    Return<ErrorCode> deleteKey(const hidl_vec<uint8_t>& keyBlob) override {
        return dev_->deleteKey(keyBlob);
    }

    Return<ErrorCode> deleteAllKeys() override { return dev_->deleteAllKeys(); }

    Return<ErrorCode> destroyAttestationIds() override { return dev_->destroyAttestationIds(); }

    Return<void> begin(KeyPurpose purpose, const hidl_vec<uint8_t>& key,
                       const hidl_vec<KeyParameter>& inParams, const HardwareAuthToken& authToken,
                       begin_cb _hidl_cb) override {
        return dev_->begin(purpose, key, inParams, authToken, _hidl_cb);
    }

    Return<void> update(uint64_t operationHandle, const hidl_vec<KeyParameter>& inParams,
                        const hidl_vec<uint8_t>& input, const HardwareAuthToken& authToken,
                        const VerificationToken& verificationToken, update_cb _hidl_cb) override {
        return dev_->update(operationHandle, inParams, input, authToken, verificationToken,
                            _hidl_cb);
    }

    Return<void> finish(uint64_t operationHandle, const hidl_vec<KeyParameter>& inParams,
                        const hidl_vec<uint8_t>& input, const hidl_vec<uint8_t>& signature,
                        const HardwareAuthToken& authToken,
                        const VerificationToken& verificationToken, finish_cb _hidl_cb) override {
        return dev_->finish(operationHandle, inParams, input, signature, authToken,
                            verificationToken, _hidl_cb);
    }

    Return<ErrorCode> abort(uint64_t operationHandle) override {
        return dev_->abort(operationHandle);
    }

  private:
    void getVersionIfNeeded();

    bool haveVersion_;
    SecurityLevel securityLevel_;
    sp<IKeymaster4Device> dev_;
};

}  // namespace keystore

#endif  // KEYSTORE_KEYMASTER_3_H_
