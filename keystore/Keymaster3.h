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

#ifndef KEYSTORE_KEYMASTER_3_H_
#define KEYSTORE_KEYMASTER_3_H_

#include <keystore/keymaster_types.h>
#include <utils/StrongPointer.h>

#include "Keymaster.h"

namespace keystore {

using android::sp;
using IKeymaster3Device = ::android::hardware::keymaster::V3_0::IKeymasterDevice;

class Keymaster3 : public Keymaster {
  public:
    Keymaster3(sp<IKeymasterDevice> km3_dev) : km3_dev_(km3_dev) {}

    VersionResult halVersion() override;

    Return<void> getHardwareFeatures(getHardwareFeatures_cb _hidl_cb) override {
        getVersionIfNeeded();
        _hidl_cb(isSecure_, supportsEllipticCurve_, supportsSymmetricCryptography_,
                 supportsAttestation_, supportsAllDigests_,
                 keymasterName_ + " (wrapped by keystore::Keymaster3)", authorName_);
        return android::hardware::Void();
    }

    Return<ErrorCode> addRngEntropy(const hidl_vec<uint8_t>& data) override {
        return km3_dev_->addRngEntropy(data);
    }

    Return<void> generateKey(const hidl_vec<KeyParameter>& keyParams,
                             generateKey_cb _hidl_cb) override {
        return km3_dev_->generateKey(keyParams, _hidl_cb);
    }

    Return<void> getKeyCharacteristics(const hidl_vec<uint8_t>& keyBlob,
                                       const hidl_vec<uint8_t>& clientId,
                                       const hidl_vec<uint8_t>& appData,
                                       getKeyCharacteristics_cb _hidl_cb) override {
        return km3_dev_->getKeyCharacteristics(keyBlob, clientId, appData, _hidl_cb);
    }

    Return<void> importKey(const hidl_vec<KeyParameter>& params, KeyFormat keyFormat,
                           const hidl_vec<uint8_t>& keyData, importKey_cb _hidl_cb) override {
        return km3_dev_->importKey(params, keyFormat, keyData, _hidl_cb);
    }

    Return<void> exportKey(KeyFormat exportFormat, const hidl_vec<uint8_t>& keyBlob,
                           const hidl_vec<uint8_t>& clientId, const hidl_vec<uint8_t>& appData,
                           exportKey_cb _hidl_cb) override {
        return km3_dev_->exportKey(exportFormat, keyBlob, clientId, appData, _hidl_cb);
    }

    Return<void> attestKey(const hidl_vec<uint8_t>& keyToAttest,
                           const hidl_vec<KeyParameter>& attestParams,
                           attestKey_cb _hidl_cb) override {
        return km3_dev_->attestKey(keyToAttest, attestParams, _hidl_cb);
    }

    Return<void> upgradeKey(const hidl_vec<uint8_t>& keyBlobToUpgrade,
                            const hidl_vec<KeyParameter>& upgradeParams,
                            upgradeKey_cb _hidl_cb) override {
        return km3_dev_->upgradeKey(keyBlobToUpgrade, upgradeParams, _hidl_cb);
    }

    Return<ErrorCode> deleteKey(const hidl_vec<uint8_t>& keyBlob) override {
        return km3_dev_->deleteKey(keyBlob);
    }

    Return<ErrorCode> deleteAllKeys() override { return km3_dev_->deleteAllKeys(); }

    Return<ErrorCode> destroyAttestationIds() override { return km3_dev_->destroyAttestationIds(); }

    Return<void> begin(KeyPurpose purpose, const hidl_vec<uint8_t>& key,
                       const hidl_vec<KeyParameter>& inParams, begin_cb _hidl_cb) override {
        return km3_dev_->begin(purpose, key, inParams, _hidl_cb);
    }

    Return<void> update(uint64_t operationHandle, const hidl_vec<KeyParameter>& inParams,
                        const hidl_vec<uint8_t>& input, update_cb _hidl_cb) override {
        return km3_dev_->update(operationHandle, inParams, input, _hidl_cb);
    }

    Return<void> finish(uint64_t operationHandle, const hidl_vec<KeyParameter>& inParams,
                        const hidl_vec<uint8_t>& input, const hidl_vec<uint8_t>& signature,
                        finish_cb _hidl_cb) override {
        return km3_dev_->finish(operationHandle, inParams, input, signature, _hidl_cb);
    }

    Return<ErrorCode> abort(uint64_t operationHandle) override {
        return km3_dev_->abort(operationHandle);
    }

  private:
    void getVersionIfNeeded();

    sp<IKeymaster3Device> km3_dev_;

    bool haveVersion_ = false;
    uint8_t majorVersion_;
    bool isSecure_;
    bool supportsEllipticCurve_;
    bool supportsSymmetricCryptography_;
    bool supportsAttestation_;
    bool supportsAllDigests_;
    std::string keymasterName_;
    std::string authorName_;
};

}  // namespace keystore

#endif  // KEYSTORE_KEYMASTER_3_H_
