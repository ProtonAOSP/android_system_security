/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef KEYSTORE_OPERATION_H_
#define KEYSTORE_OPERATION_H_

#include <binder/Binder.h>
#include <binder/IBinder.h>
#include <keystore/keymaster_tags.h>
#include <map>
#include <utils/LruCache.h>
#include <utils/StrongPointer.h>
#include <vector>

namespace keystore {

using ::android::IBinder;
using ::android::sp;

/**
 * OperationMap handles the translation of uint64_t's and keymaster2_device_t's to opaque binder
 * tokens that can be used to reference that operation at a later time by applications. It also does
 * LRU tracking for operation pruning and keeps a mapping of clients to operations to allow for
 * graceful handling of application death.
 */

class OperationMap {
    typedef ::android::sp<::android::hardware::keymaster::V3_0::IKeymasterDevice> km_device_t;

  public:
    explicit OperationMap(IBinder::DeathRecipient* deathRecipient);
    android::sp<android::IBinder> addOperation(uint64_t handle, uint64_t keyid, KeyPurpose purpose,
                                               const km_device_t& dev,
                                               const android::sp<android::IBinder>& appToken,
                                               KeyCharacteristics&& characteristics,
                                               bool pruneable);
    bool getOperation(const android::sp<android::IBinder>& token, uint64_t* outHandle,
                      uint64_t* outKeyid, KeyPurpose* outPurpose, km_device_t* outDev,
                      const KeyCharacteristics** outCharacteristics);
    bool removeOperation(const android::sp<android::IBinder>& token);
    bool hasPruneableOperation() const;
    size_t getOperationCount() const { return mMap.size(); }
    size_t getPruneableOperationCount() const;
    bool getOperationAuthToken(const android::sp<android::IBinder>& token,
                               const HardwareAuthToken** outToken);
    bool setOperationAuthToken(const android::sp<android::IBinder>& token,
                               const HardwareAuthToken* authToken);
    android::sp<android::IBinder> getOldestPruneableOperation();
    std::vector<android::sp<android::IBinder>>
    getOperationsForToken(const android::sp<android::IBinder>& appToken);

  private:
    void updateLru(const android::sp<android::IBinder>& token);
    void removeOperationTracking(const android::sp<android::IBinder>& token,
                                 const android::sp<android::IBinder>& appToken);
    struct Operation {
        Operation();
        Operation(uint64_t handle, uint64_t keyid, KeyPurpose purpose, const km_device_t& device,
                  KeyCharacteristics&& characteristics, android::sp<android::IBinder> appToken);
        uint64_t handle;
        uint64_t keyid;
        KeyPurpose purpose;
        km_device_t device;
        KeyCharacteristics characteristics;
        android::sp<android::IBinder> appToken;
        std::unique_ptr<HardwareAuthToken> authToken;
    };
    std::map<android::sp<android::IBinder>, Operation> mMap;
    std::vector<android::sp<android::IBinder>> mLru;
    std::map<android::sp<android::IBinder>, std::vector<android::sp<android::IBinder>>>
        mAppTokenMap;
    android::IBinder::DeathRecipient* mDeathRecipient;
};

}  // namespace keystore

#endif
