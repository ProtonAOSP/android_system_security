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

#include <hardware/hw_auth_token.h>
#include <hardware/keymaster1.h>
#include <binder/Binder.h>
#include <binder/IBinder.h>
#include <utils/LruCache.h>
#include <utils/StrongPointer.h>
#include <map>
#include <vector>

namespace android {

struct keymaster_key_characteristics_t_Delete {
    void operator()(keymaster_key_characteristics_t* characteristics) const {
        keymaster_free_characteristics(characteristics);
        delete characteristics;
    }
};
typedef std::unique_ptr<keymaster_key_characteristics_t, keymaster_key_characteristics_t_Delete>
    Unique_keymaster_key_characteristics;

/**
 * OperationMap handles the translation of keymaster_operation_handle_t's and
 * keymaster1_device_t's to opaque binder tokens that can be used to reference
 * that operation at a later time by applications. It also does LRU tracking
 * for operation pruning and keeps a mapping of clients to operations to allow
 * for graceful handling of application death.
 */
class OperationMap {
public:
    OperationMap(IBinder::DeathRecipient* deathRecipient);
    sp<IBinder> addOperation(keymaster_operation_handle_t handle, uint64_t keyid,
                             keymaster_purpose_t purpose, const keymaster1_device_t* dev,
                             sp<IBinder> appToken, keymaster_key_characteristics_t* characteristics,
                             bool pruneable);
    bool getOperation(sp<IBinder> token, keymaster_operation_handle_t* outHandle,
                      uint64_t* outKeyid, keymaster_purpose_t* outPurpose,
                      const keymaster1_device_t** outDev,
                      const keymaster_key_characteristics_t** outCharacteristics);
    bool removeOperation(sp<IBinder> token);
    bool hasPruneableOperation() const;
    size_t getPruneableOperationCount() const;
    bool getOperationAuthToken(sp<IBinder> token, const hw_auth_token_t** outToken);
    bool setOperationAuthToken(sp<IBinder> token, const hw_auth_token_t* authToken);
    sp<IBinder> getOldestPruneableOperation();
    std::vector<sp<IBinder>> getOperationsForToken(sp<IBinder> appToken);

private:
    void updateLru(sp<IBinder> token);
    void removeOperationTracking(sp<IBinder> token, sp<IBinder> appToken);
    struct Operation {
        Operation();
        Operation(keymaster_operation_handle_t handle, uint64_t keyid, keymaster_purpose_t purpose,
                  const keymaster1_device_t* device,
                  keymaster_key_characteristics_t* characteristics, sp<IBinder> appToken);
        keymaster_operation_handle_t handle;
        uint64_t keyid;
        keymaster_purpose_t purpose;
        const keymaster1_device_t* device;
        Unique_keymaster_key_characteristics characteristics;
        sp<IBinder> appToken;
        std::unique_ptr<hw_auth_token_t> authToken;
    };
    std::map<sp<IBinder>, struct Operation> mMap;
    std::vector<sp<IBinder>> mLru;
    std::map<sp<IBinder>, std::vector<sp<IBinder>>> mAppTokenMap;
    IBinder::DeathRecipient* mDeathRecipient;
};
} // namespace android
#endif
