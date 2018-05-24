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
#define LOG_TAG "KeystoreOperation"

#include "operation.h"

#include <algorithm>

namespace keystore {

OperationMap::OperationMap(IBinder::DeathRecipient* deathRecipient)
    : mDeathRecipient(deathRecipient) {}

sp<IBinder> OperationMap::addOperation(uint64_t handle, uint64_t keyid, KeyPurpose purpose,
                                       const sp<Keymaster>& dev, const sp<IBinder>& appToken,
                                       KeyCharacteristics&& characteristics,
                                       const hidl_vec<KeyParameter>& params, bool pruneable) {
    sp<IBinder> token = new ::android::BBinder();
    mMap.emplace(token, Operation(handle, keyid, purpose, dev, std::move(characteristics), appToken,
                                  params));
    if (pruneable) mLru.push_back(token);
    if (mAppTokenMap.find(appToken) == mAppTokenMap.end()) appToken->linkToDeath(mDeathRecipient);
    mAppTokenMap[appToken].push_back(token);
    return token;
}

NullOr<const Operation&> OperationMap::getOperation(const sp<IBinder>& token) {
    auto entry = mMap.find(token);
    if (entry == mMap.end()) return {};

    updateLru(token);
    return entry->second;
}

void OperationMap::updateLru(const sp<IBinder>& token) {
    auto lruEntry = std::find(mLru.begin(), mLru.end(), token);
    if (lruEntry != mLru.end()) {
        mLru.erase(lruEntry);
        mLru.push_back(token);
    }
}

NullOr<Operation> OperationMap::removeOperation(const sp<IBinder>& token, bool wasSuccessful) {
    auto entry = mMap.find(token);
    if (entry == mMap.end()) return {};

    Operation op = std::move(entry->second);
    uploadOpAsProto(op, wasSuccessful);
    mMap.erase(entry);

    auto lruEntry = std::find(mLru.begin(), mLru.end(), token);
    if (lruEntry != mLru.end()) mLru.erase(lruEntry);
    removeOperationTracking(token, op.appToken);
    return op;
}

void OperationMap::removeOperationTracking(const sp<IBinder>& token, const sp<IBinder>& appToken) {
    auto appEntry = mAppTokenMap.find(appToken);
    if (appEntry == mAppTokenMap.end()) {
        ALOGE("Entry for %p contains unmapped application token %p", token.get(), appToken.get());
        return;
    }
    auto tokenEntry = std::find(appEntry->second.begin(), appEntry->second.end(), token);
    appEntry->second.erase(tokenEntry);
    // Stop listening for death if all operations tied to the token have finished.
    if (appEntry->second.size() == 0) {
        appToken->unlinkToDeath(mDeathRecipient);
        mAppTokenMap.erase(appEntry);
    }
}

bool OperationMap::hasPruneableOperation() const {
    return !mLru.empty();
}

size_t OperationMap::getPruneableOperationCount() const {
    return mLru.size();
}

sp<IBinder> OperationMap::getOldestPruneableOperation() {
    if (!hasPruneableOperation()) return sp<IBinder>(nullptr);
    return mLru.front();
}

void OperationMap::setOperationAuthToken(const sp<IBinder>& token, HardwareAuthToken authToken) {
    auto entry = mMap.find(token);
    if (entry == mMap.end()) return;

    entry->second.authToken = std::move(authToken);
}

void OperationMap::setOperationVerificationToken(const sp<IBinder>& token,
                                                 VerificationToken verificationToken) {
    auto entry = mMap.find(token);
    if (entry == mMap.end()) return;

    entry->second.verificationToken = std::move(verificationToken);
}

std::vector<sp<IBinder>> OperationMap::getOperationsForToken(const sp<IBinder>& appToken) {
    auto appEntry = mAppTokenMap.find(appToken);
    if (appEntry == mAppTokenMap.end()) return {};
    return appEntry->second;
}

}  // namespace keystore
