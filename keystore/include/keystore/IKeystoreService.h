/*
 * Copyright (C) 2012 The Android Open Source Project
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

#ifndef KEYSTORE_IKEYSTORESERVICE_H
#define KEYSTORE_IKEYSTORESERVICE_H

#include "keystore.h"
#include "keystore_return_types.h"
#include <binder/IInterface.h>
#include <binder/Parcel.h>
#include <keystore/keymaster_tags.h>
#include <utils/RefBase.h>
#include <vector>

namespace android {

class KeystoreArg : public RefBase {
  public:
    KeystoreArg(const void* data, size_t len);
    ~KeystoreArg();

    const void* data() const;
    size_t size() const;

  private:
    const void* mData;
    size_t mSize;
};

struct MallocDeleter {
    void operator()(uint8_t* p) { free(p); }
};

// struct for serializing the results of begin/update/finish
struct OperationResult : public ::android::Parcelable {
    OperationResult();
    ~OperationResult();
    status_t readFromParcel(const Parcel* in) override;
    status_t writeToParcel(Parcel* out) const override;

    ::keystore::KeyStoreServiceReturnCode resultCode;
    sp<IBinder> token;
    uint64_t handle;
    int inputConsumed;
    ::keystore::hidl_vec<uint8_t> data;
    ::keystore::hidl_vec<::keystore::KeyParameter> outParams;
};

// struct for serializing the results of export
struct ExportResult : public ::android::Parcelable {
    ExportResult();
    ~ExportResult();
    status_t readFromParcel(const Parcel* in) override;
    status_t writeToParcel(Parcel* out) const override;

    ::keystore::KeyStoreServiceReturnCode resultCode;
    ::keystore::hidl_vec<uint8_t> exportData;
};

/*
 * This must be kept manually in sync with frameworks/base's IKeystoreService.java
 */
class IKeystoreService : public IInterface {
  public:
    enum {
        GET_STATE = IBinder::FIRST_CALL_TRANSACTION + 0,
        GET = IBinder::FIRST_CALL_TRANSACTION + 1,
        INSERT = IBinder::FIRST_CALL_TRANSACTION + 2,
        DEL = IBinder::FIRST_CALL_TRANSACTION + 3,
        EXIST = IBinder::FIRST_CALL_TRANSACTION + 4,
        LIST = IBinder::FIRST_CALL_TRANSACTION + 5,
        RESET = IBinder::FIRST_CALL_TRANSACTION + 6,
        ON_USER_PASSWORD_CHANGED = IBinder::FIRST_CALL_TRANSACTION + 7,
        LOCK = IBinder::FIRST_CALL_TRANSACTION + 8,
        UNLOCK = IBinder::FIRST_CALL_TRANSACTION + 9,
        IS_EMPTY = IBinder::FIRST_CALL_TRANSACTION + 10,
        GENERATE = IBinder::FIRST_CALL_TRANSACTION + 11,
        IMPORT = IBinder::FIRST_CALL_TRANSACTION + 12,
        SIGN = IBinder::FIRST_CALL_TRANSACTION + 13,
        VERIFY = IBinder::FIRST_CALL_TRANSACTION + 14,
        GET_PUBKEY = IBinder::FIRST_CALL_TRANSACTION + 15,
        GRANT = IBinder::FIRST_CALL_TRANSACTION + 16,
        UNGRANT = IBinder::FIRST_CALL_TRANSACTION + 17,
        GETMTIME = IBinder::FIRST_CALL_TRANSACTION + 18,
        DUPLICATE = IBinder::FIRST_CALL_TRANSACTION + 19,
        IS_HARDWARE_BACKED = IBinder::FIRST_CALL_TRANSACTION + 20,
        CLEAR_UID = IBinder::FIRST_CALL_TRANSACTION + 21,
        ADD_RNG_ENTROPY = IBinder::FIRST_CALL_TRANSACTION + 22,
        GENERATE_KEY = IBinder::FIRST_CALL_TRANSACTION + 23,
        GET_KEY_CHARACTERISTICS = IBinder::FIRST_CALL_TRANSACTION + 24,
        IMPORT_KEY = IBinder::FIRST_CALL_TRANSACTION + 25,
        EXPORT_KEY = IBinder::FIRST_CALL_TRANSACTION + 26,
        BEGIN = IBinder::FIRST_CALL_TRANSACTION + 27,
        UPDATE = IBinder::FIRST_CALL_TRANSACTION + 28,
        FINISH = IBinder::FIRST_CALL_TRANSACTION + 29,
        ABORT = IBinder::FIRST_CALL_TRANSACTION + 30,
        IS_OPERATION_AUTHORIZED = IBinder::FIRST_CALL_TRANSACTION + 31,
        ADD_AUTH_TOKEN = IBinder::FIRST_CALL_TRANSACTION + 32,
        ON_USER_ADDED = IBinder::FIRST_CALL_TRANSACTION + 33,
        ON_USER_REMOVED = IBinder::FIRST_CALL_TRANSACTION + 34,
        ATTEST_KEY = IBinder::FIRST_CALL_TRANSACTION + 35,
        ATTEST_DEVICE_IDS = IBinder::FIRST_CALL_TRANSACTION + 36,
        ON_DEVICE_OFF_BODY = IBinder::FIRST_CALL_TRANSACTION + 37,
    };

    DECLARE_META_INTERFACE(KeystoreService);

    virtual ::keystore::KeyStoreServiceReturnCode getState(int32_t userId) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode get(const String16& name, int32_t uid,
                                                      ::keystore::hidl_vec<uint8_t>* item) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode insert(const String16& name,
                                                         const ::keystore::hidl_vec<uint8_t>& item,
                                                         int uid, int32_t flags) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode del(const String16& name, int uid) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode exist(const String16& name, int uid) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode list(const String16& prefix, int uid,
                                                       Vector<String16>* matches) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode reset() = 0;

    virtual ::keystore::KeyStoreServiceReturnCode
    onUserPasswordChanged(int32_t userId, const String16& newPassword) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode lock(int32_t userId) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode unlock(int32_t userId,
                                                         const String16& password) = 0;

    virtual bool isEmpty(int32_t userId) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode generate(const String16& name, int32_t uid,
                                                           int32_t keyType, int32_t keySize,
                                                           int32_t flags,
                                                           Vector<sp<KeystoreArg>>* args) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode import(const String16& name,
                                                         const ::keystore::hidl_vec<uint8_t>& data,
                                                         int uid, int32_t flags) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode sign(const String16& name,
                                                       const ::keystore::hidl_vec<uint8_t>& data,
                                                       ::keystore::hidl_vec<uint8_t>* out) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode
    verify(const String16& name, const ::keystore::hidl_vec<uint8_t>& data,
           const ::keystore::hidl_vec<uint8_t>& signature) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode
    get_pubkey(const String16& name, ::keystore::hidl_vec<uint8_t>* pubKey) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode grant(const String16& name,
                                                        int32_t granteeUid) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode ungrant(const String16& name,
                                                          int32_t granteeUid) = 0;

    virtual int64_t getmtime(const String16& name, int32_t uid) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode
    duplicate(const String16& srcKey, int32_t srcUid, const String16& destKey, int32_t destUid) = 0;

    virtual int32_t is_hardware_backed(const String16& keyType) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode clear_uid(int64_t uid) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode
    addRngEntropy(const ::keystore::hidl_vec<uint8_t>& entropy) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode
    generateKey(const String16& name, const ::keystore::hidl_vec<::keystore::KeyParameter>& params,
                const ::keystore::hidl_vec<uint8_t>& entropy, int uid, int flags,
                ::keystore::KeyCharacteristics* outCharacteristics) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode
    getKeyCharacteristics(const String16& name, const ::keystore::hidl_vec<uint8_t>& clientId,
                          const ::keystore::hidl_vec<uint8_t>& appData, int32_t uid,
                          ::keystore::KeyCharacteristics* outCharacteristics) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode
    importKey(const String16& name, const ::keystore::hidl_vec<::keystore::KeyParameter>& params,
              ::keystore::KeyFormat format, const ::keystore::hidl_vec<uint8_t>& key, int uid,
              int flags, ::keystore::KeyCharacteristics* outCharacteristics) = 0;

    virtual void exportKey(const String16& name, ::keystore::KeyFormat format,
                           const ::keystore::hidl_vec<uint8_t>& clientId,
                           const ::keystore::hidl_vec<uint8_t>& appData, int uid,
                           ExportResult* result) = 0;

    virtual void begin(const sp<IBinder>& apptoken, const String16& name,
                       ::keystore::KeyPurpose purpose, bool pruneable,
                       const ::keystore::hidl_vec<::keystore::KeyParameter>& params,
                       const ::keystore::hidl_vec<uint8_t>& entropy, int32_t uid,
                       OperationResult* opResult) = 0;

    virtual void update(const sp<IBinder>& token,
                        const ::keystore::hidl_vec<::keystore::KeyParameter>& params,
                        const ::keystore::hidl_vec<uint8_t>& data, OperationResult* opResult) = 0;

    virtual void finish(const sp<IBinder>& token,
                        const ::keystore::hidl_vec<::keystore::KeyParameter>& params,
                        const ::keystore::hidl_vec<uint8_t>& signature,
                        const ::keystore::hidl_vec<uint8_t>& entropy,
                        OperationResult* opResult) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode abort(const sp<IBinder>& handle) = 0;

    virtual bool isOperationAuthorized(const sp<IBinder>& handle) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode addAuthToken(const uint8_t* token,
                                                               size_t length) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode onUserAdded(int32_t userId, int32_t parentId) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode onUserRemoved(int32_t userId) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode
    attestKey(const String16& name, const ::keystore::hidl_vec<::keystore::KeyParameter>& params,
              ::keystore::hidl_vec<::keystore::hidl_vec<uint8_t>>* outChain) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode attestDeviceIds(
            const ::keystore::hidl_vec<::keystore::KeyParameter>& params,
            ::keystore::hidl_vec<::keystore::hidl_vec<uint8_t>>* outChain) = 0;

    virtual ::keystore::KeyStoreServiceReturnCode onDeviceOffBody() = 0;
};

// ----------------------------------------------------------------------------

class BnKeystoreService : public BnInterface<IKeystoreService> {
  public:
    virtual status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply,
                                uint32_t flags = 0);
};

}  // namespace android

#endif
