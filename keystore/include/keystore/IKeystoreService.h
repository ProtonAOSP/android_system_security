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

#include <hardware/keymaster_defs.h>
#include <utils/RefBase.h>
#include <binder/IInterface.h>
#include <binder/Parcel.h>
#include <vector>

namespace android {

class KeystoreArg : public RefBase {
public:
    KeystoreArg(const void *data, size_t len);
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

// struct for serializing/deserializing a list of keymaster_key_param_t's
struct KeymasterArguments {
    KeymasterArguments();
    ~KeymasterArguments();
    void readFromParcel(const Parcel& in);
    void writeToParcel(Parcel* out) const;

    std::vector<keymaster_key_param_t> params;
};

// struct for serializing the results of begin/update/finish
struct OperationResult {
    OperationResult();
    ~OperationResult();
    void readFromParcel(const Parcel& in);
    void writeToParcel(Parcel* out) const;

    int resultCode;
    sp<IBinder> token;
    keymaster_operation_handle_t handle;
    int inputConsumed;
    std::unique_ptr<uint8_t[], MallocDeleter> data;
    size_t dataLength;
    KeymasterArguments outParams;
};

// struct for serializing the results of export
struct ExportResult {
    ExportResult();
    ~ExportResult();
    void readFromParcel(const Parcel& in);
    void writeToParcel(Parcel* out) const;

    int resultCode;
    std::unique_ptr<uint8_t[], MallocDeleter> exportData;
    size_t dataLength;
};

// struct for serializing keymaster_key_characteristics_t's
struct KeyCharacteristics {
    KeyCharacteristics();
    ~KeyCharacteristics();
    void readFromParcel(const Parcel& in);
    void writeToParcel(Parcel* out) const;

    keymaster_key_characteristics_t characteristics;
};

bool readKeymasterArgumentFromParcel(const Parcel& in, keymaster_key_param_t* out);
void writeKeymasterArgumentToParcel(const keymaster_key_param_t& param, Parcel* out);

/*
 * This must be kept manually in sync with frameworks/base's IKeystoreService.java
 */
class IKeystoreService: public IInterface {
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
    };

    DECLARE_META_INTERFACE(KeystoreService);

    virtual int32_t getState(int32_t userId) = 0;

    virtual int32_t get(const String16& name, uint8_t** item, size_t* itemLength) = 0;

    virtual int32_t insert(const String16& name, const uint8_t* item, size_t itemLength, int uid,
            int32_t flags) = 0;

    virtual int32_t del(const String16& name, int uid) = 0;

    virtual int32_t exist(const String16& name, int uid) = 0;

    virtual int32_t list(const String16& prefix, int uid, Vector<String16>* matches) = 0;

    virtual int32_t reset() = 0;

    virtual int32_t onUserPasswordChanged(int32_t userId, const String16& newPassword) = 0;

    virtual int32_t lock(int32_t userId) = 0;

    virtual int32_t unlock(int32_t userId, const String16& password) = 0;

    virtual bool isEmpty(int32_t userId) = 0;

    virtual int32_t generate(const String16& name, int32_t uid, int32_t keyType, int32_t keySize,
            int32_t flags, Vector<sp<KeystoreArg> >* args) = 0;

    virtual int32_t import(const String16& name, const uint8_t* data, size_t length, int uid,
            int32_t flags) = 0;

    virtual int32_t sign(const String16& name, const uint8_t* data, size_t length, uint8_t** out,
            size_t* outLength) = 0;

    virtual int32_t verify(const String16& name, const uint8_t* data, size_t dataLength,
            const uint8_t* signature, size_t signatureLength) = 0;

    virtual int32_t get_pubkey(const String16& name, uint8_t** pubkey, size_t* pubkeyLength) = 0;

    virtual int32_t grant(const String16& name, int32_t granteeUid) = 0;

    virtual int32_t ungrant(const String16& name, int32_t granteeUid) = 0;

    virtual int64_t getmtime(const String16& name) = 0;

    virtual int32_t duplicate(const String16& srcKey, int32_t srcUid, const String16& destKey,
            int32_t destUid) = 0;

    virtual int32_t is_hardware_backed(const String16& keyType) = 0;

    virtual int32_t clear_uid(int64_t uid) = 0;

    virtual int32_t addRngEntropy(const uint8_t* data, size_t dataLength) = 0;

    virtual int32_t generateKey(const String16& name, const KeymasterArguments& params,
                                const uint8_t* entropy, size_t entropyLength, int uid, int flags,
                                KeyCharacteristics* outCharacteristics) = 0;

    virtual int32_t getKeyCharacteristics(const String16& name,
                                          const keymaster_blob_t* clientId,
                                          const keymaster_blob_t* appData,
                                          KeyCharacteristics* outCharacteristics) = 0;

    virtual int32_t importKey(const String16& name, const KeymasterArguments&  params,
                              keymaster_key_format_t format, const uint8_t *keyData,
                              size_t keyLength, int uid, int flags,
                              KeyCharacteristics* outCharacteristics) = 0;

    virtual void exportKey(const String16& name, keymaster_key_format_t format,
                           const keymaster_blob_t* clientId,
                           const keymaster_blob_t* appData, ExportResult* result) = 0;

    virtual void begin(const sp<IBinder>& apptoken, const String16& name,
                       keymaster_purpose_t purpose, bool pruneable,
                       const KeymasterArguments& params, const uint8_t* entropy,
                       size_t entropyLength, OperationResult* result) = 0;

    virtual void update(const sp<IBinder>& token, const KeymasterArguments& params,
                        const uint8_t* data, size_t dataLength, OperationResult* result) = 0;

    virtual void finish(const sp<IBinder>& token, const KeymasterArguments& params,
                        const uint8_t* signature, size_t signatureLength,
                        const uint8_t* entropy, size_t entropyLength,
                        OperationResult* result) = 0;

    virtual int32_t abort(const sp<IBinder>& handle) = 0;

    virtual bool isOperationAuthorized(const sp<IBinder>& handle) = 0;

    virtual int32_t addAuthToken(const uint8_t* token, size_t length) = 0;

    virtual int32_t onUserAdded(int32_t userId, int32_t parentId) = 0;

    virtual int32_t onUserRemoved(int32_t userId) = 0;

};

// ----------------------------------------------------------------------------

class BnKeystoreService: public BnInterface<IKeystoreService> {
public:
    virtual status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply,
            uint32_t flags = 0);
};

} // namespace android

#endif
