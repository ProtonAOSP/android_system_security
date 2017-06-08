/*
**
** Copyright 2008, The Android Open Source Project
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

#include <stdint.h>
#include <sys/limits.h>
#include <sys/types.h>

#include <algorithm>
#include <limits>

#define LOG_TAG "KeystoreService"
#include <utils/Log.h>

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>

#include <keystore/IKeystoreService.h>
#include <keystore/keystore_hidl_support.h>

#include "keystore_aidl_hidl_marshalling_utils.h"

namespace android {
using namespace ::keystore;

const ssize_t MAX_GENERATE_ARGS = 3;

KeystoreArg::KeystoreArg(const void* data, size_t len) : mData(data), mSize(len) {}

KeystoreArg::~KeystoreArg() {}

const void* KeystoreArg::data() const {
    return mData;
}

size_t KeystoreArg::size() const {
    return mSize;
}

OperationResult::OperationResult() : resultCode(), token(), handle(0), inputConsumed(0), data() {}

OperationResult::~OperationResult() {}

status_t OperationResult::readFromParcel(const Parcel* inn) {
    const Parcel& in = *inn;
    resultCode = ErrorCode(in.readInt32());
    token = in.readStrongBinder();
    handle = static_cast<uint64_t>(in.readInt64());
    inputConsumed = in.readInt32();
    data = readKeymasterBlob(in);
    outParams = readParamSetFromParcel(in);
    return OK;
}

status_t OperationResult::writeToParcel(Parcel* out) const {
    out->writeInt32(resultCode);
    out->writeStrongBinder(token);
    out->writeInt64(handle);
    out->writeInt32(inputConsumed);
    writeKeymasterBlob(data, out);
    writeParamSetToParcel(outParams, out);
    return OK;
}

ExportResult::ExportResult() : resultCode() {}

ExportResult::~ExportResult() {}

status_t ExportResult::readFromParcel(const Parcel* inn) {
    const Parcel& in = *inn;
    resultCode = ErrorCode(in.readInt32());
    exportData = readKeymasterBlob(in);
    return OK;
}

status_t ExportResult::writeToParcel(Parcel* out) const {
    out->writeInt32(resultCode);
    writeKeymasterBlob(exportData, out);
    return OK;
}

/**
 * Read a byte array from in. The data at *data is still owned by the parcel
 */
static void readByteArray(const Parcel& in, const uint8_t** data, size_t* length) {
    ssize_t slength = in.readInt32();
    if (slength > 0) {
        *data = reinterpret_cast<const uint8_t*>(in.readInplace(slength));
        if (*data) {
            *length = static_cast<size_t>(slength);
        } else {
            *length = 0;
        }
    } else {
        *data = NULL;
        *length = 0;
    }
}

class BpKeystoreService : public BpInterface<IKeystoreService> {
  public:
    explicit BpKeystoreService(const sp<IBinder>& impl) : BpInterface<IKeystoreService>(impl) {}

    // test ping
    KeyStoreServiceReturnCode getState(int32_t userId) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeInt32(userId);
        status_t status = remote()->transact(BnKeystoreService::GET_STATE, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("getState() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        ResponseCode ret = ResponseCode(reply.readInt32());
        if (err < 0) {
            ALOGD("getState() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        return ret;
    }

    KeyStoreServiceReturnCode get(const String16& name, int32_t uid,
                                  hidl_vec<uint8_t>* item) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(uid);
        status_t status = remote()->transact(BnKeystoreService::GET, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("get() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("get() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        auto resultItem = readBlobAsByteArray(reply);
        if (item) *item = resultItem.value();
        return ResponseCode(reply.readInt32());
    }

    KeyStoreServiceReturnCode insert(const String16& name, const hidl_vec<uint8_t>& item, int uid,
                                     int32_t flags) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        writeBlobAsByteArray(item, &data);
        data.writeInt32(uid);
        data.writeInt32(flags);
        status_t status = remote()->transact(BnKeystoreService::INSERT, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("import() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("import() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        return ResponseCode(reply.readInt32());
    }

    KeyStoreServiceReturnCode del(const String16& name, int uid) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(uid);
        status_t status = remote()->transact(BnKeystoreService::DEL, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("del() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("del() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        return ResponseCode(reply.readInt32());
    }

    KeyStoreServiceReturnCode exist(const String16& name, int uid) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(uid);
        status_t status = remote()->transact(BnKeystoreService::EXIST, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("exist() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("exist() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        return ResponseCode(reply.readInt32());
    }

    KeyStoreServiceReturnCode list(const String16& prefix, int uid,
                                   Vector<String16>* matches) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(prefix);
        data.writeInt32(uid);
        status_t status = remote()->transact(BnKeystoreService::LIST, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("list() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        int32_t numMatches = reply.readInt32();
        for (int32_t i = 0; i < numMatches; i++) {
            matches->push(reply.readString16());
        }
        if (err < 0) {
            ALOGD("list() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        return ResponseCode(reply.readInt32());
    }

    KeyStoreServiceReturnCode reset() override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        status_t status = remote()->transact(BnKeystoreService::RESET, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("reset() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("reset() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        return ResponseCode(reply.readInt32());
    }

    KeyStoreServiceReturnCode onUserPasswordChanged(int32_t userId,
                                                    const String16& password) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeInt32(userId);
        data.writeString16(password);
        status_t status =
            remote()->transact(BnKeystoreService::ON_USER_PASSWORD_CHANGED, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("onUserPasswordChanged() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("onUserPasswordChanged() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        return ResponseCode(reply.readInt32());
    }

    KeyStoreServiceReturnCode lock(int32_t userId) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeInt32(userId);
        status_t status = remote()->transact(BnKeystoreService::LOCK, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("lock() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("lock() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        return ResponseCode(reply.readInt32());
    }

    KeyStoreServiceReturnCode unlock(int32_t userId, const String16& password) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeInt32(userId);
        data.writeString16(password);
        status_t status = remote()->transact(BnKeystoreService::UNLOCK, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("unlock() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("unlock() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        return ResponseCode(reply.readInt32());
    }

    bool isEmpty(int32_t userId) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeInt32(userId);
        status_t status = remote()->transact(BnKeystoreService::IS_EMPTY, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("isEmpty() could not contact remote: %d\n", status);
            return false;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("isEmpty() caught exception %d\n", err);
            return false;
        }
        return reply.readInt32() != 0;
    }

    KeyStoreServiceReturnCode generate(const String16& name, int32_t uid, int32_t keyType,
                                       int32_t keySize, int32_t flags,
                                       Vector<sp<KeystoreArg>>* args) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(uid);
        data.writeInt32(keyType);
        data.writeInt32(keySize);
        data.writeInt32(flags);
        data.writeInt32(1);
        data.writeInt32(args->size());
        for (Vector<sp<KeystoreArg>>::iterator it = args->begin(); it != args->end(); ++it) {
            sp<KeystoreArg> item = *it;
            size_t keyLength = item->size();
            data.writeInt32(keyLength);
            void* buf = data.writeInplace(keyLength);
            memcpy(buf, item->data(), keyLength);
        }
        status_t status = remote()->transact(BnKeystoreService::GENERATE, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("generate() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("generate() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        return ResponseCode(reply.readInt32());
    }

    KeyStoreServiceReturnCode import(const String16& name, const hidl_vec<uint8_t>& key, int uid,
                                     int flags) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        writeBlobAsByteArray(key, &data);
        data.writeInt32(uid);
        data.writeInt32(flags);
        status_t status = remote()->transact(BnKeystoreService::IMPORT, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("import() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("import() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        return ResponseCode(reply.readInt32());
    }

    KeyStoreServiceReturnCode sign(const String16& name, const hidl_vec<uint8_t>& in,
                                   hidl_vec<uint8_t>* out) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        writeBlobAsByteArray(in, &data);
        status_t status = remote()->transact(BnKeystoreService::SIGN, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("import() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("import() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        auto outBlob = readBlobAsByteArray(reply);
        if (out) {
            // don't need to check outBlob.isOk()
            // if !outBlob.isOk() the wrapped value is default constructed and therefore empty,
            // as expected.
            *out = outBlob.value();
        }
        return ResponseCode(reply.readInt32());
    }

    KeyStoreServiceReturnCode verify(const String16& name, const hidl_vec<uint8_t>& in,
                                     const hidl_vec<uint8_t>& signature) override {
        Parcel data, reply;

        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        writeBlobAsByteArray(in, &data);
        writeBlobAsByteArray(signature, &data);
        status_t status = remote()->transact(BnKeystoreService::VERIFY, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("verify() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("verify() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        return ResponseCode(reply.readInt32());
    }

    KeyStoreServiceReturnCode get_pubkey(const String16& name, hidl_vec<uint8_t>* pubkey) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        status_t status = remote()->transact(BnKeystoreService::GET_PUBKEY, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("get_pubkey() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("get_pubkey() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        auto resultKey = readBlobAsByteArray(reply);
        if (pubkey) *pubkey = resultKey.value();
        return ResponseCode(reply.readInt32());
    }

    String16 grant(const String16& name, int32_t granteeUid) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(granteeUid);
        status_t status = remote()->transact(BnKeystoreService::GRANT, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("grant() could not contact remote: %d\n", status);
            return String16();
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("grant() caught exception %d\n", err);
            return String16();
        }
        return reply.readString16();
    }

    KeyStoreServiceReturnCode ungrant(const String16& name, int32_t granteeUid) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(granteeUid);
        status_t status = remote()->transact(BnKeystoreService::UNGRANT, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("ungrant() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("ungrant() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        return ResponseCode(reply.readInt32());
    }

    int64_t getmtime(const String16& name, int32_t uid) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(uid);
        status_t status = remote()->transact(BnKeystoreService::GETMTIME, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("getmtime() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("getmtime() caught exception %d\n", err);
            return -1;
        }
        return reply.readInt64();
    }

    KeyStoreServiceReturnCode duplicate(const String16& srcKey, int32_t srcUid,
                                        const String16& destKey, int32_t destUid) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(srcKey);
        data.writeInt32(srcUid);
        data.writeString16(destKey);
        data.writeInt32(destUid);
        status_t status = remote()->transact(BnKeystoreService::DUPLICATE, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("duplicate() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("duplicate() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        return ResponseCode(reply.readInt32());
    }

    int32_t is_hardware_backed(const String16& keyType) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(keyType);
        status_t status = remote()->transact(BnKeystoreService::IS_HARDWARE_BACKED, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("is_hardware_backed() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("is_hardware_backed() caught exception %d\n", err);
            return -1;
        }
        return reply.readInt32();
    }

    KeyStoreServiceReturnCode clear_uid(int64_t uid) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeInt64(uid);
        status_t status = remote()->transact(BnKeystoreService::CLEAR_UID, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("clear_uid() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("clear_uid() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        return ResponseCode(reply.readInt32());
    }

    KeyStoreServiceReturnCode addRngEntropy(const hidl_vec<uint8_t>& entropy) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        writeBlobAsByteArray(entropy, &data);
        status_t status = remote()->transact(BnKeystoreService::ADD_RNG_ENTROPY, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("addRngEntropy() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("addRngEntropy() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        return ResponseCode(reply.readInt32());
    };

    KeyStoreServiceReturnCode generateKey(const String16& name,
                                          const hidl_vec<KeyParameter>& params,
                                          const hidl_vec<uint8_t>& entropy, int uid, int flags,
                                          KeyCharacteristics* outCharacteristics) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        nullable(writeParamSetToParcel, params, &data);
        writeBlobAsByteArray(entropy, &data);
        data.writeInt32(uid);
        data.writeInt32(flags);
        status_t status = remote()->transact(BnKeystoreService::GENERATE_KEY, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("generateKey() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        ResponseCode ret = ResponseCode(reply.readInt32());
        if (err < 0) {
            ALOGD("generateKey() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        if (outCharacteristics) {
            *outCharacteristics = nullable(readKeyCharacteristicsFromParcel, reply).value();
        }
        return ret;
    }
    KeyStoreServiceReturnCode
    getKeyCharacteristics(const String16& name, const hidl_vec<uint8_t>& clientId,
                          const hidl_vec<uint8_t>& appData, int32_t uid,
                          KeyCharacteristics* outCharacteristics) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        writeBlobAsByteArray(clientId, &data);
        writeBlobAsByteArray(appData, &data);
        data.writeInt32(uid);
        status_t status =
            remote()->transact(BnKeystoreService::GET_KEY_CHARACTERISTICS, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("getKeyCharacteristics() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        ResponseCode ret = ResponseCode(reply.readInt32());
        if (err < 0) {
            ALOGD("getKeyCharacteristics() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        if (outCharacteristics) {
            *outCharacteristics = nullable(readKeyCharacteristicsFromParcel, reply).value();
        }
        return ret;
    }
    KeyStoreServiceReturnCode importKey(const String16& name, const hidl_vec<KeyParameter>& params,
                                        KeyFormat format, const hidl_vec<uint8_t>& keyData, int uid,
                                        int flags,
                                        KeyCharacteristics* outCharacteristics) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        nullable(writeParamSetToParcel, params, &data);
        data.writeInt32(uint32_t(format));
        writeBlobAsByteArray(keyData, &data);
        data.writeInt32(uid);
        data.writeInt32(flags);
        status_t status = remote()->transact(BnKeystoreService::IMPORT_KEY, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("importKey() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        ResponseCode ret = ResponseCode(reply.readInt32());
        if (err < 0) {
            ALOGD("importKey() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        if (outCharacteristics) {
            *outCharacteristics = nullable(readKeyCharacteristicsFromParcel, reply).value();
        }
        return ret;
    }

    void exportKey(const String16& name, KeyFormat format, const hidl_vec<uint8_t>& clientId,
                   const hidl_vec<uint8_t>& appData, int32_t uid, ExportResult* result) override {
        if (!result) {
            return;
        }

        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(int32_t(format));
        writeBlobAsByteArray(clientId, &data);
        writeBlobAsByteArray(appData, &data);
        data.writeInt32(uid);
        status_t status = remote()->transact(BnKeystoreService::EXPORT_KEY, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("exportKey() could not contact remote: %d\n", status);
            result->resultCode = ResponseCode::SYSTEM_ERROR;
            return;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("exportKey() caught exception %d\n", err);
            result->resultCode = ResponseCode::SYSTEM_ERROR;
            return;
        }

        reply.readParcelable(result);
    }

    void begin(const sp<IBinder>& appToken, const String16& name, KeyPurpose purpose,
               bool pruneable, const hidl_vec<KeyParameter>& params,
               const hidl_vec<uint8_t>& entropy, int32_t uid, OperationResult* result) override {
        if (!result) {
            return;
        }
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeStrongBinder(appToken);
        data.writeString16(name);
        data.writeInt32(int32_t(purpose));
        data.writeInt32(pruneable ? 1 : 0);
        nullable(writeParamSetToParcel, params, &data);
        writeBlobAsByteArray(entropy, &data);
        data.writeInt32(uid);
        status_t status = remote()->transact(BnKeystoreService::BEGIN, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("begin() could not contact remote: %d\n", status);
            result->resultCode = ResponseCode::SYSTEM_ERROR;
            return;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("begin() caught exception %d\n", err);
            result->resultCode = ResponseCode::SYSTEM_ERROR;
            return;
        }

        reply.readParcelable(result);
    }

    void update(const sp<IBinder>& token, const hidl_vec<KeyParameter>& params,
                const hidl_vec<uint8_t>& opData, OperationResult* result) override {
        if (!result) {
            return;
        }
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeStrongBinder(token);
        nullable(writeParamSetToParcel, params, &data);
        writeBlobAsByteArray(opData, &data);
        status_t status = remote()->transact(BnKeystoreService::UPDATE, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("update() could not contact remote: %d\n", status);
            result->resultCode = ResponseCode::SYSTEM_ERROR;
            return;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("update() caught exception %d\n", err);
            result->resultCode = ResponseCode::SYSTEM_ERROR;
            return;
        }

        reply.readParcelable(result);
    }

    void finish(const sp<IBinder>& token, const hidl_vec<KeyParameter>& params,
                const hidl_vec<uint8_t>& signature, const hidl_vec<uint8_t>& entropy,
                OperationResult* result) override {
        if (!result) {
            return;
        }
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeStrongBinder(token);
        nullable(writeParamSetToParcel, params, &data);
        writeBlobAsByteArray(signature, &data);
        writeBlobAsByteArray(entropy, &data);
        status_t status = remote()->transact(BnKeystoreService::FINISH, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("finish() could not contact remote: %d\n", status);
            result->resultCode = ResponseCode::SYSTEM_ERROR;
            return;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("finish() caught exception %d\n", err);
            result->resultCode = ResponseCode::SYSTEM_ERROR;
            return;
        }

        reply.readParcelable(result);
    }

    KeyStoreServiceReturnCode abort(const sp<IBinder>& token) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeStrongBinder(token);
        status_t status = remote()->transact(BnKeystoreService::ABORT, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("abort() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("abort() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        return ResponseCode(reply.readInt32());
    }

    bool isOperationAuthorized(const sp<IBinder>& token) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeStrongBinder(token);
        status_t status =
            remote()->transact(BnKeystoreService::IS_OPERATION_AUTHORIZED, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("isOperationAuthorized() could not contact remote: %d\n", status);
            return false;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("isOperationAuthorized() caught exception %d\n", err);
            return false;
        }
        return reply.readInt32() == 1;
    }

    KeyStoreServiceReturnCode addAuthToken(const uint8_t* token, size_t length) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeByteArray(length, token);
        status_t status = remote()->transact(BnKeystoreService::ADD_AUTH_TOKEN, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("addAuthToken() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("addAuthToken() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        return ResponseCode(reply.readInt32());
    };

    KeyStoreServiceReturnCode onUserAdded(int32_t userId, int32_t parentId) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeInt32(userId);
        data.writeInt32(parentId);
        status_t status = remote()->transact(BnKeystoreService::ON_USER_ADDED, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("onUserAdded() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("onUserAdded() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        return ResponseCode(reply.readInt32());
    }

    KeyStoreServiceReturnCode onUserRemoved(int32_t userId) override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeInt32(userId);
        status_t status = remote()->transact(BnKeystoreService::ON_USER_REMOVED, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("onUserRemoved() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("onUserRemoved() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        return ResponseCode(reply.readInt32());
    }

    KeyStoreServiceReturnCode attestKey(const String16& name, const hidl_vec<KeyParameter>& params,
                                        hidl_vec<hidl_vec<uint8_t>>* outChain) override {
        if (!outChain) return ErrorCode::OUTPUT_PARAMETER_NULL;

        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        nullable(writeParamSetToParcel, params, &data);

        status_t status = remote()->transact(BnKeystoreService::ATTEST_KEY, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("attestkey() count not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        ResponseCode ret = ResponseCode(reply.readInt32());
        if (err < 0) {
            ALOGD("attestKey() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        if (reply.readInt32() != 0) {
            *outChain = readCertificateChainFromParcel(reply);
        }
        return ret;
    }

    KeyStoreServiceReturnCode attestDeviceIds(const hidl_vec<KeyParameter>& params,
                                              hidl_vec<hidl_vec<uint8_t>>* outChain) override {
        if (!outChain) return ErrorCode::OUTPUT_PARAMETER_NULL;

        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        nullable(writeParamSetToParcel, params, &data);

        status_t status = remote()->transact(BnKeystoreService::ATTEST_DEVICE_IDS, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("attestDeviceIds() count not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        ResponseCode ret = ResponseCode(reply.readInt32());
        if (err < 0) {
            ALOGD("attestDeviceIds() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        if (reply.readInt32() != 0) {
            *outChain = readCertificateChainFromParcel(reply);
        }
        return ret;
    }

    KeyStoreServiceReturnCode onDeviceOffBody() override {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        status_t status = remote()->transact(BnKeystoreService::ON_DEVICE_OFF_BODY, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("onDeviceOffBody() could not contact remote: %d\n", status);
            return ResponseCode::SYSTEM_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("onDeviceOffBody() caught exception %d\n", err);
            return ResponseCode::SYSTEM_ERROR;
        }
        return ResponseCode(reply.readInt32());
    }
};

IMPLEMENT_META_INTERFACE(KeystoreService, "android.security.IKeystoreService");

// ----------------------------------------------------------------------

status_t BnKeystoreService::onTransact(uint32_t code, const Parcel& data, Parcel* reply,
                                       uint32_t flags) {
    switch (code) {
    case GET_STATE: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        int32_t userId = data.readInt32();
        int32_t ret = getState(userId);
        reply->writeNoException();
        reply->writeInt32(ret);
        return NO_ERROR;
    } break;
    case GET: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        String16 name = data.readString16();
        int32_t uid = data.readInt32();
        hidl_vec<uint8_t> out;
        auto ret = get(name, uid, &out);
        reply->writeNoException();
        if (ret.isOk()) {
            writeBlobAsByteArray(out, reply);
        } else {
            reply->writeInt32(-1);
        }
        reply->writeInt32(ret);
        return NO_ERROR;
    } break;
    case INSERT: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        String16 name = data.readString16();
        auto in = readBlobAsByteArray(data);
        int uid = data.readInt32();
        int32_t flags = data.readInt32();
        int32_t ret = insert(name, in.value(), uid, flags);
        reply->writeNoException();
        reply->writeInt32(ret);
        return NO_ERROR;
    } break;
    case DEL: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        String16 name = data.readString16();
        int uid = data.readInt32();
        int32_t ret = del(name, uid);
        reply->writeNoException();
        reply->writeInt32(ret);
        return NO_ERROR;
    } break;
    case EXIST: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        String16 name = data.readString16();
        int uid = data.readInt32();
        int32_t ret = exist(name, uid);
        reply->writeNoException();
        reply->writeInt32(ret);
        return NO_ERROR;
    } break;
    case LIST: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        String16 prefix = data.readString16();
        int uid = data.readInt32();
        Vector<String16> matches;
        int32_t ret = list(prefix, uid, &matches);
        reply->writeNoException();
        reply->writeInt32(matches.size());
        Vector<String16>::const_iterator it = matches.begin();
        for (; it != matches.end(); ++it) {
            reply->writeString16(*it);
        }
        reply->writeInt32(ret);
        return NO_ERROR;
    } break;
    case RESET: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        int32_t ret = reset();
        reply->writeNoException();
        reply->writeInt32(ret);
        return NO_ERROR;
    } break;
    case ON_USER_PASSWORD_CHANGED: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        int32_t userId = data.readInt32();
        String16 pass = data.readString16();
        int32_t ret = onUserPasswordChanged(userId, pass);
        reply->writeNoException();
        reply->writeInt32(ret);
        return NO_ERROR;
    } break;
    case LOCK: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        int32_t userId = data.readInt32();
        int32_t ret = lock(userId);
        reply->writeNoException();
        reply->writeInt32(ret);
        return NO_ERROR;
    } break;
    case UNLOCK: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        int32_t userId = data.readInt32();
        String16 pass = data.readString16();
        int32_t ret = unlock(userId, pass);
        reply->writeNoException();
        reply->writeInt32(ret);
        return NO_ERROR;
    } break;
    case IS_EMPTY: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        int32_t userId = data.readInt32();
        bool ret = isEmpty(userId);
        reply->writeNoException();
        reply->writeInt32(ret ? 1 : 0);
        return NO_ERROR;
    } break;
    case GENERATE: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        String16 name = data.readString16();
        int32_t uid = data.readInt32();
        int32_t keyType = data.readInt32();
        int32_t keySize = data.readInt32();
        int32_t flags = data.readInt32();
        Vector<sp<KeystoreArg>> args;
        int32_t argsPresent = data.readInt32();
        if (argsPresent == 1) {
            ssize_t numArgs = data.readInt32();
            if (numArgs > MAX_GENERATE_ARGS) {
                return BAD_VALUE;
            }
            if (numArgs > 0) {
                for (size_t i = 0; i < (size_t)numArgs; i++) {
                    ssize_t inSize = data.readInt32();
                    if (inSize >= 0 && (size_t)inSize <= data.dataAvail()) {
                        sp<KeystoreArg> arg = new KeystoreArg(data.readInplace(inSize), inSize);
                        args.push_back(arg);
                    } else {
                        args.push_back(NULL);
                    }
                }
            }
        }
        int32_t ret = generate(name, uid, keyType, keySize, flags, &args);
        reply->writeNoException();
        reply->writeInt32(ret);
        return NO_ERROR;
    } break;
    case IMPORT: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        String16 name = data.readString16();
        auto in = readBlobAsByteArray(data);
        int uid = data.readInt32();
        int32_t flags = data.readInt32();
        auto ret = import(name, in.value(), uid, flags);
        reply->writeNoException();
        reply->writeInt32(ret);
        return NO_ERROR;
    } break;
    case SIGN: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        String16 name = data.readString16();
        auto in = readBlobAsByteArray(data);
        hidl_vec<uint8_t> out;
        auto ret = sign(name, in.value(), &out);
        reply->writeNoException();
        writeBlobAsByteArray(out, reply);
        reply->writeInt32(ret);
        return NO_ERROR;
    } break;
    case VERIFY: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        String16 name = data.readString16();
        auto in = readBlobAsByteArray(data);
        auto signature = readBlobAsByteArray(data);
        auto ret = verify(name, in.value(), signature.value());
        reply->writeNoException();
        reply->writeInt32(ret);
        return NO_ERROR;
    } break;
    case GET_PUBKEY: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        String16 name = data.readString16();
        hidl_vec<uint8_t> out;
        auto ret = get_pubkey(name, &out);
        reply->writeNoException();
        writeBlobAsByteArray(out, reply);
        reply->writeInt32(ret);
        return NO_ERROR;
    } break;
    case GRANT: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        String16 name = data.readString16();
        int32_t granteeUid = data.readInt32();
        String16 ret = grant(name, granteeUid);
        reply->writeNoException();
        reply->writeString16(ret);
        return NO_ERROR;
    } break;
    case UNGRANT: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        String16 name = data.readString16();
        int32_t granteeUid = data.readInt32();
        int32_t ret = ungrant(name, granteeUid);
        reply->writeNoException();
        reply->writeInt32(ret);
        return NO_ERROR;
    } break;
    case GETMTIME: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        String16 name = data.readString16();
        int32_t uid = data.readInt32();
        int64_t ret = getmtime(name, uid);
        reply->writeNoException();
        reply->writeInt64(ret);
        return NO_ERROR;
    } break;
    case DUPLICATE: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        String16 srcKey = data.readString16();
        int32_t srcUid = data.readInt32();
        String16 destKey = data.readString16();
        int32_t destUid = data.readInt32();
        int32_t ret = duplicate(srcKey, srcUid, destKey, destUid);
        reply->writeNoException();
        reply->writeInt32(ret);
        return NO_ERROR;
    } break;
    case IS_HARDWARE_BACKED: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        String16 keyType = data.readString16();
        int32_t ret = is_hardware_backed(keyType);
        reply->writeNoException();
        reply->writeInt32(ret);
        return NO_ERROR;
    }
    case CLEAR_UID: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        int64_t uid = data.readInt64();
        int32_t ret = clear_uid(uid);
        reply->writeNoException();
        reply->writeInt32(ret);
        return NO_ERROR;
    }
    case ADD_RNG_ENTROPY: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        auto entropy = readBlobAsByteArray(data);
        auto ret = addRngEntropy(entropy.value());
        reply->writeNoException();
        reply->writeInt32(ret);
        return NO_ERROR;
    }
    case GENERATE_KEY: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        String16 name = data.readString16();
        auto params = nullable(readParamSetFromParcel, data);
        auto entropy = readBlobAsByteArray(data);
        int32_t uid = data.readInt32();
        int32_t flags = data.readInt32();
        KeyCharacteristics outCharacteristics;
        int32_t ret =
            generateKey(name, params.value(), entropy.value(), uid, flags, &outCharacteristics);
        reply->writeNoException();
        reply->writeInt32(ret);
        nullable(writeKeyCharacteristicsToParcel, outCharacteristics, reply);
        return NO_ERROR;
    }
    case GET_KEY_CHARACTERISTICS: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        String16 name = data.readString16();
        auto clientId = nullable(readKeymasterBlob, data, true);
        auto appData = nullable(readKeymasterBlob, data, true);
        int32_t uid = data.readInt32();
        KeyCharacteristics outCharacteristics;
        int ret = getKeyCharacteristics(name, clientId.value(), appData.value(), uid,
                                        &outCharacteristics);
        reply->writeNoException();
        reply->writeInt32(ret);
        nullable(writeKeyCharacteristicsToParcel, outCharacteristics, reply);
        return NO_ERROR;
    }
    case IMPORT_KEY: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        String16 name = data.readString16();
        auto args = nullable(readParamSetFromParcel, data);
        KeyFormat format = static_cast<KeyFormat>(data.readInt32());
        auto keyData = readBlobAsByteArray(data);
        int32_t uid = data.readInt32();
        int32_t flags = data.readInt32();
        KeyCharacteristics outCharacteristics;
        int32_t ret =
            importKey(name, args.value(), format, keyData.value(), uid, flags, &outCharacteristics);
        reply->writeNoException();
        reply->writeInt32(ret);
        nullable(writeKeyCharacteristicsToParcel, outCharacteristics, reply);
        return NO_ERROR;
    }
    case EXPORT_KEY: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        String16 name = data.readString16();
        KeyFormat format = static_cast<KeyFormat>(data.readInt32());
        auto clientId = nullable(readKeymasterBlob, data, true);
        auto appData = nullable(readKeymasterBlob, data, true);
        int32_t uid = data.readInt32();
        ExportResult result;
        exportKey(name, format, clientId.value(), appData.value(), uid, &result);
        reply->writeNoException();
        reply->writeParcelable(result);

        return NO_ERROR;
    }
    case BEGIN: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        sp<IBinder> token = data.readStrongBinder();
        String16 name = data.readString16();
        KeyPurpose purpose = static_cast<KeyPurpose>(data.readInt32());
        bool pruneable = data.readInt32() != 0;
        auto args = nullable(readParamSetFromParcel, data);
        auto entropy = readBlobAsByteArray(data);
        int32_t uid = data.readInt32();
        OperationResult result;
        begin(token, name, purpose, pruneable, args.value(), entropy.value(), uid, &result);
        reply->writeNoException();
        reply->writeParcelable(result);

        return NO_ERROR;
    }
    case UPDATE: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        sp<IBinder> token = data.readStrongBinder();
        auto args = nullable(readParamSetFromParcel, data);
        auto buf = readBlobAsByteArray(data);
        OperationResult result;
        update(token, args.value(), buf.value(), &result);
        reply->writeNoException();
        reply->writeParcelable(result);

        return NO_ERROR;
    }
    case FINISH: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        sp<IBinder> token = data.readStrongBinder();
        auto args = nullable(readParamSetFromParcel, data);
        auto signature = readBlobAsByteArray(data);
        auto entropy = readBlobAsByteArray(data);
        OperationResult result;
        finish(token, args.value(), signature.value(), entropy.value(), &result);
        reply->writeNoException();
        reply->writeParcelable(result);

        return NO_ERROR;
    }
    case ABORT: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        sp<IBinder> token = data.readStrongBinder();
        int32_t result = abort(token);
        reply->writeNoException();
        reply->writeInt32(result);

        return NO_ERROR;
    }
    case IS_OPERATION_AUTHORIZED: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        sp<IBinder> token = data.readStrongBinder();
        bool result = isOperationAuthorized(token);
        reply->writeNoException();
        reply->writeInt32(result ? 1 : 0);

        return NO_ERROR;
    }
    case ADD_AUTH_TOKEN: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        const uint8_t* token_bytes = NULL;
        size_t size = 0;
        readByteArray(data, &token_bytes, &size);
        int32_t result = addAuthToken(token_bytes, size);
        reply->writeNoException();
        reply->writeInt32(result);

        return NO_ERROR;
    }
    case ON_USER_ADDED: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        int32_t userId = data.readInt32();
        int32_t parentId = data.readInt32();
        int32_t result = onUserAdded(userId, parentId);
        reply->writeNoException();
        reply->writeInt32(result);

        return NO_ERROR;
    }
    case ON_USER_REMOVED: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        int32_t userId = data.readInt32();
        int32_t result = onUserRemoved(userId);
        reply->writeNoException();
        reply->writeInt32(result);

        return NO_ERROR;
    }
    case ATTEST_KEY: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        String16 name = data.readString16();
        auto params = nullable(readParamSetFromParcel, data);
        hidl_vec<hidl_vec<uint8_t>> chain;
        int ret = attestKey(name, params.value(), &chain);
        reply->writeNoException();
        reply->writeInt32(ret);
        nullable(writeCertificateChainToParcel, chain, reply);

        return NO_ERROR;
    }

    case ATTEST_DEVICE_IDS: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        auto params = nullable(readParamSetFromParcel, data);
        hidl_vec<hidl_vec<uint8_t>> chain;
        int ret = attestDeviceIds(params.value(), &chain);
        reply->writeNoException();
        reply->writeInt32(ret);
        nullable(writeCertificateChainToParcel, chain, reply);

        return NO_ERROR;
    }

    case ON_DEVICE_OFF_BODY: {
        CHECK_INTERFACE(IKeystoreService, data, reply);
        int32_t ret = onDeviceOffBody();
        reply->writeNoException();
        reply->writeInt32(ret);

        return NO_ERROR;
    }
    default:
        return BBinder::onTransact(code, data, reply, flags);
    }
}

// ----------------------------------------------------------------------------

};  // namespace android
