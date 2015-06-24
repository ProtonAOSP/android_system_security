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

#define LOG_TAG "KeystoreService"
#include <utils/Log.h>

#include <binder/Parcel.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>

#include <keystore/IKeystoreService.h>

namespace android {

const ssize_t MAX_GENERATE_ARGS = 3;
static keymaster_key_param_t* readParamList(const Parcel& in, size_t* length);

KeystoreArg::KeystoreArg(const void* data, size_t len)
    : mData(data), mSize(len) {
}

KeystoreArg::~KeystoreArg() {
}

const void *KeystoreArg::data() const {
    return mData;
}

size_t KeystoreArg::size() const {
    return mSize;
}

OperationResult::OperationResult() : resultCode(0), token(), handle(0), inputConsumed(0),
    data(NULL), dataLength(0) {
}

OperationResult::~OperationResult() {
}

void OperationResult::readFromParcel(const Parcel& in) {
    resultCode = in.readInt32();
    token = in.readStrongBinder();
    handle = static_cast<keymaster_operation_handle_t>(in.readInt64());
    inputConsumed = in.readInt32();
    ssize_t length = in.readInt32();
    dataLength = 0;
    if (length > 0) {
        const void* buf = in.readInplace(length);
        if (buf) {
            data.reset(reinterpret_cast<uint8_t*>(malloc(length)));
            if (data.get()) {
                memcpy(data.get(), buf, length);
                dataLength = (size_t) length;
            } else {
                ALOGE("Failed to allocate OperationResult buffer");
            }
        } else {
            ALOGE("Failed to readInplace OperationResult data");
        }
    }
    outParams.readFromParcel(in);
}

void OperationResult::writeToParcel(Parcel* out) const {
    out->writeInt32(resultCode);
    out->writeStrongBinder(token);
    out->writeInt64(handle);
    out->writeInt32(inputConsumed);
    out->writeInt32(dataLength);
    if (dataLength && data) {
        void* buf = out->writeInplace(dataLength);
        if (buf) {
            memcpy(buf, data.get(), dataLength);
        } else {
            ALOGE("Failed to writeInplace OperationResult data.");
        }
    }
    outParams.writeToParcel(out);
}

ExportResult::ExportResult() : resultCode(0), exportData(NULL), dataLength(0) {
}

ExportResult::~ExportResult() {
}

void ExportResult::readFromParcel(const Parcel& in) {
    resultCode = in.readInt32();
    ssize_t length = in.readInt32();
    dataLength = 0;
    if (length > 0) {
        const void* buf = in.readInplace(length);
        if (buf) {
            exportData.reset(reinterpret_cast<uint8_t*>(malloc(length)));
            if (exportData.get()) {
                memcpy(exportData.get(), buf, length);
                dataLength = (size_t) length;
            } else {
                ALOGE("Failed to allocate ExportData buffer");
            }
        } else {
            ALOGE("Failed to readInplace ExportData data");
        }
    }
}

void ExportResult::writeToParcel(Parcel* out) const {
    out->writeInt32(resultCode);
    out->writeInt32(dataLength);
    if (exportData && dataLength) {
        void* buf = out->writeInplace(dataLength);
        if (buf) {
            memcpy(buf, exportData.get(), dataLength);
        } else {
            ALOGE("Failed to writeInplace ExportResult data.");
        }
    }
}

KeymasterArguments::KeymasterArguments() {
}

KeymasterArguments::~KeymasterArguments() {
    keymaster_free_param_values(params.data(), params.size());
}

void KeymasterArguments::readFromParcel(const Parcel& in) {
    ssize_t length = in.readInt32();
    size_t ulength = (size_t) length;
    if (length < 0) {
        ulength = 0;
    }
    keymaster_free_param_values(params.data(), params.size());
    params.clear();
    for(size_t i = 0; i < ulength; i++) {
        keymaster_key_param_t param;
        if (!readKeymasterArgumentFromParcel(in, &param)) {
            ALOGE("Error reading keymaster argument from parcel");
            break;
        }
        params.push_back(param);
    }
}

void KeymasterArguments::writeToParcel(Parcel* out) const {
    out->writeInt32(params.size());
    for (auto param : params) {
        out->writeInt32(1);
        writeKeymasterArgumentToParcel(param, out);
    }
}

KeyCharacteristics::KeyCharacteristics() {
    memset((void*) &characteristics, 0, sizeof(characteristics));
}

KeyCharacteristics::~KeyCharacteristics() {
    keymaster_free_characteristics(&characteristics);
}

void KeyCharacteristics::readFromParcel(const Parcel& in) {
    size_t length = 0;
    keymaster_key_param_t* params = readParamList(in, &length);
    characteristics.sw_enforced.params = params;
    characteristics.sw_enforced.length = length;

    params = readParamList(in, &length);
    characteristics.hw_enforced.params = params;
    characteristics.hw_enforced.length = length;
}

void KeyCharacteristics::writeToParcel(Parcel* out) const {
    if (characteristics.sw_enforced.params) {
        out->writeInt32(characteristics.sw_enforced.length);
        for (size_t i = 0; i < characteristics.sw_enforced.length; i++) {
            out->writeInt32(1);
            writeKeymasterArgumentToParcel(characteristics.sw_enforced.params[i], out);
        }
    } else {
        out->writeInt32(0);
    }
    if (characteristics.hw_enforced.params) {
        out->writeInt32(characteristics.hw_enforced.length);
        for (size_t i = 0; i < characteristics.hw_enforced.length; i++) {
            out->writeInt32(1);
            writeKeymasterArgumentToParcel(characteristics.hw_enforced.params[i], out);
        }
    } else {
        out->writeInt32(0);
    }
}

void writeKeymasterArgumentToParcel(const keymaster_key_param_t& param, Parcel* out) {
    switch (keymaster_tag_get_type(param.tag)) {
        case KM_ENUM:
        case KM_ENUM_REP: {
            out->writeInt32(param.tag);
            out->writeInt32(param.enumerated);
            break;
        }
        case KM_UINT:
        case KM_UINT_REP: {
            out->writeInt32(param.tag);
            out->writeInt32(param.integer);
            break;
        }
        case KM_ULONG:
        case KM_ULONG_REP: {
            out->writeInt32(param.tag);
            out->writeInt64(param.long_integer);
            break;
        }
        case KM_DATE: {
            out->writeInt32(param.tag);
            out->writeInt64(param.date_time);
            break;
        }
        case KM_BOOL: {
            out->writeInt32(param.tag);
            break;
        }
        case KM_BIGNUM:
        case KM_BYTES: {
            out->writeInt32(param.tag);
            out->writeInt32(param.blob.data_length);
            void* buf = out->writeInplace(param.blob.data_length);
            if (buf) {
                memcpy(buf, param.blob.data, param.blob.data_length);
            } else {
                ALOGE("Failed to writeInplace keymaster blob param");
            }
            break;
        }
        default: {
            ALOGE("Failed to write argument: Unsupported keymaster_tag_t %d", param.tag);
        }
    }
}


bool readKeymasterArgumentFromParcel(const Parcel& in, keymaster_key_param_t* out) {
    if (in.readInt32() == 0) {
        return false;
    }
    keymaster_tag_t tag = static_cast<keymaster_tag_t>(in.readInt32());
    switch (keymaster_tag_get_type(tag)) {
        case KM_ENUM:
        case KM_ENUM_REP: {
            uint32_t value = in.readInt32();
            *out = keymaster_param_enum(tag, value);
            break;
        }
        case KM_UINT:
        case KM_UINT_REP: {
            uint32_t value = in.readInt32();
            *out = keymaster_param_int(tag, value);
            break;
        }
        case KM_ULONG:
        case KM_ULONG_REP: {
            uint64_t value = in.readInt64();
            *out = keymaster_param_long(tag, value);
            break;
        }
        case KM_DATE: {
            uint64_t value = in.readInt64();
            *out = keymaster_param_date(tag, value);
            break;
        }
        case KM_BOOL: {
            *out = keymaster_param_bool(tag);
            break;
        }
        case KM_BIGNUM:
        case KM_BYTES: {
            ssize_t length = in.readInt32();
            uint8_t* data = NULL;
            size_t ulength = 0;
            if (length >= 0) {
                ulength = (size_t) length;
                // use malloc here so we can use keymaster_free_param_values
                // consistently.
                data = reinterpret_cast<uint8_t*>(malloc(ulength));
                const void* buf = in.readInplace(ulength);
                if (!buf || !data) {
                    ALOGE("Failed to allocate buffer for keymaster blob param");
                    return false;
                }
                memcpy(data, buf, ulength);
            }
            *out = keymaster_param_blob(tag, data, ulength);
            break;
        }
        default: {
            ALOGE("Unsupported keymaster_tag_t %d", tag);
            return false;
        }
    }
    return true;
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

// Read a keymaster_key_param_t* from a Parcel for use in a
// keymaster_key_characteristics_t. This will be free'd by calling
// keymaster_free_key_characteristics.
static keymaster_key_param_t* readParamList(const Parcel& in, size_t* length) {
    ssize_t slength = in.readInt32();
    *length = 0;
    if (slength < 0) {
        return NULL;
    }
    *length = (size_t) slength;
    if (*length >= UINT_MAX / sizeof(keymaster_key_param_t)) {
        return NULL;
    }
    keymaster_key_param_t* list =
            reinterpret_cast<keymaster_key_param_t*>(malloc(*length *
                                                            sizeof(keymaster_key_param_t)));
    if (!list) {
        ALOGD("Failed to allocate buffer for generateKey outCharacteristics");
        goto err;
    }
    for (size_t i = 0; i < *length ; i++) {
        if (!readKeymasterArgumentFromParcel(in, &list[i])) {
            ALOGE("Failed to read keymaster argument");
            keymaster_free_param_values(list, i);
            goto err;
        }
    }
    return list;
err:
    free(list);
    return NULL;
}

static std::unique_ptr<keymaster_blob_t> readKeymasterBlob(const Parcel& in) {
    std::unique_ptr<keymaster_blob_t> blob;
    if (in.readInt32() != 1) {
        blob.reset(NULL);
        return blob;
    }
    ssize_t length = in.readInt32();
    blob.reset(new keymaster_blob_t);
    if (length > 0) {
        blob->data = reinterpret_cast<const uint8_t*>(in.readInplace(length));
        if (blob->data) {
            blob->data_length = static_cast<size_t>(length);
        } else {
            blob->data_length = 0;
        }
    } else {
        blob->data = NULL;
        blob->data_length = 0;
    }
    return blob;
}

class BpKeystoreService: public BpInterface<IKeystoreService>
{
public:
    BpKeystoreService(const sp<IBinder>& impl)
        : BpInterface<IKeystoreService>(impl)
    {
    }

    // test ping
    virtual int32_t getState(int32_t userId)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeInt32(userId);
        status_t status = remote()->transact(BnKeystoreService::GET_STATE, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("getState() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("getState() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t get(const String16& name, uint8_t** item, size_t* itemLength)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        status_t status = remote()->transact(BnKeystoreService::GET, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("get() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        ssize_t len = reply.readInt32();
        if (len >= 0 && (size_t) len <= reply.dataAvail()) {
            size_t ulen = (size_t) len;
            const void* buf = reply.readInplace(ulen);
            *item = (uint8_t*) malloc(ulen);
            if (*item != NULL) {
                memcpy(*item, buf, ulen);
                *itemLength = ulen;
            } else {
                ALOGE("out of memory allocating output array in get");
                *itemLength = 0;
            }
        } else {
            *itemLength = 0;
        }
        if (err < 0) {
            ALOGD("get() caught exception %d\n", err);
            return -1;
        }
        return 0;
    }

    virtual int32_t insert(const String16& name, const uint8_t* item, size_t itemLength, int uid,
            int32_t flags)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(itemLength);
        void* buf = data.writeInplace(itemLength);
        memcpy(buf, item, itemLength);
        data.writeInt32(uid);
        data.writeInt32(flags);
        status_t status = remote()->transact(BnKeystoreService::INSERT, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("import() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("import() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t del(const String16& name, int uid)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(uid);
        status_t status = remote()->transact(BnKeystoreService::DEL, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("del() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("del() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t exist(const String16& name, int uid)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(uid);
        status_t status = remote()->transact(BnKeystoreService::EXIST, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("exist() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("exist() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t list(const String16& prefix, int uid, Vector<String16>* matches)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(prefix);
        data.writeInt32(uid);
        status_t status = remote()->transact(BnKeystoreService::LIST, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("list() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t numMatches = reply.readInt32();
        for (int32_t i = 0; i < numMatches; i++) {
            matches->push(reply.readString16());
        }
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("list() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t reset()
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        status_t status = remote()->transact(BnKeystoreService::RESET, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("reset() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("reset() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t onUserPasswordChanged(int32_t userId, const String16& password)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeInt32(userId);
        data.writeString16(password);
        status_t status = remote()->transact(BnKeystoreService::ON_USER_PASSWORD_CHANGED, data,
                                             &reply);
        if (status != NO_ERROR) {
            ALOGD("onUserPasswordChanged() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("onUserPasswordChanged() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t lock(int32_t userId)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeInt32(userId);
        status_t status = remote()->transact(BnKeystoreService::LOCK, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("lock() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("lock() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t unlock(int32_t userId, const String16& password)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeInt32(userId);
        data.writeString16(password);
        status_t status = remote()->transact(BnKeystoreService::UNLOCK, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("unlock() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("unlock() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual bool isEmpty(int32_t userId)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeInt32(userId);
        status_t status = remote()->transact(BnKeystoreService::IS_EMPTY, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("isEmpty() could not contact remote: %d\n", status);
            return false;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("isEmpty() caught exception %d\n", err);
            return false;
        }
        return ret != 0;
    }

    virtual int32_t generate(const String16& name, int32_t uid, int32_t keyType, int32_t keySize,
            int32_t flags, Vector<sp<KeystoreArg> >* args)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(uid);
        data.writeInt32(keyType);
        data.writeInt32(keySize);
        data.writeInt32(flags);
        data.writeInt32(1);
        data.writeInt32(args->size());
        for (Vector<sp<KeystoreArg> >::iterator it = args->begin(); it != args->end(); ++it) {
            sp<KeystoreArg> item = *it;
            size_t keyLength = item->size();
            data.writeInt32(keyLength);
            void* buf = data.writeInplace(keyLength);
            memcpy(buf, item->data(), keyLength);
        }
        status_t status = remote()->transact(BnKeystoreService::GENERATE, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("generate() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("generate() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t import(const String16& name, const uint8_t* key, size_t keyLength, int uid,
            int flags)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(keyLength);
        void* buf = data.writeInplace(keyLength);
        memcpy(buf, key, keyLength);
        data.writeInt32(uid);
        data.writeInt32(flags);
        status_t status = remote()->transact(BnKeystoreService::IMPORT, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("import() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("import() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t sign(const String16& name, const uint8_t* in, size_t inLength, uint8_t** out,
            size_t* outLength)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(inLength);
        void* buf = data.writeInplace(inLength);
        memcpy(buf, in, inLength);
        status_t status = remote()->transact(BnKeystoreService::SIGN, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("import() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        ssize_t len = reply.readInt32();
        if (len >= 0 && (size_t) len <= reply.dataAvail()) {
            size_t ulen = (size_t) len;
            const void* outBuf = reply.readInplace(ulen);
            *out = (uint8_t*) malloc(ulen);
            if (*out != NULL) {
                memcpy((void*) *out, outBuf, ulen);
                *outLength = ulen;
            } else {
                ALOGE("out of memory allocating output array in sign");
                *outLength = 0;
            }
        } else {
            *outLength = 0;
        }
        if (err < 0) {
            ALOGD("import() caught exception %d\n", err);
            return -1;
        }
        return 0;
    }

    virtual int32_t verify(const String16& name, const uint8_t* in, size_t inLength,
            const uint8_t* signature, size_t signatureLength)
    {
        Parcel data, reply;
        void* buf;

        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(inLength);
        buf = data.writeInplace(inLength);
        memcpy(buf, in, inLength);
        data.writeInt32(signatureLength);
        buf = data.writeInplace(signatureLength);
        memcpy(buf, signature, signatureLength);
        status_t status = remote()->transact(BnKeystoreService::VERIFY, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("verify() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("verify() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t get_pubkey(const String16& name, uint8_t** pubkey, size_t* pubkeyLength)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        status_t status = remote()->transact(BnKeystoreService::GET_PUBKEY, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("get_pubkey() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        ssize_t len = reply.readInt32();
        if (len >= 0 && (size_t) len <= reply.dataAvail()) {
            size_t ulen = (size_t) len;
            const void* buf = reply.readInplace(ulen);
            *pubkey = (uint8_t*) malloc(ulen);
            if (*pubkey != NULL) {
                memcpy(*pubkey, buf, ulen);
                *pubkeyLength = ulen;
            } else {
                ALOGE("out of memory allocating output array in get_pubkey");
                *pubkeyLength = 0;
            }
        } else {
            *pubkeyLength = 0;
        }
        if (err < 0) {
            ALOGD("get_pubkey() caught exception %d\n", err);
            return -1;
        }
        return 0;
     }

    virtual int32_t grant(const String16& name, int32_t granteeUid)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(granteeUid);
        status_t status = remote()->transact(BnKeystoreService::GRANT, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("grant() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("grant() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t ungrant(const String16& name, int32_t granteeUid)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(granteeUid);
        status_t status = remote()->transact(BnKeystoreService::UNGRANT, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("ungrant() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("ungrant() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    int64_t getmtime(const String16& name)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        status_t status = remote()->transact(BnKeystoreService::GETMTIME, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("getmtime() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int64_t ret = reply.readInt64();
        if (err < 0) {
            ALOGD("getmtime() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t duplicate(const String16& srcKey, int32_t srcUid, const String16& destKey,
            int32_t destUid)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(srcKey);
        data.writeInt32(srcUid);
        data.writeString16(destKey);
        data.writeInt32(destUid);
        status_t status = remote()->transact(BnKeystoreService::DUPLICATE, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("duplicate() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("duplicate() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t is_hardware_backed(const String16& keyType)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(keyType);
        status_t status = remote()->transact(BnKeystoreService::IS_HARDWARE_BACKED, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("is_hardware_backed() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("is_hardware_backed() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t clear_uid(int64_t uid)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeInt64(uid);
        status_t status = remote()->transact(BnKeystoreService::CLEAR_UID, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("clear_uid() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("clear_uid() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t addRngEntropy(const uint8_t* buf, size_t bufLength)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeByteArray(bufLength, buf);
        status_t status = remote()->transact(BnKeystoreService::ADD_RNG_ENTROPY, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("addRngEntropy() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("addRngEntropy() caught exception %d\n", err);
            return -1;
        }
        return ret;
    };

    virtual int32_t generateKey(const String16& name, const KeymasterArguments& params,
                                const uint8_t* entropy, size_t entropyLength, int uid, int flags,
                                KeyCharacteristics* outCharacteristics)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(1);
        params.writeToParcel(&data);
        data.writeByteArray(entropyLength, entropy);
        data.writeInt32(uid);
        data.writeInt32(flags);
        status_t status = remote()->transact(BnKeystoreService::GENERATE_KEY, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("generateKey() could not contact remote: %d\n", status);
            return KM_ERROR_UNKNOWN_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("generateKey() caught exception %d\n", err);
            return KM_ERROR_UNKNOWN_ERROR;
        }
        if (reply.readInt32() != 0 && outCharacteristics) {
            outCharacteristics->readFromParcel(reply);
        }
        return ret;
    }
    virtual int32_t getKeyCharacteristics(const String16& name,
                                          const keymaster_blob_t* clientId,
                                          const keymaster_blob_t* appData,
                                          KeyCharacteristics* outCharacteristics)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        if (clientId) {
            data.writeByteArray(clientId->data_length, clientId->data);
        } else {
            data.writeInt32(-1);
        }
        if (appData) {
            data.writeByteArray(appData->data_length, appData->data);
        } else {
            data.writeInt32(-1);
        }
        status_t status = remote()->transact(BnKeystoreService::GET_KEY_CHARACTERISTICS,
                                             data, &reply);
        if (status != NO_ERROR) {
            ALOGD("getKeyCharacteristics() could not contact remote: %d\n", status);
            return KM_ERROR_UNKNOWN_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("getKeyCharacteristics() caught exception %d\n", err);
            return KM_ERROR_UNKNOWN_ERROR;
        }
        if (reply.readInt32() != 0 && outCharacteristics) {
            outCharacteristics->readFromParcel(reply);
        }
        return ret;
    }
    virtual int32_t importKey(const String16& name, const KeymasterArguments&  params,
                              keymaster_key_format_t format, const uint8_t *keyData,
                              size_t keyLength, int uid, int flags,
                              KeyCharacteristics* outCharacteristics)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(1);
        params.writeToParcel(&data);
        data.writeInt32(format);
        data.writeByteArray(keyLength, keyData);
        data.writeInt32(uid);
        data.writeInt32(flags);
        status_t status = remote()->transact(BnKeystoreService::IMPORT_KEY, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("importKey() could not contact remote: %d\n", status);
            return KM_ERROR_UNKNOWN_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("importKey() caught exception %d\n", err);
            return KM_ERROR_UNKNOWN_ERROR;
        }
        if (reply.readInt32() != 0 && outCharacteristics) {
            outCharacteristics->readFromParcel(reply);
        }
        return ret;
    }

    virtual void exportKey(const String16& name, keymaster_key_format_t format,
                           const keymaster_blob_t* clientId,
                           const keymaster_blob_t* appData, ExportResult* result)
    {
        if (!result) {
            return;
        }

        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeString16(name);
        data.writeInt32(format);
        if (clientId) {
            data.writeByteArray(clientId->data_length, clientId->data);
        } else {
            data.writeInt32(-1);
        }
        if (appData) {
            data.writeByteArray(appData->data_length, appData->data);
        } else {
            data.writeInt32(-1);
        }
        status_t status = remote()->transact(BnKeystoreService::EXPORT_KEY, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("exportKey() could not contact remote: %d\n", status);
            result->resultCode = KM_ERROR_UNKNOWN_ERROR;
            return;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("exportKey() caught exception %d\n", err);
            result->resultCode = KM_ERROR_UNKNOWN_ERROR;
            return;
        }
        if (reply.readInt32() != 0) {
            result->readFromParcel(reply);
        }
    }

    virtual void begin(const sp<IBinder>& appToken, const String16& name,
                       keymaster_purpose_t purpose, bool pruneable,
                       const KeymasterArguments& params, const uint8_t* entropy,
                       size_t entropyLength, OperationResult* result)
    {
        if (!result) {
            return;
        }
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeStrongBinder(appToken);
        data.writeString16(name);
        data.writeInt32(purpose);
        data.writeInt32(pruneable ? 1 : 0);
        data.writeInt32(1);
        params.writeToParcel(&data);
        data.writeByteArray(entropyLength, entropy);
        status_t status = remote()->transact(BnKeystoreService::BEGIN, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("begin() could not contact remote: %d\n", status);
            result->resultCode = KM_ERROR_UNKNOWN_ERROR;
            return;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("begin() caught exception %d\n", err);
            result->resultCode = KM_ERROR_UNKNOWN_ERROR;
            return;
        }
        if (reply.readInt32() != 0) {
            result->readFromParcel(reply);
        }
    }

    virtual void update(const sp<IBinder>& token, const KeymasterArguments& params,
                        const uint8_t* opData, size_t dataLength, OperationResult* result)
    {
        if (!result) {
            return;
        }
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeStrongBinder(token);
        data.writeInt32(1);
        params.writeToParcel(&data);
        data.writeByteArray(dataLength, opData);
        status_t status = remote()->transact(BnKeystoreService::UPDATE, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("update() could not contact remote: %d\n", status);
            result->resultCode = KM_ERROR_UNKNOWN_ERROR;
            return;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("update() caught exception %d\n", err);
            result->resultCode = KM_ERROR_UNKNOWN_ERROR;
            return;
        }
        if (reply.readInt32() != 0) {
            result->readFromParcel(reply);
        }
    }

    virtual void finish(const sp<IBinder>& token, const KeymasterArguments& params,
                        const uint8_t* signature, size_t signatureLength,
                        const uint8_t* entropy, size_t entropyLength,
                        OperationResult* result)
    {
        if (!result) {
            return;
        }
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeStrongBinder(token);
        data.writeInt32(1);
        params.writeToParcel(&data);
        data.writeByteArray(signatureLength, signature);
        data.writeByteArray(entropyLength, entropy);
        status_t status = remote()->transact(BnKeystoreService::FINISH, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("finish() could not contact remote: %d\n", status);
            result->resultCode = KM_ERROR_UNKNOWN_ERROR;
            return;
        }
        int32_t err = reply.readExceptionCode();
        if (err < 0) {
            ALOGD("finish() caught exception %d\n", err);
            result->resultCode = KM_ERROR_UNKNOWN_ERROR;
            return;
        }
        if (reply.readInt32() != 0) {
            result->readFromParcel(reply);
        }
    }

    virtual int32_t abort(const sp<IBinder>& token)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeStrongBinder(token);
        status_t status = remote()->transact(BnKeystoreService::ABORT, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("abort() could not contact remote: %d\n", status);
            return KM_ERROR_UNKNOWN_ERROR;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("abort() caught exception %d\n", err);
            return KM_ERROR_UNKNOWN_ERROR;
        }
        return ret;
    }

    virtual bool isOperationAuthorized(const sp<IBinder>& token)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeStrongBinder(token);
        status_t status = remote()->transact(BnKeystoreService::IS_OPERATION_AUTHORIZED, data,
                                             &reply);
        if (status != NO_ERROR) {
            ALOGD("isOperationAuthorized() could not contact remote: %d\n", status);
            return false;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("isOperationAuthorized() caught exception %d\n", err);
            return false;
        }
        return ret == 1;
    }

    virtual int32_t addAuthToken(const uint8_t* token, size_t length)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeByteArray(length, token);
        status_t status = remote()->transact(BnKeystoreService::ADD_AUTH_TOKEN, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("addAuthToken() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("addAuthToken() caught exception %d\n", err);
            return -1;
        }
        return ret;
    };

    virtual int32_t onUserAdded(int32_t userId, int32_t parentId)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeInt32(userId);
        data.writeInt32(parentId);
        status_t status = remote()->transact(BnKeystoreService::ON_USER_ADDED, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("onUserAdded() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("onUserAdded() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

    virtual int32_t onUserRemoved(int32_t userId)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IKeystoreService::getInterfaceDescriptor());
        data.writeInt32(userId);
        status_t status = remote()->transact(BnKeystoreService::ON_USER_REMOVED, data, &reply);
        if (status != NO_ERROR) {
            ALOGD("onUserRemoved() could not contact remote: %d\n", status);
            return -1;
        }
        int32_t err = reply.readExceptionCode();
        int32_t ret = reply.readInt32();
        if (err < 0) {
            ALOGD("onUserRemoved() caught exception %d\n", err);
            return -1;
        }
        return ret;
    }

};

IMPLEMENT_META_INTERFACE(KeystoreService, "android.security.IKeystoreService");

// ----------------------------------------------------------------------

status_t BnKeystoreService::onTransact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
    switch(code) {
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
            void* out = NULL;
            size_t outSize = 0;
            int32_t ret = get(name, (uint8_t**) &out, &outSize);
            reply->writeNoException();
            if (ret == 1) {
                reply->writeInt32(outSize);
                void* buf = reply->writeInplace(outSize);
                memcpy(buf, out, outSize);
                free(out);
            } else {
                reply->writeInt32(-1);
            }
            return NO_ERROR;
        } break;
        case INSERT: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            ssize_t inSize = data.readInt32();
            const void* in;
            if (inSize >= 0 && (size_t) inSize <= data.dataAvail()) {
                in = data.readInplace(inSize);
            } else {
                in = NULL;
                inSize = 0;
            }
            int uid = data.readInt32();
            int32_t flags = data.readInt32();
            int32_t ret = insert(name, (const uint8_t*) in, (size_t) inSize, uid, flags);
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
            Vector<sp<KeystoreArg> > args;
            int32_t argsPresent = data.readInt32();
            if (argsPresent == 1) {
                ssize_t numArgs = data.readInt32();
                if (numArgs > MAX_GENERATE_ARGS) {
                    return BAD_VALUE;
                }
                if (numArgs > 0) {
                    for (size_t i = 0; i < (size_t) numArgs; i++) {
                        ssize_t inSize = data.readInt32();
                        if (inSize >= 0 && (size_t) inSize <= data.dataAvail()) {
                            sp<KeystoreArg> arg = new KeystoreArg(data.readInplace(inSize),
                                                                  inSize);
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
            ssize_t inSize = data.readInt32();
            const void* in;
            if (inSize >= 0 && (size_t) inSize <= data.dataAvail()) {
                in = data.readInplace(inSize);
            } else {
                in = NULL;
                inSize = 0;
            }
            int uid = data.readInt32();
            int32_t flags = data.readInt32();
            int32_t ret = import(name, (const uint8_t*) in, (size_t) inSize, uid, flags);
            reply->writeNoException();
            reply->writeInt32(ret);
            return NO_ERROR;
        } break;
        case SIGN: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            ssize_t inSize = data.readInt32();
            const void* in;
            if (inSize >= 0 && (size_t) inSize <= data.dataAvail()) {
                in = data.readInplace(inSize);
            } else {
                in = NULL;
                inSize = 0;
            }
            void* out = NULL;
            size_t outSize = 0;
            int32_t ret = sign(name, (const uint8_t*) in, (size_t) inSize, (uint8_t**) &out, &outSize);
            reply->writeNoException();
            if (outSize > 0 && out != NULL) {
                reply->writeInt32(outSize);
                void* buf = reply->writeInplace(outSize);
                memcpy(buf, out, outSize);
                delete[] reinterpret_cast<uint8_t*>(out);
            } else {
                reply->writeInt32(-1);
            }
            reply->writeInt32(ret);
            return NO_ERROR;
        } break;
        case VERIFY: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            ssize_t inSize = data.readInt32();
            const void* in;
            if (inSize >= 0 && (size_t) inSize <= data.dataAvail()) {
                in = data.readInplace(inSize);
            } else {
                in = NULL;
                inSize = 0;
            }
            ssize_t sigSize = data.readInt32();
            const void* sig;
            if (sigSize >= 0 && (size_t) sigSize <= data.dataAvail()) {
                sig = data.readInplace(sigSize);
            } else {
                sig = NULL;
                sigSize = 0;
            }
            bool ret = verify(name, (const uint8_t*) in, (size_t) inSize, (const uint8_t*) sig,
                    (size_t) sigSize);
            reply->writeNoException();
            reply->writeInt32(ret ? 1 : 0);
            return NO_ERROR;
        } break;
        case GET_PUBKEY: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            void* out = NULL;
            size_t outSize = 0;
            int32_t ret = get_pubkey(name, (unsigned char**) &out, &outSize);
            reply->writeNoException();
            if (outSize > 0 && out != NULL) {
                reply->writeInt32(outSize);
                void* buf = reply->writeInplace(outSize);
                memcpy(buf, out, outSize);
                free(out);
            } else {
                reply->writeInt32(-1);
            }
            reply->writeInt32(ret);
            return NO_ERROR;
        } break;
        case GRANT: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            int32_t granteeUid = data.readInt32();
            int32_t ret = grant(name, granteeUid);
            reply->writeNoException();
            reply->writeInt32(ret);
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
            int64_t ret = getmtime(name);
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
            const uint8_t* bytes = NULL;
            size_t size = 0;
            readByteArray(data, &bytes, &size);
            int32_t ret = addRngEntropy(bytes, size);
            reply->writeNoException();
            reply->writeInt32(ret);
            return NO_ERROR;
        }
        case GENERATE_KEY: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            KeymasterArguments args;
            if (data.readInt32() != 0) {
                args.readFromParcel(data);
            }
            const uint8_t* entropy = NULL;
            size_t entropyLength = 0;
            readByteArray(data, &entropy, &entropyLength);
            int32_t uid = data.readInt32();
            int32_t flags = data.readInt32();
            KeyCharacteristics outCharacteristics;
            int32_t ret = generateKey(name, args, entropy, entropyLength, uid, flags,
                                      &outCharacteristics);
            reply->writeNoException();
            reply->writeInt32(ret);
            reply->writeInt32(1);
            outCharacteristics.writeToParcel(reply);
            return NO_ERROR;
        }
        case GET_KEY_CHARACTERISTICS: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            std::unique_ptr<keymaster_blob_t> clientId = readKeymasterBlob(data);
            std::unique_ptr<keymaster_blob_t> appData = readKeymasterBlob(data);
            KeyCharacteristics outCharacteristics;
            int ret = getKeyCharacteristics(name, clientId.get(), appData.get(),
                                            &outCharacteristics);
            reply->writeNoException();
            reply->writeInt32(ret);
            reply->writeInt32(1);
            outCharacteristics.writeToParcel(reply);
            return NO_ERROR;
        }
        case IMPORT_KEY: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            KeymasterArguments args;
            if (data.readInt32() != 0) {
                args.readFromParcel(data);
            }
            keymaster_key_format_t format = static_cast<keymaster_key_format_t>(data.readInt32());
            const uint8_t* keyData = NULL;
            size_t keyLength = 0;
            readByteArray(data, &keyData, &keyLength);
            int32_t uid = data.readInt32();
            int32_t flags = data.readInt32();
            KeyCharacteristics outCharacteristics;
            int32_t ret = importKey(name, args, format, keyData, keyLength, uid, flags,
                                    &outCharacteristics);
            reply->writeNoException();
            reply->writeInt32(ret);
            reply->writeInt32(1);
            outCharacteristics.writeToParcel(reply);

            return NO_ERROR;
        }
        case EXPORT_KEY: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            String16 name = data.readString16();
            keymaster_key_format_t format = static_cast<keymaster_key_format_t>(data.readInt32());
            std::unique_ptr<keymaster_blob_t> clientId = readKeymasterBlob(data);
            std::unique_ptr<keymaster_blob_t> appData = readKeymasterBlob(data);
            ExportResult result;
            exportKey(name, format, clientId.get(), appData.get(), &result);
            reply->writeNoException();
            reply->writeInt32(1);
            result.writeToParcel(reply);

            return NO_ERROR;
        }
        case BEGIN: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            sp<IBinder> token = data.readStrongBinder();
            String16 name = data.readString16();
            keymaster_purpose_t purpose = static_cast<keymaster_purpose_t>(data.readInt32());
            bool pruneable = data.readInt32() != 0;
            KeymasterArguments args;
            if (data.readInt32() != 0) {
                args.readFromParcel(data);
            }
            const uint8_t* entropy = NULL;
            size_t entropyLength = 0;
            readByteArray(data, &entropy, &entropyLength);
            OperationResult result;
            begin(token, name, purpose, pruneable, args, entropy, entropyLength, &result);
            reply->writeNoException();
            reply->writeInt32(1);
            result.writeToParcel(reply);

            return NO_ERROR;
        }
        case UPDATE: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            sp<IBinder> token = data.readStrongBinder();
            KeymasterArguments args;
            if (data.readInt32() != 0) {
                args.readFromParcel(data);
            }
            const uint8_t* buf = NULL;
            size_t bufLength = 0;
            readByteArray(data, &buf, &bufLength);
            OperationResult result;
            update(token, args, buf, bufLength, &result);
            reply->writeNoException();
            reply->writeInt32(1);
            result.writeToParcel(reply);

            return NO_ERROR;
        }
        case FINISH: {
            CHECK_INTERFACE(IKeystoreService, data, reply);
            sp<IBinder> token = data.readStrongBinder();
            KeymasterArguments args;
            if (data.readInt32() != 0) {
                args.readFromParcel(data);
            }
            const uint8_t* signature = NULL;
            size_t signatureLength = 0;
            readByteArray(data, &signature, &signatureLength);
            const uint8_t* entropy = NULL;
            size_t entropyLength = 0;
            readByteArray(data, &entropy, &entropyLength);
            OperationResult result;
            finish(token, args, signature, signatureLength, entropy, entropyLength,  &result);
            reply->writeNoException();
            reply->writeInt32(1);
            result.writeToParcel(reply);

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
        default:
            return BBinder::onTransact(code, data, reply, flags);
    }
}

// ----------------------------------------------------------------------------

}; // namespace android
