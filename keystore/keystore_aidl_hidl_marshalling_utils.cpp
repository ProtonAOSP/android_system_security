/*
**
** Copyright 2016, The Android Open Source Project
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

#define LOG_TAG "KeystoreService"
#include <utils/Log.h>

#include "keystore_aidl_hidl_marshalling_utils.h"
#include <keystore/keystore_hidl_support.h>

namespace keystore {

hidl_vec<uint8_t> readKeymasterBlob(const android::Parcel& in, bool inPlace) {
    ssize_t length = in.readInt32();
    if (length <= 0) {
        return {};
    }

    const void* buf = in.readInplace(length);
    if (!buf) return {};

    return blob2hidlVec(reinterpret_cast<const uint8_t*>(buf), size_t(length), inPlace);
}

android::status_t writeKeymasterBlob(const hidl_vec<uint8_t>& blob, android::Parcel* out) {
    int32_t size = int32_t(std::min<size_t>(blob.size(), std::numeric_limits<int32_t>::max()));

    auto rc = out->writeInt32(size);
    if (rc != ::android::OK) return rc;

    if (!size) return ::android::OK;

    return out->write(&blob[0], size);
}

NullOr<hidl_vec<uint8_t>> readBlobAsByteArray(const android::Parcel& in, bool inPlace) {
    // The distinction from readKeymasterBob is that the byte array is not prefixed with a presence
    // value, instead a -1 in the length field indicates NULL.
    ssize_t length = in.readInt32();
    if (length < 0) {
        return {};
    }

    if (length == 0) {
        return hidl_vec<uint8_t>();
    }

    const void* buf = in.readInplace(length);
    if (!buf) return hidl_vec<uint8_t>();

    return blob2hidlVec(reinterpret_cast<const uint8_t*>(buf), size_t(length), inPlace);
}

android::status_t writeBlobAsByteArray(const NullOr<const hidl_vec<uint8_t>&>& blob,
                                       android::Parcel* out) {
    if (!blob.isOk()) {
        return out->writeInt32(-1);
    }
    int32_t size =
        int32_t(std::min<size_t>(blob.value().size(), std::numeric_limits<int32_t>::max()));

    auto rc = out->writeInt32(size);
    if (rc != ::android::OK) return rc;

    if (!size) return ::android::OK;

    return out->write(&blob.value()[0], size);
}

NullOr<KeyParameter> readKeyParameterFromParcel(const android::Parcel& in) {
    if (in.readInt32() == 0) {
        return {};
    }
    KeyParameter result;

    Tag tag = static_cast<Tag>(in.readInt32());
    result.tag = tag;
    switch (typeFromTag(tag)) {
    case TagType::ENUM:
    case TagType::ENUM_REP:
    case TagType::UINT:
    case TagType::UINT_REP:
        result.f.integer = in.readInt32();
        break;
    case TagType::ULONG:
    case TagType::ULONG_REP:
    case TagType::DATE:
        result.f.longInteger = in.readInt64();
        break;
    case TagType::BOOL:
        result.f.boolValue = true;
        break;
    case TagType::BIGNUM:
    case TagType::BYTES:
        result.blob = readKeymasterBlob(in);
        break;
    default:
        ALOGE("Unsupported KeyParameter tag %d", tag);
        return {};
    }
    return result;
}

android::status_t writeKeyParameterToParcel(const KeyParameter& param, android::Parcel* out) {
    auto tag = param.tag;
    auto rc = out->writeInt32(uint32_t(tag));
    if (rc != ::android::OK) return rc;
    switch (typeFromTag(param.tag)) {
    case TagType::ENUM:
    case TagType::ENUM_REP:
    case TagType::UINT:
    case TagType::UINT_REP:
        rc = out->writeInt32(param.f.integer);
        break;
    case TagType::ULONG:
    case TagType::ULONG_REP:
    case TagType::DATE:
        rc = out->writeInt64(param.f.longInteger);
        break;
    case TagType::BOOL:
        // nothing to do here presence indicates true
        break;
    case TagType::BIGNUM:
    case TagType::BYTES:
        rc = writeKeymasterBlob(param.blob, out);
        break;
    default:
        ALOGE("Failed to write KeyParameter: Unsupported tag %d", param.tag);
        rc = android::BAD_VALUE;
        break;
    }
    return rc;
}

hidl_vec<KeyParameter> readParamSetFromParcel(const android::Parcel& in) {
    ssize_t length = in.readInt32();
    size_t ulength = (size_t)length;
    if (length < 0) {
        ulength = 0;
    }
    hidl_vec<KeyParameter> result;
    result.resize(ulength);
    for (size_t i = 0; i < ulength; ++i) {
        auto param = readKeyParameterFromParcel(in);
        if (!param.isOk()) {
            ALOGE("Error reading KeyParameter from parcel");
            return {};
        }
        result[i] = param.value();
    }
    return result;
}

android::status_t writeParamSetToParcel(const hidl_vec<KeyParameter>& params,
                                        android::Parcel* out) {
    int32_t size = int32_t(std::min<size_t>(params.size(), std::numeric_limits<int32_t>::max()));

    auto rc = out->writeInt32(size);
    if (rc != ::android::OK) return rc;
    for (int32_t i = 0; i < size; ++i) {
        rc = out->writeInt32(1);
        if (rc != ::android::OK) return rc;
        rc = writeKeyParameterToParcel(params[i], out);
        if (rc != ::android::OK) return rc;
    }
    return rc;
}

KeyCharacteristics readKeyCharacteristicsFromParcel(const android::Parcel& in) {
    KeyCharacteristics result;
    result.softwareEnforced = readParamSetFromParcel(in);
    result.teeEnforced = readParamSetFromParcel(in);
    return result;
}

android::status_t writeKeyCharacteristicsToParcel(const KeyCharacteristics& keyChara,
                                                  android::Parcel* out) {
    auto rc = writeParamSetToParcel(keyChara.softwareEnforced, out);
    if (rc != ::android::OK) return rc;

    return writeParamSetToParcel(keyChara.teeEnforced, out);
}

hidl_vec<hidl_vec<uint8_t>> readCertificateChainFromParcel(const android::Parcel& in) {
    hidl_vec<hidl_vec<uint8_t>> result;

    ssize_t count = in.readInt32();
    size_t ucount = count;
    if (count <= 0) {
        return result;
    }

    result.resize(ucount);

    for (size_t i = 0; i < ucount; ++i) {
        result[i] = readKeymasterBlob(in);
    }
    return result;
}

android::status_t writeCertificateChainToParcel(const hidl_vec<hidl_vec<uint8_t>>& certs,
                                                android::Parcel* out) {
    int32_t count = int32_t(std::min<size_t>(certs.size(), std::numeric_limits<int32_t>::max()));
    auto rc = out->writeInt32(count);

    for (int32_t i = 0; i < count; ++i) {
        rc = writeKeymasterBlob(certs[i], out);
        if (rc != ::android::OK) return rc;
    }
    return rc;
}
}
