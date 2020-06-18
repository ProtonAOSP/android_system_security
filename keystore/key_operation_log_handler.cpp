/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "key_operation_log_handler.h"
#include "key_creation_log_handler.h"

#include <keystore/keystore_hidl_support.h>
#include <statslog.h>

namespace keystore {

template <typename Tag>
int32_t getOptionalEnumTagValue(const AuthorizationSet& authorization_set, Tag tag) {
    auto tagValue = authorization_set.GetTagValue(tag);
    if (tagValue.isOk()) {
        static_assert(sizeof(decltype(tagValue.value())) <= sizeof(int32_t),
                      "Tag type value will be truncated, if cast to int32_t");
        return static_cast<int32_t>(tagValue.value());
    }
    //-1 is an invalid value for all enum types.
    return -1;
}

int32_t generateBitMapForPaddingModeValue(const AuthorizationSet& authorization_set) {
    auto tagValue = authorization_set.GetTagValue(TAG_PADDING);
    if (tagValue.isOk()) {
        auto value = tagValue.value();
        switch (value) {
        case PaddingMode::NONE:
            return (1 << NONE_BIT_POS);
        case PaddingMode::RSA_OAEP:
            return (1 << PaddingModeBitPosition::RSA_OAEP_BIT_POS);
        case PaddingMode::RSA_PSS:
            return (1 << PaddingModeBitPosition::RSA_PSS_BIT_POS);
        case PaddingMode::RSA_PKCS1_1_5_ENCRYPT:
            return (1 << PaddingModeBitPosition::RSA_PKCS1_1_5_ENCRYPT_BIT_POS);
        case PaddingMode::RSA_PKCS1_1_5_SIGN:
            return (1 << PaddingModeBitPosition::RSA_PKCS1_1_5_SIGN_BIT_POS);
        case PaddingMode::PKCS7:
            return (1 << PaddingModeBitPosition::PKCS7_BIT_POS);
        default:
            break;
        }
    }
    // unlike in the single enum fields, if no value is provided,
    // 0 is set for the bitmap
    return 0;
}

int32_t generateBitMapForDigestValue(const AuthorizationSet& authorization_set) {
    auto tagValue = authorization_set.GetTagValue(TAG_DIGEST);
    if (tagValue.isOk()) {
        auto value = tagValue.value();
        switch (value) {
        case Digest::NONE:
            return (1 << NONE_BIT_POS);
        case Digest::MD5:
            return (1 << DigestBitPosition::MD5_BIT_POS);
        case Digest::SHA1:
            return (1 << DigestBitPosition::SHA1_BIT_POS);
        case Digest::SHA_2_224:
            return (1 << DigestBitPosition::SHA_2_224_BIT_POS);
        case Digest::SHA_2_256:
            return (1 << DigestBitPosition::SHA_2_256_BIT_POS);
        case Digest::SHA_2_384:
            return (1 << DigestBitPosition::SHA_2_384_BIT_POS);
        case Digest::SHA_2_512:
            return (1 << DigestBitPosition::SHA_2_512_BIT_POS);
        default:
            break;
        }
    }
    // unlike in the single enum fields, if no value is provided,
    // 0 is set for the bitmap
    return 0;
}

int32_t generateBitMapForBlockModeValue(const AuthorizationSet& authorization_set) {
    auto tagValue = authorization_set.GetTagValue(TAG_BLOCK_MODE);
    if (tagValue.isOk()) {
        auto value = tagValue.value();
        switch (value) {
        case BlockMode::ECB:
            return (1 << BlockModeBitPosition::ECB_BIT_POS);
        case BlockMode::CBC:
            return (1 << BlockModeBitPosition::CBC_BIT_POS);
        case BlockMode::CTR:
            return (1 << BlockModeBitPosition::CTR_BIT_POS);
        case BlockMode::GCM:
            return (1 << BlockModeBitPosition::GCM_BIT_POS);
        default:
            break;
        }
    }
    // unlike in the single enum fields, if no value is provided,
    // 0 is set for the bitmap
    return 0;
}

void logKeystoreKeyOperationEvent(const Operation& op, bool wasOperationSuccessful,
                                  int32_t responseCode) {
    AuthorizationSet authorization_set(op.characteristics.softwareEnforced);
    authorization_set.Union(op.characteristics.hardwareEnforced);
    AuthorizationSet operation_params(op.params);

    android::util::stats_write(
        android::util::KEYSTORE_KEY_EVENT_REPORTED,
        getOptionalEnumTagValue(authorization_set, TAG_ALGORITHM),
        getOptionalEnumTagValue(authorization_set, TAG_KEY_SIZE),
        getOptionalEnumTagValue(authorization_set, TAG_ORIGIN),
        getOptionalEnumTagValue(authorization_set, TAG_USER_AUTH_TYPE),
        getOptionalEnumTagValue(authorization_set, TAG_AUTH_TIMEOUT),
        generateBitMapForPaddingModeValue(operation_params),
        generateBitMapForDigestValue(operation_params),
        generateBitMapForBlockModeValue(operation_params), static_cast<int32_t>(op.purpose),
        getOptionalEnumTagValue(authorization_set, TAG_EC_CURVE),
        getOptionalEnumTagValue(authorization_set, TAG_BLOB_USAGE_REQUIREMENTS),
        android::util::KEYSTORE_KEY_EVENT_REPORTED__TYPE__KEY_OPERATION, wasOperationSuccessful,
        responseCode);
}

}  // namespace keystore