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

#include "key_creation_log_handler.h"
#include <statslog.h>

namespace keystore {

template <typename Tag>
int32_t getEnumTagValue(const AuthorizationSet& authorization_set, Tag tag) {
    auto tagValue = authorization_set.GetTagValue(tag);
    if (tagValue.isOk()) {
        static_assert(sizeof(decltype(tagValue.value())) <= sizeof(int32_t),
                      "Tag type value will be truncated, if cast to int32_t");
        return static_cast<int32_t>(tagValue.value());
    }
    // Usually, if the value is not present, 0 is set. However, since 0 is a valid
    // enum value, -1 is set for single enum fields.
    return -1;
}

int32_t generateBitMapForPaddingModeValues(const AuthorizationSet& authorization_set) {
    int32_t bitMap = 0;
    int32_t tagValueCount = authorization_set.GetTagCount(TAG_PADDING);
    if (tagValueCount == 0) {
        // unlike in the single enum fields, if no value is provided,
        // 0 is set for the bitmap
        return bitMap;
    }
    int current_offset = -1;
    while (tagValueCount > 0) {
        current_offset = authorization_set.find(TAG_PADDING, current_offset);
        KeyParameter keyParam = authorization_set[current_offset];
        auto tagValue = accessTagValue(TAG_PADDING, keyParam);
        switch (tagValue) {
        case PaddingMode::NONE:
            bitMap |= (1 << NONE_BIT_POS);
            break;
        case PaddingMode::RSA_OAEP:
            bitMap |= (1 << PaddingModeBitPosition::RSA_OAEP_BIT_POS);
            break;
        case PaddingMode::RSA_PSS:
            bitMap |= (1 << PaddingModeBitPosition::RSA_PSS_BIT_POS);
            break;
        case PaddingMode::RSA_PKCS1_1_5_ENCRYPT:
            bitMap |= (1 << PaddingModeBitPosition::RSA_PKCS1_1_5_ENCRYPT_BIT_POS);
            break;
        case PaddingMode::RSA_PKCS1_1_5_SIGN:
            bitMap |= (1 << PaddingModeBitPosition::RSA_PKCS1_1_5_SIGN_BIT_POS);
            break;
        case PaddingMode::PKCS7:
            bitMap |= (1 << PaddingModeBitPosition::PKCS7_BIT_POS);
            break;
        default:
            break;
        }
        tagValueCount -= 1;
    }
    return bitMap;
}

int32_t generateBitMapForDigestValues(const AuthorizationSet& authorization_set) {
    int32_t bitMap = 0;
    int32_t tagValueCount = authorization_set.GetTagCount(TAG_DIGEST);
    if (tagValueCount == 0) {
        // unlike in the single enum fields, if no value is provided,
        // 0 is set for the bitmap
        return bitMap;
    }
    int current_offset = -1;
    while (tagValueCount > 0) {
        current_offset = authorization_set.find(TAG_DIGEST, current_offset);
        KeyParameter keyParam = authorization_set[current_offset];
        auto tagValue = accessTagValue(TAG_DIGEST, keyParam);
        switch (tagValue) {
        case Digest::NONE:
            bitMap |= (1 << NONE_BIT_POS);
            break;
        case Digest::MD5:
            bitMap |= (1 << DigestBitPosition::MD5_BIT_POS);
            break;
        case Digest::SHA1:
            bitMap |= (1 << DigestBitPosition::SHA1_BIT_POS);
            break;
        case Digest::SHA_2_224:
            bitMap |= (1 << DigestBitPosition::SHA_2_224_BIT_POS);
            break;
        case Digest::SHA_2_256:
            bitMap |= (1 << DigestBitPosition::SHA_2_256_BIT_POS);
            break;
        case Digest::SHA_2_384:
            bitMap |= (1 << DigestBitPosition::SHA_2_384_BIT_POS);
            break;
        case Digest::SHA_2_512:
            bitMap |= (1 << DigestBitPosition::SHA_2_512_BIT_POS);
            break;
        default:
            break;
        }
        tagValueCount -= 1;
    }
    return bitMap;
}

int32_t generateBitMapForBlockModeValues(const AuthorizationSet& authorization_set) {
    int32_t bitMap = 0;
    int32_t tagValueCount = authorization_set.GetTagCount(TAG_BLOCK_MODE);
    if (tagValueCount == 0) {
        // unlike in the single enum fields, if no value is provided,
        // 0 is set for the bitmap
        return bitMap;
    }
    int current_offset = -1;
    while (tagValueCount > 0) {
        current_offset = authorization_set.find(TAG_BLOCK_MODE, current_offset);
        KeyParameter keyParam = authorization_set[current_offset];
        auto tagValue = accessTagValue(TAG_BLOCK_MODE, keyParam);
        switch (tagValue) {
        case BlockMode::ECB:
            bitMap |= (1 << BlockModeBitPosition::ECB_BIT_POS);
            break;
        case BlockMode::CBC:
            bitMap |= (1 << BlockModeBitPosition::CBC_BIT_POS);
            break;
        case BlockMode::CTR:
            bitMap |= (1 << BlockModeBitPosition::CTR_BIT_POS);
            break;
        case BlockMode::GCM:
            bitMap |= (1 << BlockModeBitPosition::GCM_BIT_POS);
            break;
        default:
            break;
        }
        tagValueCount -= 1;
    }
    return bitMap;
}

int32_t generateBitMapForKeyPurposeValues(const AuthorizationSet& authorization_set) {
    int32_t bitMap = 0;
    int32_t tagValueCount = authorization_set.GetTagCount(TAG_PURPOSE);
    if (tagValueCount == 0) {
        // unlike in the single enum fields, if no value is provided,
        // 0 is set for the bitmap
        return bitMap;
    }
    int current_offset = -1;
    while (tagValueCount > 0) {
        current_offset = authorization_set.find(TAG_PURPOSE, current_offset);
        KeyParameter keyParam = authorization_set[current_offset];
        auto tagValue = accessTagValue(TAG_PURPOSE, keyParam);
        switch (tagValue) {
        case KeyPurpose::ENCRYPT:
            bitMap |= (1 << KeyPurposeBitPosition::ENCRYPT_BIT_POS);
            break;
        case KeyPurpose::DECRYPT:
            bitMap |= (1 << KeyPurposeBitPosition::DECRYPT_BIT_POS);
            break;
        case KeyPurpose::SIGN:
            bitMap |= (1 << KeyPurposeBitPosition::SIGN_BIT_POS);
            break;
        case KeyPurpose::VERIFY:
            bitMap |= (1 << KeyPurposeBitPosition::VERIFY_BIT_POS);
            break;
        case KeyPurpose::WRAP_KEY:
            bitMap |= (1 << KeyPurposeBitPosition::WRAP_KEY_BIT_POS);
            break;
        default:
            break;
        }
        tagValueCount -= 1;
    }
    return bitMap;
}

void logKeystoreKeyCreationEvent(const hidl_vec<KeyParameter>& keyParams,
                                 bool wasCreationSuccessful, int32_t errorCode) {
    AuthorizationSet authorization_set(keyParams);
    authorization_set.Deduplicate();

    android::util::stats_write(android::util::KEYSTORE_KEY_EVENT_REPORTED,
                               getEnumTagValue(authorization_set, TAG_ALGORITHM),
                               getEnumTagValue(authorization_set, TAG_KEY_SIZE),
                               getEnumTagValue(authorization_set, TAG_ORIGIN),
                               getEnumTagValue(authorization_set, TAG_USER_AUTH_TYPE),
                               getEnumTagValue(authorization_set, TAG_AUTH_TIMEOUT),
                               generateBitMapForPaddingModeValues(authorization_set),
                               generateBitMapForDigestValues(authorization_set),
                               generateBitMapForBlockModeValues(authorization_set),
                               generateBitMapForKeyPurposeValues(authorization_set),
                               getEnumTagValue(authorization_set, TAG_EC_CURVE),
                               getEnumTagValue(authorization_set, TAG_BLOB_USAGE_REQUIREMENTS),
                               android::util::KEYSTORE_KEY_EVENT_REPORTED__TYPE__KEY_CREATION,
                               wasCreationSuccessful, errorCode);
}

}  // namespace keystore
