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

#ifndef KEY_CREATION_LOG_HANDLER_H_
#define KEY_CREATION_LOG_HANDLER_H_

#include <keystore/keystore_hidl_support.h>

namespace keystore {

/**
 * Following enums are defined as a part of the workaround to log the repeated
 * values of ENUM_REP type. The workaround is to represent the repeated values
 * of ENUM_REP type as a bitmap and the following enums define their positions
 * in the bitmap.
 */

enum PaddingModeBitPosition : int32_t {
    RSA_OAEP_BIT_POS = 1,
    RSA_PSS_BIT_POS = 2,
    RSA_PKCS1_1_5_ENCRYPT_BIT_POS = 3,
    RSA_PKCS1_1_5_SIGN_BIT_POS = 4,
    PKCS7_BIT_POS = 5,
};

enum DigestBitPosition : int32_t {
    MD5_BIT_POS = 1,
    SHA1_BIT_POS = 2,
    SHA_2_224_BIT_POS = 3,
    SHA_2_256_BIT_POS = 4,
    SHA_2_384_BIT_POS = 5,
    SHA_2_512_BIT_POS = 6,
};

enum BlockModeBitPosition : int32_t {
    ECB_BIT_POS = 1,
    CBC_BIT_POS = 2,
    CTR_BIT_POS = 3,
    GCM_BIT_POS = 4,
};

enum KeyPurposeBitPosition : int32_t {
    ENCRYPT_BIT_POS = 1,
    DECRYPT_BIT_POS = 2,
    SIGN_BIT_POS = 3,
    VERIFY_BIT_POS = 4,
    WRAP_KEY_BIT_POS = 5,
};

// None is an enum value for digest and a deprecated value for padding mode
const int32_t NONE_BIT_POS = 0;

void logKeystoreKeyCreationEvent(const hidl_vec<KeyParameter>& keyParams,
                                 bool wasCreationSuccessful, int32_t errorCode);

}  // namespace keystore

#endif  // KEY_CREATION_LOG_HANDLER_H_
