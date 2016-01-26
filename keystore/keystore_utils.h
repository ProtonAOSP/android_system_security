/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef KEYSTORE_KEYSTORE_UTILS_H_
#define KEYSTORE_KEYSTORE_UTILS_H_

#include <stdint.h>

#include <vector>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <hardware/keymaster_defs.h>

#include <UniquePtr.h>

size_t readFully(int fd, uint8_t* data, size_t size);
size_t writeFully(int fd, uint8_t* data, size_t size);

void add_legacy_key_authorizations(int keyType, std::vector<keymaster_key_param_t>* params);

/**
 * Returns the app ID (in the Android multi-user sense) for the current
 * UNIX UID.
 */
uid_t get_app_id(uid_t uid);

/**
 * Returns the user ID (in the Android multi-user sense) for the current
 * UNIX UID.
 */
uid_t get_user_id(uid_t uid);

struct EVP_PKEY_Delete {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
typedef UniquePtr<EVP_PKEY, EVP_PKEY_Delete> Unique_EVP_PKEY;

struct PKCS8_PRIV_KEY_INFO_Delete {
    void operator()(PKCS8_PRIV_KEY_INFO* p) const { PKCS8_PRIV_KEY_INFO_free(p); }
};
typedef UniquePtr<PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_Delete> Unique_PKCS8_PRIV_KEY_INFO;

#endif  // KEYSTORE_KEYSTORE_UTILS_H_
