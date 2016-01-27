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

#define LOG_TAG "keystore"

#include "keystore_utils.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <cutils/log.h>
#include <private/android_filesystem_config.h>

#include <keymaster/android_keymaster_utils.h>

size_t readFully(int fd, uint8_t* data, size_t size) {
    size_t remaining = size;
    while (remaining > 0) {
        ssize_t n = TEMP_FAILURE_RETRY(read(fd, data, remaining));
        if (n <= 0) {
            return size - remaining;
        }
        data += n;
        remaining -= n;
    }
    return size;
}

size_t writeFully(int fd, uint8_t* data, size_t size) {
    size_t remaining = size;
    while (remaining > 0) {
        ssize_t n = TEMP_FAILURE_RETRY(write(fd, data, remaining));
        if (n < 0) {
            ALOGW("write failed: %s", strerror(errno));
            return size - remaining;
        }
        data += n;
        remaining -= n;
    }
    return size;
}

void add_legacy_key_authorizations(int keyType, std::vector<keymaster_key_param_t>* params) {
    params->push_back(keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_SIGN));
    params->push_back(keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_VERIFY));
    params->push_back(keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_ENCRYPT));
    params->push_back(keymaster_param_enum(KM_TAG_PURPOSE, KM_PURPOSE_DECRYPT));
    params->push_back(keymaster_param_enum(KM_TAG_PADDING, KM_PAD_NONE));
    if (keyType == EVP_PKEY_RSA) {
        params->push_back(keymaster_param_enum(KM_TAG_PADDING, KM_PAD_RSA_PKCS1_1_5_SIGN));
        params->push_back(keymaster_param_enum(KM_TAG_PADDING, KM_PAD_RSA_PKCS1_1_5_ENCRYPT));
        params->push_back(keymaster_param_enum(KM_TAG_PADDING, KM_PAD_RSA_PSS));
        params->push_back(keymaster_param_enum(KM_TAG_PADDING, KM_PAD_RSA_OAEP));
    }
    params->push_back(keymaster_param_enum(KM_TAG_DIGEST, KM_DIGEST_NONE));
    params->push_back(keymaster_param_enum(KM_TAG_DIGEST, KM_DIGEST_MD5));
    params->push_back(keymaster_param_enum(KM_TAG_DIGEST, KM_DIGEST_SHA1));
    params->push_back(keymaster_param_enum(KM_TAG_DIGEST, KM_DIGEST_SHA_2_224));
    params->push_back(keymaster_param_enum(KM_TAG_DIGEST, KM_DIGEST_SHA_2_256));
    params->push_back(keymaster_param_enum(KM_TAG_DIGEST, KM_DIGEST_SHA_2_384));
    params->push_back(keymaster_param_enum(KM_TAG_DIGEST, KM_DIGEST_SHA_2_512));
    params->push_back(keymaster_param_bool(KM_TAG_ALL_USERS));
    params->push_back(keymaster_param_bool(KM_TAG_NO_AUTH_REQUIRED));
    params->push_back(keymaster_param_date(KM_TAG_ORIGINATION_EXPIRE_DATETIME, LLONG_MAX));
    params->push_back(keymaster_param_date(KM_TAG_USAGE_EXPIRE_DATETIME, LLONG_MAX));
    params->push_back(keymaster_param_date(KM_TAG_ACTIVE_DATETIME, 0));
}

uid_t get_app_id(uid_t uid) {
    return uid % AID_USER;
}

uid_t get_user_id(uid_t uid) {
    return uid / AID_USER;
}
