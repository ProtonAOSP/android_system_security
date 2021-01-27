/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "aaid.hpp"

#include <keystore/keystore_attestation_id.h>

using android::security::gather_attestation_application_id;

uint32_t aaid_keystore_attestation_id(uint32_t uid, uint8_t* aaid, size_t* aaid_size) {
    static_assert(sizeof(uint32_t) == sizeof(uid_t), "uid_t has unexpected size");
    static_assert(sizeof(uint32_t) == sizeof(android::status_t), "status_t has unexpected size");
    static_assert(KEY_ATTESTATION_APPLICATION_ID_MAX_SIZE ==
                      android::security::KEY_ATTESTATION_APPLICATION_ID_MAX_SIZE,
                  "KEY_ATTESTATION_APPLICATION_ID_MAX_SIZE sizes don't match.");
    auto result = gather_attestation_application_id(uid);
    if (!result.isOk()) {
        return result.status();
    }
    if (result.value().size() > KEY_ATTESTATION_APPLICATION_ID_MAX_SIZE) {
        return ::android::NO_MEMORY;
    }
    if (*aaid_size != KEY_ATTESTATION_APPLICATION_ID_MAX_SIZE) {
        return ::android::BAD_VALUE;
    }
    std::copy(result.value().begin(), result.value().end(), aaid);
    *aaid_size = result.value().size();
    return ::android::OK;
}
