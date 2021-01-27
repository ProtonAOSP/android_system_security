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
#pragma once

#include <stdint.h>
#include <stddef.h>

/**
 * This is a redefinition of KEY_ATTESTATION_APPLICATION_ID_MAX_SIZE in
 * system/security/keystore/keystore_attestation_id.h and must be kept in sync.
 * There is a static assert in aaid.cpp to assure that they are in sync.
 * We redefine this here to avoid unnecessary build dependencies for
 * the rust bindgen target.
 */
constexpr const size_t KEY_ATTESTATION_APPLICATION_ID_MAX_SIZE = 1024;

extern "C" {
    /**
     * Fills the buffer at aaid with the attestation application id of the app uid.
     * The buffer must be exactly KEY_ATTESTATION_APPLICATION_ID_MAX_SIZE bytes in size.
     * *aaid_size is set to the number of bytes written to aaid.
     *
     * @param uid the uid of the app to retrieve the aaid for.
     * @param aaid output buffer for the attestation id.
     * @param aaid_size must be set to the size of the output buffer, which must be exactly
     *          KEY_ATTESTATION_APPLICATION_ID_MAX_SIZE bytes in size, by the caller. On success
     *          it is set to the number of bytes written.
     * @return OK on success.
     */
    uint32_t aaid_keystore_attestation_id(uint32_t uid, uint8_t* aaid, size_t* aaid_size);
}
