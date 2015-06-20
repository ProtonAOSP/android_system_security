/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef KEYSTORE_KEYMASTER_ENFORCEMENT_H_
#define KEYSTORE_KEYMASTER_ENFORCEMENT_H_

#include <time.h>

#include <keymaster/keymaster_enforcement.h>

/**
 * This is a specialization of the KeymasterEnforcement class to be used by Keystore to enforce
 * keymaster requirements on all key operation.
 */
class KeystoreKeymasterEnforcement : public keymaster::KeymasterEnforcement {
  public:
    KeystoreKeymasterEnforcement() : KeymasterEnforcement(64, 64) {}

    uint32_t get_current_time() const override {
        struct timespec tp;
        int err = clock_gettime(CLOCK_MONOTONIC, &tp);
        if (err || tp.tv_sec < 0)
            return 0;
        return static_cast<uint32_t>(tp.tv_sec);
    }

    bool activation_date_valid(uint64_t activation_date) const override {
        // Convert java date to time_t, non-portably.
        time_t activation_time = activation_date / 1000;
        return difftime(time(NULL), activation_time) >= 0;
    }

    bool expiration_date_passed(uint64_t expiration_date) const override {
        // Convert jave date to time_t, non-portably.
        time_t expiration_time = expiration_date / 1000;
        return difftime(time(NULL), expiration_time) > 0;
    }

    bool auth_token_timed_out(const hw_auth_token_t&, uint32_t) const {
        // Non-secure world cannot check token timeouts because it doesn't have access to the secure
        // clock.  Assume the token is good.
        return true;
    }

    bool ValidateTokenSignature(const hw_auth_token_t&) const override {
        // Non-secure world cannot validate token signatures because it doesn't have access to the
        // signing key. Assume the token is good.
        return true;
    }
};

#endif  // KEYSTORE_KEYMASTER_ENFORCEMENT_H_
