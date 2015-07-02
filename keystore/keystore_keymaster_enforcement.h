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
        time_t now = time(NULL);
        if (now == static_cast<time_t>(-1)) {
            // Failed to obtain current time -- fail safe: activation_date hasn't yet occurred.
            return false;
        } else if (now < 0) {
            // Current time is prior to start of the epoch -- activation_date hasn't yet occurred.
            return false;
        }

        // time(NULL) returns seconds since epoch and "loses" milliseconds information. We thus add
        // 999 ms to now_date to avoid a situation where an activation_date of up to 999ms in the
        // past may still be considered to still be in the future. This can be removed once
        // time(NULL) is replaced by a millisecond-precise source of time.
        uint64_t now_date = static_cast<uint64_t>(now) * 1000 + 999;
        return now_date >= activation_date;
    }

    bool expiration_date_passed(uint64_t expiration_date) const override {
        time_t now = time(NULL);
        if (now == static_cast<time_t>(-1)) {
            // Failed to obtain current time -- fail safe: expiration_date has passed.
            return true;
        } else if (now < 0) {
            // Current time is prior to start of the epoch: expiration_date hasn't yet occurred.
            return false;
        }

        // time(NULL) returns seconds since epoch and "loses" milliseconds information. As a result,
        // expiration_date of up to 999 ms in the past may still be considered in the future. This
        // is OK.
        uint64_t now_date = static_cast<uint64_t>(now) * 1000;
        return now_date > expiration_date;
    }

    bool auth_token_timed_out(const hw_auth_token_t&, uint32_t) const {
        // Assume the token has not timed out, because AuthTokenTable would not have returned it if
        // the timeout were past.  Secure hardware will also check timeouts if it supports them.
        return false;
    }

    bool ValidateTokenSignature(const hw_auth_token_t&) const override {
        // Non-secure world cannot validate token signatures because it doesn't have access to the
        // signing key. Assume the token is good.
        return true;
    }
};

#endif  // KEYSTORE_KEYMASTER_ENFORCEMENT_H_
