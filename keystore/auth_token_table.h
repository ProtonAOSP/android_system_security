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

#include <memory>
#include <vector>

#include <hardware/hw_auth_token.h>
#include <keymaster/authorization_set.h>

#ifndef KEYSTORE_AUTH_TOKEN_TABLE_H_
#define KEYSTORE_AUTH_TOKEN_TABLE_H_

namespace keymaster {

namespace test {
class AuthTokenTableTest;
}  // namespace test

time_t clock_gettime_raw();

/**
 * AuthTokenTable manages a set of received authorization tokens and can provide the appropriate
 * token for authorizing a key operation.
 *
 * To keep the table from growing without bound, superseded entries are removed when possible, and
 * least recently used entries are automatically pruned when when the table exceeds a size limit,
 * which is expected to be relatively small, since the implementation uses a linear search.
 */
class AuthTokenTable {
  public:
    AuthTokenTable(size_t max_entries = 32, time_t (*clock_function)() = clock_gettime_raw)
        : max_entries_(max_entries), last_off_body_(clock_function()), clock_function_(clock_function) {}

    enum Error {
        OK,
        AUTH_NOT_REQUIRED = -1,
        AUTH_TOKEN_EXPIRED = -2,    // Found a matching token, but it's too old.
        AUTH_TOKEN_WRONG_SID = -3,  // Found a token with the right challenge, but wrong SID.  This
                                    // most likely indicates that the authenticator was updated
                                    // (e.g. new fingerprint enrolled).
        OP_HANDLE_REQUIRED = -4,    // The key requires auth per use but op_handle was zero.
        AUTH_TOKEN_NOT_FOUND = -5,
    };

    /**
     * Add an authorization token to the table.  The table takes ownership of the argument.
     */
    void AddAuthenticationToken(const hw_auth_token_t* token);

    /**
     * Find an authorization token that authorizes the operation specified by \p operation_handle on
     * a key with the characteristics specified in \p key_info.
     *
     * This method is O(n * m), where n is the number of KM_TAG_USER_SECURE_ID entries in key_info
     * and m is the number of entries in the table.  It could be made better, but n and m should
     * always be small.
     *
     * The table retains ownership of the returned object.
     */
    Error FindAuthorization(const AuthorizationSet& key_info, keymaster_purpose_t purpose,
                            keymaster_operation_handle_t op_handle, const hw_auth_token_t** found);

    /**
     * Find an authorization token that authorizes the operation specified by \p operation_handle on
     * a key with the characteristics specified in \p key_info.
     *
     * This method is O(n * m), where n is the number of KM_TAG_USER_SECURE_ID entries in key_info
     * and m is the number of entries in the table.  It could be made better, but n and m should
     * always be small.
     *
     * The table retains ownership of the returned object.
     */
    Error FindAuthorization(const keymaster_key_param_t* params, size_t params_count,
                            keymaster_purpose_t purpose, keymaster_operation_handle_t op_handle,
                            const hw_auth_token_t** found) {
        return FindAuthorization(AuthorizationSet(params, params_count), purpose, op_handle, found);
    }

    /**
     * Mark operation completed.  This allows tokens associated with the specified operation to be
     * superseded by new tokens.
     */
    void MarkCompleted(const keymaster_operation_handle_t op_handle);

    /**
     * Update the last_off_body_ timestamp so that tokens which remain authorized only so long as
     * the device stays on body can be revoked.
     */
    void onDeviceOffBody();

    void Clear();

    size_t size() { return entries_.size(); }

  private:
    friend class AuthTokenTableTest;

    class Entry {
      public:
        Entry(const hw_auth_token_t* token, time_t current_time);
        Entry(Entry&& entry) { *this = std::move(entry); }

        void operator=(Entry&& rhs) {
            token_ = std::move(rhs.token_);
            time_received_ = rhs.time_received_;
            last_use_ = rhs.last_use_;
            operation_completed_ = rhs.operation_completed_;
        }

        bool operator<(const Entry& rhs) const { return last_use_ < rhs.last_use_; }

        void UpdateLastUse(time_t time);

        bool Supersedes(const Entry& entry) const;
        bool SatisfiesAuth(const std::vector<uint64_t>& sids, hw_authenticator_type_t auth_type);

        bool is_newer_than(const Entry* entry) {
            if (!entry)
                return true;
            return timestamp_host_order() > entry->timestamp_host_order();
        }

        void mark_completed() { operation_completed_ = true; }

        const hw_auth_token_t* token() { return token_.get(); }
        time_t time_received() const { return time_received_; }
        bool completed() const { return operation_completed_; }
        uint32_t timestamp_host_order() const;
        hw_authenticator_type_t authenticator_type() const;

      private:
        std::unique_ptr<const hw_auth_token_t> token_;
        time_t time_received_;
        time_t last_use_;
        bool operation_completed_;
    };

    Error FindAuthPerOpAuthorization(const std::vector<uint64_t>& sids,
                                     hw_authenticator_type_t auth_type,
                                     keymaster_operation_handle_t op_handle,
                                     const hw_auth_token_t** found);
    Error FindTimedAuthorization(const std::vector<uint64_t>& sids,
                                 hw_authenticator_type_t auth_type,
                                 const AuthorizationSet& key_info, const hw_auth_token_t** found);
    void ExtractSids(const AuthorizationSet& key_info, std::vector<uint64_t>* sids);
    void RemoveEntriesSupersededBy(const Entry& entry);
    bool IsSupersededBySomeEntry(const Entry& entry);

    std::vector<Entry> entries_;
    size_t max_entries_;
    time_t last_off_body_;
    time_t (*clock_function_)();
};

}  // namespace keymaster

#endif  // KEYSTORE_AUTH_TOKEN_TABLE_H_
