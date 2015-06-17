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

#include "auth_token_table.h"

#include <assert.h>
#include <time.h>

#include <algorithm>

#include <keymaster/android_keymaster_utils.h>
#include <keymaster/logger.h>

namespace keymaster {

//
// Some trivial template wrappers around std algorithms, so they take containers not ranges.
//
template <typename Container, typename Predicate>
typename Container::iterator find_if(Container& container, Predicate pred) {
    return std::find_if(container.begin(), container.end(), pred);
}

template <typename Container, typename Predicate>
typename Container::iterator remove_if(Container& container, Predicate pred) {
    return std::remove_if(container.begin(), container.end(), pred);
}

template <typename Container> typename Container::iterator min_element(Container& container) {
    return std::min_element(container.begin(), container.end());
}

time_t clock_gettime_raw() {
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC_RAW, &time);
    return time.tv_sec;
}

void AuthTokenTable::AddAuthenticationToken(const hw_auth_token_t* auth_token) {
    Entry new_entry(auth_token, clock_function_());
    RemoveEntriesSupersededBy(new_entry);
    if (entries_.size() >= max_entries_) {
        LOG_W("Auth token table filled up; replacing oldest entry", 0);
        *min_element(entries_) = std::move(new_entry);
    } else {
        entries_.push_back(std::move(new_entry));
    }
}

inline bool is_secret_key_operation(keymaster_algorithm_t algorithm, keymaster_purpose_t purpose) {
    if ((algorithm != KM_ALGORITHM_RSA || algorithm != KM_ALGORITHM_EC))
        return true;
    if (purpose == KM_PURPOSE_SIGN || purpose == KM_PURPOSE_DECRYPT)
        return true;
    return false;
}

inline bool KeyRequiresAuthentication(const AuthorizationSet& key_info,
                                      keymaster_purpose_t purpose) {
    keymaster_algorithm_t algorithm = KM_ALGORITHM_AES;
    key_info.GetTagValue(TAG_ALGORITHM, &algorithm);
    return is_secret_key_operation(algorithm, purpose) && key_info.find(TAG_NO_AUTH_REQUIRED) == -1;
}

inline bool KeyRequiresAuthPerOperation(const AuthorizationSet& key_info,
                                        keymaster_purpose_t purpose) {
    keymaster_algorithm_t algorithm = KM_ALGORITHM_AES;
    key_info.GetTagValue(TAG_ALGORITHM, &algorithm);
    return is_secret_key_operation(algorithm, purpose) && key_info.find(TAG_AUTH_TIMEOUT) == -1;
}

AuthTokenTable::Error AuthTokenTable::FindAuthorization(const AuthorizationSet& key_info,
                                                        keymaster_purpose_t purpose,
                                                        keymaster_operation_handle_t op_handle,
                                                        const hw_auth_token_t** found) {
    if (!KeyRequiresAuthentication(key_info, purpose))
        return AUTH_NOT_REQUIRED;

    hw_authenticator_type_t auth_type = HW_AUTH_NONE;
    key_info.GetTagValue(TAG_USER_AUTH_TYPE, &auth_type);

    std::vector<uint64_t> key_sids;
    ExtractSids(key_info, &key_sids);

    if (KeyRequiresAuthPerOperation(key_info, purpose))
        return FindAuthPerOpAuthorization(key_sids, auth_type, op_handle, found);
    else
        return FindTimedAuthorization(key_sids, auth_type, key_info, found);
}

AuthTokenTable::Error AuthTokenTable::FindAuthPerOpAuthorization(
    const std::vector<uint64_t>& sids, hw_authenticator_type_t auth_type,
    keymaster_operation_handle_t op_handle, const hw_auth_token_t** found) {
    if (op_handle == 0)
        return OP_HANDLE_REQUIRED;

    auto matching_op = find_if(
        entries_, [&](Entry& e) { return e.token()->challenge == op_handle && !e.completed(); });

    if (matching_op == entries_.end())
        return AUTH_TOKEN_NOT_FOUND;

    if (!matching_op->SatisfiesAuth(sids, auth_type))
        return AUTH_TOKEN_WRONG_SID;

    *found = matching_op->token();
    return OK;
}

AuthTokenTable::Error AuthTokenTable::FindTimedAuthorization(const std::vector<uint64_t>& sids,
                                                             hw_authenticator_type_t auth_type,
                                                             const AuthorizationSet& key_info,
                                                             const hw_auth_token_t** found) {
    Entry* newest_match = NULL;
    for (auto& entry : entries_)
        if (entry.SatisfiesAuth(sids, auth_type) && entry.is_newer_than(newest_match))
            newest_match = &entry;

    if (!newest_match)
        return AUTH_TOKEN_NOT_FOUND;

    uint32_t timeout;
    key_info.GetTagValue(TAG_AUTH_TIMEOUT, &timeout);
    time_t now = clock_function_();
    if (static_cast<int64_t>(newest_match->time_received()) + timeout < static_cast<int64_t>(now))
        return AUTH_TOKEN_EXPIRED;

    newest_match->UpdateLastUse(now);
    *found = newest_match->token();
    return OK;
}

void AuthTokenTable::ExtractSids(const AuthorizationSet& key_info, std::vector<uint64_t>* sids) {
    assert(sids);
    for (auto& param : key_info)
        if (param.tag == TAG_USER_SECURE_ID)
            sids->push_back(param.long_integer);
}

void AuthTokenTable::RemoveEntriesSupersededBy(const Entry& entry) {
    entries_.erase(remove_if(entries_, [&](Entry& e) { return entry.Supersedes(e); }),
                   entries_.end());
}

void AuthTokenTable::Clear() {
    entries_.clear();
}

bool AuthTokenTable::IsSupersededBySomeEntry(const Entry& entry) {
    return std::any_of(entries_.begin(), entries_.end(),
                       [&](Entry& e) { return e.Supersedes(entry); });
}

void AuthTokenTable::MarkCompleted(const keymaster_operation_handle_t op_handle) {
    auto found = find_if(entries_, [&](Entry& e) { return e.token()->challenge == op_handle; });
    if (found == entries_.end())
        return;

    assert(!IsSupersededBySomeEntry(*found));
    found->mark_completed();

    if (IsSupersededBySomeEntry(*found))
        entries_.erase(found);
}

AuthTokenTable::Entry::Entry(const hw_auth_token_t* token, time_t current_time)
    : token_(token), time_received_(current_time), last_use_(current_time),
      operation_completed_(token_->challenge == 0) {
}

uint32_t AuthTokenTable::Entry::timestamp_host_order() const {
    return ntoh(token_->timestamp);
}

hw_authenticator_type_t AuthTokenTable::Entry::authenticator_type() const {
    hw_authenticator_type_t result = static_cast<hw_authenticator_type_t>(
        ntoh(static_cast<uint32_t>(token_->authenticator_type)));
    return result;
}

bool AuthTokenTable::Entry::SatisfiesAuth(const std::vector<uint64_t>& sids,
                                          hw_authenticator_type_t auth_type) {
    for (auto sid : sids)
        if ((sid == token_->authenticator_id) ||
            (sid == token_->user_id && (auth_type & authenticator_type()) != 0))
            return true;
    return false;
}

void AuthTokenTable::Entry::UpdateLastUse(time_t time) {
    this->last_use_ = time;
}

bool AuthTokenTable::Entry::Supersedes(const Entry& entry) const {
    if (!entry.completed())
        return false;

    return (token_->user_id == entry.token_->user_id &&
            token_->authenticator_type == entry.token_->authenticator_type &&
            token_->authenticator_type == entry.token_->authenticator_type &&
            timestamp_host_order() > entry.timestamp_host_order());
}

}  // namespace keymaster
