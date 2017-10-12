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

#define LOG_TAG "keystore"

#include "auth_token_table.h"

#include <assert.h>
#include <time.h>

#include <algorithm>

#include <cutils/log.h>

namespace keystore {

template <typename IntType, uint32_t byteOrder> struct choose_hton;

template <typename IntType> struct choose_hton<IntType, __ORDER_LITTLE_ENDIAN__> {
    inline static IntType hton(const IntType& value) {
        IntType result = 0;
        const unsigned char* inbytes = reinterpret_cast<const unsigned char*>(&value);
        unsigned char* outbytes = reinterpret_cast<unsigned char*>(&result);
        for (int i = sizeof(IntType) - 1; i >= 0; --i) {
            *(outbytes++) = inbytes[i];
        }
        return result;
    }
};

template <typename IntType> struct choose_hton<IntType, __ORDER_BIG_ENDIAN__> {
    inline static IntType hton(const IntType& value) { return value; }
};

template <typename IntType> inline IntType hton(const IntType& value) {
    return choose_hton<IntType, __BYTE_ORDER__>::hton(value);
}

template <typename IntType> inline IntType ntoh(const IntType& value) {
    // same operation and hton
    return choose_hton<IntType, __BYTE_ORDER__>::hton(value);
}

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

void AuthTokenTable::AddAuthenticationToken(const HardwareAuthToken* auth_token) {
    Entry new_entry(auth_token, clock_function_());
    //STOPSHIP: debug only, to be removed
    ALOGD("AddAuthenticationToken: timestamp = %llu (%llu), time_received = %lld",
        static_cast<unsigned long long>(new_entry.timestamp_host_order()),
        static_cast<unsigned long long>(auth_token->timestamp),
        static_cast<long long>(new_entry.time_received()));

    RemoveEntriesSupersededBy(new_entry);
    if (entries_.size() >= max_entries_) {
        ALOGW("Auth token table filled up; replacing oldest entry");
        *min_element(entries_) = std::move(new_entry);
    } else {
        entries_.push_back(std::move(new_entry));
    }
}

inline bool is_secret_key_operation(Algorithm algorithm, KeyPurpose purpose) {
    if ((algorithm != Algorithm::RSA && algorithm != Algorithm::EC))
        return true;
    if (purpose == KeyPurpose::SIGN || purpose == KeyPurpose::DECRYPT)
        return true;
    return false;
}

inline bool KeyRequiresAuthentication(const AuthorizationSet& key_info, KeyPurpose purpose) {
    auto algorithm = defaultOr(key_info.GetTagValue(TAG_ALGORITHM), Algorithm::AES);
    return is_secret_key_operation(algorithm, purpose) &&
           key_info.find(Tag::NO_AUTH_REQUIRED) == -1;
}

inline bool KeyRequiresAuthPerOperation(const AuthorizationSet& key_info, KeyPurpose purpose) {
    auto algorithm = defaultOr(key_info.GetTagValue(TAG_ALGORITHM), Algorithm::AES);
    return is_secret_key_operation(algorithm, purpose) && key_info.find(Tag::AUTH_TIMEOUT) == -1;
}

AuthTokenTable::Error AuthTokenTable::FindAuthorization(const AuthorizationSet& key_info,
                                                        KeyPurpose purpose, uint64_t op_handle,
                                                        const HardwareAuthToken** found) {
    if (!KeyRequiresAuthentication(key_info, purpose)) return AUTH_NOT_REQUIRED;

    auto auth_type =
        defaultOr(key_info.GetTagValue(TAG_USER_AUTH_TYPE), HardwareAuthenticatorType::NONE);

    std::vector<uint64_t> key_sids;
    ExtractSids(key_info, &key_sids);

    if (KeyRequiresAuthPerOperation(key_info, purpose))
        return FindAuthPerOpAuthorization(key_sids, auth_type, op_handle, found);
    else
        return FindTimedAuthorization(key_sids, auth_type, key_info, found);
}

AuthTokenTable::Error
AuthTokenTable::FindAuthPerOpAuthorization(const std::vector<uint64_t>& sids,
                                           HardwareAuthenticatorType auth_type, uint64_t op_handle,
                                           const HardwareAuthToken** found) {
    if (op_handle == 0) return OP_HANDLE_REQUIRED;

    auto matching_op = find_if(
        entries_, [&](Entry& e) { return e.token()->challenge == op_handle && !e.completed(); });

    if (matching_op == entries_.end()) return AUTH_TOKEN_NOT_FOUND;

    if (!matching_op->SatisfiesAuth(sids, auth_type)) return AUTH_TOKEN_WRONG_SID;

    *found = matching_op->token();
    return OK;
}

AuthTokenTable::Error AuthTokenTable::FindTimedAuthorization(const std::vector<uint64_t>& sids,
                                                             HardwareAuthenticatorType auth_type,
                                                             const AuthorizationSet& key_info,
                                                             const HardwareAuthToken** found) {
    Entry* newest_match = NULL;
    for (auto& entry : entries_)
        if (entry.SatisfiesAuth(sids, auth_type) && entry.is_newer_than(newest_match))
            newest_match = &entry;

    if (!newest_match) return AUTH_TOKEN_NOT_FOUND;

    auto timeout = defaultOr(key_info.GetTagValue(TAG_AUTH_TIMEOUT), 0);

    time_t now = clock_function_();
    if (static_cast<int64_t>(newest_match->time_received()) + timeout < static_cast<int64_t>(now))
        return AUTH_TOKEN_EXPIRED;

    if (key_info.GetTagValue(TAG_ALLOW_WHILE_ON_BODY).isOk()) {
        if (static_cast<int64_t>(newest_match->time_received()) <
            static_cast<int64_t>(last_off_body_)) {
            return AUTH_TOKEN_EXPIRED;
        }
    }

    newest_match->UpdateLastUse(now);
    *found = newest_match->token();
    return OK;
}

void AuthTokenTable::ExtractSids(const AuthorizationSet& key_info, std::vector<uint64_t>* sids) {
    assert(sids);
    for (auto& param : key_info)
        if (param.tag == Tag::USER_SECURE_ID)
            sids->push_back(authorizationValue(TAG_USER_SECURE_ID, param).value());
}

void AuthTokenTable::RemoveEntriesSupersededBy(const Entry& entry) {
    entries_.erase(remove_if(entries_, [&](Entry& e) { return entry.Supersedes(e); }),
                   entries_.end());
}

void AuthTokenTable::onDeviceOffBody() {
    last_off_body_ = clock_function_();
}

void AuthTokenTable::Clear() {
    entries_.clear();
}

bool AuthTokenTable::IsSupersededBySomeEntry(const Entry& entry) {
    return std::any_of(entries_.begin(), entries_.end(),
                       [&](Entry& e) { return e.Supersedes(entry); });
}

void AuthTokenTable::MarkCompleted(const uint64_t op_handle) {
    auto found = find_if(entries_, [&](Entry& e) { return e.token()->challenge == op_handle; });
    if (found == entries_.end()) return;

    assert(!IsSupersededBySomeEntry(*found));
    found->mark_completed();

    if (IsSupersededBySomeEntry(*found)) entries_.erase(found);
}

AuthTokenTable::Entry::Entry(const HardwareAuthToken* token, time_t current_time)
    : token_(token), time_received_(current_time), last_use_(current_time),
      operation_completed_(token_->challenge == 0) {}

uint64_t AuthTokenTable::Entry::timestamp_host_order() const {
    return ntoh(token_->timestamp);
}

HardwareAuthenticatorType AuthTokenTable::Entry::authenticator_type() const {
    HardwareAuthenticatorType result = static_cast<HardwareAuthenticatorType>(
        ntoh(static_cast<uint32_t>(token_->authenticatorType)));
    return result;
}

bool AuthTokenTable::Entry::SatisfiesAuth(const std::vector<uint64_t>& sids,
                                          HardwareAuthenticatorType auth_type) {
    for (auto sid : sids)
        if ((sid == token_->authenticatorId) ||
            (sid == token_->userId && (auth_type & authenticator_type()) != 0))
            return true;
    return false;
}

void AuthTokenTable::Entry::UpdateLastUse(time_t time) {
    this->last_use_ = time;
}

bool AuthTokenTable::Entry::Supersedes(const Entry& entry) const {
    if (!entry.completed()) return false;

    return (token_->userId == entry.token_->userId &&
            token_->authenticatorType == entry.token_->authenticatorType &&
            token_->authenticatorId == entry.token_->authenticatorId &&
            timestamp_host_order() > entry.timestamp_host_order());
}

}  // namespace keymaster
