/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "grant_store.h"

#include <algorithm>
#include <sstream>

namespace keystore {

static constexpr uint64_t kInvalidGrantNo = std::numeric_limits<uint64_t>::max();
static const char* kKeystoreGrantInfix = "_KEYSTOREGRANT_";
static constexpr size_t kKeystoreGrantInfixLength = 15;

Grant::Grant(const std::string& alias, const std::string& owner_dir_name, const uid_t owner_uid,
             const uint64_t grant_no)
        : alias_(alias), owner_dir_name_(owner_dir_name), owner_uid_(owner_uid),
          grant_no_(grant_no) {}

static std::pair<uint64_t, std::string> parseGrantAlias(const std::string& grantAlias) {
    auto pos = grantAlias.rfind(kKeystoreGrantInfix);
    if (pos == std::string::npos) return {kInvalidGrantNo, ""};
    std::stringstream s(grantAlias.substr(pos + kKeystoreGrantInfixLength));
    std::string wrapped_alias = grantAlias.substr(0, pos);
    uint64_t grant_no = kInvalidGrantNo;
    s >> grant_no;
    if (s.fail() || grant_no == kInvalidGrantNo) return {kInvalidGrantNo, ""};
    return {grant_no, wrapped_alias};
}

std::string GrantStore::put(const uid_t uid, const std::string& alias,
                            const std::string& owner_dir_name, const uid_t owner_uid) {
    std::stringstream s;
    s << alias << kKeystoreGrantInfix;
    auto& uid_grant_list = grants_[uid];

    bool success = false;
    auto iterator = std::find_if(uid_grant_list.begin(), uid_grant_list.end(),
            [&](auto& entry) {
                return success = entry.alias_ == alias && entry.owner_dir_name_ == owner_dir_name
                        && entry.owner_uid_ == owner_uid;
            });
    while (!success) {
        std::tie(iterator, success) = uid_grant_list.emplace(alias, owner_dir_name, owner_uid,
                                                             std::rand());
    }
    s << iterator->grant_no_;
    return s.str();
}

const Grant* GrantStore::get(const uid_t uid, const std::string& alias) const {
    uint64_t grant_no;
    std::string wrappedAlias;
    std::tie(grant_no, wrappedAlias) = parseGrantAlias(alias);
    if (grant_no == kInvalidGrantNo) return nullptr;
    auto uid_set_iter = grants_.find(uid);
    if (uid_set_iter == grants_.end()) return nullptr;
    auto& uid_grant_list = uid_set_iter->second;
    auto grant = uid_grant_list.find(grant_no);
    if (grant == uid_grant_list.end()) return nullptr;
    if (grant->alias_ != wrappedAlias) return nullptr;
    return &(*grant);
}

bool GrantStore::removeByFileAlias(const uid_t uid, const std::string& alias) {
    auto& uid_grant_list = grants_[uid];
    for (auto i = uid_grant_list.begin(); i != uid_grant_list.end(); ++i) {
        if (i->alias_ == alias) {
            uid_grant_list.erase(i);
            return true;
        }
    }
    return false;
}

}  // namespace keystore
