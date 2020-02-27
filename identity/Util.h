/*
 * Copyright (c) 2019, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SYSTEM_SECURITY_IDENTITY_UTIL_H_
#define SYSTEM_SECURITY_IDENTITY_UTIL_H_

#include <string>
#include <vector>

#include <binder/Status.h>

namespace android {
namespace security {
namespace identity {

using ::std::optional;
using ::std::string;
using ::std::vector;

using ::android::binder::Status;

// Converts a HAL status to a credstore service-specific error with code
// ICredentialStore::ERROR_GENERIC.
Status halStatusToGenericError(const Status& halStatus);

// Converts a HAL status to a credstore service-specific error of a given value
Status halStatusToError(const Status& halStatus, int credStoreError);

// Helper function to atomically write |data| into file at |path|.
//
// Returns true on success, false on error.
//
bool fileSetContents(const string& path, const vector<uint8_t>& data);

// Helper function which reads contents offile at |path| into |data|.
//
// Returns nothing on error, the content on success.
//
optional<vector<uint8_t>> fileGetContents(const string& path);

}  // namespace identity
}  // namespace security
}  // namespace android

#endif  // SYSTEM_SECURITY_IDENTITY_UTIL_H_
