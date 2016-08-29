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

#ifndef KEYSTORE_KEYSTORE_ATTESTATION_ID_H_
#define KEYSTORE_KEYSTORE_ATTESTATION_ID_H_

#include <utils/Errors.h>
#include <vector>

namespace android {
namespace security {

/**
 * Gathers the attestation id for the application determined by uid by querying the package manager
 * As of this writing uids can be shared in android, which is why the asn.1 encoded result may
 * contain more than one application attestation id.
 *
 * @returns .first the asn.1 encoded attestation application id if .second is NO_ERROR. If .second
 *          is not NO_ERROR the content of .first is undefined.
 */
std::pair<std::vector<uint8_t>, status_t> gather_attestation_application_id(uid_t uid);

}  // namespace security
}  // namespace android
#endif  // KEYSTORE_KEYSTORE_ATTESTATION_ID_H_
