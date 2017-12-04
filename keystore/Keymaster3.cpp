/*
 **
 ** Copyright 2017, The Android Open Source Project
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

#include "Keymaster3.h"

#include <android-base/logging.h>

#include <keystore/keystore_hidl_support.h>

namespace keystore {

using android::hardware::hidl_string;

void Keymaster3::getVersionIfNeeded() {
    if (haveVersion_) return;

    auto rc = km3_dev_->getHardwareFeatures(
        [&](bool isSecure, bool supportsEllipticCurve, bool supportsSymmetricCryptography,
            bool supportsAttestation, bool supportsAllDigests, const hidl_string& keymasterName,
            const hidl_string& keymasterAuthorName) {
            isSecure_ = isSecure;
            supportsEllipticCurve_ = supportsEllipticCurve;
            supportsSymmetricCryptography_ = supportsSymmetricCryptography;
            supportsAttestation_ = supportsAttestation;
            supportsAllDigests_ = supportsAllDigests;
            keymasterName_ = keymasterName;
            authorName_ = keymasterAuthorName;

            if (!isSecure) {
                majorVersion_ = 3;  // SW version is 3 (don't think this should happen).
            } else if (supportsAttestation) {
                majorVersion_ = 2;  // Could be 3, no real difference.
            } else if (supportsSymmetricCryptography) {
                majorVersion_ = 1;
            } else {
                majorVersion_ = 0;
            }
        });

    CHECK(rc.isOk()) << "Got error " << rc.description() << " trying to get hardware features";
}

Keymaster::VersionResult Keymaster3::halVersion() {
    getVersionIfNeeded();
    return {ErrorCode::OK, majorVersion_, isSecure_, supportsEllipticCurve_};
}

}  // namespace keystore
