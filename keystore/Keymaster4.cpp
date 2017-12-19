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
#include "Keymaster4.h"

#include <android-base/logging.h>

namespace keystore {

void Keymaster4::getVersionIfNeeded() {
    if (haveVersion_) return;

    auto rc = dev_->getHardwareInfo([&](SecurityLevel securityLevel, auto...) {
        securityLevel_ = securityLevel;
        haveVersion_ = true;
    });

    CHECK(rc.isOk()) << "Got error " << rc.description() << " trying to get hardware info";
}

Keymaster::VersionResult Keymaster4::halVersion() {
    getVersionIfNeeded();
    return {ErrorCode::OK, halMajorVersion(), securityLevel_, true};
}

}  // namespace keystore
