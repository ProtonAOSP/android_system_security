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

#ifndef SYSTEM_SECURITY_KEYSTORE_KEYMASTER__H_
#define SYSTEM_SECURITY_KEYSTORE_KEYMASTER__H_

#include <keystore/keymaster_types.h>

namespace keystore {

/**
 * Keymaster abstracts the underlying Keymaster device.  It will always inherit from the latest
 * keymaster HAL interface, and there will be one subclass which is a trivial passthrough, for
 * devices that actually support the latest version.  One or more additional subclasses will handle
 * wrapping older HAL versions, if needed.
 *
 * The reason for adding this additional layer, rather than simply using the latest HAL directly and
 * subclassing it to wrap any older HAL, is because this provides a place to put additional
 * methods which keystore can use when it needs to distinguish between different underlying HAL
 * versions, while still having to use only the latest interface.
 */
class Keymaster : public keymaster::IKeymasterDevice {
  public:
    virtual ~Keymaster() {}

    struct VersionResult {
        ErrorCode error;
        uint8_t majorVersion;
        SecurityLevel securityLevel;
        bool supportsEc;
    };

    virtual VersionResult halVersion() = 0;
};

}  // namespace keystore

#endif  // SYSTEM_SECURITY_KEYSTORE_KEYMASTER_DEVICE_H_
