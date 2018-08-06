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

#include "include/keystore/KeystoreArguments.h"
#include "keystore_aidl_hidl_marshalling_utils.h"

#include <binder/Parcel.h>

namespace android {
namespace security {

using ::android::security::KeystoreArg;
using ::android::security::KeystoreArguments;

const ssize_t MAX_GENERATE_ARGS = 3;
status_t KeystoreArguments::readFromParcel(const android::Parcel* in) {
    ssize_t numArgs = in->readInt32();
    if (numArgs > MAX_GENERATE_ARGS) {
        return BAD_VALUE;
    }
    if (numArgs > 0) {
        for (size_t i = 0; i < static_cast<size_t>(numArgs); i++) {
            ssize_t inSize = in->readInt32();
            if (inSize >= 0 && static_cast<size_t>(inSize) <= in->dataAvail()) {
                sp<KeystoreArg> arg = new KeystoreArg(in->readInplace(inSize), inSize);
                args.push_back(arg);
            } else {
                args.push_back(nullptr);
            }
        }
    }
    return OK;
};

status_t KeystoreArguments::writeToParcel(android::Parcel* out) const {
    out->writeInt32(args.size());
    for (sp<KeystoreArg> item : args) {
        size_t keyLength = item->size();
        out->writeInt32(keyLength);
        void* buf = out->writeInplace(keyLength);
        memcpy(buf, item->data(), keyLength);
    }
    return OK;
}

}  // namespace security
}  // namespace android
