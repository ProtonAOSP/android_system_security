/*
 * Copyright (C) 2012 The Android Open Source Project
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

#ifndef KEYSTORE_INCLUDE_KEYSTORE_KEYSTOREARG_H
#define KEYSTORE_INCLUDE_KEYSTORE_KEYSTOREARG_H

#include <utils/RefBase.h>

namespace android {
namespace security {

// Simple pair of generic pointer and length of corresponding data structure.
class KeystoreArg : public RefBase {
  public:
    KeystoreArg(const void* data, size_t len) : mData(data), mSize(len) {}
    ~KeystoreArg() {}

    const void* data() const { return mData; }
    size_t size() const { return mSize; }

  private:
    const void* mData;  // provider of the data must handle memory clean-up.
    size_t mSize;
};

}  // namespace security
}  // namespace android

#endif  // KEYSTORE_INCLUDE_KEYSTORE_KEYSTOREARG_H
